"""Run every lab attack against the live sensor and measure detection, time to detect and blocking.

    python scripts/lab_attacks.py                         # all attacks, dry-run then blocking
    python scripts/lab_attacks.py --attacks portscan --modes dry-run

For each attack and mode: start the sensor (lab/sensor/live.sh, so alerts go to the lab SOC),
record everything to and from the attacker on the sensor with tcpdump (ground truth), run the
attack script in the attacker container, wait until the sensor has reported every flow, then
read the alerts and block decisions back from the SOC. The recording is also scored offline with
the same model, which separates model mistakes from flows the live capture missed.

Needs the lab up, the model copied into the sensor (models/ is baked into the image; see
lab/README.md) and lab/.env with LAB_VICTIM_PASSWORD, LAB_SOC_CHECK_USER, LAB_SOC_CHECK_PASSWORD.
Writes reports/lab_attacks.json and prints a markdown table. Standard library only; runs on the
host. See docs/live.md, "Every lab attack".
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_benign as bb  # noqa: E402
import bench_sensor as bs  # noqa: E402

ROOT = bs.ROOT
REPORT = ROOT / "reports" / "lab_attacks.json"
MODEL = "models/week_xgboost.joblib"
ATTACKER = "10.10.1.10"
ALLOWLIST = bs.ALLOWLIST
BLOCK_TTL = 60
PCAP = "/tmp/lab_attack_truth.pcap"
FLOWS = "/tmp/lab_attack_truth.parquet"
DRAIN_MIN = 150  # flows end 120 s after their last packet
DRAIN_MAX = 600
MAX_ALERTS = 400_000
WINDOW_SLACK_MS = 10_000  # alerts for flows that ended before the run (minus this) are old ones
ALERT_FLOOR = 0.5         # the sensor's default min_alert_confidence
ATTACK_PROCS = ("nmap", "hydra", "hping3", "slowhttptest", "sqlmap", "python3")

# name -> (command in the attacker, max seconds, classes that count as the right family)
ATTACKS = {
    "portscan": ("sh /attacks/portscan.sh", 300, ("PortScan",)),
    # 200 wrong guesses before the real password: a small but real dictionary attack.
    "ssh_bruteforce": ("sh /attacks/ssh_bruteforce.sh 200", 600, ("SSH-Patator",)),
    # 2,000 SYN/s for 20 s: a flood the sensor can follow (each SYN is its own flow); an
    # unlimited --flood measures the capture limit (step 1), not the model.
    "syn_flood": ("sh /attacks/dos.sh syn u500", 60, ("DDoS", "DoS Hulk", "DoS GoldenEye",
                                                     "DoS slowloris", "DoS Slowhttptest")),
    "slow_dos": ("sh /attacks/dos.sh slow", 400, ("DoS slowloris", "DoS Slowhttptest")),
    "web_sqli": ("sh /attacks/webattack.sh", 900, ("Web Attack - Brute Force", "Web Attack - XSS",
                                                  "Web Attack - Sql Injection")),
}
MODES = ("dry-run", "blocking")

# Runs inside the sensor: score the recorded flows offline with the same model.
OFFLINE_PY = r"""
import json, sys
from idps.features import read_features
from idps.detect.bundle import load_bundle
df, meta = read_features(sys.argv[1])
a = sys.argv[3]
df = df[(df.src_ip == a) | (df.dst_ip == a)]
out = {"flows": int(len(df)), "by_class": {}, "confident_attack": 0, "attack": 0}
if len(df):
    b = load_bundle(sys.argv[2])
    p = b.predict_proba(b.select(df, meta).astype(float))
    cls = b.label_encoder.classes_[p.argmax(1)]
    conf = p.max(1)
    out["by_class"] = {str(k): int(v) for k, v in zip(*__import__("numpy").unique(cls, return_counts=True))}
    att = (cls != "BENIGN") & (conf >= float(sys.argv[4]))
    out["attack"] = int(att.sum())
    out["confident_attack"] = int((att & (conf >= 0.9)).sum())
print(json.dumps(out))
"""


def log(msg: str) -> None:
    print(f"[attacks {datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


# ---- pure helpers (unit-tested) ---------------------------------------------------------------

def _ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def attacker_alerts(alerts: list[dict], start_ms: float, attacker: str = ATTACKER) -> list[dict]:
    """Alerts of this run for flows to or from the attacker, one per flow (the SOC may hold
    duplicates). Flows that ended before the run (resent from an old outbox) are left out."""
    seen, out = set(), []
    for a in alerts:
        if attacker not in (a["src_ip"], a["dst_ip"]) or a["end_ms"] < start_ms - WINDOW_SLACK_MS:
            continue
        k = bb.alert_key(a)
        if k not in seen:
            seen.add(k)
            out.append(a)
    return out


def summarize(alerts: list[dict], *, started: datetime, truth_flows: int | None,
              family: tuple[str, ...]) -> dict:
    """Detection numbers for one run. `truth_flows`: attacker flows in the recording."""
    by_class = Counter(a["predicted_class"] for a in alerts)
    right = sum(by_class[c] for c in family)
    first = [_ts(a["received_at"]) for a in alerts if a["predicted_class"] in family]
    lat = sorted((_ts(a["received_at"]).timestamp() * 1000 - a["end_ms"]) / 1000 for a in alerts)
    conf = [a["confidence"] for a in alerts]
    return {
        "alerts": len(alerts),
        "by_class": dict(by_class.most_common()),
        "right_family": right,
        "right_family_share": round(right / len(alerts), 4) if alerts else None,
        # Share of the attacker's recorded flows alerted in the right family / as any attack.
        "detection_rate": round(right / truth_flows, 4) if truth_flows else None,
        "any_attack_rate": round(len(alerts) / truth_flows, 4) if truth_flows else None,
        "time_to_first_alert_s": round((min(first) - started).total_seconds(), 1) if first else None,
        "flow_end_to_soc_p50_s": round(statistics.median(lat), 1) if lat else None,
        "confidence_median": round(statistics.median(conf), 4) if conf else None,
        "confident_share": round(sum(c >= 0.9 for c in conf) / len(conf), 4) if conf else None,
    }


def detected(entry: dict) -> bool:
    """An attack counts as detected when at least one alert is in the right family."""
    return bool(entry.get("live", {}).get("right_family"))


def build_table(entries: list[dict]) -> str:
    rows = ["| Attack | Mode | Attacker flows | Alerts | Detection rate | Right family | Main class "
            "| First alert (s) | Offline attack share | Block |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for e in entries:
        lv, off = e.get("live", {}), e.get("offline", {})
        main = next(iter(lv.get("by_class", {})), "—")
        ttd = lv.get("time_to_first_alert_s")
        share = (f"{off['attack'] / off['flows']:.1%}" if off.get("flows") else "—")
        rate = lv.get("detection_rate")
        fam = lv.get("right_family_share")
        rows.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            e["attack"], e["mode"], off.get("flows", "—"), lv.get("alerts", "—"),
            "—" if rate is None else f"{rate:.1%}", "—" if fam is None else f"{fam:.1%}", main,
            "—" if ttd is None else ttd, share, e.get("block", {}).get("summary", "—")))
    return "\n".join(rows)


# ---- lab actions ------------------------------------------------------------------------------

def sh(service: str, script: str, timeout: float = 120, check: bool = False,
       secrets: dict | None = None) -> subprocess.CompletedProcess:
    """`secrets` go to the container as `-e NAME` (value from this process's environment), so
    they never appear in a command line."""
    names = [x for k in (secrets or {}) for x in ("-e", k)]
    return subprocess.run(["docker", "compose", "exec", "-T", *names, service, "sh", "-c", script],
                          cwd=bs.LAB, env={**bs._env(), **(secrets or {})}, text=True,
                          errors="replace", capture_output=True, check=check, timeout=timeout)


def in_set(nft_output: str, ip: str = ATTACKER) -> bool:
    """Whether `ip` is an element of a `nft list set` listing (10.10.1.100 does not count)."""
    return re.search(r"(?<![\d.])" + re.escape(ip) + r"(?![\d.])", nft_output) is not None


def blocked_now() -> bool | None:
    """True/False, or None when nft could not be asked."""
    r = sh("sensor", "nft list set inet idps blocked4", timeout=30)
    return in_set(r.stdout) if r.returncode == 0 else None


def sensor_ms() -> int:
    """The Docker VM's clock (sensor, SOC and alert times all use it), in ms."""
    return int(sh("sensor", "date +%s%3N", timeout=30, check=True).stdout.strip())


def probe() -> str:
    """HTTP status the attacker gets from the victim ('000' = no answer)."""
    try:
        r = sh("attacker", "curl -s -m 3 -o /dev/null -w %{http_code} http://10.10.2.10/", timeout=30)
    except subprocess.TimeoutExpired:
        return "000"
    return r.stdout.strip() or "000"


def kill_attack() -> None:
    sh("attacker", "for p in " + " ".join(ATTACK_PROCS) + "; do kill $(pidof $p) 2>/dev/null; done; true",
       timeout=30)


class BlockWatch(threading.Thread):
    """Polls the sensor's nftables set; on the first block, checks the attacker is cut off."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.first_block_ms: int | None = None
        self.probe_blocked: str | None = None
        self.nft_errors = 0

    def run(self) -> None:
        while not self.stop.wait(2):
            try:
                on = blocked_now()
                if on is None:
                    self.nft_errors += 1
                elif on and self.first_block_ms is None:
                    self.first_block_ms = sensor_ms()
                    self.probe_blocked = probe()
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError):
                self.nft_errors += 1


class LiveSensor(bb.RunSensor):
    """RunSensor (tolerant log reader, stop() that waits) with this script's model and mode. Both
    modes use the same 60 s block time, so dry-run would-blocks compare with real blocks."""

    def __init__(self, duration: int, blocking: bool) -> None:  # noqa: D107
        env = ["-e", f"IDPS_ALLOWLIST={ALLOWLIST}", "-e", f"IDPS_BLOCK_TTL_SECONDS={BLOCK_TTL}"]
        if blocking:
            env += ["-e", "IDPS_DRY_RUN=false"]
        cmd = ["docker", "compose", "exec", "-T", *env, "sensor", "live.sh", "--interface",
               bs.INTERFACE, "--model", MODEL, "--duration", str(duration)]
        self.proc = subprocess.Popen(cmd, cwd=bs.LAB, env=bs._env(), text=True, errors="replace",
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.metrics, self.lines = [], []
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()


def extract_cmd(pcap: str = PCAP, flows: str = FLOWS) -> str:
    """Shell command (run in the sensor) that extracts the flows of a pcap with the same features and
    backend the live sensor uses; NFStream cuts the flows still open at the end of the file."""
    return f"python -m idps.features extract {pcap} -o {flows} --backend nfstream"


def tcpdump_pattern(pcap: str = PCAP) -> str:
    """Regex for `pgrep -f` / `pkill -f` that matches the tcpdump writing `pcap` and not the shell that
    runs pgrep (the bracket keeps the pattern from matching its own command line)."""
    return f"[t]cpdump .*-w {pcap}"


def tcpdump_running(pcap: str = PCAP) -> bool:
    return sh("sensor", f"pgrep -f '{tcpdump_pattern(pcap)}'", timeout=30).returncode == 0


def start_tcpdump(pcap: str = PCAP, host: str = ATTACKER, old_wait: float = 15) -> None:
    """Record everything to and from `host` in the sensor into `pcap`. Waits for an earlier tcpdump
    writing the same file to exit first; raises if that does not happen or the new one did not start."""
    end = time.monotonic() + old_wait
    while tcpdump_running(pcap):
        if time.monotonic() > end:
            raise RuntimeError(f"an earlier tcpdump writing {pcap} is still running in the sensor")
        time.sleep(1)
    bs.compose("exec", "-d", "sensor", "tcpdump", "-i", bs.INTERFACE, "-s", "0", "-U", "-w", pcap,
               "host", host)
    time.sleep(2)
    if not tcpdump_running(pcap):
        raise RuntimeError("tcpdump did not start in the sensor")


def offline(model: str) -> dict:
    r = sh("sensor", f"{extract_cmd()} >/dev/null 2>&1 && python -c '{OFFLINE_PY}' {FLOWS} {model} "
                     f"{ATTACKER} {ALERT_FLOOR}",
           timeout=900)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {"error": (r.stderr or r.stdout)[-500:]}


def run_one(name: str, mode: str, soc: bb.Soc, env: dict) -> dict:
    cmd, max_s, family = ATTACKS[name]
    blocking = mode == "blocking"
    log(f"{name} ({mode})")
    entry: dict = {"attack": name, "mode": mode, "command": cmd, "model": MODEL, "family": list(family)}
    waiting = bb.outbox_file_alerts()
    if waiting:
        raise RuntimeError(f"{waiting} alert(s) are waiting in the sensor outbox from an earlier run")
    sh("sensor", "nft flush set inet idps blocked4; pkill -INT tcpdump; rm -f /tmp/lab_attack_truth.*")
    kill_attack()
    sensor = LiveSensor(max_s + DRAIN_MAX + 120, blocking)
    watch = BlockWatch() if blocking else None
    try:
        sensor.wait_ready()
        start_tcpdump()
        entry["probe_before"] = probe() if blocking else None
        start_ms = sensor_ms()
        started = datetime.fromtimestamp(start_ms / 1000, UTC)
        if watch:
            watch.start()
        t0 = time.monotonic()
        try:
            r = sh("attacker", cmd, timeout=max_s,
                   secrets={"LAB_VICTIM_PASSWORD": env["LAB_VICTIM_PASSWORD"]}
                   if name == "ssh_bruteforce" else None)
            entry["attack_exit"] = r.returncode
        except subprocess.TimeoutExpired:
            entry["attack_exit"] = "timeout"
        entry["attack_seconds"] = round(time.monotonic() - t0, 1)
        end_ms = sensor_ms()
        kill_attack()
        log(f"  attack ended after {entry['attack_seconds']} s (exit {entry['attack_exit']}); draining")
        entry["drained"] = sensor.wait_drained(DRAIN_MIN, DRAIN_MAX)
        if watch:
            # Let the last block expire, then check the attacker is let through again.
            expired = None
            for _ in range(BLOCK_TTL + 30):
                if blocked_now() is False:
                    expired = sensor_ms()
                    break
                time.sleep(1)
            watch.stop.set()
            watch.join(timeout=40)
            fb = watch.first_block_ms
            entry["block"] = {
                "first_block_s": None if fb is None else round((fb - start_ms) / 1000, 1),
                "blocked_while_attack_ran": fb is not None and fb <= end_ms,
                "probe_before": entry.pop("probe_before"),
                "probe_while_blocked": watch.probe_blocked,
                "probe_after_expiry": probe() if expired else None,
                "expired": expired is not None,
                "nft_errors": watch.nft_errors,
            }
    finally:
        if watch:
            watch.stop.set()
        sensor.stop()
        sh("sensor", "pkill -INT tcpdump")
        kill_attack()
    entry["live_flows"] = sensor.metrics[-1]["flows"] if sensor.metrics else None
    entry["offline"] = offline(MODEL)
    soc.login()
    raw = soc.pages("/alerts", {"ip": ATTACKER, "since": (started - timedelta(seconds=5)).isoformat(),
                                "until": datetime.now(UTC).isoformat()}, max_items=MAX_ALERTS)
    entry["alerts_truncated"] = soc.truncated
    alerts = attacker_alerts(raw, start_ms)
    entry["live"] = summarize(alerts, started=started, truth_flows=entry["offline"].get("flows"),
                              family=family)
    entry["live"]["attack_ended_s"] = round((end_ms - start_ms) / 1000, 1)
    wb = [w for w in soc.would_blocks_since(started, 1) if w.get("ip") == ATTACKER]
    if blocking:
        b = entry["block"]
        b["summary"] = (f"blocked at {b['first_block_s']:.0f} s, HTTP {b['probe_before']} -> "
                        f"{b['probe_while_blocked']} -> {b['probe_after_expiry']}"
                        if b["first_block_s"] is not None else "no block")
    else:
        first = min((_ts(w["at"]) for w in wb), default=None)
        entry["block"] = {"would_block": len(wb),
                          "first_would_block_s": None if first is None
                          else round((first - started).total_seconds(), 1),
                          "summary": f"would block ({len(wb)})" if wb else "no would-block"}
    lv = entry["live"]
    log(f"  {lv['alerts']} alerts ({lv['by_class']}), offline {entry['offline']}, {entry['block']['summary']}")
    return entry


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--attacks", nargs="+", choices=list(ATTACKS), default=list(ATTACKS))
    ap.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES))
    ap.add_argument("-o", "--output", type=Path, default=REPORT)
    args = ap.parse_args(argv)
    env = bb.parse_env((bs.LAB / ".env").read_text())
    for k in ("LAB_VICTIM_PASSWORD", "LAB_SOC_CHECK_USER", "LAB_SOC_CHECK_PASSWORD"):
        if not env.get(k):
            print(f"{k} missing in lab/.env", file=sys.stderr)
            return 2
    if bs.sensor_running():
        print("a sensor loop (idps.live) is already running in the lab; stop it first", file=sys.stderr)
        return 2
    soc = bb.Soc(env["LAB_SOC_CHECK_USER"], env["LAB_SOC_CHECK_PASSWORD"], bb.fetch_ca())
    soc.login()
    entries = []
    for mode in args.modes:
        for name in args.attacks:
            try:
                entries.append(run_one(name, mode, soc, env))
            except Exception as exc:  # noqa: BLE001  record it and go on with the next attack
                log(f"  {name} ({mode}) failed: {exc!r}")
                entries.append({"attack": name, "mode": mode, "error": repr(exc)})
            args.output.write_text(json.dumps({"model": MODEL, "runs": entries}, indent=2) + "\n")
    print(build_table(entries))
    print(f"\nwrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
