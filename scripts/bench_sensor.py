"""Benchmark the live sensor in the Docker lab: replay a sample of the Friday capture at several
rates and record flows/s, capture ratio, CPU, memory and alert latency.

    python scripts/bench_sensor.py                      # 10, 50, 100, 200 Mbit/s
    python scripts/bench_sensor.py --rates 50           # a short smoke test
    python scripts/bench_sensor.py --prepare-only       # only make the sample and count its flows

Needs the lab up (`docker compose up -d --build` in lab/) and the Friday capture at
data/raw/pcap/Friday-WorkingHours.pcap (only to cut the sample; the whole file is never copied).
Writes reports/perf.json and prints a markdown table. Standard library only; runs on the host.
See docs/live.md, "Performance benchmark".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "lab"
FRIDAY = ROOT / "data" / "raw" / "pcap" / "Friday-WorkingHours.pcap"
SAMPLE = ROOT / "data" / "processed" / "bench_sample.pcap"
SAMPLE_META = ROOT / "data" / "processed" / "bench_sample.json"
REPORT = ROOT / "reports" / "perf.json"
WIRESHARK = Path("/Applications/Wireshark.app/Contents/MacOS")
DOCKER_BIN = "/Applications/Docker.app/Contents/Resources/bin"

# Time windows (UTC, as in the CIC-IDS2017 labels) of the Friday afternoon: four minutes of the
# PortScan burst and sixteen of the DDoS. Together a few hundred MB with real alerts of both classes.
WINDOWS = [("2017-07-07 17:52:00", "2017-07-07 17:56:00"),
           ("2017-07-07 18:56:00", "2017-07-07 19:12:00")]

TCPDUMP = "/usr/sbin/tcpdump"
MAX_FRAME = 1514  # largest Ethernet frame the lab links carry (MTU 1500 plus the header)
SENSOR = "idps-sensor"
INTERFACE = "lab_attack"
MODEL = "models/friday_xgboost.joblib"
ALLOWLIST = "10.10.1.1,10.10.1.2,10.10.2.0/24,10.10.3.0/24"
REMOTE_SAMPLE = "/tmp/bench_sample.pcap"
MIN_FLUSH_SECONDS = 130  # never stop sooner than the 120 s idle timeout plus a margin after the replay
FLUSH_SECONDS = 600      # upper limit for the wait after the replay (the sensor's --duration cap)
PLATEAU_LINES = 4        # flows unchanged over this many metrics lines (about 40 s): drained
STARTUP_SECONDS = 45   # allowance for the sensor to load the model and print 2 metrics lines
READY_TIMEOUT = 90
STATS_INTERVAL = 2.0
BUSY_TAIL_SECONDS = 10  # CPU is averaged over the replay plus this long after it


# ---- pure parsing and formatting (unit-tested) ------------------------------------------------

def parse_tcpreplay(text: str) -> dict:
    """Numbers from tcpreplay's closing report. Missing lines give None."""
    out = {"packets_sent": None, "bytes_sent": None, "seconds": None, "mbps": None, "pps": None,
           "failed_packets": None}
    m = re.search(r"Actual:\s+(\d+)\s+packets\s+\((\d+)\s+bytes\)\s+sent in\s+([\d.]+)\s+seconds", text)
    if m:
        out.update(packets_sent=int(m[1]), bytes_sent=int(m[2]), seconds=float(m[3]))
    m = re.search(r"Rated:.*?([\d.]+)\s+Mbps,\s+([\d.]+)\s+pps", text)
    if m:
        out.update(mbps=float(m[1]), pps=float(m[2]))
    m = re.search(r"Failed packets:\s+(\d+)", text)
    if m:
        out["failed_packets"] = int(m[1])
    return out


_UNITS = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "kib": 1024, "mib": 1024**2, "gib": 1024**3}


def parse_size_mib(text: str) -> float | None:
    """'123.4MiB', '1.5GiB', '900kB' -> MiB."""
    m = re.fullmatch(r"\s*([\d.]+)\s*([A-Za-z]+)\s*", text or "")
    if not m or m[2].lower() not in _UNITS:
        return None
    return float(m[1]) * _UNITS[m[2].lower()] / 1024**2


def parse_docker_stats(line: str) -> dict | None:
    """One `docker stats --no-stream --format '{{json .}}'` line -> {cpu_pct, mem_mib}."""
    try:
        d = json.loads(line)
        cpu = float(str(d["CPUPerc"]).strip().rstrip("%"))
        mem = parse_size_mib(str(d["MemUsage"]).split("/")[0])
    except (ValueError, KeyError, TypeError):
        return None
    return None if mem is None else {"cpu_pct": cpu, "mem_mib": mem}


def parse_metrics_line(line: str) -> dict | None:
    """A sensor log line holding the JSON 'metrics' event (maybe behind a log prefix)."""
    start = line.find("{")
    if start < 0 or '"metrics"' not in line:
        return None
    try:
        d = json.loads(line[start:])
    except ValueError:
        return None
    return d if isinstance(d, dict) and d.get("event") == "metrics" else None


def parse_cgroup_sample(text: str) -> dict | None:
    """`usage_usec N` (cpu.stat), then memory.current and inactive_file (bytes) -> raw numbers."""
    m = re.search(r"usage_usec\s+(\d+)\s+(\d+)\s+inactive_file\s+(\d+)", text)
    if not m:
        return None
    return {"usage_usec": int(m[1]),
            "mem_mib": max(int(m[2]) - int(m[3]), 0) / 1024**2}  # what `docker stats` shows


def cgroup_cpu_pct(prev: dict, cur: dict, wall_s: float) -> float:
    """CPU % in docker's convention (100 = one core) from two cgroup samples."""
    return round((cur["usage_usec"] - prev["usage_usec"]) / (wall_s * 1e6) * 100, 2) if wall_s > 0 else 0.0


def summarize_stats(busy: list[dict], everything: list[dict] | None = None) -> dict:
    """CPU mean/max over `busy` (the samples while traffic is arriving: the flush wait is idle and
    would dilute the mean); peak memory over all samples."""
    everything = busy if everything is None else everything
    if not busy and not everything:
        return {"source": None, "cpu_mean_pct": None, "cpu_max_pct": None, "mem_max_mib": None,
                "samples": 0, "busy_samples": 0}
    cpu = [x["cpu_pct"] for x in busy]
    return {"source": (everything or busy)[0].get("source", "docker stats"),
            "cpu_mean_pct": round(statistics.fmean(cpu), 1) if cpu else None,
            "cpu_max_pct": round(max(cpu), 1) if cpu else None,
            "mem_max_mib": round(max(x["mem_mib"] for x in everything), 1) if everything else None,
            "samples": len(everything), "busy_samples": len(busy)}


def parse_net_counters(text: str) -> dict:
    """`rx_packets rx_dropped rx_errors softnet_dropped` as four integers on one line."""
    parts = text.split()
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return {}
    return dict(zip(("rx_packets", "rx_dropped", "rx_errors", "softnet_dropped"),
                    map(int, parts), strict=True))


def counter_delta(before: dict, after: dict) -> dict:
    return {k: after[k] - before[k] for k in before if k in after}


def capture_ratio(live_flows: int | None, offline_flows: int | None) -> float | None:
    if live_flows is None or not offline_flows:
        return None
    return round(live_flows / offline_flows, 4)


def drained(flow_counts: list[int], plateau: int = PLATEAU_LINES) -> bool:
    """True when the flow counter of the last `plateau` metrics lines did not move: everything the
    sensor was going to score has been scored (flows only appear when they expire or time out)."""
    return len(flow_counts) > plateau and len(set(flow_counts[-(plateau + 1):])) == 1


def estimate_duration(sample_bytes: int, mbit: float, flush: float = FLUSH_SECONDS) -> int:
    """Sensor --duration cap: start-up, the replay (with 25% slack), then at most `flush` seconds.
    The run normally ends sooner: the script stops the sensor once it has drained."""
    replay = sample_bytes * 8 / (mbit * 1e6) * 1.25 + 10
    return int(STARTUP_SECONDS + replay + flush)


def build_entry(rate: float, replay: dict, final: dict, peak_fps: float | None, stats: dict,
                offline_flows: int | None, net: dict) -> dict:
    lat = final.get("latency_flow_end_to_alert_s") or {}
    shap = final.get("shap_ms_per_alert") or {}
    dropped = final.get("dropped") or {}
    return {
        "target_mbit_s": rate,
        "replay": replay,
        "flows": final.get("flows"),
        "flows_per_s_mean": final.get("flows_per_s"),
        "flows_per_s_peak": peak_fps,
        "alerts": final.get("alerts"),
        "alerts_sent": final.get("alerts_sent"),
        "dropped": dropped,
        "errors": final.get("errors"),
        "latency_p50_s": lat.get("p50"),
        "latency_p95_s": lat.get("p95"),
        "shap_p50_ms": shap.get("p50"),
        "shap_p95_ms": shap.get("p95"),
        "stats_source": stats.get("source"),
        "cpu_mean_pct": stats["cpu_mean_pct"],
        "cpu_max_pct": stats["cpu_max_pct"],
        "mem_max_mib": stats["mem_max_mib"],
        "offline_flows": offline_flows,
        "capture_ratio": capture_ratio(final.get("flows"), offline_flows),
        "interface_delta": net,
    }


def _fmt(v, nd=1) -> str:
    if v is None:
        return "n/a"
    return f"{v:.{nd}f}" if isinstance(v, float) else str(v)


def build_table(entries: list[dict]) -> str:
    """Markdown table, one row per rate."""
    head = ["Target Mbit/s", "Actual Mbit/s", "Packets sent", "Flows", "Capture ratio",
            "Peak flows/s", "Alerts", "Sent to SOC", "Dropped (alerts)", "Latency p50/p95 (s)",
            "SHAP p95 (ms)", "CPU replay mean/max (%)", "CPU drain mean (%)", "Mem max (MiB)",
            "Drained"]
    rows = []
    for e in entries:
        rp = e.get("replay") or {}
        drop = (e.get("dropped") or {}).get("alerts")
        rows.append([
            _fmt(e["target_mbit_s"], 0), _fmt(rp.get("mbps"), 1), _fmt(rp.get("packets_sent")),
            _fmt(e.get("flows")), _fmt(e.get("capture_ratio"), 3),
            _fmt(e.get("flows_per_s_peak"), 0), _fmt(e.get("alerts")), _fmt(e.get("alerts_sent")),
            _fmt(drop), f"{_fmt(e.get('latency_p50_s'))}/{_fmt(e.get('latency_p95_s'))}",
            _fmt(e.get("shap_p95_ms"), 2),
            f"{_fmt(e.get('cpu_mean_pct'))}/{_fmt(e.get('cpu_max_pct'))}",
            _fmt(e.get("cpu_drain_mean_pct")), _fmt(e.get("mem_max_mib"), 0),
            {True: "yes", False: "no"}.get(e.get("drained"), "–")])
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(lines)


# ---- running things ---------------------------------------------------------------------------

def _env() -> dict:
    env = dict(os.environ)
    if shutil.which("docker") is None:
        env["PATH"] = env.get("PATH", "") + os.pathsep + DOCKER_BIN
    return env


def compose(*args: str, check: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", *args], cwd=LAB, env=_env(), text=True,
                          capture_output=True, check=check, timeout=timeout)


def log(msg: str) -> None:
    print(f"[bench {datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def _local(utc_text: str) -> str:
    """editcap reads times as local time; the windows are written in UTC."""
    t = datetime.strptime(utc_text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    return t.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def count_packets(path: Path) -> int | None:
    capinfos = WIRESHARK / "capinfos"
    if not capinfos.exists():
        return None
    out = subprocess.run([str(capinfos), "-c", "-M", str(path)], text=True, capture_output=True).stdout
    m = re.search(r"Number of packets:\s+([\d,]+)", out)
    return int(m[1].replace(",", "")) if m else None


def make_sample(force: bool = False) -> None:
    if SAMPLE.exists() and SAMPLE_META.exists() and not force:
        return
    if not FRIDAY.exists():
        sys.exit(f"missing {FRIDAY}")
    editcap, mergecap = WIRESHARK / "editcap", WIRESHARK / "mergecap"
    if not editcap.exists() or not mergecap.exists():
        sys.exit("Wireshark's editcap/mergecap not found; install Wireshark")
    parts = []
    try:
        for i, (a, b) in enumerate(WINDOWS):
            part = SAMPLE.with_suffix(f".part{i}.pcap")
            log(f"cutting {a} .. {b} UTC from the Friday capture (scans the whole file)")
            subprocess.run([str(editcap), "-F", "pcap", "-A", _local(a), "-B", _local(b),
                            str(FRIDAY), str(part)], check=True)
            parts.append(part)
        merged = SAMPLE.with_suffix(".merged.pcap")
        parts.append(merged)
        subprocess.run([str(mergecap), "-F", "pcap", "-w", str(merged), *map(str, parts[:-1])],
                       check=True)
        # The capture was taken with offloading on, so it holds frames larger than the 1500-byte
        # MTU (up to 64 KB). tcpreplay's TX ring cannot send them and stalls, so they are dropped
        # here; the offline ground truth is counted on the same file.
        subprocess.run([TCPDUMP, "-r", str(merged), "-w", str(SAMPLE), f"less {MAX_FRAME}"],
                       check=True, capture_output=True)
    finally:
        for p in parts:
            p.unlink(missing_ok=True)
    SAMPLE_META.write_text(json.dumps({"windows_utc": WINDOWS}))
    log(f"sample: {SAMPLE} ({SAMPLE.stat().st_size / 1e6:.0f} MB)")


def sample_info() -> dict:
    info = {"path": str(SAMPLE.relative_to(ROOT)), "size_bytes": SAMPLE.stat().st_size,
            "packets": count_packets(SAMPLE), "sha256": sha256_of(SAMPLE),
            "windows_utc": WINDOWS}
    return info


def offline_flow_count(info: dict) -> int:
    """Ground truth: the project's own extractor (NFStream, 120 s timeouts) in the sensor image."""
    log("extracting the sample offline in the sensor container (ground-truth flow count)")
    compose("cp", str(SAMPLE), f"sensor:{REMOTE_SAMPLE}")
    code = ("import pandas as pd;print('FLOWS', len(pd.read_parquet('/tmp/bench_flows.parquet')))")
    compose("exec", "-T", "sensor", "sh", "-c",
            f"python -m idps.features extract {REMOTE_SAMPLE} -o /tmp/bench_flows.parquet "
            f"--backend nfstream >/dev/null 2>&1 && python -c \"{code}\"")
    out = compose("exec", "-T", "sensor", "sh", "-c",
                  f"python -c \"{code}\"; rm -f {REMOTE_SAMPLE} /tmp/bench_flows.parquet").stdout
    m = re.search(r"FLOWS (\d+)", out)
    if not m:
        sys.exit("could not count the offline flows")
    return int(m[1])


NET_SCRIPT = (
    "import sys;d='/sys/class/net/%s/statistics/'%sys.argv[1];"
    "r=lambda n:open(d+n).read().strip();"
    "sn=sum(int(l.split()[1],16) for l in open('/proc/net/softnet_stat'));"
    "print(r('rx_packets'),r('rx_dropped'),r('rx_errors'),sn)")


def read_net() -> dict:
    r = compose("exec", "-T", "sensor", "python", "-c", NET_SCRIPT, INTERFACE, check=False)
    return parse_net_counters(r.stdout)


CGROUP_SH = ("grep usage_usec /sys/fs/cgroup/cpu.stat; cat /sys/fs/cgroup/memory.current; "
             "grep '^inactive_file ' /sys/fs/cgroup/memory.stat")


SENSOR_EXTRA_ARGS: list[str] = []  # set from --batch-size


class Sensor:
    """The live sensor process in the container, with its log lines collected."""

    def __init__(self, duration: int) -> None:
        cmd = ["docker", "compose", "exec", "-T", "-e", f"IDPS_ALLOWLIST={ALLOWLIST}", "sensor",
               "live.sh", "--interface", INTERFACE, "--model", MODEL, "--duration", str(duration), *SENSOR_EXTRA_ARGS]
        self.proc = subprocess.Popen(cmd, cwd=LAB, env=_env(), text=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
        self.metrics: list[dict] = []
        self.lines: list[str] = []
        self._thread = threading.Thread(target=self._read, daemon=True)
        self._thread.start()

    def _read(self) -> None:
        for line in self.proc.stdout:
            self.lines.append(line.rstrip())
            m = parse_metrics_line(line)
            if m:
                self.metrics.append(m)

    def wait_ready(self, timeout: float = READY_TIMEOUT) -> None:
        end = time.monotonic() + timeout
        while len(self.metrics) < 2:
            if self.proc.poll() is not None or time.monotonic() > end:
                tail = "\n".join(self.lines[-15:])
                raise RuntimeError(f"sensor not ready (needs 2 metrics lines):\n{tail}")
            time.sleep(0.5)

    def wait_drained(self, min_wait: float, max_wait: float) -> bool:
        """Wait until the flow counter stops moving (after at least `min_wait` s). True if it did,
        False if `max_wait` ran out or the sensor exited first."""
        start = time.monotonic()
        while time.monotonic() - start < max_wait and self.proc.poll() is None:
            if time.monotonic() - start >= min_wait and drained([m["flows"] for m in self.metrics]):
                return True
            time.sleep(1)
        return False

    def wait_done(self, timeout: float) -> None:
        self.proc.wait(timeout=timeout)
        self._thread.join(timeout=5)

    def stop(self) -> None:
        """End the sensor inside the container too (killing `docker exec` does not)."""
        compose("exec", "-T", "sensor", "pkill", "-TERM", "-f", "idps.live", check=False, timeout=30)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            compose("exec", "-T", "sensor", "pkill", "-KILL", "-f", "idps.live", check=False, timeout=30)


class StatsSampler(threading.Thread):
    """CPU % and memory of the sensor container every ~2 s.

    Uses `docker stats`. In some Docker Desktop states it reports 0 B / 0 PIDs for a container
    that is running; then the sample comes from the container's own cgroup files instead (the
    same numbers docker would show), and the report says which source was used."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.samples: list[dict] = []
        self._stop_evt = threading.Event()
        self._prev: tuple[float, dict] | None = None

    def _docker_stats(self) -> dict | None:
        r = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}", SENSOR],
                           env=_env(), text=True, capture_output=True)
        lines = r.stdout.strip().splitlines()
        s = parse_docker_stats(lines[0]) if lines else None
        return {**s, "source": "docker stats"} if s and s["mem_mib"] > 0 else None

    def _cgroup(self) -> dict | None:
        now = time.monotonic()
        r = compose("exec", "-T", "sensor", "sh", "-c", CGROUP_SH, check=False, timeout=20)
        cur = parse_cgroup_sample(r.stdout.replace("\n", " "))
        if cur is None:
            return None
        prev, self._prev = self._prev, (now, cur)
        if prev is None:
            return None  # a rate needs two samples
        return {"cpu_pct": cgroup_cpu_pct(prev[1], cur, now - prev[0]), "mem_mib": cur["mem_mib"],
                "source": "cgroup"}

    def run(self) -> None:
        use_cgroup = False
        while not self._stop_evt.is_set():
            t0 = time.monotonic()
            try:
                s = self._cgroup() if use_cgroup else self._docker_stats()
                if s is None and not use_cgroup and not self.samples:
                    use_cgroup = True  # docker stats gives nothing usable: switch for the run
                    s = self._cgroup()
            except (subprocess.SubprocessError, OSError):
                s = None
            if s:
                self.samples.append({**s, "t": time.monotonic()})
            self._stop_evt.wait(max(0.0, STATS_INTERVAL - (time.monotonic() - t0)))

    def finish(self) -> list[dict]:
        self._stop_evt.set()
        self.join(timeout=30)
        return self.samples


def stop_replay() -> None:
    """End a tcpreplay left running in the attacker (killing `docker exec` does not)."""
    compose("exec", "-T", "attacker", "sh", "-c", "kill $(pidof tcpreplay-edit) 2>/dev/null; true",
            check=False, timeout=30)


def sensor_running() -> bool:
    r = compose("exec", "-T", "sensor", "pgrep", "-f", "idps.live", check=False)
    return r.returncode == 0 and bool(r.stdout.strip())


def run_rate(rate: float, size_bytes: int, offline_flows: int | None, flush: float) -> dict:
    duration = estimate_duration(size_bytes, rate, flush)
    log(f"rate {rate:g} Mbit/s: sensor --duration {duration} s")
    sensor = Sensor(duration)
    sampler = StatsSampler()
    try:
        sensor.wait_ready()
        log("sensor ready (2 metrics lines seen); replaying")
        before = read_net()
        sampler.start()
        t_start = time.monotonic()
        r = compose("exec", "-T", "attacker", "/attacks/replay.sh", REMOTE_SAMPLE, f"{rate:g}",
                    check=False, timeout=duration)
        replay_text = r.stdout + r.stderr
        replay = parse_tcpreplay(replay_text)
        if r.returncode != 0 or replay["packets_sent"] is None:
            raise RuntimeError(f"replay failed (exit {r.returncode}):\n{replay_text[-800:]}")
        t_end = time.monotonic()
        after = read_net()
        mismatch = (rate <= 100 and replay["mbps"] is not None
                    and abs(replay["mbps"] - rate) / rate > 0.15)
        if mismatch:  # e.g. a stale attacker image that ignores the rate argument
            log(f"WARNING: asked for {rate:g} Mbit/s, tcpreplay reports {replay['mbps']} Mbit/s")
        log(f"replayed {replay['packets_sent']} packets at {replay['mbps']} Mbit/s; "
            f"waiting for the sensor to drain (flow count steady for ~{PLATEAU_LINES * 10} s, "
            f"at least {MIN_FLUSH_SECONDS} s, at most {flush:g} s)")
        is_drained = sensor.wait_drained(MIN_FLUSH_SECONDS, flush)
        log("drained" if is_drained else "NOT drained (limit reached): flows may be incomplete")
        sensor.stop()  # SIGTERM: the sensor prints its final metrics line on the way out
        sensor.wait_done(timeout=60)
    finally:
        stop_replay()  # normally already finished; matters after a timeout or Ctrl-C
        samples = sampler.finish() if sampler.is_alive() or sampler.samples else []
        sensor.stop()
    if not sensor.metrics:
        raise RuntimeError("sensor printed no metrics")
    final = sensor.metrics[-1]
    peak = max((m.get("flows_per_s") or 0.0) for m in sensor.metrics[:-1] or sensor.metrics)
    net = counter_delta(before, after) if before and after else {}
    busy = [x for x in samples if t_start <= x["t"] <= t_end + BUSY_TAIL_SECONDS]
    entry = build_entry(rate, replay, final, peak, summarize_stats(busy, samples), offline_flows, net)
    drain = [x for x in samples if x["t"] > t_end + BUSY_TAIL_SECONDS]
    entry["cpu_drain_mean_pct"] = summarize_stats(drain, samples)["cpu_mean_pct"] if drain else None
    entry["rate_mismatch"] = mismatch
    entry["drained"] = is_drained
    entry["sensor_duration_s"] = duration
    entry["flows_timeline"] = [[m.get("uptime_s"), m.get("flows")] for m in sensor.metrics]
    return entry


def write_report(path: Path, info: dict, offline_flows: int | None, entries: list[dict]) -> None:
    path.parent.mkdir(exist_ok=True)
    doc = {"generated": datetime.now(UTC).isoformat(timespec="seconds"),
           "sample": {**info, "offline_flows": offline_flows},
           "notes": ("latency percentiles are over the sensor's last 2,000 alerts (its metrics window), "
                     "so for runs with more alerts they describe the end of the drain. "
                     "cpu_mean_pct/cpu_max_pct cover the replay plus 10 s; cpu_drain_mean_pct the "
                     "rest. capture_ratio = live flows / offline flows of the same sample (NFStream, "
                     "120 s timeouts); the sensor does not expose NFStream's own drop counter, "
                     "so interface_delta (rx_packets, rx_dropped, rx_errors, softnet_dropped "
                     "deltas of lab_attack during the replay) is reported next to it."),
           "sensor_args": list(SENSOR_EXTRA_ARGS),
           "rates": entries}
    path.write_text(json.dumps(doc, indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rates", default="10,50,100,200",
                    help="comma-separated Mbit/s (default 10,50,100,200)")
    ap.add_argument("--flush-seconds", type=float, default=FLUSH_SECONDS,
                    help="most the script waits after the replay for the sensor to drain "
                         "(default %(default)s; it stops earlier once the flow count is steady)")
    ap.add_argument("--rebuild-sample", action="store_true", help="cut the sample again")
    ap.add_argument("--prepare-only", action="store_true",
                    help="make the sample and count its offline flows, then stop")
    ap.add_argument("--batch-size", type=int,
                    help="the sensor's micro-batch size (its default is 64); recorded in the report")
    ap.add_argument("-o", "--output", type=Path, default=REPORT)
    args = ap.parse_args(argv)
    if args.batch_size is not None:
        if args.batch_size < 1:
            print("--batch-size must be at least 1", file=sys.stderr)
            return 2
        SENSOR_EXTRA_ARGS[:] = ["--batch-size", str(args.batch_size)]
    try:
        rates = [float(r) for r in args.rates.split(",") if r.strip()]
    except ValueError:
        print("bad --rates", file=sys.stderr)
        return 2
    if not rates or any(r <= 0 for r in rates):
        print("--rates needs positive numbers", file=sys.stderr)
        return 2

    make_sample(args.rebuild_sample)
    info = sample_info()
    log(f"sample {info['size_bytes'] / 1e6:.0f} MB, {info['packets']} packets, "
        f"sha256 {info['sha256'][:12]}")
    if sensor_running():
        print("a live sensor is already running in the container; stop it first", file=sys.stderr)
        return 1
    offline = offline_flow_count(info)
    log(f"offline flows: {offline}")
    if args.prepare_only:
        return 0

    compose("cp", str(SAMPLE), f"attacker:{REMOTE_SAMPLE}")
    entries: list[dict] = []
    interrupted = False

    def on_sigterm(_s, _f):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_sigterm)
    try:
        for rate in rates:
            entries.append(run_rate(rate, info["size_bytes"], offline, args.flush_seconds))
            write_report(args.output, info, offline, entries)  # keep what is done if a later rate fails
    except KeyboardInterrupt:
        interrupted = True
        log("interrupted; stopping the sensor and the replay")
        compose("exec", "-T", "sensor", "pkill", "-TERM", "-f", "idps.live", check=False, timeout=30)
        stop_replay()
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        return 1
    finally:
        compose("exec", "-T", "attacker", "rm", "-f", REMOTE_SAMPLE, check=False, timeout=30)
    if entries:
        print(build_table(entries))
        print(f"\nwrote {args.output}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
