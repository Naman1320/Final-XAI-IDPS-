"""scripts/lab_unseen.py: labelling, families, the alert floor, metrics and the comparison table.
Small synthetic frames; nothing here starts docker or loads a model."""

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))
_spec = importlib.util.spec_from_file_location("lab_unseen", _SCRIPTS / "lab_unseen.py")
lu = importlib.util.module_from_spec(_spec)
sys.modules["lab_unseen"] = lu
_spec.loader.exec_module(lu)

A = "10.10.1.10"
V = "10.10.2.10"
CLASSES = ["BENIGN", "DDoS", "DoS slowloris", "PortScan", "SSH-Patator", "Web Attack - XSS"]


def flows(rows):
    return pd.DataFrame([{"src_ip": s, "dst_ip": d, "dst_port": 80} for s, d in rows])


# ---- families and labelling ---------------------------------------------------------------------

@pytest.mark.parametrize("label,fam", [
    ("BENIGN", "BENIGN"), ("PortScan", "PortScan"), ("SSH-Patator", "BruteForce"),
    ("FTP-Patator", "BruteForce"), ("DDoS", "DoS"), ("DoS Hulk", "DoS"), ("DoS slowloris", "DoS"),
    ("DoS SYN flood", "DoS"), ("Web Attack - XSS", "WebAttack"),
    ("Web Attack - Sql Injection", "WebAttack"), ("Bot", "Other"), ("Heartbleed", "Other"),
])
def test_family_of(label, fam):
    assert lu.family_of(label) == fam


def test_every_truth_label_has_a_lab_family():
    assert {lu.family_of(v) for v in lu.TRUTH.values()} == {
        "PortScan", "BruteForce", "DoS", "WebAttack", "BENIGN"}
    assert set(lu.TRUTH) == set(lu.la.ATTACKS) | {"benign"}
    assert lu.TRUTH["syn_flood"] == "DoS SYN flood" and lu.TRUTH["web_sqli"] == "Web Attack - Sql Injection"


def test_attack_session_keeps_only_attacker_flows():
    df = flows([(A, V), (V, A), ("10.10.2.10", "10.10.3.5"), ("10.10.1.2", V)])
    out = lu.label_session(df, "portscan", 2)
    assert len(out) == 2
    assert set(out["label"]) == {"PortScan"} and set(out["family"]) == {"PortScan"}
    assert set(out["session"]) == {"portscan"} and set(out["repeat"]) == {2}
    assert list(out.columns[:4]) == ["session", "repeat", "label", "family"]


def test_benign_session_keeps_every_flow():
    df = flows([(A, V), ("10.10.2.10", "10.10.3.5")])
    out = lu.label_session(df, "benign", 1)
    assert len(out) == 2 and set(out["label"]) == {"BENIGN"} and set(out["family"]) == {"BENIGN"}


def test_label_session_unknown_and_empty():
    with pytest.raises(ValueError):
        lu.label_session(flows([(A, V)]), "nope", 1)
    assert len(lu.label_session(flows([("1.1.1.1", "2.2.2.2")]), "syn_flood", 1)) == 0


def test_label_session_does_not_change_input():
    df = flows([(A, V)])
    lu.label_session(df, "web_sqli", 1)
    assert list(df.columns) == ["src_ip", "dst_ip", "dst_port"]


# ---- floor --------------------------------------------------------------------------------------

def test_floor_turns_weak_attack_predictions_into_benign():
    got = lu.apply_floor(["PortScan", "PortScan", "BENIGN", "DDoS"], [0.49, 0.5, 0.3, 0.99], 0.5)
    assert got == ["BENIGN", "PortScan", "BENIGN", "DDoS"]


# ---- metrics ------------------------------------------------------------------------------------

def test_per_label_metrics():
    truth = ["PortScan"] * 4 + ["DoS SYN flood"] * 3
    pred = ["PortScan", "PortScan", "BENIGN", "DDoS", "DoS Hulk", "DDoS", "BENIGN"]
    m = lu.per_label_metrics(truth, pred, CLASSES)
    ps = m["PortScan"]
    assert ps["flows"] == 4 and ps["exact_recall"] == 0.5 and ps["family_recall"] == 0.5
    assert ps["top_predicted"][0] == {"class": "PortScan", "flows": 2, "share": 0.5}
    syn = m["DoS SYN flood"]
    assert syn["is_model_class"] is False and syn["exact_recall"] is None
    assert syn["family_recall"] == pytest.approx(0.6667, abs=1e-4)  # DoS Hulk and DDoS count


def test_benign_false_positives():
    truth = ["BENIGN"] * 4 + ["PortScan"]
    pred = ["BENIGN", "BENIGN", "DDoS", "DDoS", "PortScan"]
    b = lu.benign_false_positives(truth, pred)
    assert b == {"flows": 4, "false_positives": 2, "false_positive_rate": 0.5, "by_class": {"DDoS": 2}}
    assert lu.benign_false_positives(["PortScan"], ["PortScan"])["false_positive_rate"] is None


def test_family_scores_and_macro_f1():
    truth = ["BENIGN", "BENIGN", "DoS", "DoS"]
    pred = ["BENIGN", "DoS", "DoS", "DoS"]
    s = lu.family_scores(truth, pred)
    # BENIGN: tp1 fp0 fn1 -> F1 2/3; DoS: tp2 fp1 fn0 -> F1 0.8
    assert s["per_family"]["BENIGN"]["f1"] == pytest.approx(0.6667, abs=1e-4)
    assert s["per_family"]["DoS"]["f1"] == 0.8
    assert s["macro_f1"] == pytest.approx(0.7333, abs=1e-4)


def test_family_macro_ignores_families_absent_from_truth():
    s = lu.family_scores(["BENIGN", "BENIGN"], ["BENIGN", "Other"])
    assert set(s["per_family"]) == {"BENIGN"} and s["macro_f1"] == 0.6667


def test_exact_class_scores_skip_non_class_truth():
    truth = ["PortScan", "PortScan", "BENIGN", "Web Attack - Sql Injection"]
    pred = ["PortScan", "BENIGN", "BENIGN", "PortScan"]  # the last one must not hurt PortScan precision
    s = lu.exact_class_scores(truth, pred, CLASSES)
    assert set(s) == {"PortScan", "BENIGN"}
    assert s["PortScan"] == {"support": 2, "precision": 1.0, "recall": 0.5, "f1": 0.6667}


# ---- comparison and the whole frame -------------------------------------------------------------

TEST_PER_CLASS = {"PortScan": {"f1": 0.9, "recall": 0.95, "support": 1000},
                  "BENIGN": {"f1": 0.99, "recall": 0.98, "support": 5000},
                  "DoS Hulk": {"f1": 0.96, "recall": 0.92, "support": 100}}


def test_compare_only_classes_in_both():
    lab = {"PortScan": {"support": 10, "precision": 1.0, "recall": 0.5, "f1": 0.6667},
           "SSH-Patator": {"support": 5, "precision": 1.0, "recall": 1.0, "f1": 1.0}}
    rows = lu.compare(lab, TEST_PER_CLASS)
    assert [r["class"] for r in rows] == ["PortScan"]
    r = rows[0]
    assert (r["lab_f1"], r["test_f1"], r["test_recall"], r["test_support"]) == (0.6667, 0.9, 0.95, 1000)
    assert r["f1_change"] == pytest.approx(-0.2333, abs=1e-4)


def make_frame():
    rows = ([("portscan", 1, "PortScan")] * 4 + [("syn_flood", 1, "DoS SYN flood")] * 2
            + [("benign", 1, "BENIGN")] * 4)
    df = pd.DataFrame(rows, columns=["session", "repeat", "label"])
    df["family"] = df["label"].map(lu.family_of)
    plain = ["PortScan"] * 3 + ["BENIGN"] + ["DDoS", "DoS Hulk"] + ["BENIGN"] * 3 + ["PortScan"]
    floor = list(plain)
    floor[2] = "BENIGN"  # a weak PortScan prediction the floor turns into BENIGN
    return df, floor, plain


def test_score_frame_both_variants_and_table():
    df, floor, plain = make_frame()
    r = lu.score_frame(df, floor, plain, CLASSES, TEST_PER_CLASS)
    assert r["flows"] == 10
    assert r["flows_by_session"] == {"benign#1": 4, "portscan#1": 4, "syn_flood#1": 2}
    assert r["no_floor"]["per_label"]["PortScan"]["exact_recall"] == 0.75
    assert r["with_floor"]["per_label"]["PortScan"]["exact_recall"] == 0.5
    assert r["no_floor"]["per_label"]["DoS SYN flood"]["family_recall"] == 1.0
    assert r["with_floor"]["benign"]["false_positive_rate"] == 0.25
    assert set(r["no_floor"]["family"]["per_family"]) == {"BENIGN", "DoS", "PortScan"}
    assert {c["class"] for c in r["no_floor"]["comparison"]} == {"PortScan", "BENIGN"}
    # comparison F1 differs between the variants: the floor costs PortScan recall
    cmp_ = {v: {c["class"]: c for c in r[v]["comparison"]} for v in ("with_floor", "no_floor")}
    assert cmp_["no_floor"]["PortScan"]["lab_recall"] > cmp_["with_floor"]["PortScan"]["lab_recall"]
    table = lu.build_table(r, 0.66, 0.011)
    assert "| PortScan | 4 | 50.0% | 75.0% | 50.0% | 75.0% |" in table
    assert "not a class" in table and "(with floor): 25.0% (1 of 4 flows)" in table
    assert "without the alert floor" in table and "Test-split F1" in table
    assert "Recall is the fair column" in table
    assert "| Truth \\ predicted |" in table


def test_confusion():
    c = lu.confusion(["A", "A", "B"], ["A", "B", "B"])
    assert c == {"truth": ["A", "B"], "predicted": ["A", "B"], "matrix": [[1, 1], [0, 1]]}
    assert "| A | 1 | 1 |" in lu.confusion_table(c) and "| B | . | 1 |" in lu.confusion_table(c)


# ---- exit codes, marker, merge --------------------------------------------------------------------

@pytest.mark.parametrize("session,code,bad", [
    ("portscan", 0, False), ("portscan", 1, True), ("portscan", 124, True),
    ("syn_flood", 124, False), ("syn_flood", 0, False), ("syn_flood", 2, True),
    ("ssh_bruteforce", 255, True), ("slow_dos", "timeout", True), ("web_sqli", 1, True),
    ("benign", 0, False), ("benign", 2, True), ("benign", "timeout", True),
])
def test_session_errors(session, code, bad):
    info = {"exit": code, "sqlmap_start_ms": 1000}
    assert bool(lu.session_errors(session, info)) is bad


def test_web_sqli_needs_the_marker():
    assert lu.session_errors("web_sqli", {"exit": 0, "sqlmap_start_ms": None})
    assert not lu.session_errors("web_sqli", {"exit": 0, "sqlmap_start_ms": 5000})


def test_sqlmap_start_ms():
    assert lu.sqlmap_start_ms("noise\nwebattack: sqlmap-start 1700000000\nsqlmap says hi\n") == 1_700_000_001_000
    assert lu.sqlmap_start_ms("webattack: no CSRF token") is None
    assert lu.sqlmap_start_ms(None) is None


def test_label_session_not_before():
    df = flows([(A, V), (A, V), (V, A)])
    df["start_ms"] = [1000, 2000, 3000]
    out = lu.label_session(df, "web_sqli", 1, not_before_ms=2000)
    assert out["start_ms"].tolist() == [2000, 3000]


def lab_df(session, repeat, n=2):
    return lu.label_session(flows([(A, V)] * n), session, repeat)


def test_merge_frames_replaces_same_session_repeat():
    old = pd.concat([lab_df("portscan", 1, 3), lab_df("portscan", 2, 1), lab_df("benign", 1, 2)], ignore_index=True)
    new = lab_df("portscan", 1, 5)
    out = lu.merge_frames(old, new)
    counts = out.groupby(["session", "repeat"]).size().to_dict()
    assert counts == {("portscan", 1): 5, ("portscan", 2): 1, ("benign", 1): 2}
    assert len(lu.merge_frames(None, new)) == 5


# ---- score() with a fake bundle -------------------------------------------------------------------

class FakeBundle:
    label_encoder = SimpleNamespace(classes_=np.array(CLASSES))
    features = ["dst_port"]

    def select(self, df, meta):
        return df[self.features]

    def predict_proba(self, X):
        # row 0: PortScan 0.45 (below the floor) over BENIGN 0.30; row 1: PortScan 0.9; row 2: BENIGN 0.8
        p = np.full((3, len(CLASSES)), 0.01)
        p[0, CLASSES.index("PortScan")], p[0, 0] = 0.45, 0.30
        p[1, CLASSES.index("PortScan")], p[1, 0] = 0.90, 0.05
        p[2, 0] = 0.80
        return p


def test_score_floor_and_no_floor(tmp_path, monkeypatch):
    import idps.detect.bundle as bundle_mod
    from idps.features import write_features

    monkeypatch.setattr(bundle_mod, "load_bundle", lambda path: FakeBundle())
    monkeypatch.setattr(bundle_mod, "read_digest", lambda path: "ab" * 32)
    df = pd.concat([lab_df("portscan", 1, 2), lab_df("benign", 1, 1)], ignore_index=True)
    df["dst_port"] = 80
    data = tmp_path / "lab.parquet"
    write_features(df, data, {"extractor": "x"})
    rep = tmp_path / "week.json"
    rep.write_text(json.dumps({"metrics": {"test": {
        "macro_f1": 0.66, "benign_false_positive_rate": 0.01,
        "per_class": {"PortScan": {"f1": 0.7, "recall": 0.99, "support": 10},
                      "BENIGN": {"f1": 0.99, "recall": 0.98, "support": 100}}}}}))
    r = lu.score(data, tmp_path / "m.joblib", rep, floor=0.5)
    assert r["model_sha256"] == "ab" * 32 and r["alert_floor"] == 0.5
    assert r["no_floor"]["per_label"]["PortScan"]["exact_recall"] == 1.0
    assert r["with_floor"]["per_label"]["PortScan"]["exact_recall"] == 0.5
    assert r["with_floor"]["confusion"]["matrix"] == [[1, 0], [1, 1]]  # BENIGN row, PortScan row
    assert r["test_split"]["scored_without_floor"] is True and r["notes"]
    comp = {c["class"]: c for c in r["no_floor"]["comparison"]}
    assert comp["PortScan"]["test_recall"] == 0.99


# ---- collect(): overwrite, append, nothing succeeded --------------------------------------------------

META = {"extractor": "nfstream"}


def fake_runs(monkeypatch, outcomes):
    """run_session returns/raises per (session, repeat) from `outcomes`: a DataFrame or an Exception."""
    def fake(session, repeat, seconds, password):
        o = outcomes[(session, repeat)]
        if isinstance(o, Exception):
            raise o
        return o, dict(META), {"session": session, "repeat": repeat}
    monkeypatch.setattr(lu, "run_session", fake)


def read(path):
    from idps.features import read_features
    return read_features(path)[0]


def test_collect_overwrite_keeps_bak(tmp_path, monkeypatch):
    out = tmp_path / "lab.parquet"
    fake_runs(monkeypatch, {("portscan", 1): lab_df("portscan", 1, 3)})
    assert lu.collect(["portscan"], 1, 1, "pw", out)["written"]
    first = read(out)
    fake_runs(monkeypatch, {("benign", 1): lab_df("benign", 1, 2)})
    lu.collect(["benign"], 1, 1, "pw", out)
    assert set(read(out)["session"]) == {"benign"}                 # replaced
    assert set(read(out.with_name("lab.parquet.bak"))["session"]) == {"portscan"}
    assert len(first) == 3 and not list(tmp_path.glob("*.tmp"))


def test_collect_append_merges(tmp_path, monkeypatch):
    out = tmp_path / "lab.parquet"
    fake_runs(monkeypatch, {("portscan", 1): lab_df("portscan", 1, 3), ("benign", 1): lab_df("benign", 1, 2)})
    lu.collect(["portscan", "benign"], 1, 1, "pw", out)
    fake_runs(monkeypatch, {("portscan", 1): lab_df("portscan", 1, 7)})
    lu.collect(["portscan"], 1, 1, "pw", out, append=True)
    counts = read(out).groupby("session").size().to_dict()
    assert counts == {"portscan": 7, "benign": 2}


def test_collect_nothing_succeeded_writes_nothing(tmp_path, monkeypatch):
    out = tmp_path / "lab.parquet"
    fake_runs(monkeypatch, {("portscan", 1): lab_df("portscan", 1, 3)})
    lu.collect(["portscan"], 1, 1, "pw", out)
    before = out.read_bytes()
    err = lu.SessionError("the attack exited with status 1", {"exit": 1})
    fake_runs(monkeypatch, {("portscan", 1): err})
    done = lu.collect(["portscan"], 1, 1, "pw", out)
    assert done["written"] is False
    assert done["runs"][0]["error"] == "the attack exited with status 1" and done["runs"][0]["exit"] == 1
    assert out.read_bytes() == before and not out.with_name("lab.parquet.bak").exists()


def test_collect_failed_session_leaves_flows_out(tmp_path, monkeypatch):
    out = tmp_path / "lab.parquet"
    fake_runs(monkeypatch, {("portscan", 1): lab_df("portscan", 1, 3), ("slow_dos", 1): RuntimeError("boom")})
    done = lu.collect(["portscan", "slow_dos"], 1, 1, "pw", out)
    assert set(read(out)["session"]) == {"portscan"}
    assert [r.get("error") for r in done["runs"]] == [None, "boom"]


# ---- run_session with the lab mocked --------------------------------------------------------------------

class FakeLab:
    """Stands in for la.sh / bs.compose: tracks whether tcpdump runs and records every call."""

    def __init__(self, attack_exit=0, attack_stdout="", attack_raises=None, flows_rows=None):
        self.scripts, self.running = [], False
        self.attack_exit, self.attack_stdout, self.attack_raises = attack_exit, attack_stdout, attack_raises
        self.flows_rows = flows_rows

    def sh(self, service, script, timeout=120, check=False, secrets=None):
        self.scripts.append((service, script))
        rc, out = 0, ""
        if "pgrep" in script:
            rc = 0 if self.running else 1
        elif "pkill -INT" in script or "pkill -KILL" in script:
            self.running = False
        elif service == "attacker" and "pidof" not in script:
            if self.attack_raises:
                raise self.attack_raises
            rc, out = self.attack_exit, self.attack_stdout
        return subprocess.CompletedProcess([], rc, stdout=out, stderr="")

    def compose(self, *args, check=True, timeout=None):
        if args[:2] == ("exec", "-d"):
            self.running = True
        elif args[0] == "cp":
            from idps.features import write_features
            rows = self.flows_rows or [(A, V, 1000), (A, V, 2000), ("10.10.2.10", "10.10.3.5", 3000)]
            df = pd.DataFrame(rows, columns=["src_ip", "dst_ip", "start_ms"]).assign(dst_port=80)
            write_features(df, args[2], META)
        return subprocess.CompletedProcess([], 0, stdout="", stderr="")

    def ran(self, text):
        return any(text in s for _, s in self.scripts)


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda s: None)

    def install(**kw):
        fl = FakeLab(**kw)
        monkeypatch.setattr(lu.la, "sh", fl.sh)
        monkeypatch.setattr(lu.bs, "compose", fl.compose)
        return fl
    return install


def test_run_session_ok_labels_attacker_flows(lab):
    fl = lab()
    df, meta, info = lu.run_session("portscan", 1, 60, "pw")
    assert len(df) == 2 and set(df["label"]) == {"PortScan"} and meta == META
    assert info["exit"] == 0 and info["flows_total"] == 3 and info["flows_labelled"] == 2
    assert fl.ran("idps.features extract") and not fl.running


def test_run_session_keep_pcaps_copies_pcap_out_of_sensor(lab, tmp_path, monkeypatch):
    fl = lab()
    copied = []
    orig = fl.compose
    monkeypatch.setattr(lu.bs, "compose", lambda *a, **k: (copied.append(a), orig(*a, **k))[1])
    dest = tmp_path / "pcaps"
    _, _, info = lu.run_session("portscan", 2, 60, "pw", keep_pcaps=dest)
    assert ("cp", f"sensor:{lu.PCAP}", str(dest / "portscan_2.pcap.part")) in copied
    assert (dest / "portscan_2.pcap").exists() and info["pcap"].endswith("portscan_2.pcap")
    # the pcap is copied before the flows are extracted, and nothing is copied by default
    copied.clear()
    lu.run_session("portscan", 1, 60, "pw")
    assert not any(c[1] == f"sensor:{lu.PCAP}" for c in copied)


def test_run_session_keep_pcaps_not_for_failed_session(lab, tmp_path):
    lab(attack_exit=1)
    with pytest.raises(lu.SessionError):
        lu.run_session("portscan", 1, 60, "pw", keep_pcaps=tmp_path)
    assert not list(tmp_path.glob("*.pcap"))


def test_keep_pcaps_only_kept_after_the_session_succeeded(lab, tmp_path, monkeypatch):
    """The pcap is copied under a temporary name and renamed only when extraction and labelling worked."""
    seen = {}
    orig = lu.commit_pcap
    monkeypatch.setattr(lu, "commit_pcap", lambda part: (seen.update(part=part, final_before=(part.with_name(part.name.removesuffix(".part"))).exists()), orig(part))[1])
    lab()
    lu.run_session("portscan", 1, 60, "pw", keep_pcaps=tmp_path)
    assert seen["part"].name == "portscan_1.pcap.part" and seen["final_before"] is False
    assert (tmp_path / "portscan_1.pcap").exists() and not list(tmp_path.glob("*.part"))


def test_keep_pcaps_removed_when_labelling_finds_no_flows(lab, tmp_path):
    lab(flows_rows=[("10.10.2.10", "10.10.3.5", 3000)])        # no flow with the attacker as an endpoint
    with pytest.raises(lu.SessionError, match="no flows"):
        lu.run_session("portscan", 1, 60, "pw", keep_pcaps=tmp_path)
    assert not list(tmp_path.iterdir())                         # neither the final name nor a .part file


def test_keep_pcaps_removed_when_extraction_fails(lab, tmp_path, monkeypatch):
    fl = lab()
    real_sh = fl.sh
    def sh(service, script, **kw):
        if "idps.features extract" in script:
            return subprocess.CompletedProcess([], 1, stdout="", stderr="boom")
        return real_sh(service, script, **kw)
    monkeypatch.setattr(lu.la, "sh", sh)
    with pytest.raises(lu.SessionError, match="extraction failed"):
        lu.run_session("portscan", 1, 60, "pw", keep_pcaps=tmp_path)
    assert not list(tmp_path.iterdir())


def test_collect_passes_keep_pcaps_through(monkeypatch, tmp_path):
    got = []
    def fake(session, repeat, seconds, password, keep_pcaps=None):
        got.append(keep_pcaps)
        return pd.DataFrame({"session": [session], "repeat": [repeat], "label": ["PortScan"], "family": ["PortScan"],
                             "start_ms": [1]}), dict(META), {"session": session, "repeat": repeat}
    monkeypatch.setattr(lu, "run_session", fake)
    out = tmp_path / "l.parquet"
    lu.collect(["portscan"], 1, 1, "pw", out, keep_pcaps=tmp_path / "pcaps")
    lu.collect(["portscan"], 1, 1, "pw", out)
    assert got == [tmp_path / "pcaps", None]


def test_keep_pcap_destination_is_absolute_for_relative_keep_pcaps(lab, tmp_path, monkeypatch):
    """docker compose runs with cwd=lab/, so a relative destination would be resolved there."""
    monkeypatch.chdir(tmp_path)
    fl = lab()
    copied = []
    orig = fl.compose
    monkeypatch.setattr(lu.bs, "compose", lambda *a, **k: (copied.append(a), orig(*a, **k))[1])
    lu.run_session("portscan", 1, 60, "pw", keep_pcaps=Path("pcaps"))
    dests = [Path(c[2]) for c in copied if c[0] == "cp" and c[1] == f"sensor:{lu.PCAP}"]
    assert len(dests) == 1 and dests[0].is_absolute() and dests[0].parent == (tmp_path / "pcaps").resolve()
    assert (tmp_path / "pcaps" / "portscan_1.pcap").exists()


def test_keep_pcaps_option_default_dir():
    assert lu.PCAP_DIR == lu.ROOT / "data" / "raw" / "lab_pcaps"
    assert lu.pcap_name("web_sqli", 3) == "web_sqli_3.pcap"


def test_run_session_accepts_124_for_syn_flood(lab):
    lab(attack_exit=124)
    df, _, info = lu.run_session("syn_flood", 1, 60, "pw")
    assert info["exit"] == 124 and set(df["label"]) == {"DoS SYN flood"}


@pytest.mark.parametrize("kw,msg", [({"attack_exit": 1}, "status 1"),
                                    ({"attack_raises": subprocess.TimeoutExpired("x", 1)}, "time limit")])
def test_run_session_failed_attack_is_an_error(lab, kw, msg):
    fl = lab(**kw)
    with pytest.raises(lu.SessionError, match=msg) as e:
        lu.run_session("portscan", 1, 60, "pw")
    assert not fl.ran("idps.features extract")                      # nothing extracted or labelled
    assert not fl.running                                          # tcpdump stopped
    assert fl.ran("kill $(pidof")                                  # attack killed
    assert fl.scripts[-1][1].startswith("for p in") or fl.ran("pkill -INT -f")
    assert e.value.info["session"] == "portscan"


def test_run_session_web_sqli_drops_flows_before_sqlmap(lab):
    rows = [(A, "10.10.2.11", 1_700_000_000_500), (A, "10.10.2.11", 1_700_000_001_000),
            (A, "10.10.2.11", 1_700_000_005_000)]
    lab(attack_stdout="curl noise\nwebattack: sqlmap-start 1700000000\n", flows_rows=rows)
    df, _, info = lu.run_session("web_sqli", 1, 60, "pw")
    assert df["start_ms"].tolist() == [1_700_000_001_000, 1_700_000_005_000]
    assert info["flows_before_sqlmap"] == 1


def test_run_session_web_sqli_without_marker_fails(lab):
    lab(attack_stdout="no marker here")
    with pytest.raises(lu.SessionError, match="marker"):
        lu.run_session("web_sqli", 1, 60, "pw")


def test_run_session_tcpdump_that_will_not_die(lab, monkeypatch):
    fl = lab()
    monkeypatch.setattr(lu, "TCPDUMP_STOP_WAIT", 0)
    monkeypatch.setattr(lu, "TCPDUMP_KILL_WAIT", 0)
    monkeypatch.setattr(lu.la, "tcpdump_running", lambda pcap=None: True if fl.running else False)
    orig = fl.sh

    def stubborn(service, script, **kw):
        r = orig(service, script, **kw)
        if "pkill" in script:
            fl.running = True  # nothing stops it
        return r
    monkeypatch.setattr(lu.la, "sh", stubborn)
    monkeypatch.setattr(lu.la, "start_tcpdump", lambda pcap: setattr(fl, "running", True))
    with pytest.raises(lu.SessionError, match="still running"):
        lu.run_session("portscan", 1, 60, "pw")
    assert any("pkill -KILL" in s for _, s in fl.scripts)         # escalated
    assert not fl.ran("idps.features extract")


def test_run_session_benign_surfaces_activity_problems(lab, monkeypatch):
    lab()
    lines = ["2026-11-15T10:00:00Z benign web nginx keep-alive page=/ requests=3",
             "2026-11-15T10:00:01Z benign dvwa login failed (index.php status=302)"]
    fake = SimpleNamespace(lines=lines, wait=lambda timeout: 0, stop=lambda: None)
    monkeypatch.setattr(lu.bb, "setup_victim_files", lambda: None)
    monkeypatch.setattr(lu.bb, "cleanup_victim_files", lambda: None)
    monkeypatch.setattr(lu.bb, "Traffic", lambda secs, pw: fake)
    df, _, info = lu.run_session("benign", 1, 600, "pw")
    assert set(df["label"]) == {"BENIGN"} and len(df) == 3
    assert info["activity_problem_count"] == 1 and info["activity_problems"]
    assert any("problem line" in w for w in info["warnings"])


# ---- main ---------------------------------------------------------------------------------------------

def test_main_score_only_missing_file(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(lu, "score", lambda *a, **k: pytest.fail("must not score"))
    rep = tmp_path / "r.json"
    rc = lu.main(["--score-only", "--out", str(tmp_path / "missing.parquet"), "--report", str(rep)])
    assert rc == 1 and not rep.exists()
    assert "does not exist" in capsys.readouterr().err


def test_main_rejects_short_benign(capsys):
    assert lu.main(["--benign-minutes", "0.5", "--score-only"]) == 2


def test_main_no_success_does_not_score_or_write_report(tmp_path, monkeypatch, capsys):
    env = tmp_path / ".env"
    env.write_text("LAB_VICTIM_PASSWORD=pw\n")
    monkeypatch.setattr(lu.bs, "LAB", tmp_path)
    monkeypatch.setattr(lu.bs, "sensor_running", lambda: False)
    monkeypatch.setattr(lu, "collect", lambda *a, **k: {"runs": [{"session": "portscan", "repeat": 1,
                                                                  "error": "x"}], "written": False})
    monkeypatch.setattr(lu, "score", lambda *a, **k: pytest.fail("must not score"))
    rep = tmp_path / "r.json"
    rc = lu.main(["--sessions", "portscan", "--out", str(tmp_path / "o.parquet"), "--report", str(rep)])
    assert rc == 1 and not rep.exists()


def test_main_default_report_follows_out(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(lu, "score", lambda out: {"test_split": {"macro_f1": 0.5, "benign_false_positive_rate": 0.1},
                                                  "model_sha256": "x"})
    monkeypatch.setattr(lu, "build_table", lambda *a: "table")
    out = tmp_path / "lab_smoke.parquet"
    out.write_bytes(b"")
    monkeypatch.setattr(Path, "write_text", lambda self, text, *a, **k: seen.setdefault("p", self) and 0)
    lu.main(["--score-only", "--out", str(out)])
    assert seen["p"] == lu.ROOT / "reports" / "lab_smoke.json"  # not reports/lab_unseen.json
