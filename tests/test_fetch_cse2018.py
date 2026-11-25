"""scripts/fetch_cse_cic_ids2018.py: part-size maths, ETag checks, CSV to Parquet, atomic writes,
manifest handling, resumable download and the main() loop. No network, tiny files only."""

import errno
import hashlib
import importlib.util
import json
import math
import os
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))
_spec = importlib.util.spec_from_file_location("fetch_cse", _SCRIPTS / "fetch_cse_cic_ids2018.py")
fc = importlib.util.module_from_spec(_spec)
sys.modules["fetch_cse"] = fc
_spec.loader.exec_module(fc)

MIB = 1024 * 1024


# ---------- candidate_part_sizes ----------


def test_single_part_returns_size():
    assert fc.candidate_part_sizes(12345, 1) == [12345]


def test_real_looking_numbers_include_16_mib():
    sizes = fc.candidate_part_sizes(4054900000, 242)
    assert 16 * MIB in sizes
    for p in sizes:
        assert math.ceil(4054900000 / p) == 242


def test_non_listed_part_size_is_found():
    assert 10 not in fc.PART_SIZES_MIB
    size = 10 * MIB * 5 - 100
    sizes = fc.candidate_part_sizes(size, 5)
    assert 10 * MIB in sizes
    assert all(math.ceil(size / p) == 5 for p in sizes)


def test_exact_multiple_of_part_size():
    size = 16 * MIB * 4
    sizes = fc.candidate_part_sizes(size, 4)
    assert 16 * MIB in sizes
    assert all(math.ceil(size / p) == 4 for p in sizes)


@pytest.mark.parametrize("size,parts", [(100 * MIB + 1, 7), (3 * MIB, 3), (999_999_999, 60)])
def test_every_candidate_gives_the_part_count(size, parts):
    for p in fc.candidate_part_sizes(size, parts):
        assert math.ceil(size / p) == parts


# ---------- etag_matches ----------


def multipart_etag(data: bytes, part: int) -> str:
    chunks = [data[i : i + part] for i in range(0, len(data), part)]
    outer = b"".join(hashlib.md5(c).digest() for c in chunks)
    return f"{hashlib.md5(outer).hexdigest()}-{len(chunks)}"


def test_etag_single_part(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello world")
    assert fc.etag_matches(f, hashlib.md5(b"hello world").hexdigest())
    assert not fc.etag_matches(f, hashlib.md5(b"other").hexdigest())


def test_etag_multipart(tmp_path, monkeypatch):
    data = os.urandom(4096 + 100)
    f = tmp_path / "a.bin"
    f.write_bytes(data)
    monkeypatch.setattr(fc, "candidate_part_sizes", lambda size, parts: [1000, 4096])
    assert fc.etag_matches(f, multipart_etag(data, 4096))


def test_etag_multipart_wrong(tmp_path, monkeypatch):
    data = os.urandom(4096 + 100)
    f = tmp_path / "a.bin"
    f.write_bytes(data)
    monkeypatch.setattr(fc, "candidate_part_sizes", lambda size, parts: [4096])
    assert not fc.etag_matches(f, multipart_etag(data + b"x", 4096))
    assert not fc.etag_matches(f, "0" * 32 + "-2")


def test_etag_multipart_with_real_candidates(tmp_path):
    data = os.urandom(5 * MIB + 10)
    f = tmp_path / "a.bin"
    f.write_bytes(data)
    assert fc.etag_matches(f, multipart_etag(data, 5 * MIB))


# ---------- to_parquet ----------


def convert(tmp_path, raw: bytes, name="t"):
    src = tmp_path / f"{name}.csv"
    src.write_bytes(raw)
    out = tmp_path / f"{name}.parquet"
    return src, out, fc.to_parquet(src, out)


def test_bom_crlf_duplicates_and_exact_values(tmp_path):
    raw = b"\xef\xbb\xbfa,a,b\r\nInfinity,NaN,\r\n00123,x,y\r\n"
    _src, out, info = convert(tmp_path, raw)
    assert info["columns"] == ["a", "a", "b"]
    assert info["unique_columns"] == ["a", "a__1", "b"]
    table = pq.read_table(out)
    assert all(t == pa.string() for t in table.schema.types)
    assert table.column_names == ["a", "a__1", "b"]
    assert table.to_pydict() == {
        "a": ["Infinity", "00123"],
        "a__1": ["NaN", "x"],
        "b": ["", "y"],
    }
    assert info["rows"] == 2
    assert info["csv_lines"] == 2
    assert info["bad_rows"] == 0
    assert info["csv_sha256"] == hashlib.sha256(raw).hexdigest()
    assert not out.with_suffix(".badrows.txt").exists()


def test_no_trailing_newline(tmp_path):
    _, out, info = convert(tmp_path, b"a,b\n1,2\n3,4")
    assert info["rows"] == 2 == info["csv_lines"]
    assert pq.read_table(out).to_pydict() == {"a": ["1", "3"], "b": ["2", "4"]}


def test_short_row_set_aside_and_stale_file_removed(tmp_path):
    src, out, info = convert(tmp_path, b"a,b,c\n1,2,3\n4,5\n6,7,8\n")
    bad = out.with_suffix(".badrows.txt")
    assert info["bad_rows"] == 1
    assert info["rows"] == 2
    assert info["rows"] + info["bad_rows"] == info["csv_lines"]
    assert "4,5" in bad.read_text()
    # a later run with a clean file deletes the stale side file
    src.write_bytes(b"a,b,c\n1,2,3\n")
    info2 = fc.to_parquet(src, out)
    assert info2["bad_rows"] == 0
    assert not bad.exists()


def test_blank_lines_reconcile(tmp_path):
    _, out, info = convert(tmp_path, b"a,b\n1,2\n\n3,4\n\n")
    assert info["rows"] + info["bad_rows"] == info["csv_lines"] == 4
    assert pq.ParquetFile(out).metadata.num_rows == info["rows"]


def test_embedded_newline_raises_and_leaves_nothing(tmp_path):
    src = tmp_path / "t.csv"
    src.write_bytes(b'a,b\n1,"two\nlines"\n3,4\n')
    out = tmp_path / "t.parquet"
    with pytest.raises(RuntimeError):
        fc.to_parquet(src, out)
    assert not out.exists()
    assert not (tmp_path / "t.parquet.part").exists()


# ---------- atomic_write ----------


def test_atomic_write_complete(tmp_path):
    p = tmp_path / "m.json"
    fc.atomic_write(p, "hello\n")
    assert p.read_text() == "hello\n"
    assert not (tmp_path / "m.json.tmp").exists()


def test_atomic_write_failure_keeps_original(tmp_path, monkeypatch):
    p = tmp_path / "m.json"
    p.write_text("original")

    def boom(fd):
        raise OSError(errno.ENOSPC, "No space left")

    monkeypatch.setattr(fc.os, "fsync", boom)
    with pytest.raises(OSError):
        fc.atomic_write(p, "new content that must not land")
    assert p.read_text() == "original"


# ---------- load_manifest ----------


def test_load_manifest_missing(tmp_path):
    assert fc.load_manifest(tmp_path / "nope.json") == {}


def test_load_manifest_damaged(tmp_path):
    p = tmp_path / "manifest.json"
    p.write_text('{"a": ')
    with pytest.raises(SystemExit) as exc:
        fc.load_manifest(p)
    assert "damaged" in str(exc.value)
    assert "manifest" in str(exc.value)


def test_load_manifest_valid(tmp_path):
    p = tmp_path / "manifest.json"
    p.write_text('{"x": {"rows": 1}}')
    assert fc.load_manifest(p) == {"x": {"rows": 1}}


# ---------- already_done ----------


def make_done(tmp_path, rows=3):
    pq_path = tmp_path / "f.parquet"
    pq.write_table(pa.table({"a": [str(i) for i in range(rows)]}), pq_path)
    entry = {
        "etag": "e1",
        "size": 10,
        "parquet_bytes": pq_path.stat().st_size,
        "rows": rows,
    }
    return pq_path, entry, {"etag": "e1", "size": 10}


def test_already_done_true(tmp_path):
    pq_path, entry, f = make_done(tmp_path)
    assert fc.already_done(entry, f, pq_path)


def test_already_done_false_cases(tmp_path):
    pq_path, entry, f = make_done(tmp_path)
    assert not fc.already_done(None, f, pq_path)
    assert not fc.already_done(entry, {**f, "etag": "e2"}, pq_path)
    assert not fc.already_done(entry, {**f, "size": 11}, pq_path)
    assert not fc.already_done({**entry, "rows": 4}, f, pq_path)
    assert not fc.already_done({**entry, "parquet_bytes": 1}, f, pq_path)
    assert not fc.already_done(entry, f, tmp_path / "missing.parquet")


def test_already_done_truncated_and_garbage(tmp_path):
    pq_path, entry, f = make_done(tmp_path)
    good = pq_path.read_bytes()
    pq_path.write_bytes(good[: len(good) // 2])
    assert not fc.already_done(entry, f, pq_path)
    garbage = b"x" * len(good)
    pq_path.write_bytes(garbage)
    assert not fc.already_done(entry, f, pq_path)


# ---------- download ----------


class FakeResp:
    def __init__(self, data: bytes, status=200, fail_after=None):
        self.data, self.status, self.fail_after = data, status, fail_after
        self.pos = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n):
        if self.fail_after is not None and self.pos >= self.fail_after:
            raise OSError("connection reset")
        end = self.pos + n
        if self.fail_after is not None:
            end = min(end, self.fail_after)
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk


@pytest.fixture
def fast(monkeypatch):
    monkeypatch.setattr(fc.time, "sleep", lambda s: None)
    monkeypatch.setattr(fc, "CHUNK", 4)


def install(monkeypatch, handler):
    calls = []

    def fake_urlopen(request, timeout=None, context=None):
        calls.append(request.get_header("Range"))
        return handler(len(calls), request)

    monkeypatch.setattr(fc.urllib.request, "urlopen", fake_urlopen)
    return calls


DATA = b"0123456789abcdefghij"


def test_download_normal(tmp_path, monkeypatch, fast):
    calls = install(monkeypatch, lambda n, r: FakeResp(DATA))
    dest = tmp_path / "f.part"
    fc.download("dir/a b.csv", dest, len(DATA))
    assert dest.read_bytes() == DATA
    assert calls == [None]


def test_download_resumes_with_range(tmp_path, monkeypatch, fast):
    def handler(n, req):
        if n == 1:
            return FakeResp(DATA, fail_after=8)
        start = int(req.get_header("Range").split("=")[1].rstrip("-"))
        return FakeResp(DATA[start:], status=206)

    calls = install(monkeypatch, handler)
    dest = tmp_path / "f.part"
    fc.download("a.csv", dest, len(DATA))
    assert dest.read_bytes() == DATA
    assert calls == [None, "bytes=8-"]


def test_download_server_ignores_range(tmp_path, monkeypatch, fast):
    def handler(n, req):
        if n == 1:
            return FakeResp(DATA, fail_after=8)
        return FakeResp(DATA, status=200)

    calls = install(monkeypatch, handler)
    dest = tmp_path / "f.part"
    fc.download("a.csv", dest, len(DATA))
    assert dest.read_bytes() == DATA
    assert calls == [None, "bytes=8-"]


def test_download_enospc_not_retried(tmp_path, monkeypatch, fast):
    def handler(n, req):
        raise OSError(errno.ENOSPC, "No space left on device")

    calls = install(monkeypatch, handler)
    with pytest.raises(OSError) as exc:
        fc.download("a.csv", tmp_path / "f.part", len(DATA))
    assert exc.value.errno == errno.ENOSPC
    assert len(calls) == 1


def test_download_gives_up_after_tries(tmp_path, monkeypatch, fast):
    def handler(n, req):
        raise OSError("down")

    calls = install(monkeypatch, handler)
    with pytest.raises(OSError):
        fc.download("a.csv", tmp_path / "f.part", len(DATA))
    assert len(calls) == fc.DOWNLOAD_TRIES


def test_download_short_every_time_raises_runtime_error(tmp_path, monkeypatch, fast):
    calls = install(monkeypatch, lambda n, r: FakeResp(DATA[:5], status=206))
    with pytest.raises(RuntimeError, match="still short"):
        fc.download("a.csv", tmp_path / "f.part", len(DATA))
    assert len(calls) == fc.DOWNLOAD_TRIES


# ---------- main ----------

CSV_A = b"a,b\n1,2\n3,4\n"
CSV_B = b"a,b\n5,6\n"


def listing():
    return [
        {"key": "P/big.csv", "size": 2000, "etag": "e-big"},
        {"key": "P/small.csv", "size": 1000, "etag": "e-small"},
    ]


@pytest.fixture
def env(tmp_path, monkeypatch):
    out = tmp_path / "out"
    state = {"downloads": [], "fail": set(), "free": 10**12, "atomic": []}

    def fake_download(key, dest, size):
        state["downloads"].append(key)
        dest.write_bytes(CSV_A if "small" in key else CSV_B)
        if key in state["fail"]:
            raise RuntimeError("boom")

    real_atomic = fc.atomic_write

    def spy_atomic(path, text):
        real_atomic(path, text)
        state["atomic"].append(
            (path.name, json.loads(path.read_text()), (path.parent / (path.name + ".tmp")).exists())
        )

    monkeypatch.setattr(fc, "list_files", lambda: listing())
    monkeypatch.setattr(fc, "download", fake_download)
    monkeypatch.setattr(fc, "etag_matches", lambda p, e: True)
    monkeypatch.setattr(fc, "free_bytes", lambda p: state["free"])
    monkeypatch.setattr(fc, "atomic_write", spy_atomic)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["fetch", "--out", str(out), "--keep-free", "0", *extra])
        return fc.main()

    return out, state, run


def test_main_not_enough_space(env):
    out, state, run = env
    state["free"] = 1000 * 1.35 - 1  # keep-free 0: need = size * 1.35
    assert run() == 3
    assert state["downloads"] == []
    assert not (out / "manifest.json").exists()


def test_main_space_check_uses_keep_free(env, monkeypatch):
    out, state, _ = env
    state["free"] = int(1000 * 1.35 + 2e9)
    monkeypatch.setattr(sys, "argv", ["fetch", "--out", str(out), "--keep-free", "3"])
    assert fc.main() == 3
    assert state["downloads"] == []


def test_main_one_failure_does_not_stop_others(env):
    out, state, run = env
    state["fail"].add("P/small.csv")
    assert run() == 1
    assert state["downloads"] == ["P/small.csv", "P/big.csv"]
    assert list(out.glob("*.part")) == []
    manifest = json.loads((out / "manifest.json").read_text())
    assert [k for k in manifest if k != "_source"] == ["big.csv"]
    assert (out / "big.parquet").exists()
    assert not (out / "small.parquet").exists()


def test_main_manifest_written_atomically_after_each_file(env):
    out, state, run = env
    assert run() == 0
    writes = [w for w in state["atomic"] if w[0] == "manifest.json"]
    assert len(writes) == 2
    assert [k for k in writes[0][1] if k != "_source"] == ["small.csv"]
    assert [k for k in writes[1][1] if k != "_source"] == ["small.csv", "big.csv"]
    assert not any(tmp_left for _, _, tmp_left in writes)
    entry = json.loads((out / "manifest.json").read_text())["small.csv"]
    assert entry["rows"] == 2
    assert entry["parquet_bytes"] == (out / "small.parquet").stat().st_size


def test_main_second_run_skips_finished(env):
    _out, state, run = env
    assert run() == 0
    state["downloads"].clear()
    assert run() == 0
    assert state["downloads"] == []


def test_main_list_does_not_touch_disk(env):
    out, state, run = env
    assert run("--list") == 0
    assert not out.exists()
    assert state["downloads"] == []


def test_main_only_filter(env):
    _out, state, run = env
    assert run("--only", "big") == 0
    assert state["downloads"] == ["P/big.csv"]
