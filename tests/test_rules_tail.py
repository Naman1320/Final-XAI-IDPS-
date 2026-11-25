"""idps.rules.tail.EveTailer: following a file another process writes."""
import os

from idps.rules.tail import EveTailer


def append(path, text):
    with open(path, "ab") as f:
        f.write(text.encode())


def test_starts_at_the_end_of_an_existing_file(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("old1\nold2\n")
    t = EveTailer(str(p))
    assert t.read_new() == []
    append(p, "new1\n")
    assert t.read_new() == ["new1"] and t.read_new() == []


def test_from_start_reads_the_history(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("a\nb\n")
    assert EveTailer(str(p), from_start=True).read_new() == ["a", "b"]


def test_a_partial_last_line_waits_for_its_newline(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("")
    t = EveTailer(str(p))
    t.read_new()
    append(p, "one\ntw")
    assert t.read_new() == ["one"]
    assert t.read_new() == []
    append(p, "o\nthree\n")
    assert t.read_new() == ["two", "three"]


def test_a_file_that_appears_later_is_read_from_its_start(tmp_path):
    p = tmp_path / "eve.json"
    t = EveTailer(str(p))
    assert t.read_new() == [] and not t.exists
    p.write_text("first\n")
    assert t.read_new() == ["first"] and t.exists


def test_truncation_restarts_from_the_beginning_and_drops_the_half_line(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("")
    t = EveTailer(str(p))
    t.read_new()
    append(p, "aaaaaaaaaa\nbbbbbbbbbb\nhalf")
    assert t.read_new() == ["aaaaaaaaaa", "bbbbbbbbbb"]
    with open(p, "r+b") as f:  # what the lab's size cap does: `: > eve.json`
        f.truncate(0)
    append(p, "c\n")
    assert t.read_new() == ["c"] and t.truncations == 1  # "half" is gone, not glued to "c"


def test_rotation_reads_the_rest_of_the_old_file_then_the_new_one(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("")
    t = EveTailer(str(p))
    t.read_new()
    append(p, "old1\n")
    assert t.read_new() == ["old1"]
    append(p, "old2\n")  # written, not yet read, when the file is rotated
    os.rename(p, tmp_path / "eve-1.json")
    p.write_text("new1\nnew2\n")
    assert t.read_new() == ["old2", "new1", "new2"] and t.rotations == 1
    append(p, "new3\n")
    assert t.read_new() == ["new3"]


def test_rotation_with_a_gap_where_the_path_does_not_exist(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("")
    t = EveTailer(str(p))
    t.read_new()
    append(p, "x\n")
    os.rename(p, tmp_path / "eve.1")
    assert t.read_new() == ["x"]  # still reading the old handle
    assert t.read_new() == []
    p.write_text("y\n")
    assert t.read_new() == ["y"]


def test_blank_lines_and_invalid_utf8_do_not_break_it(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("")
    t = EveTailer(str(p))
    t.read_new()
    with open(p, "ab") as f:
        f.write(b"\n\n\xff\xfe ok\n")
    got = t.read_new()
    assert len(got) == 1 and got[0].endswith(" ok")


def test_an_over_long_line_is_skipped_not_buffered(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("")
    t = EveTailer(str(p), max_line_bytes=100)
    t.read_new()
    append(p, "x" * 150)
    assert t.read_new() == []
    append(p, "x" * 150 + "\nshort\n")
    assert t.read_new() == ["short"] and t.skipped_lines == 1


def test_a_half_line_dropped_by_a_truncation_is_counted(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("")
    t = EveTailer(str(p))
    t.read_new()
    append(p, '{"a":1}\n{"half')
    assert t.read_new() == ['{"a":1}']
    with open(p, "r+b") as f:
        f.truncate(0)
    append(p, '{"b":2}\n')
    assert t.read_new() == ['{"b":2}'] and t.fragments_dropped == 1


def test_a_half_line_left_behind_by_a_rotation_is_counted(tmp_path):
    p = tmp_path / "eve.json"
    p.write_text("")
    t = EveTailer(str(p))
    t.read_new()
    append(p, "whole\nhalf")
    t.read_new()
    os.rename(p, tmp_path / "old")
    p.write_text("new\n")
    assert t.read_new() == ["new"] and t.fragments_dropped == 1


def test_a_poll_is_capped_by_lines_and_bytes_and_the_rest_comes_next_time(tmp_path, monkeypatch):
    from idps.rules import tail

    monkeypatch.setattr(tail, "CHUNK", 100)
    monkeypatch.setattr(tail, "MAX_BYTES_PER_POLL", 1000)
    p = tmp_path / "eve.json"
    p.write_text("".join(f"line{i:04d}\n" for i in range(500)))  # 4500 bytes
    t = EveTailer(str(p), from_start=True)
    first = t.read_new()
    assert 0 < len(first) < 500 and len(first) * 9 <= 1100  # about one cap's worth
    got = list(first)
    for _ in range(20):
        got += t.read_new()
    assert got == [f"line{i:04d}" for i in range(500)]  # nothing lost or repeated across the cut points


def test_the_line_cap_also_holds_a_poll_back(tmp_path, monkeypatch):
    from idps.rules import tail

    monkeypatch.setattr(tail, "CHUNK", 20)
    monkeypatch.setattr(tail, "MAX_LINES_PER_POLL", 5)
    p = tmp_path / "eve.json"
    p.write_text("".join(f"{i:03d}\n" for i in range(60)))
    t = EveTailer(str(p), from_start=True)
    first = t.read_new()
    assert 5 <= len(first) < 60
    got = list(first)
    for _ in range(30):
        got += t.read_new()
    assert got == [f"{i:03d}" for i in range(60)]


def test_a_rotation_waits_until_the_old_file_is_read_to_its_end(tmp_path, monkeypatch):
    from idps.rules import tail

    monkeypatch.setattr(tail, "CHUNK", 20)
    monkeypatch.setattr(tail, "MAX_BYTES_PER_POLL", 40)
    p = tmp_path / "eve.json"
    p.write_text("")
    t = EveTailer(str(p))
    t.read_new()
    append(p, "".join(f"old{i:02d}\n" for i in range(30)))
    os.rename(p, tmp_path / "old")
    p.write_text("new\n")
    got = []
    for _ in range(40):
        got += t.read_new()
    assert got == [f"old{i:02d}" for i in range(30)] + ["new"]
