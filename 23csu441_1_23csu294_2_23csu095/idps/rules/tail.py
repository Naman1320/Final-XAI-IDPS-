"""Follow a growing text file the way `tail -F` does, without a thread: call `read_new()` to poll.

Handles what a log written by another process does to a reader:

* a line is only returned once its newline has arrived (a half-written last line waits);
* truncation (the file got smaller than what was read, e.g. emptied by a size cap): start again at
  the beginning, dropping the half line that was buffered;
* rotation (the path now names a different file, or vanished and came back): the rest of the old
  file is read first, then the new one from its beginning;
* a file that does not exist yet is waited for, and when it appears it is read from its beginning
  (it was created after we started, so none of it is old);
* what is lost: a half line that was buffered when the file was truncated or rotated away is dropped
  (counted in `fragments_dropped`), and so are lines written between the last poll and a truncation.
  A truncation followed by more new data than the old size before the next poll is not seen at all;
  at poll intervals of half a second and alert-only volume that needs a 32 MB burst, so it is
  accepted;
* a line longer than `max_line_bytes` is skipped (and counted), so one bad line cannot fill memory.

Unless `from_start` is set, a file that already exists when the tailer starts is read from its END:
what was written before the sensor started is history and is not sent again.
"""

from __future__ import annotations

import os

CHUNK = 64 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_LINES_PER_POLL = 50_000  # a poll stops reading more chunks once it has this many lines ...
MAX_BYTES_PER_POLL = 8 * 1024 * 1024  # ... or this many bytes, so a huge backlog never fills memory


class EveTailer:
    def __init__(self, path: str, *, from_start: bool = False,
                 max_line_bytes: int = MAX_LINE_BYTES) -> None:
        self.path = str(path)
        self.from_start = from_start
        self.max_line_bytes = max_line_bytes
        self.skipped_lines = 0  # lines over max_line_bytes
        self.fragments_dropped = 0  # buffered half lines discarded by a truncation or rotation
        self.truncations = 0
        self.rotations = 0
        self._f = None
        self._ident: tuple[int, int] | None = None  # (st_dev, st_ino) of the open file
        self._pos = 0
        self._buf = b""
        self._skipping = False  # inside an over-long line, until its newline
        self._first_open = True
        self._lines: list[str] = []
        self._at_eof = True

    @property
    def exists(self) -> bool:
        return self._f is not None

    def close(self) -> None:
        if self._f is not None:
            self._f.close()
            self._f = None

    def _open(self) -> bool:
        """Open the path if it exists. Raises OSError for anything but 'not there'."""
        try:
            f = open(self.path, "rb")  # noqa: SIM115  kept open between polls
        except FileNotFoundError:
            self._first_open = False  # whatever appears later was created after we started
            return False
        st = os.fstat(f.fileno())
        self._f, self._ident = f, (st.st_dev, st.st_ino)
        self._buf, self._skipping = b"", False
        if self._first_open and not self.from_start:
            self._pos = st.st_size
            f.seek(self._pos)
        else:
            self._pos = 0
        self._first_open = False
        return True

    def read_new(self) -> list[str]:
        """The complete lines written since the last call (without their newline)."""
        self._lines = []
        if self._f is None and not self._open():
            return []
        for _ in range(3):  # a rotation seen at the end of a read is followed at once
            self._read_open_file()
            if not self._at_eof or not self._rotated():  # not at the end yet: finish this file first
                break
            self.rotations += 1
            self._drop_fragment()
            self.close()
            if not self._open():
                break
        return self._lines

    def _rotated(self) -> bool:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return False  # gone for now: keep the old handle until something new appears
        return (st.st_dev, st.st_ino) != self._ident

    def _read_open_file(self) -> None:
        f = self._f
        size = os.fstat(f.fileno()).st_size
        if size < self._pos:  # truncated
            self.truncations += 1
            self._drop_fragment()
            self._pos, self._skipping = 0, False
        f.seek(self._pos)
        read = 0
        self._at_eof = False
        while len(self._lines) < MAX_LINES_PER_POLL and read < MAX_BYTES_PER_POLL:
            chunk = f.read(CHUNK)
            if not chunk:
                self._at_eof = True
                break
            read += len(chunk)
            self._pos += len(chunk)
            self._feed(chunk)
        # (an unfinished line stays in self._buf for the next poll)

    def _drop_fragment(self) -> None:
        if self._buf.strip() or self._skipping:
            self.fragments_dropped += 1
        self._buf, self._skipping = b"", False

    def _feed(self, chunk: bytes) -> None:
        while chunk:
            nl = chunk.find(b"\n")
            if nl < 0:
                self._extend(chunk)
                return
            self._extend(chunk[:nl])
            chunk = chunk[nl + 1:]
            if self._skipping:
                self._skipping = False
            elif self._buf.strip():
                self._lines.append(self._buf.decode("utf-8", errors="replace"))
            self._buf = b""

    def _extend(self, data: bytes) -> None:
        if self._skipping:
            return
        self._buf += data
        if len(self._buf) > self.max_line_bytes:
            self._buf, self._skipping = b"", True
            self.skipped_lines += 1
