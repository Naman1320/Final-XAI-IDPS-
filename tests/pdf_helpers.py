"""Reading text back out of a PDF without any PDF library (none is installed besides reportlab,
which only writes): decode the content streams and collect the strings the page draws."""

import base64
import re
import zlib

_STREAM = re.compile(rb"stream\r?\n(.*?)\s*endstream", re.S)
_TJ = re.compile(rb"\(((?:\\.|[^\\()])*)\)\s*Tj")
_BLOCK = re.compile(rb"\bBT\b(.*?)\bET\b", re.S)


def _decode(data: bytes) -> bytes:
    data = data.strip()
    if data.endswith(b"~>"):  # ASCII85, which reportlab applies before Flate by default
        data = base64.a85decode(data[:-2], adobe=False)
    try:
        return zlib.decompress(data)
    except zlib.error:
        return data


def _unescape(raw: bytes) -> str:
    out = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8)]), raw)
    out = re.sub(rb"\\(.)", rb"\1", out, flags=re.S)
    return out.decode("cp1252", "replace")


def pdf_text(pdf: bytes) -> str:
    """All the text the PDF's pages draw, one line of text per line."""
    lines = []
    for stream in _STREAM.findall(pdf):
        try:
            content = _decode(stream)
        except Exception:  # noqa: BLE001  fonts, images: not text
            continue
        for block in _BLOCK.findall(content):
            # reportlab draws a line as several strings (it breaks at "<" and ">"); T* starts a line
            for line in re.split(rb"\bT\*", block):
                parts = [_unescape(m) for m in _TJ.findall(line)]
                if parts:
                    lines.append("".join(parts))
    return "\n".join(lines)
