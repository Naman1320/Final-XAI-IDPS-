"""Text that goes into the status report must pass the SOC's check (soc/api/common.py
`unsafe_chars`, mirrored: idps does not import soc): no control, format (bidi overrides, zero
width) or line/paragraph separator characters. Otherwise the SOC would refuse the whole report."""

from __future__ import annotations

import unicodedata

UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


def is_unsafe(char: str) -> bool:
    return unicodedata.category(char) in UNSAFE_CATEGORIES


def has_unsafe(text: str) -> bool:
    return any(is_unsafe(c) for c in text)


def clean(text: str) -> str:
    """`text` without the unsafe characters."""
    return "".join(c for c in text if not is_unsafe(c))
