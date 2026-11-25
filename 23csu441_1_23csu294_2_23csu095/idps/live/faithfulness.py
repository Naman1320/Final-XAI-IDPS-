"""The model's explanation-faithfulness result, read once at start-up for the sensor status.

The file is the JSON written by `python -m idps.explain faithfulness`. Only a few numbers are
taken from it (model-level results, nothing about live flows); unknown keys are ignored. A
missing or invalid file is a warning, never a reason not to run.
"""

from __future__ import annotations

import json
import logging
import math
import os
import stat

from idps.live.text import has_unsafe

log = logging.getLogger("idps.live")

MAX_REPORT_BYTES = 1024 * 1024
METHODS = ("shap", "lime")
_UNIT = (0.0, 1.0)
_DROP = (-1.0, 1.0)  # a drop in the predicted class's probability
# The ratio is null when random removal changes nothing, and negative when the explanation's
# deletion RAISED confidence: both are real (and bad) outcomes the analyst must see.
_RATIO = (-1e9, 1e9)
# (key, low, high) of every number kept per method; ratio_to_random may also be null
METHOD_FIELDS = (("mean_drop", *_DROP), ("ratio_to_random", *_RATIO),
                 ("label_flip_rate", *_UNIT), ("share_flows_beating_random", *_UNIT))
NULLABLE = frozenset({"ratio_to_random"})
_HEX = frozenset("0123456789abcdef")


class FaithfulnessError(ValueError):
    pass


def _number(value, low: float, high: float, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FaithfulnessError(f"{what} is not a number")
    try:
        value = float(value)
    except OverflowError as exc:  # an integer with hundreds of digits
        raise FaithfulnessError(f"{what} is too large") from exc
    if not math.isfinite(value) or not low <= value <= high:
        raise FaithfulnessError(f"{what} is outside {low:g}..{high:g}")
    return value


def _integer(value, low: int, high: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise FaithfulnessError(f"{what} is not an integer in {low}..{high}")
    return value


def _dict(value, what: str) -> dict:
    if not isinstance(value, dict):
        raise FaithfulnessError(f"{what} is not an object")
    return value


def parse_report(data: object, model_name: str, model_sha256: str | None = None) -> dict:
    """The `faithfulness` part of the status payload, from a decoded report. Raises
    FaithfulnessError for anything out of bounds or missing.

    `model_sha256` is the digest of the loaded bundle. When the report has one too (reports written
    since `config.model_sha256` exists) they are compared: `model_check` is "digest". Older reports
    fall back to the algorithm name ("name"), a weak match: a retrained model of the same
    algorithm passes it."""
    data = _dict(data, "the report")
    config = _dict(data.get("config"), "config")
    model = config.get("model")
    if (not isinstance(model, str) or not model.strip() or len(model) > 64
            or has_unsafe(model)):
        raise FaithfulnessError("config.model is not a short plain string")
    methods_in = _dict(data.get("methods"), "methods")
    methods = {}
    for name in METHODS:
        if name in methods_in:
            entry = _dict(methods_in[name], f"methods.{name}")
            methods[name] = {
                key: None if key in NULLABLE and entry.get(key) is None
                else _number(entry.get(key), lo, hi, f"methods.{name}.{key}")
                for key, lo, hi in METHOD_FIELDS}
    if not methods:
        raise FaithfulnessError("no shap or lime result in methods")
    report_digest = config.get("model_sha256")
    if report_digest is not None and not (
            isinstance(report_digest, str) and len(report_digest) == 64
            and set(report_digest.lower()) <= _HEX):
        raise FaithfulnessError("config.model_sha256 is not a sha256 hex digest")
    if report_digest is not None and model_sha256:
        check, matches = "digest", report_digest.lower() == model_sha256.lower()
    else:
        check, matches = "name", model == model_name
    return {
        "model": model,
        "model_matches": matches,
        "model_check": check,
        "flows": _integer(config.get("n_flows"), 1, 10_000_000, "config.n_flows"),
        "top_k": _integer(config.get("top_k"), 1, 1_000, "config.top_k"),
        "random_mean_drop": _number(_dict(data.get("random"), "random").get("mean_drop"),
                                    *_DROP, "random.mean_drop"),
        "methods": methods,
    }


def _read_capped(path: str) -> bytes:
    """The file's bytes, at most MAX_REPORT_BYTES. Opened once and checked on the open descriptor
    (no is_file()-then-open window): never blocks on a FIFO and refuses anything but a regular
    file. The path is the operator's own setting, so a symlink to the report is fine."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise FaithfulnessError("not a regular file")
        chunks, total = [], 0
        while total <= MAX_REPORT_BYTES:
            chunk = os.read(fd, min(65536, MAX_REPORT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    if total > MAX_REPORT_BYTES:
        raise FaithfulnessError(f"file is over {MAX_REPORT_BYTES} bytes")
    return b"".join(chunks)


def load_faithfulness(path: str | None, model_name: str,
                      model_sha256: str | None = None) -> dict | None:
    """Read and validate the report once. None (with one warning) if there is none to use."""
    if not path:
        return None
    try:
        raw = _read_capped(path)
        result = parse_report(json.loads(raw), model_name, model_sha256)
    except (OSError, ValueError, ArithmeticError, RecursionError) as exc:  # incl. FaithfulnessError
        log.warning("ignoring the faithfulness report %s (%s): the status goes without it",
                    os.path.basename(path), exc)
        return None
    if not result["model_matches"]:
        log.warning("the faithfulness report is not for this model (%s check; report: %r, sensor: "
                    "%r): it is reported with model_matches=false", result["model_check"],
                    result["model"], model_name)
    elif result["model_check"] == "name":
        log.info("the faithfulness report has no model digest: matched by algorithm name only")
    return result
