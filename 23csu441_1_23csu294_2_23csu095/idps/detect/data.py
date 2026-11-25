"""Load labelled feature files for training and evaluation."""

from collections.abc import Iterable
from pathlib import Path

import pandas as pd

from idps.features import check_same_extraction, read_features
from idps.features.labels import training_rows

BENIGN = "BENIGN"
SEED = 42
# Label files whose join matched fewer flows than this are mostly guesses (wrong timezone,
# wrong PCAP, ...); training on them is refused unless the caller opts in.
MIN_MATCH_RATE = 0.5


def _check_match_rate(path: Path, meta: dict, minimum: float, allow_low: bool) -> None:
    summary = meta.get("match_summary")
    rate = summary.get("match_rate") if isinstance(summary, dict) else None
    if rate is None:
        if not allow_low:
            raise ValueError(
                f"{path} has no match_summary.match_rate in its metadata, so its label quality "
                "is unknown; re-create it with 'python -m idps.features label' or pass "
                "allow_low_match=True (--allow-low-match-rate)")
    elif rate < minimum and not allow_low:
        raise ValueError(
            f"{path} has a label match rate of {rate:.1%}, below the minimum {minimum:.0%}; "
            "most of its flows were not matched to a label. Check --utc-offset-hours and the "
            "PCAP/CSV pair, or pass allow_low_match=True (--allow-low-match-rate) to train anyway")


def load_labelled(paths: Iterable[str | Path], min_match_rate: float = MIN_MATCH_RATE,
                  allow_low_match: bool = False) -> tuple[pd.DataFrame, dict]:
    """Read one or more labelled parquet/CSV files into one frame plus their extraction meta.

    All files must have extraction metadata and the same extraction settings. If a file still
    has the join columns (label_matched / label_ambiguous), only training-safe rows are kept.
    The returned meta is the first file's, plus a `sources` list.

    Each file must carry `match_summary.match_rate` (written by 'features label') of at least
    `min_match_rate`; a file below it, or without a match summary, is refused unless
    `allow_low_match=True` (CLI: --allow-low-match-rate). Files labelled with different
    `utc_offset_hours` are never mixed: one of them has its timestamps shifted.
    """
    paths = [Path(p) for p in paths]
    if not paths:
        raise ValueError("no input files")
    frames, first_meta = [], None
    for p in paths:
        df, meta = read_features(p)
        if not meta:
            raise ValueError(
                f"{p} has no extraction metadata; refusing to use it (re-create it with "
                "'python -m idps.features extract' and 'label')")
        _check_match_rate(p, meta, min_match_rate, allow_low_match)
        if first_meta is None:
            first_meta = meta
        else:
            check_same_extraction(first_meta, meta)
            if meta.get("utc_offset_hours") != first_meta.get("utc_offset_hours"):
                raise ValueError(
                    f"{p} was labelled with utc_offset_hours={meta.get('utc_offset_hours')} but "
                    f"{paths[0]} with {first_meta.get('utc_offset_hours')}; refusing to mix "
                    "files with different timezone offsets (re-run 'features label')")
        for col in ("start_ms", "label"):
            if col not in df.columns:
                raise ValueError(f"{p} has no '{col}' column (is it a labelled file?)")
        if {"label_matched", "label_ambiguous"} <= set(df.columns):
            df = training_rows(df)
        frames.append(df)
    out = pd.concat(frames, ignore_index=True)
    return out, {**first_meta, "sources": [str(p) for p in paths]}
