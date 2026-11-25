"""Export analyst feedback as a training file for `python -m idps.detect retrain`.

    python -m soc.api.export_feedback --db sqlite:///soc.db --model models/week_xgboost.joblib \\
        -o data/processed/feedback.parquet

Rows: alerts with status false_positive (label BENIGN) or confirmed (label true_class, else the
predicted class) that carry the flow's features AND were scored by this very model
(alert.model_sha256 == the model's sha256). Repeated ingests of one flow (same sensor, 5-tuple, start and end) count once. Alerts without features, from another model or with
a missing/non-finite model feature are skipped and counted. The file holds the identity columns
and all model features (idps.features.FEATURE_COLUMNS), `label` and `alert_id`, and carries the
model's extraction metadata, so read_features / check_same_extraction work on it.

The database is opened read-only in spirit: nothing is written. A database that predates the
feedback columns must first be upgraded by starting the SOC once.
"""

from __future__ import annotations

import argparse
import math
import os
import sys

import pandas as pd
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from idps.detect.bundle import Bundle, load_bundle, read_digest
from idps.features import FEATURE_COLUMNS, ID_COLUMNS, write_features
from soc.api.db import make_engine
from soc.api.feedback import feedback_label, flow_key, judged_alerts

COUNT_KEYS = ("judged", "duplicates", "no_features", "other_model", "bad_features", "exported")


def build_feedback(db: Session, bundle: Bundle, model_sha256: str) -> tuple[pd.DataFrame, dict]:
    """The feedback frame (FEATURE_COLUMNS + label + alert_id) and the counts of what was kept
    and why the rest was not."""
    counts = dict.fromkeys(COUNT_KEYS, 0)
    rows, seen = [], set()
    for a in judged_alerts(db):
        counts["judged"] += 1
        key = flow_key(a)
        if key in seen:  # the same flow ingested twice: the first judged alert counts
            counts["duplicates"] += 1
            continue
        seen.add(key)
        if not a.features:
            counts["no_features"] += 1
            continue
        if a.model_sha256 != model_sha256:
            counts["other_model"] += 1
            continue
        feats = a.features
        try:
            values = {n: float(feats[n]) for n in bundle.features}
        except (KeyError, TypeError, ValueError):
            counts["bad_features"] += 1
            continue
        if not all(math.isfinite(v) for v in values.values()):
            counts["bad_features"] += 1
            continue
        row = {c: getattr(a, c) for c in ID_COLUMNS}
        row.update({n: float(v) for n, v in feats.items() if n not in ID_COLUMNS
                    and isinstance(v, int | float) and math.isfinite(v)})
        row.update(label=feedback_label(a), alert_id=a.id)
        rows.append(row)
        counts["exported"] += 1
    df = pd.DataFrame(rows, columns=[*FEATURE_COLUMNS, "label", "alert_id"])
    return df, counts


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m soc.api.export_feedback", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=os.environ.get("IDPS_SOC_DATABASE_URL"),
                   help="SQLAlchemy URL of the SOC database (default: IDPS_SOC_DATABASE_URL)")
    p.add_argument("--model", required=True, help="the model the alerts were scored by")
    p.add_argument("-o", "--output", required=True, help="feedback parquet to write")
    args = p.parse_args(argv)
    if not args.db:
        print("error: give --db or set IDPS_SOC_DATABASE_URL", file=sys.stderr)
        return 2
    try:
        bundle = load_bundle(args.model)
        sha = read_digest(args.model)
    except Exception as exc:  # noqa: BLE001  unpickling can fail in any way
        print(f"error: cannot load the model {args.model}: {exc}", file=sys.stderr)
        return 2
    engine = make_engine(args.db)
    if "features" not in {c["name"] for c in inspect(engine).get_columns("alerts")}:
        print("error: this database has no alerts.features column; start the SOC once with the "
              "new code (it upgrades the schema), then export again", file=sys.stderr)
        return 2
    with Session(engine) as db:
        df, counts = build_feedback(db, bundle, sha)
    summary = ", ".join(f"{k} {counts[k]}" for k in COUNT_KEYS)
    if df.empty:
        print(f"nothing to export ({summary}); no file written", file=sys.stderr)
        return 1
    meta = {**bundle.extraction_meta, "feedback": {"model_sha256": sha, "counts": counts}}
    from pathlib import Path
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    write_features(df, args.output, meta)
    print(f"{summary} -> {args.output}; labels: "
          f"{df['label'].value_counts().to_dict()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
