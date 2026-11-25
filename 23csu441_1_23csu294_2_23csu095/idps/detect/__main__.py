"""CLI: python -m idps.detect train labelled.parquet [more ...] --model xgboost|rf|mlp
                 --split class-time|day|window -o models/model.joblib --report reports/metrics.json
         python -m idps.detect evaluate <bundle> <labelled.parquet> [--report out.json]
         python -m idps.detect retrain --data labelled.parquet [...] --feedback feedback.parquet
                 --current models/old.joblib -o models/new.joblib [--feedback-weight W] [--tolerance T]
         python -m idps.detect drift-reference --model models/old.joblib --data labelled.parquet [...]
         python -m idps.detect keygen --out keys/model-signing      (signing key pair; see signing.py)
         python -m idps.detect sign models/x.joblib --key keys/model-signing.key
         python -m idps.detect verify models/x.joblib --public-key keys/model-signing.pub"""

import argparse
import json
import sys
from pathlib import Path

from idps.detect.bundle import DEFAULT_MODEL_PATH, load_bundle, read_digest, save_bundle
from idps.detect.data import SEED, load_labelled
from idps.detect.drift import sidecar_path, write_reference
from idps.detect.evaluate import evaluate_bundle, write_report
from idps.detect.models import MODEL_NAMES
from idps.detect.retrain import (
    DEFAULT_FEEDBACK_WEIGHT,
    DEFAULT_MIN_HOLDOUT,
    DEFAULT_TOLERANCE,
)
from idps.detect.split import DEFAULT_GAP_MS
from idps.detect.train import SPLIT_MODES, resplit, train_bundle_with_split


def _brief(m: dict) -> str:
    fpr = m["benign_false_positive_rate"]
    ov = m.get("train_overlap")
    overlap = "" if ov is None else f", {ov['share']:.1%} of rows identical to a train row"
    return (f"macro-F1 {m['macro_f1']:.3f}, accuracy {m['accuracy']:.3f}, "
            f"BENIGN FPR {'n/a' if fpr is None else f'{fpr:.4f}'}{overlap}")


def _train(args: argparse.Namespace) -> int:
    df, meta = load_labelled(args.inputs, allow_low_match=args.allow_low_match_rate)
    bundle, report, sp = train_bundle_with_split(
        df, meta, model=args.model, split=args.split, drop_features=args.drop_feature,
        val=args.val, test=args.test, seed=args.seed, gap_ms=args.gap_ms,
        allow_unseen_test_classes=args.allow_unseen_test_classes,
        drop_duplicates=not args.keep_duplicates)
    save_bundle(bundle, args.output)
    write_reference(args.output, sp.train, read_digest(args.output), bundle.features)
    print(f"{len(df)} rows, split={args.split}, model={args.model} -> {args.output} "
          f"(version {bundle.version}; drift reference {sidecar_path(args.output)})",
          file=sys.stderr)
    print(f"validation: {_brief(report['metrics']['validation'])}", file=sys.stderr)
    print(f"test:       {_brief(report['metrics']['test'])}", file=sys.stderr)
    if args.report:
        write_report(report, args.report)
        print(f"report -> {args.report}", file=sys.stderr)
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    df, meta = load_labelled([args.data], allow_low_match=args.allow_low_match_rate)
    bundle = load_bundle(args.bundle, live_meta=meta, live_columns=list(df.columns))
    result = evaluate_bundle(bundle, df, meta)
    if args.report:
        write_report(result, args.report)
    print(json.dumps({k: result[k] for k in ("n", "accuracy", "macro_f1",
                                             "benign_false_positive_rate")}, indent=2))
    return 0


def _retrain(args: argparse.Namespace) -> int:
    from idps.detect.retrain import EXIT_REJECTED, retrain, same_file, write_kept
    from idps.features import read_features

    if same_file(args.output, args.current):
        raise ValueError("-o must not be the --current model: a retrained model is written as a "
                         "new file, the current one is never overwritten")
    df, meta = load_labelled(args.data, allow_low_match=args.allow_low_match_rate)
    fb, fb_meta = read_features(args.feedback)
    current = load_bundle(args.current, live_meta=meta, live_columns=list(df.columns))
    result = retrain(df, meta, fb, fb_meta, current, current_sha256=read_digest(args.current),
                     feedback_weight=args.feedback_weight, tolerance=args.tolerance,
                     seed=args.seed, min_holdout=args.min_holdout,
                     allow_different_base=args.allow_different_base)
    rep = result.report
    out = Path(args.report) if args.report else Path("reports") / f"retrain_{result.bundle.version}.json"
    rep["new"]["output"] = str(args.output) if result.keep else None
    rep["written"] = result.keep
    try:
        if result.keep:
            write_kept(result, args.output)
    except Exception as exc:  # the report still says what happened; nothing half-written is left
        rep["new"]["output"], rep["written"] = None, False
        rep["error"] = f"{type(exc).__name__}: {exc}"
        write_report(rep, out)
        raise
    write_report(rep, out)
    b, h = rep["base_test"], rep["feedback_holdout"]
    print(f"base test macro-F1:  current {b['current']['macro_f1']:.4f}  new {b['new']['macro_f1']:.4f}"
          f"  (min {rep['criteria']['min_macro_f1']:.4f})", file=sys.stderr)
    print(f"feedback holdout accuracy ({h['new']['n']} rows): current {h['current']['accuracy']:.4f}"
          f"  new {h['new']['accuracy']:.4f}", file=sys.stderr)
    print(f"report -> {out}", file=sys.stderr)
    if not result.keep:
        for why in rep["decision"]["reasons"]:
            print(f"rejected: {why}", file=sys.stderr)
        print(f"the new model was NOT written; {args.current} stays in use", file=sys.stderr)
        return EXIT_REJECTED
    print(f"kept: {args.output} (version {result.bundle.version})", file=sys.stderr)
    return 0


def _drift_reference(args: argparse.Namespace) -> int:
    df, meta = load_labelled(args.data, allow_low_match=args.allow_low_match_rate)
    bundle = load_bundle(args.model, live_meta=meta, live_columns=list(df.columns))
    sp = resplit(bundle, df)
    want = bundle.split["parts"]["train"]["rows"]
    got = sp.description["parts"]["train"]["rows"]
    if got != want:
        raise ValueError(f"these data do not reproduce the model's training rows ({got} rows "
                         f"after the split, the model trained on {want}); pass the same files "
                         "the model was trained on")
    path = write_reference(args.model, sp.train, read_digest(args.model), bundle.features)
    print(f"drift reference ({len(sp.train)} training rows) -> {path}", file=sys.stderr)
    return 0


def _keygen(args: argparse.Namespace) -> int:
    from idps.detect.signing import generate_keypair, key_id, load_public_key

    priv, pub = generate_keypair(args.out)
    print(f"signing key {priv} (keep it off the sensors; mode 0600) and public key {pub} "
          f"(key id {key_id(load_public_key(pub))}): give the sensors {pub.name} "
          "as IDPS_MODEL_PUBLIC_KEY", file=sys.stderr)
    return 0


def _sign(args: argparse.Namespace) -> int:
    from idps.detect.signing import load_private_key, sign_bundle

    key = load_private_key(args.key)
    # Sign only what loads: the sha256 file, permissions and bundle format are checked first
    # (that unpickles the bundle: sign only bundles you made yourself).
    if args.cloud:  # a cloud bundle has the flow-log column layout (idps.cloud.collector)
        from idps.cloud.collector import load_cloud_bundle

        load_cloud_bundle(args.bundle)
    else:
        load_bundle(args.bundle)
    out = sign_bundle(args.bundle, key)
    print(f"signed {args.bundle} -> {out}", file=sys.stderr)
    return 0


def _verify(args: argparse.Namespace) -> int:
    from idps.detect.signing import (
        SignatureError,
        load_public_key,
        read_signature,
        verify_bytes,
    )

    data = Path(args.bundle).read_bytes()
    try:  # checks the bytes only: nothing is unpickled
        fields = verify_bytes(data, read_signature(args.bundle), load_public_key(args.public_key))
    except SignatureError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(f"OK: signed by key {fields['key_id']} at {fields['signed_at']}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m idps.detect")
    sub = parser.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train", help="train a model on labelled feature files")
    t.add_argument("inputs", nargs="+", help="labelled parquet file(s) from 'features label'")
    t.add_argument("--model", choices=MODEL_NAMES, default="xgboost")
    t.add_argument("--split", choices=SPLIT_MODES, default="class-time",
                   help="class-time (default; recommended for CIC-IDS2017), day or window")
    t.add_argument("--val", type=float, default=None,
                   help="validation size: number of days (day split, default 1) or "
                        "fraction of rows (class-time and window, default 0.2)")
    t.add_argument("--test", type=float, default=None,
                   help="test size: number of days (default 1) or fraction (default 0.2)")
    t.add_argument("--gap-ms", type=int, default=DEFAULT_GAP_MS,
                   help="class-time: drop rows starting this close to a cut (default 120000, "
                        "the active timeout)")
    t.add_argument("--allow-unseen-test-classes", action="store_true",
                   help="do not require every validation/test class to be in train "
                        "(leave-one-day-out experiments)")
    t.add_argument("--keep-duplicates", action="store_true",
                   help="do not drop exact duplicate rows within each split")
    t.add_argument("--allow-low-match-rate", action="store_true",
                   help="train on label files whose match rate is below 50%% or unknown")
    t.add_argument("--drop-feature", action="append", default=[], metavar="NAME",
                   help="exclude a model feature, e.g. dst_port (repeatable)")
    t.add_argument("--seed", type=int, default=SEED)
    t.add_argument("-o", "--output", default=DEFAULT_MODEL_PATH)
    t.add_argument("--report", default=None, help="write metrics JSON here")
    t.set_defaults(fn=_train)

    e = sub.add_parser("evaluate", help="evaluate a saved bundle on a labelled file")
    e.add_argument("bundle")
    e.add_argument("data")
    e.add_argument("--report", default=None)
    e.add_argument("--allow-low-match-rate", action="store_true",
                   help="evaluate on a label file whose match rate is below 50%% or unknown")
    e.set_defaults(fn=_evaluate)

    r = sub.add_parser("retrain", help="retrain with analyst feedback; keep it only if not worse")
    r.add_argument("--data", nargs="+", required=True,
                   help="the labelled parquet file(s) the current model was trained on")
    r.add_argument("--feedback", required=True, help="feedback.parquet from soc.api.export_feedback")
    r.add_argument("--current", required=True, help="the model in use (never overwritten)")
    r.add_argument("-o", "--output", required=True, help="where the new model goes if it is kept")
    r.add_argument("--feedback-weight", type=float, default=DEFAULT_FEEDBACK_WEIGHT,
                   help=f"weight of a feedback row (default {DEFAULT_FEEDBACK_WEIGHT:g})")
    r.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE,
                   help=f"macro-F1 the new model may lose on the base test split "
                        f"(default {DEFAULT_TOLERANCE})")
    r.add_argument("--min-holdout", type=int, default=DEFAULT_MIN_HOLDOUT,
                   help=f"fewest feedback holdout rows to trust the comparison; a model is never "
                        f"kept on fewer (default {DEFAULT_MIN_HOLDOUT})")
    r.add_argument("--allow-different-base", action="store_true",
                   help="go on although --data does not reproduce the current model's training "
                        "split (the comparison is then not on the model's own test data)")
    r.add_argument("--seed", type=int, default=SEED)
    r.add_argument("--report", default=None,
                   help="comparison report (default reports/retrain_<version>.json)")
    r.add_argument("--allow-low-match-rate", action="store_true")
    r.set_defaults(fn=_retrain)

    d = sub.add_parser("drift-reference",
                       help="write <model>.drift.json for a model that has none")
    d.add_argument("--model", required=True)
    d.add_argument("--data", nargs="+", required=True,
                   help="the labelled parquet file(s) the model was trained on")
    d.add_argument("--allow-low-match-rate", action="store_true")
    d.set_defaults(fn=_drift_reference)

    k = sub.add_parser("keygen", help="make a model signing key pair (<out>.key, <out>.pub)")
    k.add_argument("--out", required=True)
    k.set_defaults(fn=_keygen)
    sg = sub.add_parser("sign", help="sign a model bundle (writes <bundle>.sig)")
    sg.add_argument("bundle")
    sg.add_argument("--key", required=True, help="the private key from keygen")
    sg.add_argument("--cloud", action="store_true",
                    help="the bundle is a cloud model (flow-log features, idps.cloud.train_model)")
    sg.set_defaults(fn=_sign)
    v = sub.add_parser("verify", help="check a model bundle's signature (does not load it)")
    v.add_argument("bundle")
    v.add_argument("--public-key", required=True)
    v.set_defaults(fn=_verify)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, FileNotFoundError, FileExistsError) as exc:  # not other OSErrors
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
