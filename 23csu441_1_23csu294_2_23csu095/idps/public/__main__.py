"""CLI for the public-dataset experiments (plan: docs/training-dataset1.md).

    python -m idps.public run      [options]   CSE-CIC-IDS2018 + CIC-IDS2017 train/evaluate + cross-dataset
    python -m idps.public cse2018  [options]   only the CSE-CIC-IDS2018 part (steps 1-4, 6)
    python -m idps.public cross    [options]   only the CIC-IDS2017 <-> CSE-CIC-IDS2018 test
    python -m idps.public unsw     [options]   UNSW-NB15: load, split, train, evaluate, SHAP/LIME
    python -m idps.public compare  [options]   one comparison table over the datasets' reports
    python -m idps.public labels   [--dataset cic|unsw]   print a label mapping table (Markdown)

Smoke run on the files that exist: add --max-rows 200000 --cap-benign 5000 --cap-attack 3000
--faith-n 20 --lime-samples 200 --models-dir /tmp/m --reports-dir /tmp/r
"""

import argparse
import sys
from pathlib import Path

from idps.detect.data import SEED
from idps.detect.evaluate import write_report
from idps.detect.split import DEFAULT_GAP_MS
from idps.public.cic2017 import load_cic2017
from idps.public.compare import write_comparison
from idps.public.cross import DEFAULT_TRAIN_CAP, dedupe, run_cross
from idps.public.cse2018 import load_cse2018
from idps.public.labels import label_table_markdown, unsw_label_table_markdown
from idps.public.pipeline import (
    DEFAULT_MAX_GAP_LOSS,
    public_split,
    run_cic2017,
    run_cse2018,
    run_unsw,
)
from idps.public.sampling import DEFAULT_CAP_ATTACK, DEFAULT_CAP_BENIGN, Caps
from idps.public.unsw import DEFAULT_MAX_CATEGORIES, load_unsw


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _load18(args):
    caps = Caps(args.cap_benign, args.cap_attack)
    _log(f"loading CSE-CIC-IDS2018 from {args.data_2018} (caps {caps})")
    df, rep = load_cse2018(args.data_2018, caps, args.seed, args.max_rows, args.only)
    _log(
        f"CSE-CIC-IDS2018 sample: {len(df)} rows from {len(rep['files'])} file(s); "
        f"per class {df['label'].value_counts().to_dict()}"
    )
    return df, rep


def _cse2018(args):
    """Load and run the CSE-CIC-IDS2018 part; returns (frame, load report, split)."""
    df, rep = _load18(args)
    sp, _ = run_cse2018(
        df,
        rep,
        seed=args.seed,
        gap_ms=int(args.gap_s * 1000),
        max_gap_loss=args.max_gap_loss,
        models_dir=Path(args.models_dir),
        reports_dir=Path(args.reports_dir),
        faith_n=0 if args.no_faithfulness else args.faith_n,
        lime_samples=args.lime_samples,
        include_lime=not args.no_lime,
        log=_log,
    )
    return df, rep, sp


def _cross(args, held, rep18, sp18):
    """Load CIC-IDS2017, train its in-domain models through this pipeline (unless
    --no-2017-report) and run both directions against the 2018 sample and split.

    `held` is a dict holding the 2018 frame under "df18": it is taken out and replaced by its
    deduplicated copy here, so the undeduplicated frame (about 3M rows x 78 float32 at full size)
    is freed before the 2017 models are trained. Peak memory at full size is the 2018 train and
    test parts (`sp18`) plus ONE deduplicated 2018 frame plus the 2017 sample and its split; see
    docs/training-dataset1.md."""
    caps = Caps(args.cap_benign, args.cap_attack)
    all18, dups18 = dedupe(held.pop("df18"))
    _log(f"loading CIC-IDS2017 from {args.data_2017} (caps {caps})")
    df17, rep17 = load_cic2017(args.data_2017, caps, args.seed, args.max_rows)
    _log(
        f"CIC-IDS2017 sample: {len(df17)} rows; per class {df17['label'].value_counts().to_dict()}"
    )
    if args.no_2017_report:
        sp17 = public_split(df17, int(args.gap_s * 1000), args.max_gap_loss)
    else:
        sp17, _ = run_cic2017(
            df17,
            rep17,
            seed=args.seed,
            gap_ms=int(args.gap_s * 1000),
            max_gap_loss=args.max_gap_loss,
            models_dir=Path(args.models_dir),
            reports_dir=Path(args.reports_dir),
            faith_n=0 if args.no_faithfulness else args.faith_n,
            lime_samples=args.lime_samples,
            include_lime=not args.no_lime,
            log=_log,
        )
    sp17.validation = sp17.validation.iloc[:0]  # not needed any more: saves memory
    all17, dups17 = dedupe(df17)
    del df17
    result = run_cross(
        sp17,
        all17,
        sp18,
        all18,
        rep17,
        rep18,
        seed=args.seed,
        train_cap=args.cross_train_cap,
        log=_log,
        dedupe_stats=(dups17, dups18),
    )
    write_report(
        {**result, "cic_ids2017_load": rep17}, Path(args.reports_dir) / "cross_2017_2018.json"
    )
    _log(f"report -> {Path(args.reports_dir) / 'cross_2017_2018.json'}")


def _unsw(args):
    """Load and run the UNSW-NB15 part; returns (frame, load report, split)."""
    caps = Caps(args.cap_benign, args.cap_attack)
    _log(f"loading UNSW-NB15 from {args.data_unsw} (caps {caps})")
    df, rep = load_unsw(args.data_unsw, caps, args.seed, args.max_rows, args.only)
    _log(
        f"UNSW-NB15 sample: {len(df)} rows from {len(rep['files'])} file(s); "
        f"per class {df['label'].value_counts().to_dict()}"
    )
    sp, _ = run_unsw(
        df,
        rep,
        seed=args.seed,
        gap_ms=int(args.gap_s * 1000),
        max_gap_loss=args.max_gap_loss,
        models_dir=Path(args.models_dir),
        reports_dir=Path(args.reports_dir),
        faith_n=0 if args.no_faithfulness else args.faith_n,
        lime_samples=args.lime_samples,
        include_lime=not args.no_lime,
        max_categories=args.max_categories,
        log=_log,
    )
    return df, rep, sp


def _add_common_options(s) -> None:
    """The options every training command shares."""
    s.add_argument(
        "--cap-benign",
        type=int,
        default=DEFAULT_CAP_BENIGN,
        help="most BENIGN flows kept per day (default %(default)s)",
    )
    s.add_argument(
        "--cap-attack",
        type=int,
        default=DEFAULT_CAP_ATTACK,
        help="most flows kept per day and attack label (default %(default)s)",
    )
    s.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="read only the first N rows of every file (smoke tests)",
    )
    s.add_argument(
        "--gap-s",
        type=float,
        default=DEFAULT_GAP_MS / 1000,
        help="split gap around each cut in seconds (default %(default)s)",
    )
    s.add_argument(
        "--max-gap-loss",
        type=float,
        default=DEFAULT_MAX_GAP_LOSS,
        help="the split gap shrinks until at most this share of a (day, label) "
        "group is dropped; 1 = fixed gap (default %(default)s)",
    )
    s.add_argument("--seed", type=int, default=SEED)
    s.add_argument("--models-dir", default="models")
    s.add_argument("--reports-dir", default="reports")
    s.add_argument(
        "--faith-n",
        type=int,
        default=100,
        help="flows in the SHAP/LIME deletion test (default %(default)s)",
    )
    s.add_argument("--lime-samples", type=int, default=1000)
    s.add_argument("--no-lime", action="store_true")
    s.add_argument("--no-faithfulness", action="store_true")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m idps.public",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("run", "cse2018", "cross"):
        s = sub.add_parser(name)
        s.add_argument("--data-2018", default="data/raw/cse-cic-ids2018")
        s.add_argument("--data-2017", default="data/raw/cic-ids2017/TrafficLabelling")
        s.add_argument(
            "--only",
            nargs="+",
            metavar="TEXT",
            help="only 2018 files whose name contains one of these (e.g. 01-03)",
        )
        _add_common_options(s)
        s.add_argument(
            "--no-2017-report",
            action="store_true",
            help="do not train/evaluate CIC-IDS2017 on its own (reports/cic_ids2017_*.json); "
            "only split it for the cross-dataset test",
        )
        s.add_argument(
            "--cross-train-cap",
            type=int,
            default=DEFAULT_TRAIN_CAP,
            help="most training rows per class in the cross-dataset test (default %(default)s)",
        )
    u = sub.add_parser("unsw")
    u.add_argument("--data-unsw", default="data/raw/unsw-nb15")
    u.add_argument(
        "--only",
        nargs="+",
        metavar="TEXT",
        help="only UNSW-NB15 files whose name contains one of these (e.g. _1 _2)",
    )
    _add_common_options(u)
    u.add_argument(
        "--max-categories",
        type=int,
        default=DEFAULT_MAX_CATEGORIES,
        help="most categories per proto/state/service column, chosen from the training split; "
        "the rest share the code 0 (default %(default)s)",
    )
    c = sub.add_parser("compare")
    c.add_argument("--reports-dir", default="reports")
    c.add_argument(
        "--output", default=None, help="default: <reports-dir>/public_datasets_comparison.json"
    )
    lab = sub.add_parser("labels")
    lab.add_argument("--dataset", choices=("cic", "unsw"), default="cic")
    args = p.parse_args(argv)
    try:
        if args.cmd == "labels":
            print(unsw_label_table_markdown() if args.dataset == "unsw" else label_table_markdown())
        elif args.cmd == "unsw":
            _unsw(args)
        elif args.cmd == "compare":
            out = write_comparison(args.reports_dir, args.output)
            _log(f"comparison -> {out}")
        elif args.cmd == "cse2018":
            _cse2018(args)
        elif args.cmd == "run":
            df18, rep18, sp18 = _cse2018(args)
            sp18.validation = sp18.validation.iloc[:0]  # not needed any more: saves memory
            held = {"df18": df18}
            del df18
            _cross(args, held, rep18, sp18)
        else:
            df18, rep18 = _load18(args)
            sp18 = public_split(df18, int(args.gap_s * 1000), args.max_gap_loss)
            held = {"df18": df18}
            del df18
            _cross(args, held, rep18, sp18)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
