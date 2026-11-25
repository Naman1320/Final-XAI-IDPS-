"""CLI: python -m idps.features extract <pcap> -o out.parquet [--backend ...]
         python -m idps.features label flows.parquet labels.csv ... -o labelled.parquet"""

import argparse
import json
import sys

from idps.capture import (
    DEFAULT_ACTIVE_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    flows_from_pcap,
    select_backend,
)
from idps.features import extraction_meta, read_features, to_frame, write_features


def _extract(args: argparse.Namespace) -> int:
    backend = select_backend(args.backend)
    df = to_frame(flows_from_pcap(args.pcap, backend=backend,
                                  idle_timeout=args.idle_timeout,
                                  active_timeout=args.active_timeout))
    meta = {**extraction_meta(backend, args.idle_timeout, args.active_timeout),
            "source": str(args.pcap)}
    write_features(df, args.output, meta)
    print(f"{len(df)} flows -> {args.output} (extractor: {backend})", file=sys.stderr)
    return 0


def _label(args: argparse.Namespace) -> int:
    from idps.features.labels import join_labels, load_cic_labels, summarize_matches, training_rows

    flows, meta = read_features(args.flows)
    if not meta:
        print("warning: flows file has no extraction metadata (was it made by 'extract'?)",
              file=sys.stderr)
    labels = load_cic_labels(args.labels, args.utc_offset_hours)
    joined = join_labels(flows, labels, tolerance_ms=args.tolerance_ms)
    summary = summarize_matches(joined)
    out = joined if args.keep_unmatched else training_rows(joined)
    write_features(out, args.output, {
        **meta, "labels": [str(p) for p in args.labels],
        "utc_offset_hours": args.utc_offset_hours, "tolerance_ms": args.tolerance_ms,
        "label_window": "[start - tolerance, end + ts_resolution + tolerance]",
        "match_summary": {k: v for k, v in summary.items() if k != "per_label"},
        "unmatched_and_ambiguous_removed": not args.keep_unmatched,
    })
    print(json.dumps(summary, indent=2))
    if summary["flows"] and summary["match_rate"] < args.min_match_rate:
        print(f"error: match rate {summary['match_rate']:.1%} is below --min-match-rate "
              f"{args.min_match_rate:.0%}; check --utc-offset-hours and the timestamps "
              f"(output still written to {args.output})", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m idps.features")
    sub = parser.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("extract", help="PCAP -> flow features file")
    e.add_argument("pcap")
    e.add_argument("-o", "--output", required=True, help="out.parquet (or out.csv)")
    e.add_argument("--backend", choices=["nfstream", "scapy", "auto"], default=None,
                   help="default: IDPS_EXTRACTOR, else nfstream")
    e.add_argument("--idle-timeout", type=int, default=int(DEFAULT_IDLE_TIMEOUT),
                   help="seconds (whole number)")
    e.add_argument("--active-timeout", type=int, default=int(DEFAULT_ACTIVE_TIMEOUT),
                   help="seconds (whole number)")
    e.set_defaults(fn=_extract)

    j = sub.add_parser("label", help="join CIC-IDS2017 label CSVs onto extracted flows")
    j.add_argument("flows", help="parquet from 'extract'")
    j.add_argument("labels", nargs="+", help="CIC-IDS2017 label CSV file(s)")
    j.add_argument("-o", "--output", required=True)
    j.add_argument("--utc-offset-hours", type=float, default=0.0)
    j.add_argument("--tolerance-ms", type=int, default=1000,
                   help="slack on both sides of the label window, ms (default 1000); minute-only "
                        "timestamps are handled separately (the window also widens forward by "
                        "the row's timestamp resolution)")
    j.add_argument("--min-match-rate", type=float, default=0.5,
                   help="exit with an error below this match rate (default 0.5)")
    j.add_argument("--keep-unmatched", action="store_true",
                   help="keep UNMATCHED and ambiguous rows (default: only rows safe to train on)")
    j.set_defaults(fn=_label)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
