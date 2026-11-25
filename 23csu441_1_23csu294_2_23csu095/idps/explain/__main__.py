"""CLI: python -m idps.explain flow <bundle> <features.parquet> --row N [--method shap|lime]
         python -m idps.explain global <bundle> <features.parquet> -o out.json [--plot out.png]
         python -m idps.explain faithfulness <bundle> <labelled.parquet> -o out.json"""

import argparse
import json
import sys

from idps.detect.bundle import load_bundle, read_digest
from idps.detect.data import load_labelled
from idps.explain._common import DEFAULT_SEED, sample_rows
from idps.explain.faithfulness import faithfulness, write_json
from idps.explain.global_explain import global_importance, save_summary_plot
from idps.explain.lime_explain import LimeExplainer
from idps.explain.shap_explain import Explainer
from idps.features import read_features


def _load(args):
    bundle = load_bundle(args.bundle)
    df, meta = read_features(args.features)
    bundle.select(df, meta)  # refuses mismatched extraction settings / missing columns
    return bundle, df


def _background(df, args):
    return sample_rows(df, args.background_size, args.seed)


def _flow(args) -> int:
    bundle, df = _load(args)
    if not 0 <= args.row < len(df):
        print(f"--row must be in 0..{len(df) - 1}", file=sys.stderr)
        return 2
    row = df.iloc[[args.row]]
    if args.method == "lime":
        rec = LimeExplainer(bundle, _background(df, args), seed=args.seed).explain(
            row, args.top_k)[0]
    else:
        rec = Explainer(bundle, _background(df, args), seed=args.seed).explain(
            row, args.top_k)[0]
    print(json.dumps(rec, indent=2))
    return 0


def _global(args) -> int:
    bundle, df = _load(args)
    explainer = Explainer(bundle, _background(df, args), seed=args.seed)
    result = global_importance(explainer, df, sample=args.sample, seed=args.seed)
    write_json(result, args.output)
    print(f"importance -> {args.output}", file=sys.stderr)
    if args.plot:
        save_summary_plot(result, args.plot)
        print(f"plot -> {args.plot}", file=sys.stderr)
    return 0


def _faithfulness(args) -> int:
    bundle = load_bundle(args.bundle)
    df, meta = load_labelled([args.features], allow_low_match=args.allow_low_match_rate)
    bundle.select(df, meta)
    result = faithfulness(bundle, df, _background(df, args), n=args.n, k=args.top_k,
                          repeats=args.repeats, seed=args.seed,
                          include_lime=not args.no_lime, lime_samples=args.lime_samples,
                          model_sha256=read_digest(args.bundle))  # verified by load_bundle
    write_json(result, args.output)
    for name, m in result["methods"].items():
        print(f"{name}: mean drop {m['mean_drop']:.3f} vs random "
              f"{result['random']['mean_drop']:.3f}", file=sys.stderr)
    print(f"results -> {args.output}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m idps.explain", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, file_help):
        sp.add_argument("bundle", help="model bundle (.joblib)")
        sp.add_argument("features", help=file_help)
        sp.add_argument("--seed", type=int, default=DEFAULT_SEED)
        sp.add_argument("--background-size", type=int, default=200,
                        help="rows sampled from the file as background (default 200)")

    f = sub.add_parser("flow", help="explain one flow")
    common(f, "feature file (parquet/csv)")
    f.add_argument("--row", type=int, required=True)
    f.add_argument("--top-k", type=int, default=5)
    f.add_argument("--method", choices=("shap", "lime"), default="shap")
    f.set_defaults(func=_flow)

    g = sub.add_parser("global", help="global mean |SHAP| per class")
    common(g, "feature file (parquet/csv)")
    g.add_argument("-o", "--output", required=True)
    g.add_argument("--plot", help="also save a summary plot (png)")
    g.add_argument("--sample", type=int, default=500, help="flows to average over")
    g.set_defaults(func=_global)

    t = sub.add_parser("faithfulness", help="deletion test, SHAP and LIME vs random")
    common(t, "labelled file (from 'features label')")
    t.add_argument("-o", "--output", required=True)
    t.add_argument("-n", type=int, default=100, help="flows to test")
    t.add_argument("--top-k", type=int, default=5)
    t.add_argument("--repeats", type=int, default=20, help="random-feature draws")
    t.add_argument("--lime-samples", type=int, default=1000)
    t.add_argument("--no-lime", action="store_true")
    t.add_argument("--allow-low-match-rate", action="store_true")
    t.set_defaults(func=_faithfulness)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
