# Explanations

```
python -m idps.explain flow <bundle> <features.parquet> --row N [--method shap|lime] [--top-k 5]
python -m idps.explain global <bundle> <features.parquet> -o importance.json [--plot importance.png]
python -m idps.explain faithfulness <bundle> <labelled.parquet> -o faithfulness.json [-n 100 --top-k 5]
```

Library: `Explainer(bundle, background).explain(frame_or_row, top_k)` (SHAP, build once and reuse),
`lime_explain(bundle, row, background, num_features)`, `global_importance(...)`, `faithfulness(...)`.
Every result is plain JSON (floats and strings), ready to attach to an alert.

## What a record means

```
{"method": "shap", "predicted_class": "DoS", "confidence": 0.99, "base_value": -3.1,
 "output_space": "log_odds",
 "top_features": [{"feature": "fwd_packets", "value": 2011.0, "contribution": 4.2}, ...]}
```

- `contribution` is how much the feature pushed the model toward the PREDICTED class (positive)
  or away from it (negative), sorted by absolute size. Not a causal claim.
- SHAP is additive: `base_value + sum(all contributions) = model output` in `output_space`.
  XGBoost: `log_odds` (raw margin; confidence is the sigmoid/softmax of it). RandomForest and
  MLP: `probability`. Only the top-k are listed, so their sum is usually below the full gap.
- LIME (`method: "lime"`) has the same shape, but fits a local linear model on perturbed copies
  of the flow, in probability space. `contribution` is its weight, `base_value` its intercept.
  It is not additive in the SHAP sense, is approximate, and needs a background sample (it is
  seeded: the same call gives the same answer).
- `explain` always returns a list, one record per flow.

## Models and latency

- XGBoost and RandomForest use `shap.TreeExplainer` (fast, exact, no background needed).
- MLP uses `shap.KernelExplainer` with a 20-row background and 200 samples per flow. This is the
  slow, approximate path (it depends on the background); keep live alerts on a tree model.

Measured on synthetic data, 38 features, 3 classes, 200 trees, single flow per call, on the
development laptop (budget 50 ms): XGBoost median 2.6 ms (p95 2.9), RandomForest median 16 ms
(p95 17), MLP KernelExplainer median 4.4 ms. LIME with 1000 samples: 8 ms (XGBoost) to 37 ms
(RF). Explainer construction: 3 to 22 ms. Real data trained with more rows deepens RandomForest
trees, so re-measure after training on CIC-IDS2017 (the tests only smoke-check < 50 ms).

## Global importance

`global` gives mean |SHAP| per feature for each class over a random sample (default 500 flows,
all classes mixed, so a rare class's list reflects how the model treats ALL flows toward that
class). `--plot` saves one bar panel per class (top 10) with a headless matplotlib backend.

## Reading the faithfulness result

For N flows, take the predicted class and its probability. Replace the explanation's top-k
features by the background median and see how much the probability of that class falls
(`mean_drop`). Do the same with k random features (`random`, averaged over repeated draws;
`std_of_mean_across_repeats` shows its noise). A faithful explanation drops the probability
clearly more than random features:

- `mean_drop` (shap, lime) much larger than `random.mean_drop`: the named features really drive
  the prediction. `ratio_to_random` and `share_flows_beating_random` say the same per flow.
- `label_flip_rate`: share of flows whose predicted class changes after the deletion.
- SHAP and LIME run on the same flows, so their `mean_drop` can be compared directly: larger
  means the method found the more influential features.

Caveats: the median baseline can itself look like another class, features are correlated (the
model may be robust to removing one of a pair), and the sample should be held-out data, with
the background from training-like data. On the synthetic test data only four features matter, so
SHAP and LIME both pick them and score the same (drop about 0.66 vs 0.07 to 0.08 random, 8 to
10 times); real CIC-IDS2017 results are the ones for the report.
