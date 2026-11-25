"""Public intrusion-detection datasets with their own published feature tables.

Kept apart from the PCAP/flow pipeline (`idps.features`, which extracts MODEL_FEATURES from our
own captures): these modules read the datasets' CSVs as they were published, with their column
names, and reuse the detect/explain code that does not care which features it is given.
Plan and preprocessing: docs/training-dataset1.md. Run: `python -m idps.public run`.
"""
