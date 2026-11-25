"""Read a capture from stdin inside a disposable sensor with --network none."""
import json
import sys
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from idps.capture import flows_from_pcap
from idps.config import Settings
from idps.detect.bundle import load_bundle
from idps.features import to_frame
from idps.respond.engine import ResponseEngine
from idps.respond.nft import NftBlocker
from idps.respond.policy import Detection
from idps.soc_client import score_frame

source = "10.10.1.10"
with TemporaryDirectory() as tmp:
    capture = Path(tmp) / "input.pcap"
    capture.write_bytes(sys.stdin.buffer.read())
    frame = to_frame(flows_from_pcap(capture, backend="scapy"))
frame = frame[frame.src_ip == source].sort_values("end_ms")
bundle = load_bundle("models/week_xgboost.joblib", public_key="keys/model-signing.pub")
blocker = NftBlocker()
engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.2.0/24"]), blocker=blocker)
before = blocker.list_blocked()
labels = Counter()
for row, pred in zip(frame.itertuples(), score_frame(bundle, frame), strict=True):
    if pred.label.lower() != "benign" and pred.confidence >= engine.policy.confidence_threshold:
        labels[pred.label] += 1
    engine.handle(Detection(src_ip=row.src_ip, label=pred.label, confidence=pred.confidence,
                            timestamp=row.end_ms / 1000))
print(json.dumps({"labels": labels, "threshold": engine.policy.confidence_threshold,
                  "before": before, "after": blocker.list_blocked()}))
