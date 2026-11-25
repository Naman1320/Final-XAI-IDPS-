"""Live detection loop: capture -> features -> model -> SHAP -> alert (SOC or file) -> response.

Run it with `python -m idps.live --interface NAME` (or `--pcap FILE` to replay a capture).
See docs/live.md.
"""

from idps.live.config import LiveSettings
from idps.live.detector import LiveDetector
from idps.live.metrics import Metrics
from idps.live.sinks import JsonlSink, SocSink

__all__ = ["JsonlSink", "LiveDetector", "LiveSettings", "Metrics", "SocSink"]
