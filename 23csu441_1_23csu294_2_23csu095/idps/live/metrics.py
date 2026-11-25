"""Counters and latency samples of the live loop, reported as one JSON log line."""

from __future__ import annotations

import threading
import time
from collections import deque

import numpy as np

COUNTERS = (
    "flows",              # flows scored
    "malicious",          # non-BENIGN predictions
    "alerts",             # alerts produced (malicious and confidence >= the floor)
    "below_floor",        # malicious but under the alert floor (not sent; blocking still sees them)
    "would_block",        # block decisions in dry-run
    "blocked",            # block decisions applied
    "explained",          # alerts that got a SHAP explanation
    "explanations_shed",  # alerts sent without one: over the per-batch cap, backlog, or no explainer
    "explain_errors",     # SHAP raised; the alerts went out without explanation
    "alerts_dropped",     # alerts lost: outbox full or the alert file not writable
    "alerts_sent",        # accepted by the SOC
    "alerts_rejected",    # refused by the SOC (4xx), dropped
    "blocks_sent",        # block reports accepted by the SOC
    "blocks_dropped",     # block reports lost: queue full (oldest dropped)
    "blocks_rejected",    # block reports refused by the SOC (4xx), dropped
    "response_errors",    # the response engine raised on a detection
    "batch_errors",       # a whole batch failed unexpectedly (logged at error level, loop continues)
    "reply_direction",    # detections handed to the response engine with dst_ip (flow was a reply)
    "heartbeat_flows",    # our own heartbeat flows, dropped before scoring (see idps.live.heartbeat)
    "flows_discarded",    # flows read from the capture but not scored (stop with --max-flows)
    "blocks_suppressed",  # automatic blocks withheld: an analyst unblocked the address recently
    "actions_executed",   # analyst actions (block_ip / unblock_ip) applied and reported as success
    "actions_failed",     # analyst actions refused or failed (reported to the SOC as failed)
    "soc_config_errors",  # SOC answered 401/403/404: alerts kept, configuration needs fixing
)


def _percentiles(samples) -> dict:
    if not samples:
        return {"p50": None, "p95": None, "n": 0}
    a = np.asarray(samples, dtype=float)
    return {"p50": round(float(np.percentile(a, 50)), 3),
            "p95": round(float(np.percentile(a, 95)), 3), "n": len(a)}


class Metrics:
    """Thread-safe: the sender thread counts sent alerts while the detection loop counts the rest.

    Latency and SHAP samples are the last `window` ones, so the percentiles describe recent
    behaviour and memory stays fixed."""

    def __init__(self, window: int = 2_000, clock=time.monotonic) -> None:
        self._lock = threading.Lock()
        self._clock = clock
        self.counts = dict.fromkeys(COUNTERS, 0)
        self._shap_ms: deque[float] = deque(maxlen=window)
        self._latency_s: deque[float] = deque(maxlen=window)
        self._started = clock()
        self._last = (self._started, 0)  # (time, flows) at the previous snapshot

    def add(self, name: str, n: int = 1) -> None:
        with self._lock:
            self.counts[name] += n

    def observe_shap_ms(self, per_alert_ms: float, alerts: int = 1) -> None:
        """Record SHAP time per alert (a batch of `alerts` counts as `alerts` samples)."""
        with self._lock:
            self._shap_ms.extend([per_alert_ms] * alerts)

    def observe_latency_s(self, seconds: float) -> None:
        with self._lock:
            self._latency_s.append(seconds)

    def status(self) -> dict:
        """The numbers of the sensor status report. Unlike snapshot() it does not move the
        flow-rate baseline, so the periodic metrics line is not affected."""
        with self._lock:
            counts = dict(self.counts)
            shap = _percentiles(self._shap_ms)
        return {"flows": counts["flows"], "alerts": counts["alerts"],
                "blocked": counts["blocked"], "would_block": counts["would_block"],
                "shap_p95_ms": shap["p95"]}

    def snapshot(self, *, pending: int = 0, dry_run: bool = True, since_start: bool = False) -> dict:
        now = self._clock()
        with self._lock:
            counts = dict(self.counts)
            shap, latency = _percentiles(self._shap_ms), _percentiles(self._latency_s)
            last_t, last_flows = self._last
            if since_start:  # the average over the whole run (used for the final line)
                last_t, last_flows = self._started, 0
            self._last = (now, counts["flows"])
        interval = max(now - last_t, 1e-9)
        return {
            "event": "metrics",
            "uptime_s": round(now - self._started, 1),
            "flows": counts["flows"],
            "flows_per_s": round((counts["flows"] - last_flows) / interval, 1),
            "alerts": counts["alerts"],
            "malicious": counts["malicious"],
            "below_floor": counts["below_floor"],
            "dry_run": dry_run,
            "blocks": counts["would_block"] if dry_run else counts["blocked"],
            "would_block": counts["would_block"],
            "blocked": counts["blocked"],
            "blocks_suppressed": counts["blocks_suppressed"],
            "actions": {"executed": counts["actions_executed"], "failed": counts["actions_failed"]},
            "dropped": {"explanations": counts["explanations_shed"],
                        "alerts": counts["alerts_dropped"],
                        "alerts_rejected_by_soc": counts["alerts_rejected"],
                        "blocks": counts["blocks_dropped"],
                        "blocks_rejected_by_soc": counts["blocks_rejected"]},
            "errors": {"explain": counts["explain_errors"], "response": counts["response_errors"],
                       "batch": counts["batch_errors"], "soc_config": counts["soc_config_errors"]},
            "reply_direction": counts["reply_direction"],
            "heartbeat_flows": counts["heartbeat_flows"],
            "flows_discarded": counts["flows_discarded"],
            "explained": counts["explained"],
            "alerts_sent": counts["alerts_sent"],
            "blocks_sent": counts["blocks_sent"],
            "outbox_pending": pending,
            "shap_ms_per_alert": shap,
            "latency_flow_end_to_alert_s": latency,
        }
