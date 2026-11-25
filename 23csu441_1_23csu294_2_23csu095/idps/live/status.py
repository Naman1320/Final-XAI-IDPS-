"""Sensor status report: what this sensor is doing, sent to the SOC every `status_seconds`.

The SOC shows it on the dashboard (mode, policy, allowlist, health) and treats a sensor that has
not reported for two minutes as offline. Everything in the payload is something the sensor
already knows; nothing secret (no token, no URL) is in it. A failed report is logged once per
streak and retried at the next interval: reporting never stops detection.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from importlib import metadata

from idps.detect.bundle import model_version
from idps.live.text import clean
from idps.soc_client import SocError, SocRejectedError

log = logging.getLogger("idps.live")

MAX_ALLOWLIST_ENTRIES = 100  # soc/api/routes/sensors.py MAX_ALLOWLIST (mirrored)
MAX_TEXT = 64


def _version() -> str | None:
    try:
        return metadata.version("idps")[:32]
    except metadata.PackageNotFoundError:
        return None


def build_status(*, engine, bundle, live_settings, metrics, sink, heartbeat=None,
                 interface: str | None, checksum_ok: bool = True,
                 faithfulness: dict | None = None, model_sha256: str | None = None,
                 drift=None, extended: bool = True, rules: dict | None = None,
                 signed_by: str | None = None) -> dict:
    """The body of POST /sensor/status.

    `checksum_ok` is True because load_bundle() refuses to start on a bundle whose sha256 does
    not match; the live loop never runs with a failed check.

    `model_sha256` is the digest load_bundle verified. `drift` is an idps.detect.drift monitor
    (DriftMonitor or NoDrift); its report goes out as `drift`. `extended=False` leaves out the
    model digest/version, the drift and `rules` (an older SOC refuses unknown fields).
    `rules` is idps.rules.forward's status (RuleForwarder.status or disabled_status).
    `signed_by` is the key id of the model signature checked at start-up (None: not checked)."""
    policy = engine.policy
    stats = metrics.status()
    payload = {
        "dry_run": bool(engine.dry_run),
        "blocking_enabled": not engine.dry_run,  # the engine only builds a real blocker then
        "interface": clean(interface)[:MAX_TEXT] or None if interface else None,
        "mode": "live" if interface else "replay",
        "model": {"name": clean(str(bundle.model_name))[:MAX_TEXT], "checksum_ok": bool(checksum_ok)},
        "policy": {
            "confidence_threshold": policy.confidence_threshold,
            "min_flows": policy.min_flows,
            "window_seconds": policy.window_seconds,
            "min_alert_confidence": live_settings.min_alert_confidence,
            "block_ttl_seconds": policy.ttl_seconds,
            "unblock_grace_seconds": engine.grace_seconds,
            "max_analyst_blocks": engine.max_analyst_blocks,
        },
        "allowlist": [str(net)[:MAX_TEXT] for net in policy.allowlist][:MAX_ALLOWLIST_ENTRIES],
        "allowlist_total": len(policy.allowlist),  # the list above is cut at 100
        "outbox_pending": int(sink.pending()),
        "shap_p95_ms": stats["shap_p95_ms"],
        "heartbeat": {"enabled": heartbeat is not None,
                      "ok": heartbeat is not None and not heartbeat.failing},
        "counters": {k: stats[k] for k in ("flows", "alerts", "blocked", "would_block")},
        "sensor_version": _version(),
        "sent_at": datetime.now(UTC).isoformat(),
    }
    if extended:
        payload["model"] |= {"sha256": model_sha256,
                             "version": clean(model_version(bundle, model_sha256))[:80]}
        if signed_by is not None:  # the key id the model's signature was verified with
            payload["model"]["signed_by"] = signed_by
        if drift is not None:
            payload["drift"] = drift.report()
        if rules is not None:
            payload["rules"] = rules
    if faithfulness is not None:  # read once at start-up (idps.live.faithfulness)
        payload["faithfulness"] = faithfulness
    return payload


class StatusReporter:
    """A daemon thread: one report at start, then one every `interval` seconds."""

    def __init__(self, client, build, *, interval: float = 30.0) -> None:
        self.client = client
        self.build = build  # () -> dict
        self.interval = interval
        self._streak = False  # a failure was logged and no success has followed
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="status-reporter", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            self.report_once()
            self._stop.wait(self.interval)

    def report_once(self) -> bool:
        """Build and send one report; never raises. False if it did not get through."""
        try:
            self.client.post_status(self.build())
        except SocRejectedError as exc:
            if exc.status == 404:
                self._fail("the SOC has no /sensor/status endpoint (HTTP 404, an older SOC?)")
            else:
                self._fail(f"the SOC answered HTTP {exc.status} to the status report")
            return False
        except SocError as exc:
            self._fail(str(exc))
            return False
        except Exception as exc:  # noqa: BLE001  reporting must never stop detection
            self._fail(f"{type(exc).__name__}: {exc}")
            return False
        if self._streak:
            self._streak = False
            log.info("the SOC is reachable again; status reports resume")
        return True

    def _fail(self, why: str) -> None:
        if not self._streak:
            self._streak = True
            log.error("status report not delivered (%s); retrying every %g s (further failures "
                      "are not logged until it recovers). Detection is not affected", why,
                      self.interval)
