"""The detection loop: flows in, alerts and responses out.

    reader thread ──flows──> bounded queue ──> micro-batch ──> score ──> SHAP (capped) ──┬─> response engine
                                                                                         └─> sink (SOC outbox or file)

Why a reader thread: NFStream blocks until a flow expires, so a batch that is only flushed when
a new flow arrives could wait forever on a quiet link. The loop reads from the queue with a
timeout instead, which is what makes "flush after T seconds" work. The queue is bounded: when
scoring falls behind, the reader blocks (and the capture's own buffers absorb the burst) instead
of memory growing.

A batch is scored when it holds `batch_size` flows or `batch_seconds` have passed since its first
flow. Within a batch the response engine sees detections in flow order (its windows use the
flows' own timestamps, so a replay behaves the same every time) and it never waits for the SOC.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pandas as pd

from idps.detect.bundle import Bundle
from idps.explain.shap_explain import Explainer
from idps.features import to_frame
from idps.live.config import LiveSettings
from idps.live.heartbeat import is_heartbeat
from idps.live.metrics import Metrics
from idps.live.sinks import Sink
from idps.respond.engine import ResponseEngine
from idps.respond.policy import BENIGN_LABELS, Action, Detection, normalise_ip
from idps.soc_client import Prediction, alert_payload, score_frame

log = logging.getLogger("idps.live")

POLL_SECONDS = 0.2
# Above this share of the outbox's capacity the loop stops building explanations (they are the
# biggest part of an alert), so that what is left of the cap goes to alerts, not to SHAP detail.
SHED_EXPLANATIONS_AT = 0.8


EPHEMERAL_PORT = 32768  # ports from here up are what clients pick; servers listen below it


def block_candidate(row: dict) -> str:
    """The address the response engine should treat as the offender for this flow.

    NFStream names the sender of a flow's first captured packet `src`. When the capture starts
    mid-conversation, or a long flow is cut by the 120 s timeout, that packet can be a server's
    reply, so `src_ip` would be the protected server. A TCP/UDP flow whose source port is a
    service port and whose destination port is an ephemeral one (src < dst, dst >= 32768,
    src < 32768) is read as a reply, and its destination is the likelier offender.

    This is a heuristic and an attacker can imitate it (send from port 80 to a high port), so it
    is not the safeguard: protected servers must be in IDPS_ALLOWLIST. The alert itself is not
    changed; it shows the flow as observed.
    """
    if row["protocol"] in (6, 17):
        sport, dport = int(row["src_port"]), int(row["dst_port"])
        if sport < dport and dport >= EPHEMERAL_PORT and sport < EPHEMERAL_PORT:
            return row["dst_ip"]
    return row["src_ip"]


class _End:
    pass


@dataclass
class _Failed:
    error: BaseException


class LiveDetector:
    """Never raises from handle_batch/run on a bad batch: it is logged, counted and skipped.

    `live=False` is replay mode: the flow-end-to-alert latency is not recorded (a replayed
    capture is old, so the number would only measure how old the file is)."""

    def __init__(
        self,
        bundle: Bundle,
        engine: ResponseEngine,
        sink: Sink,
        settings: LiveSettings,
        meta: dict,
        *,
        metrics: Metrics | None = None,
        live: bool = True,
        outbox_capacity: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        heartbeat=None,
        model_sha256: str | None = None,
        model_version: str | None = None,
        drift=None,
        send_features: bool = True,
    ) -> None:
        self.bundle, self.engine, self.sink, self.settings = bundle, engine, sink, settings
        self.meta = meta
        # Which model scored each alert (sent with it, so the SOC can export retraining rows),
        # and the drift monitor (idps.detect.drift) that sees every scored flow, or None.
        self.model_sha256, self.model_version, self.drift = model_sha256, model_version, drift
        self.send_features = send_features  # False: an older SOC would refuse `features`
        self.metrics = metrics or Metrics()
        self.live = live
        self.outbox_capacity = outbox_capacity
        self._clock, self._wall = clock, wall
        # The running Heartbeat (or None): its flow is dropped before scoring, see heartbeat.py.
        self.heartbeat = heartbeat
        self._background: list[pd.Series] = []  # the first background_size BENIGN flows seen
        self.explainer: Explainer | None = None
        try:
            # Tree models need no background, so the explainer exists from the start.
            self.explainer = Explainer(bundle, None)
        except ValueError:
            log.info("this model's explainer needs a background sample: it is built from the "
                     "first %d BENIGN flows", settings.background_size)
        # Blocking and alerting thresholds decide which detections are worth a SHAP explanation.
        self._explain_floor = min(
            settings.min_alert_confidence,
            getattr(getattr(engine, "policy", None), "confidence_threshold", 1.0))

    # --- one batch ------------------------------------------------------------------------------

    def _background_frame(self) -> pd.DataFrame | None:
        return pd.DataFrame(self._background) if self._background else None

    def _explainer_ready(self) -> bool:
        if self.explainer is None:
            bg = self._background_frame()
            if bg is None:
                return False
            try:
                self.explainer = Explainer(self.bundle, bg)
            except (ValueError, TypeError) as exc:
                log.error("cannot build the explainer: %s", exc)
                return False
        return True

    def _explain(self, X: pd.DataFrame, wanted: list[int]) -> dict[int, dict]:
        """SHAP records for the rows in `wanted`, keyed by row. Never raises."""
        if not wanted:
            return {}
        if not self._explainer_ready():
            return {}
        started = time.perf_counter()
        try:
            records = self.explainer.explain(X.iloc[wanted], top_k=self.settings.top_k)
        except Exception as exc:  # noqa: BLE001  a SHAP failure must not stop detection
            log.error("SHAP failed for %d alert(s): %s: %s", len(wanted), type(exc).__name__, exc)
            self.metrics.add("explain_errors")
            return {}
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        self.metrics.observe_shap_ms(elapsed_ms / len(wanted), len(wanted))
        self.metrics.add("explained", len(wanted))
        return dict(zip(wanted, records, strict=True))

    def _block_critical(self, malicious: list[int], rows: list[dict],
                        preds: list[Prediction]) -> set[int]:
        """Rows that may trigger a block: for each blockable address, its first `min_flows`
        detections at or above the block threshold in this batch. The policy blocks on the
        min_flows-th such flow inside its window, so at most min_flows of a batch's flows
        precede the block, and the one that triggers it is among them. Bounded by
        min_flows per distinct address, never more than the batch."""
        policy = getattr(self.engine, "policy", None)
        threshold = getattr(policy, "confidence_threshold", None)
        if policy is None or threshold is None:
            return set()
        min_flows = getattr(policy, "min_flows", 5)
        per_ip: dict[str, int] = {}
        critical: set[int] = set()
        for i, row in zip(malicious, rows, strict=True):
            if preds[i].confidence < threshold:
                continue
            ip = block_candidate(row)
            addr = normalise_ip(ip)
            if addr is None or policy.is_protected(addr):
                continue
            if per_ip.get(ip, 0) < min_flows:
                per_ip[ip] = per_ip.get(ip, 0) + 1
                critical.add(i)
        return critical

    def _explanation_budget(self) -> int:
        cap = self.settings.max_explanations_per_batch
        if self.outbox_capacity and self.sink.pending() >= SHED_EXPLANATIONS_AT * self.outbox_capacity:
            return 0
        return cap

    def handle_batch(self, flows: list) -> list[dict]:
        """Score, explain, respond and queue one batch; returns the alerts it produced.

        Never raises: a batch that fails (a bug, or flows that do not match the model's
        extraction) is logged at error level and counted in `errors.batch`, and detection goes on
        with the next batch. Callers must not retry the same flows: some of them may already have
        reached the response engine."""
        note = getattr(self.heartbeat, "note_flows", None)
        if note is not None:
            note(len(flows))  # lets the heartbeat speed up while a backlog drains
        key = getattr(self.heartbeat, "key", None)
        kept = [f for f in flows if not is_heartbeat(f, key)] if key else flows
        if len(kept) != len(flows):
            self.metrics.add("heartbeat_flows", len(flows) - len(kept))
        flows = kept
        if not flows:
            return []
        try:
            return self._handle_batch(flows)
        except Exception:
            log.exception("batch of %d flow(s) failed and was skipped", len(flows))
            self.metrics.add("batch_errors")
            return []

    def _handle_batch(self, flows: list) -> list[dict]:
        frame = to_frame(flows)
        X = self.bundle.select(frame, self.meta)  # refuses mismatched extraction or columns
        preds = score_frame(self.bundle, X)
        self.metrics.add("flows", len(flows))
        if self.drift is not None:
            try:
                self.drift.update(frame)  # all flows, not only alerts
            except Exception:
                log.exception("drift monitor failed; continuing without it for this batch")

        for i, p in enumerate(preds):  # background: the first BENIGN flows seen
            if len(self._background) >= self.settings.background_size:
                break
            if _is_benign(p):
                self._background.append(X.iloc[i])

        malicious = [i for i, p in enumerate(preds) if not _is_benign(p)]
        if not malicious:
            return []
        self.metrics.add("malicious", len(malicious))
        floor = self.settings.min_alert_confidence

        # SHAP is the expensive part: explain the most confident detections first, up to the cap.
        rows = frame.iloc[malicious].to_dict("records")
        worth = sorted((i for i in malicious if preds[i].confidence >= self._explain_floor),
                       key=lambda i: -preds[i].confidence)
        budget = self._explanation_budget()
        chosen = set(worth[:budget])
        # A block must be audited with its why, so detections that can lead to one are explained
        # even when the budget is spent (see _block_critical).
        chosen |= self._block_critical(malicious, rows, preds)
        explanations = self._explain(X, sorted(chosen))
        shed = sum(1 for i in malicious
                   if preds[i].confidence >= floor and i not in explanations)
        if shed:
            self.metrics.add("explanations_shed", shed)
            log.warning("sent %d alert(s) without a SHAP explanation (cap %d per batch, "
                        "%d explained)", shed, budget, len(explanations))

        alerts: list[dict] = []
        for i, row in zip(malicious, rows, strict=True):
            pred, explanation = preds[i], explanations.get(i)
            self._respond(row, pred, explanation)
            if pred.confidence < floor:
                self.metrics.add("below_floor")
                continue
            payload = alert_payload(row, pred, explanation, model_sha256=self.model_sha256,
                                    model_version=self.model_version, with_features=self.send_features)
            if payload is None:  # confidence or times the SOC would refuse
                log.warning("not alerting on a flow with unusable confidence/times: %s", row["src_ip"])
                self.metrics.add("alerts_dropped")
                continue
            alerts.append(payload)
            if self.live:
                self.metrics.observe_latency_s(max(0.0, self._wall() - row["end_ms"] / 1000.0))
        self.metrics.add("alerts", len(alerts))
        self._submit(alerts)
        return alerts

    def _respond(self, row: dict, pred: Prediction, explanation: dict | None) -> None:
        try:
            offender = block_candidate(row)
            if offender != row["src_ip"]:
                self.metrics.add("reply_direction")
                log.info("flow %s:%s -> %s:%s looks like a reply: the response engine gets %s",
                         row["src_ip"], row["src_port"], row["dst_ip"], row["dst_port"], offender)
            detection = Detection(
                src_ip=offender, label=pred.label, confidence=pred.confidence,
                timestamp=row["end_ms"] / 1000.0, explanation=explanation)
        except Exception as exc:  # noqa: BLE001  one bad detection must not stop the loop
            log.error("response engine failed for %s: %s: %s", row["src_ip"],
                      type(exc).__name__, exc)
            self.metrics.add("response_errors")
            return
        self.respond(detection)

    def respond(self, detection: Detection) -> None:
        """Hand one detection to the response engine and report what it decided (a block, a
        would-block in dry-run, or a suppression). Used for the model's detections and, from the
        rule forwarder's thread, for rules explicitly allowed to block; never raises."""
        try:
            decision = self.engine.handle(detection)
        except Exception as exc:  # noqa: BLE001  one bad detection must not stop the loop
            log.error("response engine failed for %s: %s: %s", detection.src_ip,
                      type(exc).__name__, exc)
            self.metrics.add("response_errors")
            return
        if decision.action is Action.SUPPRESSED:
            self.metrics.add("blocks_suppressed")
        if decision.action is Action.BLOCK:
            self.metrics.add("would_block" if self.engine.dry_run else "blocked")
            if not self.engine.dry_run:  # the engine returns BLOCK only after the blocker succeeded
                self._report_block(decision)
            else:  # nothing was blocked: tell the SOC what would have been, as its own event
                self._report_would_block(decision)

    def _report_block(self, decision) -> None:
        # An absolute expiry, taken now: the SOC would count a ttl from the moment it receives the
        # report, which is wrong for a report delayed by an outage.
        event = {"event": "blocked", "ip": decision.ip, "reason": (decision.reason or "")[:500],
                 "source": "auto"}
        if decision.ttl_seconds:
            event["expires_at"] = (datetime.now(UTC)
                                   + timedelta(seconds=decision.ttl_seconds)).isoformat()
        try:
            self.sink.submit_blocks([event])
        except Exception as exc:  # noqa: BLE001  reporting must never stop detection
            log.error("cannot queue the block report for %s: %s: %s", decision.ip,
                      type(exc).__name__, exc)
            self.metrics.add("blocks_dropped")

    def _report_would_block(self, decision) -> None:
        """Dry-run only (never called when blocking for real). The SOC keeps these apart from
        blocks, so they never count as active blocks or reach the firewall."""
        event = {"event": "would_block", "ip": decision.ip,
                 "reason": (decision.reason or "")[:500], "source": "auto",
                 # the decision time, so an event delayed in the queue keeps its real time
                 "decided_at": datetime.now(UTC).isoformat()}
        if decision.ttl_seconds:
            event["ttl_seconds"] = int(decision.ttl_seconds)
        try:
            self.sink.submit_blocks([event])
        except Exception as exc:  # noqa: BLE001  reporting must never stop detection
            log.error("cannot queue the would-block report for %s: %s: %s", decision.ip,
                      type(exc).__name__, exc)
            self.metrics.add("blocks_dropped")

    def _submit(self, alerts: list[dict]) -> None:
        try:
            self.sink.submit(alerts)
        except Exception as exc:  # noqa: BLE001
            log.error("cannot queue %d alert(s): %s: %s", len(alerts), type(exc).__name__, exc)
            self.metrics.add("alerts_dropped", len(alerts))

    # --- the loop -------------------------------------------------------------------------------

    def _log_metrics(self, final: bool = False) -> dict:
        """Log one metrics line and return it. The final one averages over the whole run."""
        snap = self.metrics.snapshot(pending=self.sink.pending(), dry_run=self.engine.dry_run,
                                     since_start=final)
        log.info(json.dumps(snap))
        return snap

    def run(self, flows: Iterable, stop: threading.Event | None = None, *,
            max_flows: int | None = None, duration: float | None = None) -> dict:
        """Consume `flows` until they end, `stop` is set, `max_flows` flows were read or
        `duration` seconds passed. Returns the final metrics snapshot; re-raises an error of the
        flow source (after the flush).

        On the way out every flow that already left the capture is scored: the open batch is
        flushed and, for stop/duration/end of input, so is whatever waits in the queue. With
        `max_flows` the queue's surplus beyond the limit is discarded and counted
        (`flows_discarded`). What the capture itself still holds (NFStream's own buffers, a flow
        the reader had in hand when stopped, counted too) is not processed."""
        stop = stop or threading.Event()
        halt = threading.Event()  # tells the reader to give up
        q: queue.Queue = queue.Queue(maxsize=max(self.settings.batch_size * 4, 16))
        reader = threading.Thread(target=self._read, args=(flows, q, halt, self.metrics),
                                  daemon=True, name="flow-reader")
        reader.start()

        batch: list = []
        batch_started = 0.0
        seen = 0
        started = self._clock()
        last_metrics = started
        failure: BaseException | None = None
        limit_reached = False
        try:
            while not stop.is_set():
                now = self._clock()
                if duration is not None and now - started >= duration:
                    break
                wait = POLL_SECONDS
                if batch:
                    wait = min(wait, max(0.0, batch_started + self.settings.batch_seconds - now))
                try:
                    item = q.get(timeout=wait)
                except queue.Empty:
                    item = None
                if isinstance(item, _End):
                    break
                if isinstance(item, _Failed):
                    failure = item.error
                    break
                if item is not None:
                    if not batch:
                        batch_started = self._clock()
                    batch.append(item)
                    seen += 1
                now = self._clock()
                if batch and (len(batch) >= self.settings.batch_size
                              or now - batch_started >= self.settings.batch_seconds):
                    flush, batch = batch, []  # cleared first: a batch is never handled twice
                    self.handle_batch(flush)
                if max_flows is not None and seen >= max_flows:
                    limit_reached = True
                    break
                if now - last_metrics >= self.settings.metrics_seconds:
                    last_metrics = now
                    self._log_metrics()
                    self.sink.checkpoint()
        finally:
            halt.set()
            reader.join(timeout=2.0)
            self._finish(batch, q, limit_reached)
        snapshot = self._log_metrics(final=True)
        if failure is not None:
            raise failure
        return snapshot

    def _finish(self, batch: list, q: queue.Queue, limit_reached: bool) -> None:
        """Score the open batch and the flows still queued (or count them as discarded)."""
        leftover = []
        while True:
            try:
                item = q.get_nowait()
            except queue.Empty:
                break
            if not isinstance(item, (_End, _Failed)):
                leftover.append(item)
        if limit_reached:
            if leftover:
                self.metrics.add("flows_discarded", len(leftover))
                log.info("%d flow(s) beyond --max-flows were read and not scored", len(leftover))
            leftover = []
        pending = batch + leftover
        size = self.settings.batch_size
        for i in range(0, len(pending), size):
            self.handle_batch(pending[i:i + size])

    @staticmethod
    def _read(flows: Iterable, q: queue.Queue, halt: threading.Event, metrics: Metrics) -> None:
        def put(item) -> bool:
            while not halt.is_set():
                try:
                    q.put(item, timeout=POLL_SECONDS)
                except queue.Full:
                    continue
                return True
            return False

        try:
            for flow in flows:
                if not put(flow):
                    metrics.add("flows_discarded")  # in hand when the loop stopped
                    return
        except BaseException as exc:  # noqa: BLE001  handed to the main thread
            put(_Failed(exc))
            return
        put(_End())


def _is_benign(pred: Prediction) -> bool:
    return pred.label.strip().lower() in BENIGN_LABELS
