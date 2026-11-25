"""python -m idps.live (--interface NAME | --pcap FILE): detect, explain, alert, respond.

Exit codes: 0 clean stop, 1 runtime failure (e.g. the capture failed), 2 cannot start (bad
settings, model missing/tampered/trained with a different extractor). Without a model there is no
detection: it never starts "in a degraded mode".
"""

from __future__ import annotations

import argparse
import logging
import multiprocessing
import os
import signal
import sys
import threading

log = logging.getLogger("idps.live")

SOC_SEND_TIMEOUT = 5.0  # seconds; the sender thread waits this long per POST, detection never does


ACTION_STOP_TIMEOUT = 15.0  # a round in progress finishes its current request, then stops
CAPTURE_STOP_TIMEOUT = 2.0  # per capture process: SIGTERM, then SIGKILL after this long


def stop_capture_processes(timeout: float = CAPTURE_STOP_TIMEOUT) -> int:
    """Stop the capture's child processes (NFStream's meters) and return how many there were.

    NFStream's meter survives SIGTERM while it waits on the interface, and at exit Python's
    multiprocessing terminates its daemon children and then waits for them, forever. A live run
    with --duration (or a signal) therefore stopped detecting on time but never exited. So the
    loop stops them itself: terminate, wait `timeout`, then kill. Nothing else in the loop starts
    child processes."""
    children = multiprocessing.active_children()
    for proc in children:
        proc.terminate()
    for proc in children:
        proc.join(timeout)
        if proc.is_alive():
            log.warning("capture process %s ignored SIGTERM; killing it", proc.pid)
            proc.kill()
            proc.join(timeout)
    return len(children)


def _fail(message: str, code: int = 2) -> int:
    print(f"error: {message}", file=sys.stderr)
    return code


def _validation_message(exc) -> str:
    """A pydantic ValidationError as text WITHOUT the rejected input (it could be the token)."""
    return "; ".join(f"{'.'.join(str(p) for p in e['loc']) or 'settings'}: {e['msg']}"
                     for e in exc.errors(include_input=False, include_url=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m idps.live", description=__doc__.split("\n\n")[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", metavar="NAME", help="sniff this interface (needs root / CAP_NET_RAW)")
    source.add_argument("--pcap", metavar="FILE",
                        help="replay a capture as fast as possible (demos, tests); no flow-end latency is recorded")
    parser.add_argument("--model", help="model bundle (default: IDPS_MODEL_PATH, models/model.joblib)")
    parser.add_argument("--max-flows", type=int, help="stop after this many flows")
    parser.add_argument("--duration", type=float,
                        help="stop after this many seconds (live capture only)")
    parser.add_argument("--batch-size", type=int, help="flush a micro-batch at this many flows (IDPS_LIVE_BATCH_SIZE)")
    parser.add_argument("--batch-seconds", type=float,
                        help="... or this many seconds after its first flow (IDPS_LIVE_BATCH_SECONDS)")
    parser.add_argument("--min-alert-confidence", type=float,
                        help="alert floor (IDPS_LIVE_MIN_ALERT_CONFIDENCE)")
    parser.add_argument("--no-heartbeat", action="store_true",
                        help="live mode: do not send the UDP heartbeat that keeps NFStream's flow "
                             "clock moving on a quiet link (1 s, faster while a burst of finished "
                             "flows drains; see idps/live/heartbeat.py)")
    parser.add_argument("--heartbeat-burst-interval", type=float, default=None, metavar="SECONDS",
                        help="live mode: heartbeat interval while a burst of finished flows drains "
                             "(default 0.05; 0 keeps the 1 s heartbeat at all times)")
    parser.add_argument("--alerts-file", help="JSON-lines file used when no SOC is configured (IDPS_LIVE_ALERTS_FILE)")
    return parser


def run(args: argparse.Namespace) -> int:
    from pydantic import ValidationError

    from idps.capture import (
        DEFAULT_ACTIVE_TIMEOUT,
        DEFAULT_IDLE_TIMEOUT,
        flows_from_interface,
        flows_from_pcap,
        select_backend,
    )
    from idps.config import get_settings
    from idps.detect.bundle import load_bundle, model_version, read_digest
    from idps.detect.drift import load_monitor
    from idps.features import FEATURE_COLUMNS, extraction_meta
    from idps.live.actions import ActionPoller
    from idps.live.config import LiveSettings
    from idps.live.detector import LiveDetector
    from idps.live.faithfulness import load_faithfulness
    from idps.live.heartbeat import Heartbeat
    from idps.live.metrics import Metrics
    from idps.live.sinks import JsonlSink, SocSink
    from idps.live.status import StatusReporter, build_status
    from idps.respond.engine import ResponseEngine
    from idps.respond.nft import BlockerError
    from idps.rules.config import RulesSettings
    from idps.rules.forward import RuleForwarder
    from idps.soc_client import Outbox, SocClient

    try:
        settings = get_settings()  # IDPS_DRY_RUN (default on), IDPS_ALLOWLIST, ...
        overrides = {k: v for k, v in {
            "batch_size": args.batch_size, "batch_seconds": args.batch_seconds,
            "min_alert_confidence": args.min_alert_confidence,
            "alerts_file": args.alerts_file}.items() if v is not None}
        live = LiveSettings(**overrides)
        rules = RulesSettings()  # IDPS_RULES_EVE and friends (off unless an eve.json is named)
    except ValidationError as exc:
        return _fail(_validation_message(exc))
    if rules.enabled and not args.interface:
        log.warning("IDPS_RULES_EVE is ignored in replay mode (rules are read from a live sensor)")
        rules = RulesSettings(eve=None)
    if args.pcap and not os.path.isfile(args.pcap):
        return _fail(f"no such capture file: {args.pcap}")
    if args.duration is not None and args.duration <= 0:
        return _fail("--duration must be positive")
    if args.pcap and args.duration is not None:
        log.warning("--duration is ignored in replay mode (a capture file ends by itself)")
    if args.max_flows is not None and args.max_flows < 1:
        return _fail("--max-flows must be at least 1")
    if live.soc_half_configured:
        return _fail("set both IDPS_SOC_URL and IDPS_SOC_SENSOR_TOKEN (or neither, to write "
                     "alerts to a file)")

    # The capture settings the model must have been trained with (see idps/capture).
    try:
        backend = select_backend()
    except (ValueError, RuntimeError) as exc:
        return _fail(str(exc))
    meta = extraction_meta(backend, DEFAULT_IDLE_TIMEOUT, DEFAULT_ACTIVE_TIMEOUT)

    model_path = args.model or settings.model_path
    try:
        public_key = None
        if live.model_public_key:  # loaded once: the key that checks the model is the one reported
            from idps.detect.signing import load_public_key

            public_key = load_public_key(live.model_public_key)
        bundle = load_bundle(model_path, live_meta=meta, live_columns=FEATURE_COLUMNS,
                             public_key=public_key)
    except Exception as exc:  # noqa: BLE001  unpickling can fail in any way; all of them mean "no model"
        return _fail(f"cannot load the model {model_path}: {exc}\n"
                     "refusing to run without a model that matches this capture setup "
                     f"(extractor {backend}, timeouts {DEFAULT_IDLE_TIMEOUT:g}/{DEFAULT_ACTIVE_TIMEOUT:g} s)")
    log.info("model %s (%s), classes %s", model_path, bundle.model_name,
             list(bundle.label_encoder.classes_))

    try:
        engine = ResponseEngine(settings)
    except (BlockerError, ValueError, OSError) as exc:
        return _fail(f"response engine: {exc}")

    signed_by = None  # key id of the verified signature (load_bundle refused a bad one)
    if public_key is not None:
        from idps.detect.signing import key_id

        signed_by = key_id(public_key)
        log.info("model signature verified (key %s)", signed_by)
    else:
        log.warning("model signatures are not checked (IDPS_MODEL_PUBLIC_KEY is not set)")
    try:
        digest = read_digest(model_path)  # load_bundle verified it matches the loaded bytes
    except (OSError, ValueError):
        digest = None
    faithfulness = load_faithfulness(settings.faithfulness_report, bundle.model_name, digest)
    version = model_version(bundle, digest)
    drift = load_monitor(model_path, digest, live.drift_window)
    log.info("model version %s; drift %s", version,
             "monitored" if hasattr(drift, "psi_by_feature") else f"off ({drift.reason})")
    metrics = Metrics()
    outbox = None
    client = None
    try:
        if live.soc_configured:
            client = SocClient(live.soc_url, live.soc_token.get_secret_value(),
                               timeout=SOC_SEND_TIMEOUT, ca_file=live.soc_ca_file,
                               client_cert=live.soc_client_cert, client_key=live.soc_client_key)
            outbox = Outbox(live.outbox_file, max_alerts=live.outbox_max_alerts, merge=True,
                            max_rule_alerts=live.outbox_max_rule_alerts)
            sink = SocSink(client.post_alerts, outbox, metrics, post_blocks=client.post_blocks)
            log.info("alerts go to the SOC at %s (unsent ones wait in %s)", live.soc_url,
                     live.outbox_file)
        else:
            sink = JsonlSink(live.alerts_file, metrics)
            log.info("no SOC configured: alerts are appended to %s", live.alerts_file)
    except (ValueError, OSError) as exc:
        return _fail(str(exc))

    try:
        detector = LiveDetector(bundle, engine, sink, live, meta, metrics=metrics,
                                live=bool(args.interface), model_sha256=digest if live.send_features else None,
                                model_version=version if live.send_features else None,
                                drift=drift, send_features=live.send_features,
                                outbox_capacity=live.outbox_max_alerts if outbox else None)
    except (TypeError, ValueError) as exc:
        sink.close()
        return _fail(f"cannot build the SHAP explainer: {exc}")
    log.info("dry-run %s; alert floor %.2f, block threshold %.2f", "ON" if engine.dry_run else "OFF",
             live.min_alert_confidence, settings.confidence_threshold)

    stop = threading.Event()

    def on_signal(signum, _frame):
        log.info("signal %s: flushing the last batch and the outbox, then stopping", signum)
        stop.set()
        signal.signal(signum, signal.SIG_DFL)  # a second signal ends it at once

    previous = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}
    code = 0
    heartbeat = None
    poller = None
    reporter = None
    forwarder = None
    try:
        try:  # startup errors of the capture (bad interface name, ...) are "cannot start"
            if args.interface:
                # Only NFStream needs it: the scapy backend expires flows on a wall-clock timer.
                if not args.no_heartbeat and backend == "nfstream":
                    burst = args.heartbeat_burst_interval
                    heartbeat = (Heartbeat(args.interface) if burst is None
                                 else Heartbeat(args.interface, fast_interval=burst or None))
                    try:
                        heartbeat.start()
                        detector.heartbeat = heartbeat
                        log.info("heartbeat: one UDP broadcast per second on %s keeps flows "
                                 "expiring on a quiet link (faster while a burst of "
                                 "finished flows drains)", args.interface)
                    except OSError as exc:
                        heartbeat = None
                        log.warning("no heartbeat (%s): on a quiet link, finished flows are only "
                                    "reported when more traffic arrives", exc)
                flows = flows_from_interface(args.interface, backend=backend,
                                             max_flows=args.max_flows, duration=args.duration)
            else:
                flows = flows_from_pcap(args.pcap, backend=backend)
        except (OSError, ValueError, RuntimeError) as exc:
            return _fail(f"cannot start the capture: {exc}")
        # Analyst actions only make sense on a live sensor: a replay with IDPS_DRY_RUN=false
        # applies real blocks, and a capture file has no analyst waiting on it.
        if client is not None and args.interface:
            poller = ActionPoller(client, engine, sink, metrics, interval=live.action_poll_seconds)
            poller.start()
            log.info("polling the SOC for analyst actions every %g s", live.action_poll_seconds)
        if rules.enabled:
            forwarder = RuleForwarder(rules, sink, respond=detector.respond,
                                      block_weight=engine.policy.min_flows)
            forwarder.start()
            log.info("rule alerts: following %s (informational %s, repeats folded for %g s, "
                     "%d rule(s) may block)", rules.eve, "kept" if rules.include_info else "dropped",
                     rules.dedupe_seconds, len(rules.block_sids))
        if client is not None:
            reporter = StatusReporter(client, lambda: build_status(
                engine=engine, bundle=bundle, live_settings=live, metrics=metrics, sink=sink,
                heartbeat=heartbeat, interface=args.interface,
                faithfulness=faithfulness, model_sha256=digest, drift=drift,
                extended=live.send_features, signed_by=signed_by,
                rules=forwarder.status() if forwarder is not None else None),
                interval=live.status_seconds)
            reporter.start()
            log.info("reporting status to the SOC every %g s", live.status_seconds)
        try:
            detector.run(flows, stop, max_flows=args.max_flows,
                         duration=args.duration if args.interface else None)
        except Exception as exc:  # noqa: BLE001  capture failures (permissions, interface down, ...)
            code = _fail(f"{type(exc).__name__}: {exc}", 1)
    finally:
        if heartbeat is not None:
            heartbeat.stop()
        if forwarder is not None:
            forwarder.stop()  # before the sink closes: it queues alerts and block reports
        if poller is not None:
            poller.stop(timeout=ACTION_STOP_TIMEOUT)  # before the sink closes: it queues block events
        if reporter is not None:
            reporter.stop()
        sink.close()
        if args.interface:
            stop_capture_processes()  # or the process never exits (see the function)
        for s, handler in previous.items():
            signal.signal(s, handler)
    return code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.heartbeat_burst_interval is not None and args.heartbeat_burst_interval < 0:
        parser.error("--heartbeat-burst-interval must be 0 or more")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
