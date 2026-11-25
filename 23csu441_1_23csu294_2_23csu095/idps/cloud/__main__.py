"""python -m idps.cloud collect --once | parse <file> | export writer|offline|ship"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import replace
from pathlib import Path

from idps.cloud import flowlogs


def _parse(args: argparse.Namespace) -> int:
    stats = flowlogs.ParseStats()
    try:
        rows = flowlogs.to_flow_rows(flowlogs.read_path(args.file, stats))
    except (OSError, flowlogs.FlowLogError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"file": args.file, "rows": len(rows), **stats.as_dict(),
                      "errors": stats.errors}, indent=2))
    for row in rows[: args.rows]:
        print(json.dumps(row))
    return 0


def _collect(args: argparse.Namespace) -> int:
    from pydantic import ValidationError

    from idps.cloud.collector import (
        Collector,
        CollectorConfig,
        CollectorError,
        GuardRefused,
        NetworkLost,
        SocClient,
        emulator_mode,
        load_cloud_bundle,
        make_client,
        make_guard_check,
        resolve_sensor_token,
    )
    from idps.cloud.nacl import NaclBlocker
    from idps.config import get_settings
    from idps.respond.engine import ResponseEngine
    from idps.respond.nft import BlockerError
    from idps.respond.policy import ResponsePolicy

    try:
        config = CollectorConfig.from_env()
    except ValueError as exc:  # e.g. IDPS_CLOUD_MAX_DENIES=ten
        print(f"error: {exc}", file=sys.stderr)
        return 2
    overrides = {k: v for k, v in {
        "bucket": args.bucket, "prefix": args.prefix, "nacl_id": args.nacl_id,
        "model_path": args.model, "state_dir": Path(args.state_dir) if args.state_dir else None,
    }.items() if v}
    config = replace(config, **overrides)
    try:
        settings = get_settings()  # IDPS_DRY_RUN (default on), IDPS_ALLOWLIST, ...
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not config.bucket:
        print("error: set IDPS_CLOUD_BUCKET (or --bucket) to the flow-log bucket", file=sys.stderr)
        return 2
    try:
        config.validate()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not settings.dry_run and not config.nacl_id:
        print("error: real blocking needs IDPS_CLOUD_NACL_ID (or --nacl-id)", file=sys.stderr)
        return 2
    guard = None
    pin: dict = {}
    try:
        if emulator_mode():
            # The emulated AWS: the billing guard (lab/cloud/guard.py, unchanged) must approve the
            # environment now and every few minutes; the clients are pinned to the endpoint with
            # the fake keys instead of trusting the environment.
            guard = make_guard_check()
            found = guard()
            if found:
                print("billing guard: REFUSED, nothing was read", file=sys.stderr)
                for item in found:
                    print(f"  - {item}", file=sys.stderr)
                return 1
            pin = {"endpoint_url": os.environ["AWS_ENDPOINT_URL"], "fake_credentials": True}
        s3 = make_client("s3", config.region, **pin)
        ec2 = make_client("ec2", config.region, **pin) if not settings.dry_run else None
        policy = ResponsePolicy.from_settings(settings, min_flows=config.min_flows)
        blocker = NaclBlocker(
            ec2, config.nacl_id or "acl-dryrun", policy, config.state_dir / "nacl_state.json",
            dry_run=settings.dry_run, max_denies=config.max_denies)
        engine = ResponseEngine(settings, blocker=blocker, policy=policy)
        bundle = (load_cloud_bundle(config.model_path, config.model_public_key)
                  if config.model_path else None)
        client = None
        token = resolve_sensor_token(config)
        if config.soc_url and token:
            client = SocClient(config.soc_url, token, ca_file=config.soc_ca_file,
                               client_cert=config.client_cert, client_key=config.client_key)
        collector = Collector(config, s3, bundle=bundle, engine=engine, blocker=blocker,
                              post=client.post_alerts if client else None, status_client=client,
                              guard=guard)
        if args.once:
            collector.check_guard(force=True)
            collector.run_once()
        else:
            collector.run_forever(args.interval)
    except KeyboardInterrupt:
        return 0
    except (GuardRefused, NetworkLost) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (CollectorError, BlockerError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m idps.cloud", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("parse", help="parse a flow-log file (.log or .log.gz) and summarise it")
    p.add_argument("file")
    p.add_argument("--rows", type=int, default=5, help="how many flow rows to print (default 5)")
    p.set_defaults(func=_parse)

    c = sub.add_parser("collect", help="read new flow logs from S3, alert the SOC, block")
    c.add_argument("--once", action="store_true", help="run one cycle and exit")
    c.add_argument("--interval", type=float, default=60.0,
                   help="seconds between cycles when not --once (default 60)")
    c.add_argument("--bucket", help="flow-log bucket (IDPS_CLOUD_BUCKET)")
    c.add_argument("--prefix", help="S3 key prefix AWSLogs/<account-id>/vpcflowlogs/<region>/ (IDPS_CLOUD_PREFIX, required)")
    c.add_argument("--nacl-id", help="target network ACL (IDPS_CLOUD_NACL_ID)")
    c.add_argument("--model", help="cloud model bundle (IDPS_CLOUD_MODEL)")
    c.add_argument("--state-dir", help="checkpoint and block state (IDPS_CLOUD_STATE_DIR)")
    c.set_defaults(func=_collect)

    from idps.cloud.flowlog_export import add_export_parser

    add_export_parser(sub)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
