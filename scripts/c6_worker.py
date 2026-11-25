"""Host-side C6 evidence worker. The SOC supplies only a run ID and one of two fixed modes."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request
from uuid import UUID

from idps.cloud.collector import Collector, CollectorConfig, load_cloud_bundle
from idps.cloud.flowlog_export import ExportConfig, export_packets, read_pcap
from idps.cloud.nacl import RESERVED_MAX, RESERVED_MIN, NaclBlocker
from idps.config import Settings
from idps.respond.engine import ResponseEngine
from idps.respond.policy import ResponsePolicy
from lab.cloud import guard
from scripts.demo_runner import build_opener

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "10.10.1.10"
CAPTURE = ROOT / "data/raw/lab_pcaps/ssh_bruteforce_1.pcap"
PREFIX = "AWSLogs/000000000000/vpcflowlogs/eu-west-1/"
REGION = "eu-west-1"
ENDPOINT = "http://127.0.0.1:4566"


class EvidenceError(RuntimeError):
    """A fixed, nonsecret diagnostic suitable for the dashboard."""


def clients():
    import boto3
    if (os.environ.get("AWS_ENDPOINT_URL") != ENDPOINT
            or os.environ.get("IDPS_EMULATOR_ACCOUNT") != "000000000000"
            or guard.problems(dict(os.environ))):
        raise EvidenceError("Local Moto identity or billing guard failed. Check lab/cloud/env.sh.")
    if not shutil.which("aws"):
        raise EvidenceError("The AWS CLI is missing from the worker PATH.")
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)
    return tuple(session.client(name, endpoint_url=ENDPOINT) for name in ("ec2", "s3"))


def deny_entries(response, acl):
    acls = response["NetworkAcls"]
    if len(acls) != 1 or acls[0]["NetworkAclId"] != acl or acls[0]["OwnerId"] != "000000000000":
        raise EvidenceError("ACL read-back returned an unexpected account or ACL.")
    return sorted(("egress" if e["Egress"] else "ingress", e["RuleNumber"])
                   for e in acls[0]["Entries"] if e.get("CidrBlock") == SOURCE + "/32"
                   and e["RuleAction"] == "deny" and str(e["Protocol"]) == "-1"
                   and RESERVED_MIN <= e["RuleNumber"] <= RESERVED_MAX)


def cli_readback(acl, expected):
    args = ["aws", "ec2", "describe-network-acls", "--network-acl-ids", acl,
            "--region", REGION, "--endpoint-url", ENDPOINT, "--output", "json"]
    # No user AWS profiles, plugins, proxy or per-service endpoint settings in the child.
    env = {"PATH": os.environ["PATH"], "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
           "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
           "AWS_EC2_METADATA_DISABLED": "true", "AWS_PAGER": ""}
    result = subprocess.run(args, env=env, capture_output=True, check=True, timeout=20)
    entries = deny_entries(json.loads(result.stdout), acl)
    if entries != expected or {d for d, _ in entries} != {"ingress", "egress"}:
        raise EvidenceError("The CLI could not confirm both expected deny rules.")
    return f"{' '.join(args)} returned {SOURCE}/32 deny, protocol -1: {entries}"


def replay(run, emit):
    ec2, s3 = clients()
    if not CAPTURE.is_file() or not (ROOT / "models/cloud_xgboost.joblib").is_file():
        raise EvidenceError("Missing recorded lab capture or signed cloud model; see docs/c6.md.")
    capture = CAPTURE.read_bytes()
    emit("capture", f"Reading {CAPTURE.name} offline, {len(capture)} bytes, SHA-256 "
         + hashlib.sha256(capture).hexdigest())
    cmd = ["docker", "run", "--rm", "-i", "--pull=never", "--network", "none", "--cap-drop", "ALL",
           "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges", "--memory", "768m",
           "--pids-limit", "128", "idps-lab-sensor:latest", "python", "-c",
           (ROOT / "lab/sensor/c6_replay.py").read_text()]
    result = subprocess.run(cmd, input=capture, capture_output=True, timeout=90, check=False)
    if result.returncode:
        raise EvidenceError("Isolated sensor replay failed. Check the signed week model and sensor image.")
    lab = json.loads(result.stdout)
    if not lab["labels"]:
        raise EvidenceError("Lab classifier produced no above-threshold detection.")
    emit("lab_alert", f"Signed lab model, confidence ≥{lab['threshold']} from {SOURCE}: {lab['labels']}")
    if SOURCE in lab["before"] or SOURCE not in lab["after"]:
        raise EvidenceError("The isolated sensor did not add the source to its nftables set.")
    emit("lab_block", f"Sensor read-back: {SOURCE} absent before, present in inet idps blocked4 after.")
    bundle = load_cloud_bundle(ROOT / "models/cloud_xgboost.joblib", public_key=ROOT / "lab/keys/model-signing.pub")
    with TemporaryDirectory() as tmp, ExitStack() as cleanup:
        files = export_packets(read_pcap(CAPTURE), ExportConfig(), Path(tmp), run["id"])
        vpc = ec2.create_vpc(CidrBlock="10.90.0.0/24")["Vpc"]["VpcId"]
        cleanup.callback(ec2.delete_vpc, VpcId=vpc)
        acl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
        cleanup.callback(ec2.delete_network_acl, NetworkAclId=acl)
        before = deny_entries(ec2.describe_network_acls(NetworkAclIds=[acl]), acl)
        if before:
            raise EvidenceError("A matching rule was already present at baseline.")
        emit("baseline", f"Moto {acl}: no matching managed deny for {SOURCE}/32 before scoring.")
        bucket = "c6-" + run["id"]
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
        cleanup.callback(s3.delete_bucket, Bucket=bucket)
        for n, path in enumerate(sorted(files)):
            key = f"{PREFIX}{datetime.now(UTC):%Y/%m/%d}/{n:04}.log"
            s3.put_object(Bucket=bucket, Key=key, Body=path.read_bytes())
            cleanup.callback(s3.delete_object, Bucket=bucket, Key=key)
        settings = Settings(dry_run=False, allowlist=["10.10.2.0/24", "10.10.1.1", "10.10.1.2"])
        policy = ResponsePolicy.from_settings(settings)
        blocker = NaclBlocker(ec2, acl, policy, Path(tmp)/"rules.json", dry_run=False)
        engine = ResponseEngine(settings, blocker=blocker, policy=policy)
        alerts = []

        def collect(batch):
            alerts.extend(a for a in batch if a["src_ip"] == SOURCE)
            return {"accepted": len(batch)}

        config = CollectorConfig(bucket=bucket, prefix=PREFIX, region=REGION,
                                 state_dir=Path(tmp), settle_seconds=0)
        cycle = Collector(config, s3, bundle=bundle, engine=engine, blocker=blocker, post=collect).run_once()
        if not alerts:
            raise EvidenceError("The collector emitted no cloud alert for the replayed source.")
        emit("cloud_alert", f"{len(alerts)} replay alerts for {SOURCE}; first class "
             f"{alerts[0]['predicted_class']}; {cycle.objects} S3 objects, {cycle.rows} flows.")
        entries = deny_entries(ec2.describe_network_acls(NetworkAclIds=[acl]), acl)
        if not cycle.blocked or not entries:
            raise EvidenceError("Cloud alerts arrived without a verified automatic deny response.")
        emit("response", f"Collector recorded {cycle.blocked} block decision(s); {acl} now has {entries}.")
        evidence = cli_readback(acl, entries)
    emit("acl", evidence + ". Replay resources released after read-back.")


def observe(run, emit, acl):
    if not acl or not re.fullmatch(r"acl-[a-f0-9]{8,17}", acl):
        raise EvidenceError("Set C6_LIVE_ACL_ID to the target emulator ACL before observing.")
    ec2, _ = clients()
    before = deny_entries(ec2.describe_network_acls(NetworkAclIds=[acl]), acl)
    baseline = f"Live emulator ACL {acl}, initial matching rules: {before}"
    state = emit("baseline", baseline)
    if before:
        raise EvidenceError("Matching deny already exists. A new response cannot be attributed to this run.")
    deadline = time.monotonic() + 280
    while time.monotonic() < deadline:
        # An independently reported runner step anchors the log window.
        if state["status"] != "running":
            return
        capture_at = state["capture_at"]
        if not capture_at:
            time.sleep(3)
            state = emit("baseline", baseline)
            continue
        lines = subprocess.run(["docker", "logs", "--since", capture_at, "--tail", "2000",
                                "idps-collector"], capture_output=True, timeout=10, check=True)
        for line in (lines.stdout + lines.stderr).decode(errors="replace").splitlines():
            try:
                entry = json.loads(line[line.index("{"):])
            except (ValueError, TypeError):
                continue
            if (isinstance(entry, dict) and entry.get("event") == "nacl_blocked"
                    and entry.get("ip") == SOURCE and entry.get("acl") == acl):
                expected = sorted((key, entry[key]) for key in ("ingress", "egress"))
                evidence = cli_readback(acl, expected)
                emit("response", f"idps-collector logged nacl_blocked for {SOURCE}, {acl}, {expected}")
                emit("acl", evidence)
                return
        time.sleep(3)
        state = emit("baseline", baseline)
    raise EvidenceError("Observation ended without a new matching collector deny event.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--soc-url", required=True)
    parser.add_argument("--ca-file")
    parser.add_argument("--once", action="store_true", help="exit after one claimed run")
    args = parser.parse_args()
    url = urlsplit(args.soc_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        parser.error("--soc-url must be an HTTPS origin")
    token = os.environ.get("IDPS_SOC_C6_TOKEN", "").strip()
    if len(token) < 32:
        parser.error("set IDPS_SOC_C6_TOKEN")
    opener = build_opener(args.ca_file)

    def send(path, body):
        req = Request(args.soc_url.rstrip("/") + path, data=json.dumps(body).encode(),
                      headers={"Content-Type": "application/json", "X-C6-Token": token})
        with opener.open(req, timeout=10) as res:
            return json.load(res)

    while True:
        try:
            run = send("/c6/worker/claim", {})
            if run:
                run["id"] = str(UUID(run["id"]))
                if run["mode"] not in ("replay", "observe"):
                    raise EvidenceError("Unknown C6 mode")

                def emit(stage, evidence, run_id=run["id"]):
                    body = {"run_id": run_id, "stage": stage, "evidence": evidence}
                    for retry in range(3):
                        try:
                            return send("/c6/worker/report", body)
                        except HTTPError as exc:
                            if exc.code < 500 or retry == 2:
                                raise
                        except (URLError, TimeoutError):
                            if retry == 2:
                                raise
                        time.sleep(1)
                try:
                    if run["mode"] == "replay":
                        replay(run, emit)
                    else:
                        observe(run, emit, os.environ.get("C6_LIVE_ACL_ID"))
                except Exception as exc:  # noqa: BLE001 - report failure without leaking credentials
                    detail = str(exc) if isinstance(exc, EvidenceError) else type(exc).__name__
                    emit("error", "Worker stopped: " + detail)
                    if args.once:
                        return 1
                if args.once:
                    return 0
        except (URLError, TimeoutError) as exc:
            print("C6 SOC connection failed:", type(exc).__name__, file=sys.stderr, flush=True)
        time.sleep(2)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
