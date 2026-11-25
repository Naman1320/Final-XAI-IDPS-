# Cloud architecture with live attacks, at zero cost (plan, 17 Nov 2026)

Agreed with the user; started 17 Nov 2026.

**Progress (17 Nov 2026):** emulator = **Moto 5.1.22** (chosen over LocalStack: no account ever,
50 MB of wheels instead of ~1 GB). **C1 done, tested, reviewed (Sonnet); not committed.**

**18 Nov 2026:** C3 (exporter) started in parallel with the dataset work (user's decision; rules: one
heavy training at a time, at most 3 agents at once, everything on Sonnet 5.5). First draft of the C5
write-up is in `cloud-architecture.md`. **Open design point for C4:** the lab SOC accepts the sensor
port only from the sensor's address on `mgmt_net`, and `cloud_net` has no route to it, so the
collector needs a second leg on `mgmt_net` with its own certificate (or another way in); decide in C4.

How to run it:

    docker compose -f lab/cloud/docker-compose.yml up -d
    lab/cloud/tf.sh init      # once; downloads the AWS provider (6.73.0, ~730 MB on disk)
    lab/cloud/tf.sh apply -auto-approve
    lab/cloud/tf.sh apply -auto-approve   # a fresh emulator needs a second apply, see below
    lab/cloud/tf.sh plan      # "No changes"

What is in place:
- **Emulator:** image `idps-lab-moto:5.1.22` built offline (`lab/cloud/Dockerfile.moto`, wheels in
  ~/Library/Caches/idps-lab/wheels-moto), account 000000000000, region eu-west-1, AWS managed
  IAM policies loaded. Read-only, non-root, no capabilities, CPU/memory/PID limits, 127.0.0.1:4566
  only. Its network namespace is held by `moto-net` (`lab/cloud/netguard.sh`, image built from
  `lab/cloud/Dockerfile.net`): no default route, inbound 4566 from cloud_net 10.10.4.0/24 only,
  outbound replies only (checked: a connect to the internet gets "Network is unreachable").
- **Billing guard** `lab/cloud/guard.py`: refuses unless the credentials are test/test, no
  profile/role/session token/CA bundle/proxy/per-service endpoint is set, the endpoint is
  127.0.0.1, localhost, ::1 or 10.10.4.10 on port 4566, it answers as Moto and STS says
  000000000000. `lab/cloud/env.sh` sets that environment and hides ~/.aws.
- **Terraform** 1.17.1 (checksum-verified, ~/.local/bin) runs only through `lab/cloud/tf.sh`:
  allow-listed subcommands, no -chdir/-state/-var-file options, guard first, infra/ copied to
  ~/Library/Caches/idps-lab/cloud-tf (only into a folder it made, marker `.idps-cloud-tf`; no
  tfvars copied) plus `lab/cloud/terraform/emulator_override.tf` (all endpoints to the emulator).
  Every command except init runs behind `lab/cloud/egress_proxy.py`, which refuses every host
  but the emulator and every HTTPS tunnel.
- **Result:** all 49 resources of infra/ (both VPCs, subnets, security groups, the target's network
  ACL, both instances, IAM roles and policies, KMS key, both S3 buckets, the VPC flow log to S3 in
  the v2+ format) apply to the emulator; a second plan shows no changes.

Found on the way:
- **A real bug in infra/, fixed:** `data.aws_ssm_parameter.al2023[...].insensitive_value` does not
  exist; the attribute is `insecure_value` (soc.tf, target.tf). `terraform validate` can't see it
  (for_each index), so a real `apply` would have failed too.
- **Emulator differences (state these in C5):** S3 Control puts the account id in the host name
  (000000000000.localhost), which nothing resolves; the proxy routes it. Moto ignores tags sent with
  CreateBucket, so the first apply on a fresh emulator leaves the buckets untagged and the second
  apply tags them. Moto state is in memory: after a container restart, delete
  ~/Library/Caches/idps-lab/cloud-tf/terraform.tfstate* and apply again.
- The network ACL has no attacker or web rules yet (`attacker_cidrs` and `victim_web_open` are empty
  by default). C3/C4 set the lab attacker's address for the emulated run.

**C3 built (17 Nov 2026), not committed, not yet reviewed (Opus reviewer):** live flow-log exporter
(`idps/cloud/flowlog_export.py`, `lab/cloud/README.md`): `flowlog-writer` in the sensor's namespace writes 60 s
window files, `flowlog-shipper` (cloud_net only) delivers them to the emulated bucket with the real key layout.
Found on the way: Moto ignores bucket-policy conditions, so the TLS-only Deny blocked every request; fixed in the
emulator only (`lab/cloud/terraform/secure_bucket_override.tf`, copied by `tf.sh`).

**C2 built and revised after review (18 Nov 2026), not committed:** cloud model from CIC-IDS2017 reduced to
flow-log fields (`idps/cloud/train_data.py`, `train_model.py`, `scripts/cloud_lab_eval.py`); retrained bundles are in
`models/staging/` (signed), to be promoted after C4. Details and limits in `docs/cloud.md`, "The cloud model". Headline:
CIC test macro-F1 0.68 (minute-bootstrap CI 0.60 to 0.71; lab week model 0.66, not a controlled comparison), benign
false positives 6.5% against 1.1%; on the lab replay it catches SSH brute force and, when probes get replies, the
scan (0.3% under the emulated security group's REJECT), flags the SYN flood as a scan, and misses the slow DoS.

**C4 built, reviewed (Sonnet) and revised (18 Nov 2026), not committed:** the collector runs live in its own two-legged,
locked-down namespace (`collector-net`: cloud_net `10.10.4.30` + mgmt_net `10.10.3.3`, output only 4566 to Moto and 8444 to the
SOC), authenticates to the SOC as sensor `cloud` with its own certificate (mutual TLS), verifies the signed cloud model, runs
`guard.py` at start and every 5 minutes, and adds deny entries to the emulated ACL (recorded only, no packets stopped). The SOC's
`netguard.sh` gained `SOC_EXTRA_SENSOR_ADDRS` (blank = unchanged). Review found no critical or high issue; fixed: a 401/403/404 from the SOC
now keeps the alerts queued and turns the container unhealthy (they were dropped silently); the token is created as the last
provisioning step and a token that never reached the volume is replaced; scoring in chunks of 2,000 rows with a per-object cap
(20,000) and a 512m limit; `start_collector.sh` re-adds the cloud CA if the SOC's bootstrap dropped it; isolation checks for the
collector in `lab/check_isolation.sh`; the collector exits and is restarted if `collector-net` restarts alone. Live: an SSH brute
force gave 21 alerts from sensor `cloud` in the SOC and deny rule 1 (ingress and egress) for `10.10.1.10/32` in `acl-1b806954bdadc3d40`;
the port scan (ports 1-200) gave 2 to 3 alerts in about 200 rows and no block, as the C2 numbers predict. Details: `lab/cloud/README.md`, "C4".

Original note: Goes between roadmap step 13 (done) and step 14 (write-up),
so the write-up can include it. **Wait for the user's "proceed" and their yes to the downloads
before starting.**

## Rule: no billing, ever

- No AWS account, card or email. Fake credentials (`test`/`test`), every AWS call pinned to the
  emulator at `localhost:4566`.
- A guard script refuses to run if it sees real AWS credentials or an account other than the
  emulator's (`aws sts get-caller-identity` must return the emulator account, e.g. 000000000000).
- The emulator runs on an isolated Docker network.
- Option 3 (SOC on a free cloud VM) and real AWS were discussed and NOT chosen: they need the
  user's card. Do not suggest them again unless the user asks.

## Why a cloud model is needed

`docs/cloud.md`: VPC Flow Logs carry only addresses, ports, protocol, packets, bytes, start/end
and ACCEPT/REJECT per 60 s window. The lab model's ~40 CICFlowMeter-style features are not
available, so the collector (`idps/cloud`) needs its own model with `CLOUD_MODEL_FEATURES`
(`idps.cloud.flowlogs`). No cloud model exists yet. Plan: derive it from the CIC-IDS2017 data
already on disk, reduced to flow-log fields (no dataset download).

## Steps

| # | What | Built by |
|---|---|---|
| C1 | Emulated AWS: Moto (Docker) + Terraform (LocalStack was the first idea); apply the existing `infra/` design to the emulator through an override file (provider endpoints), otherwise unchanged; billing guard script | main session (Opus) |
| C2 | Cloud model from CIC-IDS2017 reduced to flow-log fields; evaluated and compared honestly with the lab model; signed like the lab models (`python -m idps.detect sign`, key in ~/.idps-lab) | implementer (Sonnet) |
| C3 | Live flow-log exporter: watches the lab's attack network and writes AWS VPC Flow Log v2 records every 60 s into the emulated S3 bucket, with the real key layout `AWSLogs/<account>/vpcflowlogs/<region>/...` | implementer (Sonnet) |
| C4 | Collector live against the emulator (boto3 honours `AWS_ENDPOINT_URL`): alerts to the lab SOC as a "cloud" sensor, deny entries in the emulated network ACL | implementer (Sonnet) |
| C5 | Architecture diagrams and write-up: (a) the real AWS design in `infra/`, (b) the free emulated version, and what differs; `terraform validate` + apply on the emulator as proof | main session (Opus) |
| C6 | Live demo run: attacker container attacks; (1) lab sensor blocks in seconds; (2) cloud path alerts in 1-2 min and adds the deny rule, shown with `aws ec2 describe-network-acls` | main session (Opus) |

The dashboard can start a recorded-capture C6 replay and observe an independently operated live runner. The classroom replay has been verified end to end against Moto. Full live-traffic verification remains open. See the [demonstration guide](c6.md).

Reviews: Sonnet's code (C2-C4) -> Opus reviewer; Opus's parts (C1, C5, C6) -> Sonnet reviewer.
Tests: test-runner (Sonnet). Never Fable.

## Downloads that needed the user's yes (given 17 Nov 2026: Moto wheels 50 MB, Terraform 34 MB + AWS provider ~730 MB on disk; LocalStack not used; AWS CLI still to ask, C6)

| What | Size | Account |
|---|---|---|
| Terraform | ~25 MB | none |
| LocalStack community image | ~1 GB | none for known versions; if the current version asks for a sign-up/token, stop and tell the user. Fallback: Moto (open-source AWS emulator, pip package ~10 MB, never an account) |
| AWS CLI v2 | ~40 MB | none (only to show the emulated ACL rule) |

## Honest limits to state in the write-up

- Emulated EC2 instances don't really boot.
- The network ACL "block" is recorded but stops no packets (the lab sensor does the real blocking).
- The flow logs come from the lab's traffic, not Amazon's network.
- The cloud model is less accurate than the lab model (much coarser features): a finding to report.

Estimate: 5-7 hours.
