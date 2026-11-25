# IDPS with Explainable AI and a SOC Dashboard — Project Plan

## 1. Goal

Build a network Intrusion Detection and Prevention System that:

1. **Detects** attacks in network flows with ML models, using both a public dataset and live captured traffic.
2. **Explains** every alert with XAI (SHAP per alert, LIME for comparison), so an analyst can see *why* a flow was flagged.
3. **Prevents** attacks by blocking malicious IPs automatically through nftables, with safety rules.
4. **Supports SOC work** in a web dashboard: a live alert feed, explanations, block/unblock, incident cases and metrics.
5. **Runs in and protects the cloud** on AWS: the SOC is hosted there, and attacks on cloud machines are
   detected from VPC Flow Logs and blocked with network ACL rules.
6. **Shows attacks on maps**: a live world map of attack sources, and a network topology map of the
   lab and cloud machines.
7. **Includes a SOC assistant chatbot** that explains alerts and fixes, answers questions about SOC data,
   and suggests actions that an analyst must confirm.

## 2. Architecture

```
 live NIC ──┐                                    ┌──> nftables (block set, TTL)
            ├─> [capture] ─> [features] ─> [detect] ─> [respond] ──┘
 PCAP replay┘    Scapy/       flow           XGBoost +    policy engine
 (tcpreplay)     NFStream     extractor      anomaly      (allowlist, threshold)
                                               │
                                               v
                                           [explain] SHAP/LIME
                                               │
                                               v
   AWS VPC Flow Logs ─> [cloud collector] ─> [detect: NetFlow model] ─> [cloud respond] ─> network ACL deny
                                               │
                                               v
                          [SOC API] FastAPI + PostgreSQL + WebSocket  <──>  [assistant] Claude API + SOC tools
                                               │
                                               v
                          [SOC UI]  React: alerts, explanations, blocks, cases, maps, chat
```

The SOC API, database and dashboard run on AWS (section 4). The local lab sensor and the cloud
collector both send alerts to it.

**Key design rule: use one feature extractor for training and for live traffic.**
If the model is trained on the dataset's ready-made CSV features but live traffic goes through a
different extractor, live accuracy falls apart. That's the most common way projects like this fail.
To avoid it, regenerate training features from the dataset **PCAPs** with the same extractor
(`cicflowmeter` Python port, or NFStream) that runs live, then join them to the dataset labels.

## 3. Modules

| Module | Responsibility | Main libraries |
|---|---|---|
| `idps/capture` | Sniff an interface or replay PCAPs, then group packets into flows | Scapy, NFStream / cicflowmeter, tcpreplay |
| `idps/features` | Flow → feature vector; the same code is used for training and live | pandas, numpy |
| `idps/detect` | Supervised multi-class classifier plus an unsupervised anomaly detector for unseen attacks | XGBoost, scikit-learn (RandomForest, IsolationForest) |
| `idps/explain` | Per-alert SHAP values (TreeExplainer), LIME on request, global importance reports | shap, lime |
| `idps/respond` | Policy engine: confidence threshold, allowlist (gateway, DNS, the SOC host itself), ban with a TTL, dry-run mode; writes to an nftables set with timeouts | python-nftables or subprocess `nft` |
| `soc/api` | REST + WebSocket: alerts, explanations, blocks, cases, users, metrics | FastAPI, SQLAlchemy, PostgreSQL, JWT auth |
| `soc/web` | Dashboard: live feed, alert detail with a SHAP waterfall, block/unblock, case management, KPI charts | React + Vite, TypeScript, Recharts |
| `idps/cloud` | Read VPC Flow Logs, turn records into features, block with network ACL deny rules | boto3 |
| `soc/assistant` | SOC chatbot: Claude with tools that read SOC data and propose actions | anthropic (Python SDK) |
| `infra/` | AWS infrastructure as code: VPC, EC2, flow logs, IAM roles, budget alarm | Terraform |
| `lab/` | Isolated test network: attacker, victim and sensor | Docker Compose or VirtualBox VMs |

### Detection details
- **Datasets:** CIC-IDS2017 for training. Use the **corrected** labels (Engelen et al., 2021), because the
  original labels have known errors. Use UNSW-NB15 as a second dataset to test how well the model
  generalises to data it wasn't trained on.
- **Models:** XGBoost as the main classifier. RandomForest and a small MLP as baselines.
  IsolationForest or an autoencoder trained on benign traffic to flag zero-day attacks.
- **Class imbalance:** class weights or SMOTE on the training split only.
- **Splits:** split by time or capture day, not at random, so near-duplicate flows from the same day
  don't end up in both training and test data and inflate the scores.

### XAI details
- SHAP TreeExplainer for each alert (fast for tree models; budget under 50 ms per alert).
- LIME on demand from the dashboard, to compare it with SHAP.
- Global views: SHAP summary plot per attack class.
- **Faithfulness check** (strong material for the report): remove the top-k SHAP features and measure how much confidence drops,
  compared with removing k random features.

### Prevention safety
- A hard allowlist that can never be blocked: the gateway, DNS servers, the SOC host and the analyst IP.
- Block only when confidence ≥ threshold **and** an IP crosses N malicious flows within a time window.
- Every block has a TTL (for example 15 min) and is logged with its explanation.
- A dry-run mode that logs what *would* be blocked; use it while tuning.
- Run blocking **only inside the lab network**, never on a shared university or home network.

### SOC dashboard pages
1. Live alert feed (WebSocket), filterable by severity, class and IP.
2. Alert detail: flow fields, prediction and confidence, SHAP waterfall chart, a "Run LIME" button, and Block or Mark false positive buttons.
3. Active blocks: the list with TTLs and an Unblock button.
4. Cases: group alerts into an incident and add notes and a status (open, investigating, closed).
5. Metrics: alerts over time, attack-class breakdown, top source IPs, false-positive rate, detection latency.
6. Login with roles: analyst (triage) and admin (policy, allowlist, users).
7. Attack world map: live arcs from each attack source's location to the target (details below).
8. Topology map: lab and cloud machines with the traffic between them; machines under attack are highlighted.
9. Assistant: a chat panel, also opened from an alert ("Explain this alert").

### Maps
- **World map:** look up the location of each source IP with the free MaxMind GeoLite2 City database
  (needs a free MaxMind account and licence key), and draw animated arcs with deck.gl's ArcLayer on a
  base map. Lab IPs are private and have no location, so the map is filled mostly by real internet
  scanners hitting the cloud victim's public IP, which is good real-world material for the report.
  For lab demos, a clearly labelled "demo mode" can give lab IPs made-up locations.
- **Topology map:** nodes come from a host inventory (lab containers, EC2 instances) plus hosts seen in
  flows; edges are flows, coloured by alert severity. Drawn with React Flow or Cytoscape.js from a
  `/topology` API endpoint, updated over the WebSocket.

### SOC assistant (chatbot)
- **Model:** Claude through the Anthropic Python SDK in the FastAPI backend, using `claude-opus-5-5`
  with server-side fallbacks enabled for refused requests. Responses stream to the dashboard.
- **Tools the model can call** (each one is a fixed, parameterised query; the model never writes SQL):
  - `search_alerts(filters)`, `get_alert(id)` (includes the SHAP explanation), `top_attackers(window)`,
    `list_blocks()`, `get_case(id)`: read-only.
  - `propose_block(ip, reason, ttl)` and `propose_case(alert_ids, title)`: these only create a
    **pending action** that the analyst must confirm in the UI. The assistant can never block on its own.
- **Fix suggestions:** a small set of playbooks in `docs/playbooks/` (one per attack class, mapped to
  MITRE ATT&CK) that the assistant reads, so its advice stays consistent and can be checked.
- **Prompt injection:** attacker-controlled data (HTTP paths, user agents, payloads) reaches the model
  through tool results. Treat it as untrusted: label it as data in the prompt, and keep the
  analyst-confirms rule for every action, so an injected instruction can't make anything happen.
- **Cost and setup:** needs an Anthropic API key, kept in the server environment and never in the
  browser. Cache the system prompt and tool definitions. Without a key, the chat panel is disabled
  and the rest of the SOC still works.
- **Evaluation:** about 30 test questions with expected answers (for example "top attacker in the last
  hour"), checked against the database. Report accuracy, and how often it proposes the right action.

## 4. Lab and attack scenarios

Isolated Docker or VM network: `attacker` (Kali), `victim` (Ubuntu running web and SSH services), `sensor` (the IDPS).
Run every attack only against your own lab machines.

| Scenario | Tool | Expected class |
|---|---|---|
| Port scan | nmap | PortScan |
| SSH brute force | hydra (lab creds) | Brute force |
| HTTP flood / slow DoS | hping3, slowloris | DoS |
| Web attacks | sqlmap against DVWA | Web attack |
| Dataset replay | tcpreplay of CIC-IDS2017 PCAPs | Mixed |

## 4b. Cloud architecture (AWS)

**Hosting the SOC**
- One EC2 instance running the SOC API, PostgreSQL and the dashboard with Docker Compose, behind
  Caddy for HTTPS. This is the cheapest setup; ECS Fargate + RDS is the "production" alternative to
  describe in the report.
- Secrets (database password, Anthropic API key, MaxMind key) in SSM Parameter Store; trained models
  in S3; logs in CloudWatch.
- The lab sensor sends alerts to the SOC API over HTTPS with an API token.

**Protecting cloud machines**
- A separate "target" VPC with a victim EC2 instance and VPC Flow Logs turned on (delivered to S3 or
  CloudWatch Logs).
- Flow logs only have NetFlow-style fields (addresses, ports, protocol, packets, bytes, times, accept or
  reject), far fewer than the CICFlowMeter features. So the cloud side needs its **own model** trained on
  NetFlow-feature datasets such as NF-UNSW-NB15 or NF-CSE-CIC-IDS2018, which have the same kind of fields.
- Flow logs arrive in batches every 1–10 minutes, so cloud detection is near-real-time, not instant.
  Say so in the report and compare it with the lab sensor's latency.
- Blocking: add a deny rule for the attacker IP to the target subnet's **network ACL** (security groups
  can't deny), removed again when its TTL runs out. The same allowlist and dry-run rules apply.
- The collector's IAM role may only read the flow logs and edit that one network ACL. (One exception:
  `ec2:DescribeNetworkAcls` cannot be limited to a resource, so it is granted on `*`; it is read-only.)
- Caddy's certificate is self-issued: Let's Encrypt's validation servers are not in the admin address
  list that port 80 is restricted to. The database password is generated on the host, not kept in SSM.
  Details: `infra/README.md`, `docs/cloud.md`.

**Testing in AWS**
- AWS allows security testing of your own resources for most services without asking first, but
  **not DoS or flood tests**. Those need AWS's separate approval, so run DoS scenarios in the local lab only.
  Port scans and brute force from your own second EC2 instance against your own victim are fine.
- Check AWS's current penetration-testing policy before testing, since it can change.

**Cost control**
- Use free-tier instance types where possible, set an AWS Budgets alarm (for example $10), and keep
  everything in Terraform so `terraform destroy` removes it all after each test session.
  Check for AWS Educate or student credits first.

## 5. Repository layout

```
idps/          capture, features, detect, explain, respond, cloud (Python package)
soc/api/       FastAPI app
soc/assistant/ SOC chatbot (Claude + tools)
infra/         Terraform for AWS
soc/web/       React dashboard
notebooks/     EDA and model experiments
data/          raw/ and processed/ (git-ignored)
models/        trained model files (git-ignored, with a version manifest)
lab/           docker-compose.yml, attack scripts
tests/         pytest + dashboard tests
docs/          this plan, playbooks/, architecture diagrams, report drafts
```

## 6. Milestones (about 18 weeks)

Adding the cloud, maps and assistant takes the plan from 14 to about 18 weeks, which fits the 4+ months
available. If work slips, the stretch items marked ★ are the ones to cut first.

| Week | Milestone | Done when | Who builds it |
|---|---|---|---|
| 1 | Repo skeleton, lab network up, datasets downloaded | `docker compose up` runs all 3 lab nodes | implementer |
| 2–3 | Feature pipeline: PCAP → flows → features, labels joined | Same features come out of a PCAP and a live interface | implementer, test-runner |
| 4–5 | Models trained and evaluated (XGBoost + baselines + anomaly) | Per-class P/R/F1, confusion matrix, cross-dataset results in a notebook | implementer |
| 6 | XAI module: SHAP per alert, LIME, global plots, faithfulness test | Each alert comes with an explanation within the latency budget | implementer |
| 7 | Live detection loop on the sensor | A lab attack produces an alert within a few seconds | implementer, test-runner |
| 8 | Response engine + nftables, dry-run first | A lab attacker gets blocked and unblocked automatically; the allowlist is never blocked | implementer, then reviewer |
| 9 | SOC API: alerts, blocks, cases, WebSocket, JWT auth | API tests pass | Opus (auth at xhigh), test-runner |
| 10–11 | SOC dashboard pages 1–6 | All pages work against the live lab | Opus (UI) |
| 12 | Maps: world map (GeoLite2 + deck.gl) and topology map | Both maps update live from lab traffic | Opus (UI) |
| 13 | SOC assistant: read-only tools, streaming chat panel, playbooks | It answers the eval questions correctly against the database | implementer, then Opus for the chat UI |
| 14 | Assistant actions: propose block/case with analyst confirmation | No action runs without a confirm click (tested) | implementer, reviewer |
| 15 | AWS: Terraform for SOC hosting, deploy, lab sensor reporting to it | SOC reachable over HTTPS on AWS; budget alarm set | implementer |
| 16 | ★ AWS: target VPC, flow log collector, NetFlow model, network ACL blocking | A scan from your own EC2 is detected and blocked | implementer, reviewer |
| 17 | End-to-end tests of every scenario (lab and cloud), performance, security review | Results table; review findings fixed | test-runner, reviewer, Fable (audit) |
| 18 | Report, demo video, slides | Ready to submit | — |

## 7. Evaluation (for the report)

- Detection: per-class precision, recall, F1, macro-F1, false-positive rate, ROC-AUC.
- Generalisation: train on CIC-IDS2017, test on UNSW-NB15 using the features they share.
- Live: detection rate per lab scenario, time-to-alert, time-to-block.
- XAI: explanation latency, a faithfulness test of SHAP versus LIME, and an optional small user study (can analysts triage faster with explanations?).
- System: flows per second the sensor can handle before it drops packets.
- Cloud: detection rate and time-to-block from VPC Flow Logs, compared with the lab sensor.
- Assistant: answer accuracy on the test questions, right-action rate, and response time.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Live features don't match the training features | One extractor for both (see §2) |
| Model scores look excellent offline but fail live | Split by time, use corrected labels, test on lab traffic |
| Auto-block locks you out | Allowlist, TTL, dry-run mode, run in the lab only |
| SHAP is too slow | TreeExplainer only for live alerts; KernelSHAP/LIME only on demand |
| Too much scope | Weeks 1–8 are the core; cut the ★ items and trim the dashboard if time runs short |
| AWS bill grows | Budget alarm, free-tier sizes, `terraform destroy` after each session |
| Chatbot is tricked by attacker data | Read-only tools, fixed queries, analyst confirms every action |
| Flow logs too coarse for the main model | Separate NetFlow-feature model for the cloud |
