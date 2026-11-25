# Project progress — IDPS with Explainable AI and a SOC

Status as of 12 November 2026. Results on real data are in [results.md](results.md). The full plan is in [PLAN.md](PLAN.md).

## Summary

Most of the system is built and tested: the Docker lab, the feature pipeline, training, explanations,
automatic blocking, the SOC API and dashboard, both maps, the SOC assistant, and the AWS setup.
The models are now trained on the real CIC-IDS2017 Friday capture, and the explanations pass the
faithfulness test. The live detection loop now joins everything and has replayed the full Friday
capture, then run live on the lab sensor and blocked a real port scan with nftables. The lab now has
its own SOC, so live alerts, SHAP explanations and blocks show up on the dashboard as they happen.
What's left is the final tests, the security audit and the write-up.

- **Automated tests:** 611 pass, 3 skipped (Python), 7 pass (dashboard). Lint and type checks are clean.
- **Reviews:** every part was reviewed by a separate reviewer model, and all high and medium findings were fixed.

## Progress against the milestones

| Week | Milestone | Status |
|---|---|---|
| 1 | Repo skeleton, lab network, datasets | ✅ Done. Lab runs in Docker. Friday PCAP and label CSVs downloaded and checked |
| 2–3 | Feature pipeline (PCAP → flows → features, labels) | ✅ Done. Ran on the real Friday PCAP: 513,501 flows, 99.76% matched to labels |
| 4–5 | Models trained and evaluated | ✅ Done on Friday. Test macro-F1 0.729: PortScan 1.00, DDoS 0.93, Bot 0 (dataset label error, see [results.md](results.md)) |
| 6 | XAI: SHAP, LIME, global plots, faithfulness | ✅ Done. SHAP removes 38.6× more confidence than random features, LIME 16.9× |
| 7 | Live detection loop on the sensor | ✅ Done. Capture → model → SHAP → alert → response engine. Replayed the full Friday capture, then ran live on the lab sensor: a port scan was alerted and the attacker marked for blocking (see [live.md](live.md)) |
| 8 | Response engine + nftables | ✅ Done. Real nftables blocking tested in the lab: the attacker was cut off, and the block expired by itself after its 60 s time limit. Analyst override: blocks and unblocks confirmed in the SOC reach the firewall within seconds, and an analyst unblock stops auto-block from re-blocking that address for an hour |
| 9 | SOC API with JWT auth and WebSocket | ✅ Done |
| 10–11 | SOC dashboard pages | ✅ Done. Live in the lab: alerts, blocks and metrics update as a real attack happens |
| 12 | World attack map and topology map | ✅ Done (demo locations until a GeoLite2 key is added) |
| 13 | SOC assistant: tools, streaming chat, playbooks | ✅ Done. Switched off until a Claude API key is added |
| 14 | Assistant proposes blocks, analyst confirms | ✅ Done and tested |
| 15 | AWS: Terraform for hosting the SOC, budget alarm | 🟡 Written and reviewed. **Terraform never run** |
| 16 | AWS: target VPC, flow-log collector, NACL blocking | 🟡 Collector built and tested. Terraform never run |
| 17 | End-to-end tests, performance, security audit | ⬜ Not started |
| 18 | Report, demo video, slides | ⬜ Not started |

## What each part does

### 1. Lab (`lab/`)
- Three machines in Docker: **attacker → sensor → victim** (DVWA, a deliberately vulnerable web app).
- A lab SOC on its own management network that only the sensor can reach. The SOC itself can't open any connection.
- All traffic must pass through the sensor, which runs an nftables firewall.
- Containers refuse to start if the network isn't isolated (health checks fail closed).
- Attack scripts in `lab/attacks/` can only target the lab victim.

### 2. Feature pipeline (`idps/capture/`, `idps/features/`)
- Turns a PCAP file or a live interface into network flows using **NFStream**, with a scapy fallback that gives the same results.
- 47 flow features, of which the model uses 42.
- Joins CIC-IDS2017 labels to flows. It handles the dataset's date format, its 12-hour times without AM/PM, and odd characters. It stops if too few flows find a label.
- Details: [features.md](features.md).

### 3. Detection (`idps/detect/`)
- Splits data by time for each class, so the model isn't tested on data it has nearly seen.
- Trains **XGBoost**, a random forest and a neural network, plus an **Isolation Forest** to find unknown attacks.
- Reports per-class precision, recall, F1, macro-F1 and a confusion matrix.
- Saved models carry a SHA-256 checksum, so a tampered model file is refused.
- Details: [training.md](training.md).

### 4. Explainable AI (`idps/explain/`)
- **SHAP** explanation for each alert: which features pushed the decision.
- **LIME** as a second, independent explanation.
- Global feature-importance plots.
- A **faithfulness test** that checks the explanations really match the model.
- Details: [explain.md](explain.md).

### 5. Prevention (`idps/respond/`)
- Blocks attacker IPs with nftables, with a time limit on each block.
- Safety first: an allowlist is checked before anything, dry-run is the default, and real blocking refuses to run without an allowlist.

### 6. SOC API (`soc/api/`, FastAPI)
- Alerts, cases with notes, blocks, actions, metrics, topology, geo data, an audit log and user admin.
- **Security:**
  - Passwords hashed with argon2id.
  - JWT logins with token revocation and login throttling.
  - Sensor tokens stored only as hashes.
  - WebSocket login on the first message.
- Every block needs an analyst's confirmation, and a block-allowlist setting is required.
- Details: [soc.md](soc.md).

### 7. SOC dashboard (`soc/web/`, React + TypeScript)
- **Pages:** Alerts (with explanation charts), Alert detail, Actions, Blocks, Cases, Metrics, Admin and Assistant.
- **Live updates** over WebSocket.
- **World attack map:** attacks drawn as lines to the protected site, coloured by severity.
- **Network topology map:** a force layout of who talks to whom.

### 8. SOC assistant (`soc/assistant/`)
- A chatbot built on Claude that:
  - explains alerts and fixes;
  - answers questions about SOC data through 8 fixed tools;
  - can **propose** a block, which an analyst must confirm.
- Uses 7 defensive playbooks (`docs/playbooks/`), one per attack type: brute force, DoS, port scan, web attack, bot, infiltration and Heartbleed.
- Has limits on tool calls and proposals per reply, and SOC data is wrapped so it can't act as instructions.
- Streams its answers. It is switched off until `ANTHROPIC_API_KEY` is set.

### 9. AWS cloud (`infra/`, `idps/cloud/`)
- **Terraform for:**
  - the SOC server;
  - a protected target network with VPC flow logs going to a secure S3 bucket;
  - the collector's role;
  - a separate budget alarm (`infra/budget/`).
- **Secrets:** they live in SSM under their own KMS key, never in Terraform's files. The victim machine is explicitly denied access to them.
- **Collector:**
  - reads the flow logs and pairs the two directions of each flow;
  - sends alerts to the SOC, queueing them when the SOC can't be reached;
  - blocks attackers with network ACL deny rules.
- Details: [cloud.md](cloud.md).

## What's left

**Optional, for stronger results:**
- Add more CIC-IDS2017 days to test across days. Friday alone shows the pipeline works, not that it generalises.

**Needs a setup step or an account:**
- Install Terraform to validate `infra/`. Deploying needs an AWS account.
- Add `ANTHROPIC_API_KEY` to switch on the assistant.
- Add a MaxMind GeoLite2 key so real attacker locations show on the map.

**Can be done now:**
- Fix the remaining low-priority review findings:
  - map timers during alert floods;
  - back/forward with the Alerts `?ip=` filter;
  - rate-limiter counting;
  - token validity after logout;
  - logging logins to the audit log.

**Final weeks:**
- End-to-end tests, a performance check and a security audit (week 17).
- Report, demo video and slides (week 18).

## Commit history

| Commit | Date | What |
|---|---|---|
| 59e96a7 | 11 Nov 2026 | Claude Code project setup and agents |
| be296c2 | 11 Nov 2026 | Project plan |
| 0729d9d | 11 Nov 2026 | Week 1 skeleton, Docker lab |
| 6478f2f | 11 Nov 2026 | Feature pipeline, training, XAI, response engine, SOC |
| f1f40d7 | 11 Nov 2026 | Attack maps and the SOC assistant |
| 4539dab | 12 Nov 2026 | AWS infrastructure and cloud flow-log collector |
| aca37cd | 12 Nov 2026 | Live loop heartbeat, lab sensor run with real blocking |
| 712c9f2 | 12 Nov 2026 | Lab SOC and live dashboard |
