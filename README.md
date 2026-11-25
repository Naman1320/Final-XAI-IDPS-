# IDPS final year project

A network Intrusion Detection and Prevention System that detects attacks in network flows with
ML (XGBoost plus an anomaly detector), explains each alert with SHAP and LIME, blocks malicious
IPs through nftables with safety rules (allowlist, TTL, dry-run), and exposes everything to a SOC
dashboard. It is developed and tested only inside an isolated Docker lab.

## Setup

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Optional flow extractors (can be hard to install on macOS): `pip install -e ".[capture]"`.

A [double-clickable macOS dashboard](soc/web/README.md#macos-application) is available for the development and lab SOC workspaces.

## Docs

- Install and run it (Docker Compose, `deploy/install.sh`): [docs/deploy.md](docs/deploy.md)
- Project plan: [docs/PLAN.md](docs/PLAN.md)
- Lab network and attack scripts: [lab/README.md](lab/README.md)

The [C6 classroom demonstration guide](docs/c6.md) covers the dashboard, recorded-capture replay, live observation and ACL evidence.
