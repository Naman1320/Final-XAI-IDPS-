"""C4: the collector live against the emulated AWS and the lab SOC (docs/cloud-plan.md).

Unit level: how the compose service is wired, the billing guard's refusals, the SOC firewall rule
for the collector's address, the credentials provisioning, and a collector run against a stub S3
and a stub SOC that demands a client certificate. The last test needs the running lab (skipped
otherwise).
"""

from __future__ import annotations

import gzip
import http.server
import importlib.util
import io
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import tarfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("boto3")
from sklearn.dummy import DummyClassifier
from sklearn.preprocessing import LabelEncoder

from idps.cloud import __main__ as cloud_main
from idps.cloud.collector import (
    Collector,
    CollectorConfig,
    GuardRefused,
    SocClient,
    emulator_mode,
    load_cloud_bundle,
    make_guard_check,
    resolve_sensor_token,
)
from idps.cloud.flowlogs import (
    CLOUD_MODEL_FEATURES,
    cloud_extraction_meta,
    read_path,
    rows_to_frame,
    to_flow_rows,
)
from idps.config import Settings
from idps.detect import signing
from idps.detect.bundle import Bundle, save_bundle
from idps.respond.policy import ResponsePolicy
from soc.api import pki

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "lab" / "cloud" / "docker-compose.yml"
GUARD = ROOT / "lab" / "cloud" / "guard.py"
NETGUARD = ROOT / "lab" / "soc" / "netguard.sh"
SAMPLE = Path(__file__).parent / "data" / "flowlogs_sample.log"
BUCKET = "idps-fyp-flowlogs-000000000000"
PREFIX = "AWSLogs/000000000000/vpcflowlogs/eu-west-1/"
NOW = datetime(2023, 11, 14, 22, 30, tzinfo=UTC)

pytestmark = pytest.mark.skipif(not GUARD.exists(), reason="needs a repo checkout (lab/cloud)")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in [n for n in os.environ if n.startswith(("IDPS_", "AWS_"))]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


# --- compose wiring ------------------------------------------------------------------------------


def _compose_model() -> dict:
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")
    r = subprocess.run(  # noqa: PLW1510
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE),
            "--profile",
            "collector",
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "LAB_CLOUD_NACL_ID": "acl-0123456789abcdef0"},
    )
    if r.returncode != 0:
        pytest.skip(f"docker compose cannot read the file here: {r.stderr[:200]}")
    return json.loads(r.stdout)


@pytest.fixture(scope="module")
def model():
    return _compose_model()


def test_the_collector_service_is_locked_down(model):
    svc, net = model["services"]["collector"], model["services"]["collector-net"]
    assert svc["profiles"] == ["collector"] and net["profiles"] == ["collector"]
    assert svc["network_mode"] == "service:collector-net"  # no network of its own
    assert svc["cap_drop"] == ["ALL"] and not svc.get("cap_add")
    assert svc["read_only"] is True and svc["user"] == "65534:65534"
    assert svc["restart"] == "on-failure" and "healthcheck" in svc
    assert "no-new-privileges:true" in svc["security_opt"]
    assert int(svc["mem_limit"]) <= 512 * 1024 * 1024
    assert int(svc["memswap_limit"]) == int(svc["mem_limit"])  # no swap
    assert svc.get("command") == ["collect", "--interval", "60"]
    assert not svc.get("ports") and not net.get("ports")  # nothing published
    secrets = [v for v in svc["volumes"] if v["target"] == "/run/collector-secrets"]
    assert secrets and secrets[0]["read_only"] is True


def test_collector_net_has_two_legs_and_does_not_forward(model):
    net = model["services"]["collector-net"]
    legs = {name: cfg["ipv4_address"] for name, cfg in net["networks"].items()}
    assert legs == {"cloud_net": "10.10.4.30", "mgmt_net": "10.10.3.3"}
    assert str(net["sysctls"]["net.ipv4.ip_forward"]) == "0"
    assert net["cap_add"] == ["NET_ADMIN"] and net["cap_drop"] == ["ALL"]
    assert model["networks"]["mgmt_net"]["external"] is True
    assert model["networks"]["mgmt_net"]["name"] == "idps-lab_mgmt_net"
    # Only the collector joins the lab's management network; the exporter and the emulator do not.
    for name, svc in model["services"].items():
        if name != "collector-net":
            assert "mgmt_net" not in (svc.get("networks") or {})


def test_the_emulator_is_pinned_and_only_the_fake_account_is_used(model):
    env = model["services"]["collector"]["environment"]
    assert env["AWS_ENDPOINT_URL"] == "http://10.10.4.10:4566"
    assert (env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"]) == ("test", "test")
    assert env["AWS_CONFIG_FILE"] == env["AWS_SHARED_CREDENTIALS_FILE"] == "/dev/null"
    assert env["IDPS_CLOUD_EMULATOR"] == "true"
    assert env["IDPS_CLOUD_BUCKET"] == BUCKET and env["IDPS_CLOUD_PREFIX"] == PREFIX
    assert env["IDPS_SOC_URL"] == "https://10.10.3.10:8444"
    assert "IDPS_SOC_SENSOR_TOKEN" not in env  # the token is a file, not in `inspect`
    assert env["IDPS_SOC_SENSOR_TOKEN_FILE"].startswith("/run/collector-secrets/")
    assert env["IDPS_MODEL_PUBLIC_KEY"] and env["IDPS_CLOUD_MODEL"]


def test_the_environment_builds_a_working_config_and_a_safe_policy(model):
    env = {k: str(v) for k, v in model["services"]["collector"]["environment"].items()}
    cfg = CollectorConfig.from_env(env)
    cfg.validate()
    assert (cfg.nacl_id, cfg.soc_url, cfg.model_public_key) == (
        "acl-0123456789abcdef0",
        "https://10.10.3.10:8444",
        "/opt/idps/cloud-keys/model-signing.pub",
    )
    assert cfg.client_cert and cfg.client_key and cfg.soc_ca_file and cfg.settle_seconds == 30
    settings = Settings(
        **{
            k.removeprefix("IDPS_").lower(): v
            for k, v in env.items()
            if k
            in (
                "IDPS_DRY_RUN",
                "IDPS_ALLOWLIST",
                "IDPS_CONFIDENCE_THRESHOLD",
                "IDPS_BLOCK_TTL_SECONDS",
            )
        }
    )
    assert settings.dry_run is False  # deny entries are really created
    policy = ResponsePolicy.from_settings(settings)
    protected = [
        "10.10.1.1",
        "10.10.1.2",
        "10.10.2.10",
        "10.10.2.11",
        "10.10.3.2",
        "10.10.3.3",
        "10.10.3.10",
        "10.10.4.10",
        "10.10.4.20",
        "127.0.0.1",
        "224.0.0.1",
    ]
    for ip in protected:
        assert policy.is_protected(ipaddress.ip_address(ip)), ip
    # The attacker's private address is NOT refused: the code has no "private = protected" rule.
    assert not policy.is_protected(ipaddress.ip_address("10.10.1.10"))
    assert not policy.is_protected(ipaddress.ip_address("203.0.113.9"))


def test_empty_allowlist_with_real_blocking_is_refused():
    with pytest.raises(ValueError, match="allowlist"):
        Settings(dry_run=False, allowlist=[])


def test_the_nacl_id_is_required_for_real_blocking(monkeypatch, capsys):
    monkeypatch.setenv("IDPS_DRY_RUN", "false")
    monkeypatch.setenv("IDPS_ALLOWLIST", "10.10.2.0/24")
    monkeypatch.setenv("IDPS_CLOUD_BUCKET", BUCKET)
    monkeypatch.setenv("IDPS_CLOUD_PREFIX", PREFIX)
    assert cloud_main.main(["collect", "--once"]) == 2
    assert "IDPS_CLOUD_NACL_ID" in capsys.readouterr().err


def test_netguard_collector_allows_exactly_two_destinations():
    text = (ROOT / "lab" / "cloud" / "netguard_collector.sh").read_text()
    out = re.search(r"chain output \{(.*?)\n  \}", text, re.DOTALL).group(1)
    assert "policy drop" in out
    accepts = [ln.strip() for ln in out.splitlines() if "accept" in ln]
    assert accepts == [
        "oif lo accept",
        "ct state established,related accept",
        "ip daddr 10.10.4.10 tcp dport 4566 accept",
        "ip daddr 10.10.3.10 tcp dport 8444 accept",
    ]
    inp = re.search(r"chain input \{(.*?)\n  \}", text, re.DOTALL).group(1)
    assert "policy drop" in inp and "dport" not in inp  # replies only
    fwd = re.search(r"chain forward \{(.*?)\n  \}", text, re.DOTALL).group(1)
    assert "policy drop" in fwd and "accept" not in fwd
    assert "ip_forward" in text and "default route" in text


# --- the SOC's firewall rule for the collector ---------------------------------------------------


def test_the_collector_address_is_one_the_soc_firewall_accepts():
    sh = shutil.which("sh")
    cmd = f'NETGUARD_LIB=1; . "{NETGUARD}" || exit 9; sensor_addr_ok 10.10.3.3 && echo ALLOW'
    r = subprocess.run([sh, "-c", cmd], capture_output=True, text=True)  # noqa: PLW1510
    assert r.stdout.strip() == "ALLOW"
    compose = (ROOT / "lab" / "docker-compose.yml").read_text()
    assert "SOC_EXTRA_SENSOR_ADDRS: ${LAB_SOC_EXTRA_SENSOR_ADDRS:-}" in compose  # blank = unchanged
    assert "ip saddr 10.10.3.2 tcp dport 8444 accept" in NETGUARD.read_text()


# --- the billing guard ---------------------------------------------------------------------------

GOOD = {
    "AWS_ACCESS_KEY_ID": "test",
    "AWS_SECRET_ACCESS_KEY": "test",
    "AWS_CONFIG_FILE": "/dev/null",
    "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
    "AWS_ENDPOINT_URL": "http://10.10.4.10:4566",
}


def test_emulator_mode_is_on_for_any_endpoint_override():
    assert not emulator_mode({})
    assert emulator_mode({"AWS_ENDPOINT_URL": "http://10.10.4.10:4566"})
    assert emulator_mode({"AWS_ENDPOINT_URL": "https://s3.amazonaws.com"})  # then the guard refuses
    assert emulator_mode({"IDPS_CLOUD_EMULATOR": "true"})
    assert not emulator_mode({"IDPS_CLOUD_EMULATOR": "false"})


@pytest.mark.parametrize(
    "change",
    [
        {"AWS_ACCESS_KEY_ID": "AKIAABCDEFGHIJKLMNOP", "AWS_SECRET_ACCESS_KEY": "x"},
        {"AWS_ENDPOINT_URL": "https://s3.eu-west-1.amazonaws.com"},
        {"AWS_ENDPOINT_URL": ""},
        {"AWS_PROFILE": "prod"},
        {"AWS_SESSION_TOKEN": "t"},
        {"HTTPS_PROXY": "http://proxy:3128"},
        {"AWS_ENDPOINT_URL_S3": "https://s3.amazonaws.com"},
        {"AWS_CONFIG_FILE": "/root/.aws/config"},
    ],
)
def test_the_real_guard_refuses_unsafe_environments(change):
    env = {**GOOD, **change}
    found = make_guard_check(env)()  # loads lab/cloud/guard.py, the unchanged shared guard
    assert found, change


def test_a_collector_in_emulator_mode_refuses_before_any_client_is_made(
    monkeypatch, capsys, tmp_path
):
    for k, v in {
        **GOOD,
        "AWS_ENDPOINT_URL": "https://s3.amazonaws.com",
        "IDPS_CLOUD_BUCKET": BUCKET,
        "IDPS_CLOUD_PREFIX": PREFIX,
        "IDPS_CLOUD_STATE_DIR": str(tmp_path),
    }.items():
        monkeypatch.setenv(k, v)

    def boom(*a, **k):
        raise AssertionError("a boto3 client was made although the guard refused")

    monkeypatch.setattr("idps.cloud.collector.make_client", boom)
    assert cloud_main.main(["collect", "--once"]) == 1
    err = capsys.readouterr().err
    assert "billing guard: REFUSED" in err and "AWS_ENDPOINT_URL" in err


def test_the_guard_is_rechecked_and_a_refusal_ends_the_collector_for_good(tmp_path):
    answers = [[], [], ["AWS_PROFILE is set"]]
    clock = {"t": 0.0}
    cfg = CollectorConfig(bucket=BUCKET, prefix=PREFIX, state_dir=tmp_path)
    collector = Collector(cfg, s3=None, guard=lambda: answers.pop(0), monotonic=lambda: clock["t"])
    cycles = []
    collector.run_once = lambda: cycles.append(1)

    def sleep(seconds):
        clock["t"] += seconds

    with pytest.raises(GuardRefused, match="AWS_PROFILE"):
        collector.run_forever(60, sleep=sleep)
    assert len(cycles) >= 5 and not answers  # ran for 5+ minutes, then the second check refused


def test_a_guard_file_that_is_missing_fails_closed(monkeypatch):
    import idps.cloud.flowlog_export as fe

    monkeypatch.setattr(fe, "load_guard", lambda: (_ for _ in ()).throw(fe.ExportError("gone")))
    with pytest.raises(GuardRefused):
        make_guard_check({})


def test_the_guard_in_the_image_is_the_repos_file():
    dockerfile = (ROOT / "lab" / "cloud" / "Dockerfile.collector").read_text()
    assert "COPY lab/cloud/guard.py ./lab/cloud/guard.py" in dockerfile
    assert (
        "guard.py" in (ROOT / "lab" / "cloud" / "build_collector.sh").read_text()
    )  # compared by hash


# --- the signed model ----------------------------------------------------------------------------


def _model_file(tmp_path):
    X = rows_to_frame(to_flow_rows(read_path(SAMPLE)))[CLOUD_MODEL_FEATURES].astype(float)
    y = ["benign", "benign", "portscan", "portscan", "benign"]
    enc = LabelEncoder().fit(y)
    clf = DummyClassifier(strategy="prior").fit(X, enc.transform(y))
    bundle = Bundle("dummy", clf, enc, list(CLOUD_MODEL_FEATURES), cloud_extraction_meta(), {}, {})
    return save_bundle(bundle, tmp_path / "m.joblib")


def test_the_public_key_comes_from_the_environment():
    cfg = CollectorConfig.from_env({"IDPS_MODEL_PUBLIC_KEY": "/k/pub.pem"})
    assert cfg.model_public_key == "/k/pub.pem"
    assert CollectorConfig.from_env({}).model_public_key is None


def test_a_signed_model_loads_and_an_unsigned_or_tampered_one_is_refused(tmp_path):
    priv, pub = signing.generate_keypair(tmp_path / "k")
    path = _model_file(tmp_path)
    with pytest.raises(ValueError, match="signature|sig"):  # unsigned
        load_cloud_bundle(path, pub)
    signing.sign_bundle(path, signing.load_private_key(priv))
    assert load_cloud_bundle(path, pub).features == list(CLOUD_MODEL_FEATURES)
    _other_priv, other_pub = signing.generate_keypair(tmp_path / "other")
    with pytest.raises(ValueError):  # signed by another key
        load_cloud_bundle(path, other_pub)
    data = bytearray(path.read_bytes())
    data[-5] ^= 0xFF  # tampered after signing
    path.write_bytes(bytes(data))
    with pytest.raises(ValueError):
        load_cloud_bundle(path, pub)


def test_the_collector_command_refuses_an_unsigned_model_when_a_key_is_set(
    monkeypatch, capsys, tmp_path
):
    _priv, pub = signing.generate_keypair(tmp_path / "k")
    path = _model_file(tmp_path)
    for k, v in {
        "IDPS_CLOUD_BUCKET": BUCKET,
        "IDPS_CLOUD_PREFIX": PREFIX,
        "IDPS_CLOUD_MODEL": str(path),
        "IDPS_MODEL_PUBLIC_KEY": str(pub),
        "IDPS_CLOUD_STATE_DIR": str(tmp_path / "s"),
        "AWS_ACCESS_KEY_ID": "x",
        "AWS_SECRET_ACCESS_KEY": "x",
        "AWS_REGION": "eu-west-1",
    }.items():
        monkeypatch.setenv(k, v)
    assert cloud_main.main(["collect", "--once"]) == 1
    err = capsys.readouterr().err
    assert "refusing to load" in err and "is not signed" in err, err


def test_the_token_file_is_read_and_must_be_private(tmp_path):
    f = tmp_path / "token"
    f.write_text("idps_sensor_abc\n")
    f.chmod(0o644)
    cfg = CollectorConfig(bucket="b", sensor_token_file=str(f))
    with pytest.raises(ValueError, match="readable by others"):
        resolve_sensor_token(cfg)
    f.chmod(0o600)
    assert resolve_sensor_token(cfg) == "idps_sensor_abc"
    with pytest.raises(ValueError, match="not both"):
        resolve_sensor_token(
            CollectorConfig(bucket="b", sensor_token="x", sensor_token_file=str(f))
        )
    assert "idps_sensor_abc" not in repr(cfg)


# --- a collector run against a stub S3 and a stub SOC that demands a client certificate ----------


class FakeS3:
    def __init__(self, key, body):
        self.key, self.body = key, body

    def list_objects_v2(self, **params):
        if params["Prefix"].endswith("/2023/11/14/"):
            return {
                "Contents": [
                    {
                        "Key": self.key,
                        "LastModified": NOW - timedelta(minutes=10),
                        "Size": len(self.body),
                    }
                ]
            }
        return {}

    def get_object(self, Bucket, Key):
        from botocore.response import StreamingBody

        return {
            "Body": StreamingBody(io.BytesIO(self.body), len(self.body)),
            "ContentLength": len(self.body),
        }


class Bundle2:
    features = CLOUD_MODEL_FEATURES
    label_encoder = LabelEncoder().fit(["benign", "portscan"])
    anomaly = None

    def predict_proba(self, X):
        bad = X["rejected"].to_numpy() > 0
        return np.where(bad[:, None], [[0.03, 0.97]], [[0.95, 0.05]])


class MtlsSoc:
    """Stands in for the SOC's sensor port: TLS with a server certificate, client certificate required."""

    def __init__(self, tmp_path):
        self.seen: list[dict] = []
        ca_key, ca = pki.make_ca("test server CA")
        skey, scert = pki.issue_server_cert(ca_key, ca, "soc.lab", ["127.0.0.1"])
        cca_key, self.client_ca = pki.make_ca("test sensor CA")
        ckey, ccert = pki.issue_client_cert(cca_key, self.client_ca, "cloud")
        self.dir = tmp_path
        for name, data in {
            "server.pem": pki.cert_pem(scert),
            "server.key": pki.key_pem(skey),
            "server-ca.pem": pki.cert_pem(ca),
            "client.pem": pki.cert_pem(ccert),
            "client.key": pki.key_pem(ckey),
            "client-ca.pem": pki.cert_pem(self.client_ca),
        }.items():
            (tmp_path / name).write_bytes(data)
        # a certificate from a CA the SOC does not trust
        bad_key, bad_ca = pki.make_ca("rogue CA")
        k2, c2 = pki.issue_client_cert(bad_key, bad_ca, "cloud")
        (tmp_path / "rogue.pem").write_bytes(pki.cert_pem(c2))
        (tmp_path / "rogue.key").write_bytes(pki.key_pem(k2))
        seen = self.seen

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n))
                cn = dict(x[0] for x in self.connection.getpeercert()["subject"])["commonName"]
                seen.append(
                    {
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "cn": cn,
                        "alerts": body["alerts"],
                    }
                )
                payload = json.dumps({"accepted": len(body["alerts"])}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tmp_path / "server.pem", tmp_path / "server.key")
        ctx.load_verify_locations(cafile=str(tmp_path / "client-ca.pem"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"https://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def soc(tmp_path):
    s = MtlsSoc(tmp_path)
    yield s
    s.close()


def _client(soc, **kw):
    args = {
        "ca_file": str(soc.dir / "server-ca.pem"),
        "client_cert": str(soc.dir / "client.pem"),
        "client_key": str(soc.dir / "client.key"),
    }
    args.update(kw)
    return SocClient(soc.url, "idps_sensor_testtoken", **args)


def test_the_collector_sends_its_alerts_to_the_soc_as_sensor_cloud(soc, tmp_path):
    key = f"{PREFIX}2023/11/14/000000000000_vpcflowlogs_eu-west-1_fl-0abc_x.log.gz"
    s3 = FakeS3(key, gzip.compress(SAMPLE.read_bytes()))
    cfg = CollectorConfig(bucket=BUCKET, prefix=PREFIX, state_dir=tmp_path / "state")
    collector = Collector(cfg, s3, bundle=Bundle2(), post=_client(soc).post_alerts, now=lambda: NOW)
    result = collector.run_once()
    assert result.objects == 1 and result.alerts_sent == 2 and result.alerts_pending == 0
    assert [(s["path"], s["cn"], s["auth"]) for s in soc.seen] == [
        ("/ingest/alerts", "cloud", "Bearer idps_sensor_testtoken")
    ]
    assert {a["predicted_class"] for a in soc.seen[0]["alerts"]} == {"portscan"}
    assert collector.run_once().objects == 0  # processed once, not again


def test_the_soc_certificate_is_verified_and_a_wrong_client_certificate_gets_nothing_through(soc):
    from idps.cloud.collector import CollectorError

    with pytest.raises(CollectorError, match="cannot reach"):  # no client certificate
        _client(soc, client_cert=None, client_key=None, timeout=5).post_alerts([{}])
    with pytest.raises(CollectorError, match="cannot reach"):  # certificate of an untrusted CA
        _client(
            soc,
            client_cert=str(soc.dir / "rogue.pem"),
            client_key=str(soc.dir / "rogue.key"),
            timeout=5,
        ).post_alerts([{}])
    with pytest.raises(CollectorError, match="cannot reach"):  # the SOC's CA unknown: not trusted
        SocClient(
            soc.url,
            "idps_sensor_testtoken",
            client_cert=str(soc.dir / "client.pem"),
            client_key=str(soc.dir / "client.key"),
            timeout=5,
        ).post_alerts([{}])
    assert soc.seen == []


# --- provisioning the credentials ----------------------------------------------------------------


def _provision_module():
    spec = importlib.util.spec_from_file_location(
        "collector_provision", ROOT / "lab" / "cloud" / "collector_provision.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _soc_dirs(tmp_path, monkeypatch):
    data, shared = tmp_path / "data", tmp_path / "shared"
    data.mkdir(), shared.mkdir()
    _lab_key, lab_ca = pki.make_ca("IDPS lab sensor CA")
    (data / "sensor-ca.pem").write_bytes(pki.cert_pem(lab_ca))
    (shared / "ca.pem").write_text("server ca\n")
    monkeypatch.setenv("IDPS_SOC_DATABASE_URL", f"sqlite:///{tmp_path / 'soc.db'}")
    monkeypatch.setenv("IDPS_SOC_JWT_SECRET", "x" * 48)
    from soc.api import settings

    if hasattr(settings.get_settings, "cache_clear"):
        settings.get_settings.cache_clear()
    return data, shared, pki.cert_pem(lab_ca)


def _sha(token):
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()


def _untar(blob):
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        return {m.name: (tar.extractfile(m).read(), m.mode) for m in tar.getmembers()}


def test_provisioning_makes_a_token_and_a_certificate_and_keeps_them(tmp_path, monkeypatch, capfd):
    data, shared, lab_ca = _soc_dirs(tmp_path, monkeypatch)
    mod = _provision_module()
    first = _untar(mod.provision("cloud", None, False, data, shared))
    assert set(first) == {"sensor_token", "client.pem", "client.key", "soc-ca.pem"}
    assert first["sensor_token"][1] == 0o600 and first["client.key"][1] == 0o600
    token = first["sensor_token"][0].decode()
    assert token.startswith("idps_sensor_")
    bundle = (data / "sensor-ca.pem").read_bytes()
    assert len(mod.split_pem_certs(bundle)) == 2 and bundle.startswith(lab_ca)  # lab CA kept first
    err = capfd.readouterr().err
    assert token not in err and "PRIVATE KEY" not in err and "RESTART THE SOC" in err
    assert not list(data.rglob("*.key"))  # the CA key is gone
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(first["client.pem"][0])
    assert pki.common_name(cert) == "cloud"
    # the same SOC data + a volume that has everything: nothing is made again
    second = _untar(mod.provision("cloud", _sha(token), True, data, shared))
    assert (
        set(second) == {"soc-ca.pem"}
        and len(mod.split_pem_certs((data / "sensor-ca.pem").read_bytes())) == 2
    )
    # the volume lost the token: the old one is revoked, a new one made, the certificate kept
    third = _untar(mod.provision("cloud", None, True, data, shared))
    assert (
        set(third) == {"sensor_token", "soc-ca.pem"} and third["sensor_token"][0].decode() != token
    )
    # the lab CA file was rewritten by the SOC's own bootstrap: the cloud CA is added back
    (data / "sensor-ca.pem").write_bytes(lab_ca)
    fourth = _untar(
        mod.provision("cloud", _sha(third["sensor_token"][0].decode()), True, data, shared)
    )
    assert (
        set(fourth) == {"soc-ca.pem"}
        and len(mod.split_pem_certs((data / "sensor-ca.pem").read_bytes())) == 2
    )


def test_the_cloud_ca_is_replaced_not_stacked(tmp_path, monkeypatch):
    data, shared, _ = _soc_dirs(tmp_path, monkeypatch)
    mod = _provision_module()
    mod.provision("cloud", None, False, data, shared)
    mod.provision("cloud", None, False, data, shared)  # key lost: new certificate and CA
    assert len(mod.split_pem_certs((data / "sensor-ca.pem").read_bytes())) == 2


# --- live (needs the running lab, emulator and collector) ----------------------------------------


def _up(name):
    r = (
        subprocess.run(  # noqa: PLW1510
            ["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True
        )
        if shutil.which("docker")
        else None
    )
    return bool(r and r.stdout.strip() == "true")


@pytest.mark.skipif(
    not (
        shutil.which("docker")
        and all(_up(c) for c in ("idps-cloud-moto", "idps-collector", "idps-collector-net"))
    ),
    reason="needs the emulator and the collector running (lab/cloud/start_collector.sh)",
)
def test_live_the_collector_is_isolated_and_reaches_only_its_two_services():
    probe = (
        "import socket\n"
        "for h, p in [('10.10.4.10', 4566), ('10.10.3.10', 8444), ('10.10.3.10', 8443), ('10.10.3.2', 22),\n"
        "             ('10.10.2.10', 80), ('10.10.1.10', 22), ('1.1.1.1', 443)]:\n"
        "    try:\n        socket.create_connection((h, p), 3).close(); print(h, p, 'open')\n"
        "    except OSError: print(h, p, 'closed')\n"
    )
    r = subprocess.run(  # noqa: PLW1510
        ["docker", "exec", "-i", "idps-collector", "python", "-"],
        input=probe,
        capture_output=True,
        text=True,
    )
    got = {(a, int(b)): c for a, b, c in (ln.split() for ln in r.stdout.splitlines())}
    assert got[("10.10.4.10", 4566)] == "open" and got[("10.10.3.10", 8444)] == "open"
    assert [k for k, v in got.items() if v == "open"] == [
        ("10.10.4.10", 4566),
        ("10.10.3.10", 8444),
    ]


# --- review round: M1 (credential errors keep the alerts) --------------------------------------


def _collector_with_post(tmp_path, post, **cfg_kw):
    key = f"{PREFIX}2023/11/14/000000000000_vpcflowlogs_eu-west-1_fl-0abc_x.log.gz"
    s3 = FakeS3(key, gzip.compress(SAMPLE.read_bytes()))
    cfg = CollectorConfig(bucket=BUCKET, prefix=PREFIX, state_dir=tmp_path / "state", **cfg_kw)
    return Collector(cfg, s3, bundle=Bundle2(), post=post, now=lambda: NOW, sleep=lambda s: None)


@pytest.mark.parametrize("status", [401, 403, 404])
def test_a_credential_error_keeps_the_alerts_queued_and_marks_the_cycle(tmp_path, status, caplog):
    from idps.soc_client import SocRejectedError

    state = {"fail": True, "sent": []}

    def post(batch):
        if state["fail"]:
            raise SocRejectedError(f"SOC rejected the alerts: HTTP {status}", status)
        state["sent"].append(batch)
        return {}

    collector = _collector_with_post(tmp_path, post)
    result = collector.run_once()
    assert result.soc_config_error and result.alerts_sent == 0 and result.alerts_pending == 2
    assert result.batches_rejected == 0 and len(collector.outbox) == 2
    assert "SOC refused our credentials" in caplog.text
    state["fail"] = False  # token fixed: the queued alerts go out on the next cycle
    result = collector.run_once()
    assert not result.soc_config_error and result.alerts_sent == 2 and len(collector.outbox) == 0


def test_a_422_still_drops_the_batch(tmp_path):
    from idps.soc_client import SocRejectedError

    def post(batch):
        raise SocRejectedError("HTTP 422", 422)

    collector = _collector_with_post(tmp_path, post)
    result = collector.run_once()
    assert (
        result.batches_rejected == 1 and not result.soc_config_error and len(collector.outbox) == 0
    )


def test_the_alive_file_is_not_touched_while_the_soc_refuses_our_credentials(tmp_path):
    from idps.soc_client import SocRejectedError

    alive = tmp_path / "alive"
    mode = {"bad": True}

    def post(batch):
        if mode["bad"]:
            raise SocRejectedError("HTTP 401", 401)
        return {}

    collector = _collector_with_post(tmp_path, post, alive_file=alive)
    cycles = []

    def sleep(seconds):
        cycles.append(1)
        if len(cycles) == 2:
            mode["bad"] = False
        if len(cycles) == 3:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        collector.run_forever(60, sleep=sleep)
    # cycles 1 and 2 left the file alone; cycle 3 (token fixed) touched it
    assert alive.exists()
    # a collector whose credentials stay wrong never touches it
    alive2 = tmp_path / "alive2"

    def always_401(batch):
        raise SocRejectedError("HTTP 401", 401)

    bad = _collector_with_post(tmp_path / "second", always_401, alive_file=alive2)
    with pytest.raises(KeyboardInterrupt):
        bad.run_forever(60, sleep=lambda s: (_ for _ in ()).throw(KeyboardInterrupt))
    assert not alive2.exists()


# --- M3: chunked scoring and the per-object row cap ----------------------------------------------


class CountingBundle(Bundle2):
    sizes: list[int]

    def __init__(self):
        self.sizes = []

    def predict_proba(self, X):
        self.sizes.append(len(X))
        return np.tile([[0.95, 0.05]], (len(X), 1))


def _big_record_object(n):
    lines = []
    for i in range(n):
        src = f"198.51.{(i // 250) % 250}.{i % 250 + 1}"
        lines.append(
            f"2 000000000000 eni-0abc {src} 10.10.2.10 {40000 + i % 20000} 80 6 3 180 1700000000 1700000050 ACCEPT OK"
        )
    header = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
    return gzip.compress((header + "\n" + "\n".join(lines) + "\n").encode())


def test_rows_are_scored_in_chunks_of_2000(tmp_path):
    from idps.cloud.collector import SCORE_CHUNK_ROWS

    key = f"{PREFIX}2023/11/14/000000000000_vpcflowlogs_eu-west-1_fl-0abc_big.log.gz"
    s3 = FakeS3(key, _big_record_object(5000))
    bundle = CountingBundle()
    cfg = CollectorConfig(bucket=BUCKET, prefix=PREFIX, state_dir=tmp_path / "state")
    result = Collector(cfg, s3, bundle=bundle, now=lambda: NOW).run_once()
    assert SCORE_CHUNK_ROWS == 2000
    assert result.rows == 5000 and bundle.sizes == [2000, 2000, 1000] and result.rows_skipped == 0


def test_the_row_cap_skips_the_excess_counts_it_and_the_object_is_done(tmp_path, caplog):
    key = f"{PREFIX}2023/11/14/000000000000_vpcflowlogs_eu-west-1_fl-0abc_big.log.gz"
    s3 = FakeS3(key, _big_record_object(5000))
    bundle = CountingBundle()
    cfg = CollectorConfig(
        bucket=BUCKET, prefix=PREFIX, state_dir=tmp_path / "state", max_rows_per_object=3000
    )
    collector = Collector(cfg, s3, bundle=bundle, now=lambda: NOW)
    result = collector.run_once()
    assert sum(bundle.sizes) == 3000 and result.rows_skipped == 2000 and result.objects == 1
    assert '"event": "rows_skipped"' in caplog.text and '"skipped": 2000' in caplog.text
    assert collector.run_once().objects == 0  # checkpoint moved: it is not read again, no loop


def test_the_cap_can_be_turned_off_and_a_bad_value_is_refused():
    assert CollectorConfig.from_env({"IDPS_CLOUD_MAX_ROWS": "0"}).max_rows_per_object == 0
    assert CollectorConfig.from_env({}).max_rows_per_object == 20000
    with pytest.raises(ValueError):
        CollectorConfig(bucket="b", prefix=PREFIX, max_rows_per_object=-1).validate()


def test_a_dead_namespace_ends_the_collector(tmp_path, monkeypatch):
    from idps.cloud import collector as col

    cfg = CollectorConfig(bucket=BUCKET, prefix=PREFIX, state_dir=tmp_path, require_network=True)
    collector = Collector(cfg, s3=None)
    monkeypatch.setattr(col, "network_interfaces", lambda: {"lo"})
    with pytest.raises(col.NetworkLost):
        collector.run_forever(60, sleep=lambda s: None)
    monkeypatch.setattr(col, "network_interfaces", lambda: {"lo", "eth0", "eth1"})
    collector.run_once = lambda: (_ for _ in ()).throw(KeyboardInterrupt)
    with pytest.raises(KeyboardInterrupt):  # with its interfaces it carries on
        collector.run_forever(60, sleep=lambda s: None)


def test_compose_sets_the_new_limits(model):
    svc = model["services"]["collector"]
    assert int(svc["mem_limit"]) == int(svc["memswap_limit"]) == 512 * 1024 * 1024
    assert svc["environment"]["IDPS_CLOUD_REQUIRE_NETWORK"] == "true"
    assert svc["environment"]["IDPS_CLOUD_MAX_ROWS"] == "20000"
    dockerfile = (ROOT / "lab" / "cloud" / "Dockerfile.collector").read_text()
    assert "OMP_NUM_THREADS=1" in dockerfile and "MALLOC_ARENA_MAX=2" in dockerfile


# --- M2: the token is the last step, and a lost token is replaced ---------------------------------


def _cloud_tokens(tmp_path):
    import sqlite3

    con = sqlite3.connect(tmp_path / "soc.db")
    try:
        return con.execute(
            "select name, revoked, token_hash from sensor_tokens order by id"
        ).fetchall()
    except sqlite3.OperationalError:  # no database yet: nothing was made
        return []
    finally:
        con.close()


def test_a_failure_before_the_token_step_changes_nothing_at_the_soc(tmp_path, monkeypatch):
    data, shared, _ = _soc_dirs(tmp_path, monkeypatch)
    mod = _provision_module()
    (data / "sensor-ca.pem").unlink()  # the CA step cannot work
    with pytest.raises(OSError):
        mod.provision("cloud", None, False, data, shared)
    assert _cloud_tokens(tmp_path) == []  # no token made, none revoked
    (data / "sensor-ca.pem").write_bytes(pki.cert_pem(pki.make_ca("IDPS lab sensor CA")[1]))
    blob = _untar(mod.provision("cloud", None, False, data, shared))  # the re-run works
    assert "sensor_token" in blob and len(_cloud_tokens(tmp_path)) == 1


def test_a_token_that_never_reached_the_volume_is_replaced_on_the_next_run(tmp_path, monkeypatch):
    data, shared, _ = _soc_dirs(tmp_path, monkeypatch)
    mod = _provision_module()
    first = _untar(mod.provision("cloud", None, False, data, shared))
    lost = first["sensor_token"][0].decode()
    # the pipe to the volume failed: the volume still holds an OLD token (or none)
    again = _untar(mod.provision("cloud", _sha("idps_sensor_oldtoken"), True, data, shared))
    assert "sensor_token" in again and again["sensor_token"][0].decode() != lost
    rows = _cloud_tokens(tmp_path)
    assert [(n.split("-revoked")[0], r) for n, r, _ in rows] == [("cloud", 1), ("cloud", 0)]
    # a matching token is kept; --force-token replaces it anyway
    kept = _untar(
        mod.provision("cloud", _sha(again["sensor_token"][0].decode()), True, data, shared)
    )
    assert "sensor_token" not in kept
    forced = _untar(
        mod.provision("cloud", _sha(again["sensor_token"][0].decode()), True, data, shared, True)
    )
    assert "sensor_token" in forced


def test_nothing_secret_is_printed_by_the_provisioning(tmp_path, monkeypatch, capfd):
    data, shared, _ = _soc_dirs(tmp_path, monkeypatch)
    mod = _provision_module()
    blob = _untar(mod.provision("cloud", None, False, data, shared))
    out = capfd.readouterr()
    for secret in (blob["sensor_token"][0].decode(), "PRIVATE KEY"):
        assert secret not in out.out + out.err


# --- L1: start_collector.sh's check of the SOC's CA file ------------------------------------------


def test_the_check_notices_a_ca_file_that_lost_the_cloud_ca(tmp_path, monkeypatch, capsys):
    data, shared, lab_ca = _soc_dirs(tmp_path, monkeypatch)
    mod = _provision_module()
    mod.provision("cloud", None, False, data, shared)
    monkeypatch.setattr(mod, "process_started_at", lambda: None)
    assert mod.check("cloud", data) == 0
    out = capsys.readouterr().out
    assert "cloud_ca=trusted" in out and "client_cert_days_left=36" in out and "PRIVATE" not in out
    (data / "sensor-ca.pem").write_bytes(lab_ca)  # what the SOC's bootstrap does on re-issue
    assert mod.check("cloud", data) == 3
    assert "missing_from_soc_ca_file" in capsys.readouterr().out
    mod.provision("cloud", _sha("x"), True, data, shared)  # adds it back
    assert mod.check("cloud", data) == 0
    # added after the SOC started: a restart is needed
    monkeypatch.setattr(mod, "process_started_at", lambda: 1.0)
    assert mod.check("cloud", data) == 4
    monkeypatch.setattr(mod, "process_started_at", lambda: 4e9)
    assert mod.check("cloud", data) == 0


def test_the_check_without_any_provisioning_asks_for_it(tmp_path, monkeypatch):
    data, _, _ = _soc_dirs(tmp_path, monkeypatch)
    assert _provision_module().check("cloud", data) == 3


def test_start_collector_runs_the_check_and_the_expiry_warning():
    text = (ROOT / "lab" / "cloud" / "start_collector.sh").read_text()
    assert "--check" in text and "docker restart idps-soc" in text and "days_left" in text
    sh = (ROOT / "lab" / "cloud" / "collector_provision.sh").read_text()
    assert "trap 'rm -rf \"$archive\"' EXIT" in sh and "umask 077" in sh and "sha256sum" in sh
    iso = (ROOT / "lab" / "check_isolation.sh").read_text()
    assert "idps-collector-net" in iso and "ip_forward" in iso and "10.10.3.3" in iso
