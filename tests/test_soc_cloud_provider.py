"""The provider seam: the emulator guard, the read-only emulated provider (against FAKE boto3
clients: not run against a real Moto here), and how the API behaves with each."""

from datetime import UTC, datetime

import pytest
from conftest import ADMIN_PW, login
from fastapi.testclient import TestClient

from soc.api import auth
from soc.api.cloud import guard
from soc.api.cloud.provider import (
    EmulatedAwsProvider,
    MockProvider,
    ProviderUnavailable,
)
from soc.api.main import create_app
from soc.api.models import Role

GOOD = ["http://127.0.0.1:4566", "http://localhost:4566", "http://10.10.4.10:4566",
        "http://[::1]:4566", "http://192.168.1.5:4566", "http://172.16.0.9:5000",
        "http://127.0.0.1", "http://[::ffff:10.0.0.5]:4566", "http://[fd00::5]:4566"]
BAD = ["https://127.0.0.1:4566", "http://example.com:4566", "http://moto:4566",
       "http://169.254.169.254/latest", "http://8.8.8.8:4566", "http://1.1.1.1",
       "http://user:pw@127.0.0.1:4566", "http://0.0.0.0:4566", "", "file:///etc/passwd",
       "http://127.0.0.1:99999", "http://127.0.0.1.evil.com:4566", "http://localhost.evil.com",
       "127.0.0.1:4566", "http://[2001:4860:4860::8888]:4566", "http://224.0.0.1:4566",
       "http://[::ffff:8.8.8.8]:4566", "http://[::ffff:169.254.169.254]", "http://[fe80::1]:4566",
       "http://127.0.0.1:4566\n", "ftp://127.0.0.1", "http://", "http://%31%32%37.0.0.1"]


@pytest.mark.parametrize("url", GOOD)
def test_guard_accepts_local_emulator_urls(url):
    assert guard.check_endpoint(url, env={}) == url


@pytest.mark.parametrize("url", BAD)
def test_guard_refuses_everything_that_is_not_a_local_emulator(url):
    with pytest.raises(guard.EndpointRefused):
        guard.check_endpoint(url, env={})


def test_guard_refuses_while_a_proxy_is_configured_and_never_echoes_credentials():
    with pytest.raises(guard.EndpointRefused):
        guard.check_endpoint("http://127.0.0.1:4566", env={"HTTPS_PROXY": "http://proxy:3128"})
    with pytest.raises(guard.EndpointRefused) as exc:
        guard.check_endpoint("http://admin:s3cret@127.0.0.1:4566", env={})
    assert "s3cret" not in str(exc.value)


def test_from_endpoint_refuses_a_real_endpoint_before_building_any_client(monkeypatch):
    import boto3

    def boom(*a, **k):
        raise AssertionError("a boto3 session was built for a refused endpoint")

    monkeypatch.setattr(boto3.session, "Session", boom)
    for url in ("https://ec2.eu-west-1.amazonaws.com", "http://ec2.amazonaws.com",
                "http://52.95.1.1:4566"):
        with pytest.raises(ProviderUnavailable):
            EmulatedAwsProvider.from_endpoint(url)


def test_from_endpoint_uses_only_the_fake_credentials_and_the_given_endpoint(monkeypatch):
    import boto3

    seen = []

    class FakeSession:
        def __init__(self, **kw):
            seen.append(("session", kw))

        def client(self, name, **kw):
            seen.append((name, kw))
            return object()

    monkeypatch.setattr(boto3.session, "Session", FakeSession)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAREALREALREALREAL")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "realsecret")
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    monkeypatch.delenv("all_proxy", raising=False)
    EmulatedAwsProvider.from_endpoint("http://127.0.0.1:4566")
    assert seen[0] == ("session", {"aws_access_key_id": "test", "aws_secret_access_key": "test",
                                   "region_name": "eu-west-1"})
    assert [n for n, _ in seen[1:]] == ["ec2", "s3", "sts"]
    assert all(kw["endpoint_url"] == "http://127.0.0.1:4566" for _, kw in seen[1:])
    assert "AKIA" not in repr(seen)


# --- fake boto3 clients -----------------------------------------------------------------------------

LAUNCH = datetime(2026, 3, 1, 8, 0, tzinfo=UTC)


class FakeSts:
    def __init__(self, account="000000000000"):
        self.account = account

    def get_caller_identity(self):
        return {"Account": self.account}


class FakeEc2:
    def describe_instances(self, **kw):
        return {"Reservations": [{"Groups": [], "Instances": [
            {"InstanceId": "i-0abc", "InstanceType": "t3.micro", "LaunchTime": LAUNCH,
             "State": {"Name": "running"}, "Placement": {"AvailabilityZone": "eu-west-1a"},
             "VpcId": "vpc-1", "SubnetId": "subnet-1", "PrivateIpAddress": "10.0.0.5",
             "PublicIpAddress": "203.0.113.9", "PlatformDetails": "Linux/UNIX",
             "Tags": [{"Key": "Name", "Value": "emu-web"}, {"Key": "env", "Value": "test"}],
             "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web"}]},
            {"InstanceId": "i-0def", "InstanceType": "m5.large", "LaunchTime": LAUNCH,
             "State": {"Name": "stopping"}, "Placement": {"AvailabilityZone": "eu-west-1b"},
             "VpcId": "vpc-1", "SubnetId": "subnet-2", "PrivateIpAddress": "10.0.1.5",
             "SecurityGroups": [{"GroupId": "sg-1"}]}]}]}

    def describe_volumes(self, **kw):
        return {"Volumes": [{"VolumeId": "vol-1", "Size": 8, "VolumeType": "gp3",
                             "State": "in-use", "Encrypted": True,
                             "Attachments": [{"InstanceId": "i-0abc"}]}]}

    def describe_vpcs(self, **kw):
        return {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]}

    def describe_subnets(self, **kw):
        return {"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.0.0/24",
                             "AvailabilityZone": "eu-west-1a", "MapPublicIpOnLaunch": True}]}

    def describe_security_groups(self, **kw):
        return {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web", "Description": "d",
                                    "VpcId": "vpc-1",
                                    "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22,
                                                       "ToPort": 22,
                                                       "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                                    "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [
                                        {"CidrIp": "0.0.0.0/0"}]}]}]}


class NotConfigured(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def list_buckets(self):
        return {"Buckets": [{"Name": "emu-bucket", "CreationDate": LAUNCH}]}

    def get_bucket_versioning(self, Bucket):
        return {"Status": "Enabled"}

    def get_bucket_encryption(self, Bucket):
        raise NotConfigured("ServerSideEncryptionConfigurationNotFoundError")

    def get_public_access_block(self, Bucket):
        raise NotConfigured("NoSuchPublicAccessBlockConfiguration")

    def list_objects_v2(self, Bucket, MaxKeys):
        return {"KeyCount": 2, "Contents": [{"Size": 1024}, {"Size": 2048}]}


def fake_provider(sts=None):
    return EmulatedAwsProvider(FakeEc2(), FakeS3(), sts or FakeSts())


def test_emulated_provider_maps_the_inventory():
    p = fake_provider()
    assert (p.data_source, p.writable, p.cost_available) == ("emulated-aws", False, False)
    a, b = p.list_instances()
    assert a["name"] == "emu-web" and a["state"] == "running" and a["vcpus"] == 2
    assert a["tags"] == {"Name": "emu-web", "env": "test"} and a["disk_gb"] == 8
    assert a["security_group_ids"] == ["sg-1"] and a["run_start"] == LAUNCH
    assert b["state"] == "stopped" and b["run_start"] is None and b["name"] == "i-0def"
    (v,) = p.list_volumes()
    assert v["instance_id"] == "i-0abc" and v["state"] == "in-use" and v["encrypted"] is True
    (bucket,) = p.list_buckets()
    assert bucket["versioning"] is True and bucket["encrypted"] is False
    assert bucket["public_access_blocked"] is False and bucket["object_count"] == 2
    (vpc,) = p.list_vpcs()
    assert vpc["cidr"] == "10.0.0.0/16" and p.list_subnets()[0]["public"] is True
    (sg,) = p.list_security_groups()
    assert sg["instances_using"] == 2
    assert [(r["direction"], r["protocol"], r["port_from"]) for r in sg["rules"]] == [
        ("in", "tcp", 22), ("out", "all", 0)]
    assert p.cost_daily("2026-01-01", "2026-03-01") == []


def test_emulated_provider_refuses_a_non_emulator_account():
    with pytest.raises(ProviderUnavailable, match="not the emulator account"):
        fake_provider(FakeSts("123456789012")).list_vpcs()


def test_emulated_provider_reports_a_dead_emulator_without_details():
    class Dead(FakeSts):
        def get_caller_identity(self):
            raise ConnectionError("http://127.0.0.1:4566 refused with secret-token")

    with pytest.raises(ProviderUnavailable) as exc:
        fake_provider(Dead()).list_instances()
    assert "secret-token" not in str(exc.value) and "ConnectionError" in str(exc.value)


def test_the_provider_classes_share_one_interface():
    import inspect

    from soc.api.cloud.provider import CloudProvider

    names = {n for n, f in inspect.getmembers(CloudProvider, inspect.isfunction)
             if not n.startswith("_")}
    for cls in (MockProvider, EmulatedAwsProvider):
        assert names <= {n for n, _ in inspect.getmembers(cls, inspect.isfunction)}
        assert not inspect.isabstract(cls)


# --- the API with each provider -----------------------------------------------------------------------

def make_app(soc_settings, **over):
    app = create_app(soc_settings.model_copy(update=over))
    app.state.assistant_llm = None
    with app.state.session_factory() as db:
        auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
    client = TestClient(app)
    return app, client, login(client, "admin", ADMIN_PW)


def test_the_default_provider_is_the_mock(client, admin_headers):
    r = client.get("/cloud/overview", headers=admin_headers).json()
    assert r["data_source"] == "mock" and "no live cloud" in r["data_source_label"]


def test_the_emulated_provider_is_read_only_and_labelled(soc_settings):
    app, client, h = make_app(soc_settings, cloud_endpoint_url="http://127.0.0.1:4566")
    app.state.cloud_emulated = fake_provider()
    r = client.get("/cloud/instances", headers=h)
    assert r.status_code == 200 and r.json()["data_source"] == "emulated-aws"
    assert "Emulated AWS" in r.json()["data_source_label"] and r.json()["total"] == 2
    assert {i["name"] for i in r.json()["items"]} == {"emu-web", "i-0def"}
    emu = next(i for i in r.json()["items"] if i["name"] == "emu-web")
    assert emu["metrics_source"] == "mock"  # metrics are still synthetic, and say so
    assert client.get(f"/cloud/instances/{emu['id']}/metrics", headers=h).json()[
        "metrics_source"] == "mock"
    for path in ("overview", "volumes", "buckets", "network/vpcs", "network/subnets",
                 "network/security-groups", "metrics/summary", "cost"):
        r = client.get(f"/cloud/{path}", headers=h)
        assert r.status_code == 200 and r.json()["data_source"] == "emulated-aws", path
    assert client.get("/cloud/cost", headers=h).json()["available"] is False
    # every change is refused, and nothing is written to the mock tables
    for method, path, body in (
            ("POST", "/cloud/instances", {"name": "x", "instance_type": "t3.micro",
                                          "subnet_id": "s", "security_group_ids": ["g"]}),
            ("POST", "/cloud/instances/i-0abc/stop", None),
            ("DELETE", "/cloud/instances/i-0abc", None),
            ("POST", "/cloud/volumes", {"name": "v", "size_gb": 5}),
            ("POST", "/cloud/buckets", {"name": "bbb"}),
            ("POST", "/cloud/network/security-groups", {"name": "abc", "vpc_id": "vpc-1"}),
            ("POST", "/cloud/demo-data/reset", None)):
        r = client.request(method, path, json=body, headers=h)
        assert r.status_code == 409 and "read-only" in r.json()["detail"], path
    from soc.api.models import CloudInstance

    with app.state.session_factory() as db:
        assert db.query(CloudInstance).count() == 0  # never seeded: the mock was not used


def test_emulator_does_not_evaluate_or_publish_mock_alerts(soc_settings):
    app, client, h = make_app(soc_settings, cloud_endpoint_url="http://127.0.0.1:4566")
    app.state.cloud_emulated = fake_provider()
    assert client.post("/cloud/alerts/evaluate", headers=h).status_code == 409
    assert client.get("/cloud/alerts", headers=h).json()["items"] == []
    assert client.get("/cloud/notifications", headers=h).json()["total"] == 0


@pytest.mark.parametrize("url", ["https://ec2.eu-west-1.amazonaws.com", "http://8.8.8.8:4566",
                                 "http://moto.internal:4566"])
def test_a_non_local_endpoint_is_refused_with_503_and_nothing_is_contacted(soc_settings,
                                                                            monkeypatch, url):
    import boto3

    def boom(*a, **k):
        raise AssertionError("boto3 was used for a refused endpoint")

    monkeypatch.setattr(boto3.session, "Session", boom)
    _app, client, h = make_app(soc_settings, cloud_endpoint_url=url)
    for path in ("/cloud/overview", "/cloud/instances", "/cloud/activity"):
        r = client.get(path, headers=h)
        assert r.status_code == 503 and "refused" in r.json()["detail"], path
        assert url not in r.text
    assert client.post("/cloud/buckets", json={"name": "bbb"}, headers=h).status_code == 503
    # the rest of the SOC is unaffected
    assert client.get("/health").status_code == 200


def test_a_blank_endpoint_setting_means_the_mock(monkeypatch):
    from conftest import TEST_SECRET

    from soc.api.settings import SocSettings

    monkeypatch.setenv("IDPS_SOC_CLOUD_ENDPOINT_URL", "")
    assert SocSettings(jwt_secret=TEST_SECRET).cloud_endpoint_url is None
    monkeypatch.setenv("IDPS_SOC_CLOUD_ENDPOINT_URL", "http://127.0.0.1:4566")
    assert SocSettings(jwt_secret=TEST_SECRET).cloud_endpoint_url == "http://127.0.0.1:4566"
