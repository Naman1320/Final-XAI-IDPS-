"""NaclBlocker against botocore's Stubber: no network, no AWS, no credentials."""

import json
from unittest.mock import MagicMock

import pytest

pytest.importorskip("boto3")
import boto3
from botocore.stub import Stubber

from idps.cloud.nacl import LIMIT_BACKOFF, RESERVED_MAX, CapReached, NaclBlocker
from idps.config import Settings
from idps.respond.engine import ResponseEngine
from idps.respond.nft import BlockerError
from idps.respond.policy import Action, Detection, ResponsePolicy

ACL = "acl-0123456789abcdef0"
T0 = 1_000_000.0


@pytest.fixture(autouse=True)
def _no_ambient_aws(monkeypatch):
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    for name in [n for n in __import__("os").environ if n.startswith("IDPS_")]:
        monkeypatch.delenv(name)


@pytest.fixture
def ec2():
    client = boto3.client("ec2", region_name="eu-west-1",
                          aws_access_key_id="AKIAFAKEFAKEFAKEFAKE", aws_secret_access_key="fake")
    with Stubber(client) as stubber:
        client.stubber = stubber
        yield client
        stubber.assert_no_pending_responses()


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def entry(number, egress=False, cidr=None, action="allow", proto="-1", v6=None):
    e = {"RuleNumber": number, "Protocol": proto, "RuleAction": action, "Egress": egress}
    if v6:
        e["Ipv6CidrBlock"] = v6
    else:
        e["CidrBlock"] = cidr or "0.0.0.0/0"
    return e


def deny(number, ip, egress=False):
    return entry(number, egress, cidr=f"{ip}/32", action="deny")


def stub_describe(ec2, *entries):
    # Every real NACL ends with the default deny at 32767; it must be ignored.
    all_entries = [*entries, entry(32767, False, action="deny"), entry(32767, True, action="deny")]
    ec2.stubber.add_response("describe_network_acls",
                             {"NetworkAcls": [{"NetworkAclId": ACL, "Entries": all_entries}]},
                             {"NetworkAclIds": [ACL]})


def params(number, ip, egress, action="deny", v6=False):
    p = {"NetworkAclId": ACL, "RuleNumber": number, "Protocol": "-1", "RuleAction": action,
         "Egress": egress}
    p["Ipv6CidrBlock" if v6 else "CidrBlock"] = f"{ip}/{128 if v6 else 32}"
    return p


def stub_create(ec2, number, ip, egress, **kw):
    ec2.stubber.add_response("create_network_acl_entry", {}, params(number, ip, egress, **kw))


def stub_replace(ec2, number, ip, egress, **kw):
    ec2.stubber.add_response("replace_network_acl_entry", {}, params(number, ip, egress, **kw))


def stub_delete(ec2, number, egress):
    ec2.stubber.add_response("delete_network_acl_entry", {},
                             {"NetworkAclId": ACL, "RuleNumber": number, "Egress": egress})


def make(ec2, tmp_path, *, dry_run=False, clock=None, max_denies=10, allowlist=("10.60.0.0/16",),
         ttl=900):
    policy = ResponsePolicy(list(map(__import__("ipaddress").ip_network, allowlist)),
                            ttl_seconds=ttl, min_flows=1)
    return NaclBlocker(ec2, ACL, policy, tmp_path / "state.json", dry_run=dry_run,
                       max_denies=max_denies, now=clock or Clock())


def state(tmp_path):
    return json.loads((tmp_path / "state.json").read_text())


# --- Dry run ----------------------------------------------------------------------------------

def test_dry_run_is_the_default_and_makes_no_api_calls(tmp_path):
    client = MagicMock()
    policy = ResponsePolicy([], min_flows=1)
    blocker = NaclBlocker(client, ACL, policy, tmp_path / "state.json")
    assert blocker.dry_run is True
    blocker.ensure_ruleset()
    blocker.block("198.51.100.7", 60)
    blocker.unblock("198.51.100.7")
    blocker.reconcile()
    assert blocker.expire() == []
    assert client.method_calls == []
    assert not (tmp_path / "state.json").exists()


def test_dry_run_still_refuses_protected_addresses(tmp_path):
    blocker = make(None, tmp_path, dry_run=True)
    with pytest.raises(BlockerError):
        blocker.block("10.60.1.10", 60)


def test_real_blocking_needs_a_client(tmp_path):
    with pytest.raises(ValueError):
        make(None, tmp_path, dry_run=False)


def test_bad_arguments(tmp_path, ec2):
    policy = ResponsePolicy([])
    with pytest.raises(ValueError):
        NaclBlocker(ec2, "vpc-123", policy, tmp_path / "s.json")
    for cap in (0, 11, RESERVED_MAX + 1):
        with pytest.raises(ValueError):
            NaclBlocker(ec2, ACL, policy, tmp_path / "s.json", max_denies=cap)


# --- Allowlist and special addresses ----------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "10.60.1.10",            # allowlisted network
    "::ffff:10.60.1.10",     # IPv4-mapped IPv6 must not dodge the allowlist
    "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.169.254", "255.255.255.255", "::1", "fe80::1",
    "not-an-ip", "",
])
def test_protected_and_invalid_addresses_are_refused_without_api_calls(ec2, tmp_path, ip):
    blocker = make(ec2, tmp_path)
    with pytest.raises(BlockerError):
        blocker.block(ip, 60)  # the stubber has no responses queued: any API call would fail
    assert not (tmp_path / "state.json").exists()


def test_ttl_must_be_positive(ec2, tmp_path):
    with pytest.raises(BlockerError):
        make(ec2, tmp_path).block("198.51.100.7", 0)


# --- Rule number allocation and range ---------------------------------------------------------

def test_allocation_uses_lowest_free_numbers_in_1_to_90(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    stub_describe(ec2, entry(100, False), entry(100, True), entry(1, False))  # 1 ingress is taken
    stub_create(ec2, 2, "198.51.100.7", False)
    stub_create(ec2, 1, "198.51.100.7", True)
    stub_create(ec2, 3, "198.51.100.8", False)
    stub_create(ec2, 2, "198.51.100.8", True)
    blocker.block("198.51.100.7", 60)
    blocker.block("198.51.100.8", 60)
    saved = state(tmp_path)["blocks"]
    assert saved["198.51.100.7"]["ingress"] == 2 and saved["198.51.100.7"]["egress"] == 1
    assert saved["198.51.100.8"]["ingress"] == 3 and saved["198.51.100.8"]["egress"] == 2


def test_ipv6_uses_a_128_entry(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    stub_describe(ec2)
    stub_create(ec2, 1, "2001:db8::bad", False, v6=True)
    stub_create(ec2, 1, "2001:db8::bad", True, v6=True)
    blocker.block("2001:DB8::BAD", 60)


def test_exhausted_range_raises_and_never_goes_past_90(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    stub_describe(ec2, *[entry(n, False) for n in range(1, RESERVED_MAX + 1)])
    with pytest.raises(BlockerError, match="no free ingress rule number"):
        blocker.block("198.51.100.7", 60)  # no create call is queued: none may be made
    assert state(tmp_path)["blocks"] == {}


def test_entries_at_91_and_above_are_ignored_and_never_touched(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    # A deny /32 at 150 is Terraform's business (or someone's), not ours: not adopted, not deleted.
    stub_describe(ec2, deny(150, "198.51.100.99"), entry(100, False), deny(91, "198.51.100.98"))
    blocker.ensure_ruleset()
    assert blocker.active() == {}


def test_reconcile_leaves_foreign_entries_in_range_alone(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    # Rule 5 is an allow and rule 6 a port-restricted deny: neither is ours, both stay.
    stub_describe(ec2, entry(5, False), entry(6, False, cidr="198.51.100.5/32", action="deny",
                                               proto="6"))
    blocker.ensure_ruleset()
    assert blocker.active() == {}
    stub_create(ec2, 1, "198.51.100.7", False)
    stub_create(ec2, 1, "198.51.100.7", True)
    blocker.block("198.51.100.7", 60)


def test_number_taken_by_someone_else_is_refreshed_and_retried(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    stub_describe(ec2)
    ec2.stubber.add_client_error("create_network_acl_entry",
                                 service_error_code="NetworkAclEntryAlreadyExists",
                                 expected_params=params(1, "198.51.100.7", False))
    stub_describe(ec2, entry(1, False))
    stub_create(ec2, 2, "198.51.100.7", False)
    stub_create(ec2, 1, "198.51.100.7", True)
    blocker.block("198.51.100.7", 60)


def test_api_error_becomes_blockererror_and_leaves_no_state(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    stub_describe(ec2)
    ec2.stubber.add_client_error("create_network_acl_entry", service_error_code="UnauthorizedOperation")
    with pytest.raises(BlockerError, match="create_network_acl_entry failed"):
        blocker.block("198.51.100.7", 60)
    assert state(tmp_path)["blocks"] == {}


def test_limit_exceeded_means_at_the_cap_and_there_is_no_retry_storm(ec2, tmp_path):
    clock = Clock()
    blocker = make(ec2, tmp_path, clock=clock)
    stub_describe(ec2)
    ec2.stubber.add_client_error("create_network_acl_entry",
                                 service_error_code="NetworkAclEntryLimitExceeded",
                                 expected_params=params(1, "198.51.100.7", False))
    with pytest.raises(CapReached):
        blocker.block("198.51.100.7", 60)
    assert state(tmp_path)["blocks"] == {}
    for ip in ("198.51.100.8", "198.51.100.9"):  # within the back-off: no calls at all
        with pytest.raises(CapReached, match="acl_full_backoff"):
            blocker.block(ip, 60)
    clock.t += LIMIT_BACKOFF + 1  # then it tries again
    stub_create(ec2, 1, "198.51.100.8", False)
    stub_create(ec2, 1, "198.51.100.8", True)
    blocker.block("198.51.100.8", 60)


def test_a_half_installed_block_is_completed_by_the_next_block_call(ec2, tmp_path):
    clock = Clock()
    blocker = make(ec2, tmp_path, clock=clock)
    stub_describe(ec2)
    stub_create(ec2, 1, "198.51.100.7", False)
    ec2.stubber.add_client_error("create_network_acl_entry", service_error_code="InternalError")
    with pytest.raises(BlockerError):
        blocker.block("198.51.100.7", 60)
    half = blocker.active()["198.51.100.7"]
    assert half["ingress"] == 1 and half["egress"] is None  # ingress only: not a full block yet
    stub_create(ec2, 1, "198.51.100.7", True)  # only the missing direction is created
    clock.t += 5
    blocker.block("198.51.100.7", 60)
    full = blocker.active()["198.51.100.7"]
    assert full["ingress"] == 1 and full["egress"] == 1
    assert state(tmp_path)["blocks"]["198.51.100.7"]["egress"] == 1


# --- Expiry -----------------------------------------------------------------------------------

def test_expiry_deletes_both_directions(ec2, tmp_path):
    clock = Clock()
    blocker = make(ec2, tmp_path, clock=clock)
    stub_describe(ec2)
    stub_create(ec2, 1, "198.51.100.7", False)
    stub_create(ec2, 1, "198.51.100.7", True)
    blocker.block("198.51.100.7", 60)
    clock.t += 59
    assert blocker.expire() == []
    clock.t += 2
    stub_delete(ec2, 1, False)
    stub_delete(ec2, 1, True)
    assert blocker.expire() == ["198.51.100.7"]
    assert state(tmp_path)["blocks"] == {} and blocker.active() == {}


def test_blocking_again_extends_the_ttl_without_api_calls(ec2, tmp_path):
    clock = Clock()
    blocker = make(ec2, tmp_path, clock=clock)
    stub_describe(ec2)
    stub_create(ec2, 1, "198.51.100.7", False)
    stub_create(ec2, 1, "198.51.100.7", True)
    blocker.block("198.51.100.7", 60)
    clock.t += 30
    blocker.block("198.51.100.7", 60)
    assert blocker.active()["198.51.100.7"]["expires_at"] == T0 + 90
    blocker.block("198.51.100.7", 10)  # a shorter ttl never shortens an existing block
    assert blocker.active()["198.51.100.7"]["expires_at"] == T0 + 90


def test_unblock_deletes_and_tolerates_already_gone(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    stub_describe(ec2)
    stub_create(ec2, 1, "198.51.100.7", False)
    stub_create(ec2, 1, "198.51.100.7", True)
    blocker.block("198.51.100.7", 60)
    ec2.stubber.add_client_error("delete_network_acl_entry",
                                 service_error_code="InvalidNetworkAclEntry.NotFound")
    stub_delete(ec2, 1, True)
    blocker.unblock("198.51.100.7")
    assert blocker.active() == {}
    blocker.unblock("198.51.100.7")  # unknown address: nothing to do, no call


# --- Eviction at the cap ----------------------------------------------------------------------

def fill_cap(ec2, blocker, clock, ips, ttl=600):
    for i, ip in enumerate(ips, start=1):
        stub_create(ec2, i, ip, False)
        stub_create(ec2, i, ip, True)
        blocker.block(ip, ttl)
        clock.t += 1


def test_at_the_cap_a_new_block_is_refused_and_nothing_is_evicted(ec2, tmp_path, caplog):
    clock = Clock()
    blocker = make(ec2, tmp_path, clock=clock, max_denies=2)
    stub_describe(ec2)
    fill_cap(ec2, blocker, clock, ["198.51.100.1", "198.51.100.2"])
    with caplog.at_level("WARNING"), pytest.raises(BlockerError, match="cap"):
        blocker.block("198.51.100.3", 600)  # no API call queued: none may be made
    assert sorted(blocker.active()) == ["198.51.100.1", "198.51.100.2"]
    assert any("nacl_block_refused" in r.getMessage() for r in caplog.records)


def test_a_refused_block_is_released_in_the_policy_and_real_blocks_stay_blocked(ec2, tmp_path):
    clock = Clock()
    settings = Settings(dry_run=False, allowlist=["10.60.0.0/16"])
    policy = ResponsePolicy.from_settings(settings, min_flows=1)
    blocker = NaclBlocker(ec2, ACL, policy, tmp_path / "state.json", dry_run=False,
                          max_denies=1, now=clock)
    stub_describe(ec2)
    engine = ResponseEngine(settings, blocker=blocker, policy=policy)
    stub_create(ec2, 1, "198.51.100.1", False)
    stub_create(ec2, 1, "198.51.100.1", True)
    assert engine.handle(Detection("198.51.100.1", "PortScan", 0.99, T0)).action is Action.BLOCK
    spray = engine.handle(Detection("198.51.100.9", "PortScan", 0.99, T0))
    assert spray.action is Action.OBSERVE and "cap" in spray.reason  # refused, engine carried on
    assert engine.handle(Detection("198.51.100.1", "PortScan", 0.99, T0)).action is Action.ALREADY_BLOCKED
    assert "198.51.100.9" not in policy._blocked_until  # may be blocked later when there is room
    assert sorted(blocker.active()) == ["198.51.100.1"]


def test_a_block_about_to_expire_is_evicted_and_released_in_the_policy(ec2, tmp_path):
    clock = Clock()
    settings = Settings(dry_run=False, allowlist=["10.60.0.0/16"])
    policy = ResponsePolicy.from_settings(settings, min_flows=1)
    blocker = NaclBlocker(ec2, ACL, policy, tmp_path / "state.json", dry_run=False,
                          max_denies=2, now=clock)
    stub_describe(ec2)
    engine = ResponseEngine(settings, blocker=blocker, policy=policy)
    for n, ip in ((1, "198.51.100.1"), (2, "198.51.100.2")):  # the policy's TTL is 900 s
        stub_create(ec2, n, ip, False)
        stub_create(ec2, n, ip, True)
        assert engine.handle(Detection(ip, "PortScan", 0.99, clock.t)).action is Action.BLOCK
        clock.t += 800 if n == 1 else 1  # .1 has 99 s left, .2 a full TTL
    assert "198.51.100.1" in policy._blocked_until
    stub_replace(ec2, 1, "198.51.100.3", False)  # .1's numbers are reused
    stub_replace(ec2, 1, "198.51.100.3", True)
    assert engine.handle(Detection("198.51.100.3", "PortScan", 0.99, clock.t)).action is Action.BLOCK
    assert sorted(blocker.active()) == ["198.51.100.2", "198.51.100.3"]
    assert "198.51.100.1" not in policy._blocked_until  # released: it can be blocked again


def test_extending_an_existing_block_does_not_evict(ec2, tmp_path):
    blocker = make(ec2, tmp_path, max_denies=1)
    stub_describe(ec2)
    stub_create(ec2, 1, "198.51.100.1", False)
    stub_create(ec2, 1, "198.51.100.1", True)
    blocker.block("198.51.100.1", 600)
    blocker.block("198.51.100.1", 600)


# --- Reconciliation ---------------------------------------------------------------------------

def write_state(tmp_path, blocks, acl=ACL):
    (tmp_path / "state.json").write_text(json.dumps({"version": 1, "acl_id": acl, "blocks": blocks}))


def rec(expires, ingress=None, egress=None, created=T0 - 10):
    return {"created_at": created, "expires_at": expires, "ingress": ingress, "egress": egress}


def test_reconcile_adopts_unknown_denies_with_a_fresh_ttl(ec2, tmp_path):
    blocker = make(ec2, tmp_path, ttl=900)
    stub_describe(ec2, deny(4, "198.51.100.7"), deny(4, "198.51.100.7", egress=True))
    blocker.ensure_ruleset()  # state file is gone, so the NACL is the truth
    adopted = blocker.active()["198.51.100.7"]
    assert adopted["expires_at"] == T0 + 900 and (adopted["ingress"], adopted["egress"]) == (4, 4)


def test_reconcile_keeps_known_expiry_and_deletes_expired(ec2, tmp_path):
    write_state(tmp_path, {
        "198.51.100.1": rec(T0 + 500, 1, 1),   # still valid
        "198.51.100.2": rec(T0 - 5, 2, 2),     # expired while we were down
    })
    blocker = make(ec2, tmp_path)
    stub_describe(ec2, deny(1, "198.51.100.1"), deny(1, "198.51.100.1", True),
                  deny(2, "198.51.100.2"), deny(2, "198.51.100.2", True))
    stub_delete(ec2, 2, False)
    stub_delete(ec2, 2, True)
    blocker.ensure_ruleset()
    assert list(blocker.active()) == ["198.51.100.1"]
    assert blocker.active()["198.51.100.1"]["expires_at"] == T0 + 500


def test_reconcile_recreates_a_block_someone_deleted(ec2, tmp_path):
    write_state(tmp_path, {"198.51.100.1": rec(T0 + 500, 1, 1)})
    blocker = make(ec2, tmp_path)
    stub_describe(ec2)
    stub_create(ec2, 1, "198.51.100.1", False)
    stub_create(ec2, 1, "198.51.100.1", True)
    blocker.ensure_ruleset()
    assert blocker.active()["198.51.100.1"]["expires_at"] == T0 + 500


def test_reconcile_forgets_an_expired_block_that_is_already_gone(ec2, tmp_path):
    write_state(tmp_path, {"198.51.100.1": rec(T0 - 1, 1, 1)})
    blocker = make(ec2, tmp_path)
    stub_describe(ec2)  # nothing to delete, nothing to create
    blocker.ensure_ruleset()
    assert blocker.active() == {} and state(tmp_path)["blocks"] == {}


def test_reconcile_completes_a_missing_direction(ec2, tmp_path):
    write_state(tmp_path, {"198.51.100.1": rec(T0 + 500, 1, 1)})
    blocker = make(ec2, tmp_path)
    stub_describe(ec2, deny(1, "198.51.100.1"), entry(1, True))  # egress 1 now holds something else
    stub_create(ec2, 2, "198.51.100.1", True)
    blocker.ensure_ruleset()
    assert blocker.active()["198.51.100.1"]["egress"] == 2


def test_reconcile_removes_a_deny_for_a_now_protected_address(ec2, tmp_path):
    blocker = make(ec2, tmp_path)  # 10.60.0.0/16 is allowlisted
    stub_describe(ec2, deny(3, "10.60.1.10"), deny(3, "10.60.1.10", True))
    stub_delete(ec2, 3, False)
    stub_delete(ec2, 3, True)
    blocker.ensure_ruleset()
    assert blocker.active() == {}


def test_state_for_another_acl_or_garbage_is_ignored(ec2, tmp_path):
    write_state(tmp_path, {"198.51.100.1": rec(T0 + 500, 1, 1)}, acl="acl-other")
    blocker = make(ec2, tmp_path)
    stub_describe(ec2)
    blocker.ensure_ruleset()
    assert blocker.active() == {}
    (tmp_path / "state.json").write_text("{not json")
    blocker2 = make(ec2, tmp_path)
    stub_describe(ec2)
    blocker2.ensure_ruleset()


def test_state_entries_with_numbers_outside_the_range_are_dropped(ec2, tmp_path):
    write_state(tmp_path, {"198.51.100.1": rec(T0 + 500, 100, 1)})  # 100 is Terraform's
    blocker = make(ec2, tmp_path)
    stub_describe(ec2)
    blocker.ensure_ruleset()  # no delete of rule 100, no create: the entry was dropped
    assert blocker.active() == {}


def test_describe_of_a_missing_acl_fails(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    ec2.stubber.add_response("describe_network_acls", {"NetworkAcls": []}, {"NetworkAclIds": [ACL]})
    with pytest.raises(BlockerError, match="not found"):
        blocker.ensure_ruleset()


def test_state_file_is_private_and_written_atomically(ec2, tmp_path):
    blocker = make(ec2, tmp_path)
    stub_describe(ec2)
    stub_create(ec2, 1, "198.51.100.7", False)
    stub_create(ec2, 1, "198.51.100.7", True)
    blocker.block("198.51.100.7", 60)
    assert ((tmp_path / "state.json").stat().st_mode & 0o777) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]  # no temp files left behind


# --- Through the shared response engine -------------------------------------------------------

def test_engine_blocks_through_the_nacl_and_respects_the_allowlist(ec2, tmp_path):
    settings = Settings(dry_run=False, allowlist=["10.60.0.0/16"])
    policy = ResponsePolicy.from_settings(settings, min_flows=1)
    blocker = NaclBlocker(ec2, ACL, policy, tmp_path / "state.json", dry_run=False)
    stub_describe(ec2)  # the engine calls ensure_ruleset() at start-up
    engine = ResponseEngine(settings, blocker=blocker, policy=policy)
    stub_create(ec2, 1, "198.51.100.7", False)
    stub_create(ec2, 1, "198.51.100.7", True)
    d = engine.handle(Detection("198.51.100.7", "PortScan", 0.99, 1000.0))
    assert d.action is Action.BLOCK and "198.51.100.7" in blocker.active()
    d = engine.handle(Detection("10.60.1.10", "PortScan", 0.99, 1000.0))
    assert d.action is Action.ALLOWLISTED  # decided by the policy; no API call queued
