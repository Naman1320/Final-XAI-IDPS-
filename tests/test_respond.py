import json
import logging
from ipaddress import ip_network
from unittest.mock import patch

import pytest

from idps.config import Settings
from idps.respond import (
    Action,
    BlockerError,
    Detection,
    NftBlocker,
    ResponseEngine,
    ResponsePolicy,
)
from idps.respond import nft as nft_mod

ATTACKER = "10.10.1.50"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    import os

    for name in list(os.environ):
        if name.startswith("IDPS_"):
            monkeypatch.delenv(name)


def det(ip=ATTACKER, label="PortScan", conf=0.99, t=0.0, **kw):
    return Detection(ip, label, conf, t, **kw)


def policy(**kw):
    kw.setdefault("allowlist", [ip_network("10.10.1.1/32"), ip_network("10.10.2.0/24")])
    return ResponsePolicy(**kw)


def feed(p, n, **kw):
    last = None
    for i in range(n):
        last = p.evaluate(det(t=i, **kw))
    return last


def test_blocks_only_after_n_flows():
    p = policy(min_flows=3)
    assert p.evaluate(det(t=0)).action is Action.OBSERVE
    assert p.evaluate(det(t=1)).action is Action.OBSERVE
    d = p.evaluate(det(t=2))
    assert d.action is Action.BLOCK and d.ttl_seconds == 900 and d.ip == ATTACKER


def test_window_expires_old_flows():
    p = policy(min_flows=3, window_seconds=10)
    p.evaluate(det(t=0))
    p.evaluate(det(t=1))
    assert p.evaluate(det(t=30)).action is Action.OBSERVE


def test_low_confidence_and_benign_do_not_count():
    p = policy(min_flows=2)
    assert p.evaluate(det(conf=0.5)).action is Action.BELOW_THRESHOLD
    assert p.evaluate(det(conf=float("nan"))).action is Action.BELOW_THRESHOLD
    assert p.evaluate(det(label="BENIGN")).action is Action.BENIGN
    assert p.evaluate(det(t=1)).action is Action.OBSERVE  # still only 1 counted


@pytest.mark.parametrize(
    "ip",
    ["10.10.1.1", "10.10.2.77", "::ffff:10.10.2.77", " 10.10.2.5 ",
     "127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "169.254.1.1", "::1", "::"],
)
def test_never_blocks_protected(ip):
    p = policy(min_flows=1)
    for t in range(5):
        assert p.evaluate(det(ip=ip, t=t)).action is Action.ALLOWLISTED


def test_invalid_ip():
    assert policy().evaluate(det(ip="10.10.1.l")).action is Action.INVALID


def test_already_blocked_then_expires():
    p = policy(min_flows=1, ttl_seconds=60)
    assert p.evaluate(det(t=0)).action is Action.BLOCK
    assert p.evaluate(det(t=30)).action is Action.ALREADY_BLOCKED
    assert p.evaluate(det(t=61)).action is Action.BLOCK


def test_tracking_is_bounded():
    p = policy(min_flows=5, max_tracked_ips=3)
    for i in range(10):
        p.evaluate(det(ip=f"10.10.1.{100 + i}"))
    assert len(p._flows) == 3


class FakeBlocker:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def ensure_ruleset(self):
        self.calls.append(("ensure",))

    def block(self, ip, ttl):
        if self.fail:
            raise BlockerError("boom")
        self.calls.append(("block", ip, ttl))

    def unblock(self, ip):
        self.calls.append(("unblock", ip))


def settings(**kw):
    kw.setdefault("allowlist", [ip_network("10.10.1.1/32")])
    return Settings(**kw)


def test_dry_run_logs_but_never_touches_nft(caplog):
    b = FakeBlocker()
    e = ResponseEngine(settings(dry_run=True), b, min_flows=1)
    with caplog.at_level(logging.WARNING, logger="idps.respond"):
        d = e.handle(det(explanation={"top": ["Flow Duration"]}))
    assert d.action is Action.BLOCK
    assert b.calls == []
    rec = json.loads(caplog.records[0].message)
    assert rec["event"] == "would_block" and rec["explanation"] == {"top": ["Flow Duration"]}


def test_real_mode_blocks_and_unblocks():
    b = FakeBlocker()
    e = ResponseEngine(settings(dry_run=False), b, min_flows=1)
    assert b.calls == [("ensure",)]
    assert e.handle(det()).action is Action.BLOCK
    assert ("block", ATTACKER, 900) in b.calls
    assert e.handle(det(t=1)).action is Action.ALREADY_BLOCKED
    e.unblock(ATTACKER)
    assert ("unblock", ATTACKER) in b.calls
    # The analyst override sticks: no automatic re-block during the grace period.
    assert e.handle(det(t=2)).action is Action.SUPPRESSED
    b2 = FakeBlocker()
    e2 = ResponseEngine(settings(dry_run=False, unblock_grace_seconds=0), b2, min_flows=1)
    e2.handle(det())
    e2.unblock(ATTACKER)
    assert e2.handle(det(t=2)).action is Action.BLOCK  # grace disabled


def test_allowlisted_never_reaches_blocker():
    b = FakeBlocker()
    e = ResponseEngine(settings(dry_run=False), b, min_flows=1)
    assert e.handle(det(ip="10.10.1.1")).action is Action.ALLOWLISTED
    assert [c for c in b.calls if c[0] == "block"] == []


def test_failed_block_is_retried():
    b = FakeBlocker(fail=True)
    e = ResponseEngine(settings(dry_run=False), b, min_flows=1)
    assert e.handle(det()).action is Action.OBSERVE
    b.fail = False
    assert e.handle(det(t=1)).action is Action.BLOCK


class Proc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def test_nft_commands():
    with patch.object(nft_mod.subprocess, "run", return_value=Proc()) as run:
        nb = NftBlocker()
        nb.ensure_ruleset()
        nb.block("::ffff:10.10.1.50", 120)
        nb.block("2001:db8::1", 60)
    cmds = [c.args[0] for c in run.call_args_list]
    assert cmds[0] == ["nft", "-f", "-"]
    assert "hook forward priority -10" in run.call_args_list[0].kwargs["input"]
    assert ["nft", "add", "element", "inet", "idps", "blocked4", "{ 10.10.1.50 timeout 120s }"] in cmds
    assert ["nft", "add", "element", "inet", "idps", "blocked6", "{ 2001:db8::1 timeout 60s }"] in cmds
    assert all(c.kwargs.get("shell") is None for c in run.call_args_list)


@pytest.mark.parametrize("ip", ["1.2.3.4; reboot", "1.2.3.4 } ; flush ruleset", ""])
def test_nft_rejects_injection(ip):
    with patch.object(nft_mod.subprocess, "run") as run:
        with pytest.raises(BlockerError):
            NftBlocker().block(ip, 60)
        run.assert_not_called()


def test_nft_error_and_missing_binary():
    failing = Proc(1, err="Operation not permitted")
    with (patch.object(nft_mod.subprocess, "run", return_value=failing),
          pytest.raises(BlockerError)):
        NftBlocker().block(ATTACKER, 60)
    with (patch.object(nft_mod.subprocess, "run", side_effect=FileNotFoundError("nft")),
          pytest.raises(BlockerError)):
        NftBlocker().ensure_ruleset()


def test_unblock_missing_element_is_ok():
    with patch.object(
        nft_mod.subprocess, "run",
        return_value=Proc(1, err="Error: Could not process rule: No such file or directory"),
    ):
        NftBlocker().unblock(ATTACKER)
