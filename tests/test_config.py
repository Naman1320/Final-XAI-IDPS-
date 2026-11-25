from ipaddress import ip_network

import pytest
from pydantic import ValidationError

from idps.config import Settings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Tests must not depend on IDPS_* variables set in the developer's shell."""
    import os

    for name in list(os.environ):
        if name.startswith("IDPS_"):
            monkeypatch.delenv(name)


def test_defaults():
    s = Settings()
    assert s.dry_run is True
    assert s.block_ttl_seconds == 900
    assert s.confidence_threshold == 0.9
    assert s.allowlist == []


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("IDPS_DRY_RUN", "false")
    monkeypatch.setenv("IDPS_ALLOWLIST", "10.10.1.1, 10.10.2.0/24")
    s = Settings()
    assert s.dry_run is False
    assert s.allowlist == [ip_network("10.10.1.1/32"), ip_network("10.10.2.0/24")]


def test_rejects_mistyped_allowlist_ip(monkeypatch):
    monkeypatch.setenv("IDPS_ALLOWLIST", "10.10.1.l")
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.parametrize("ttl", [-5, 0, 59, 86_401])
def test_rejects_ttl_out_of_range(ttl):
    with pytest.raises(ValidationError):
        Settings(block_ttl_seconds=ttl)


@pytest.mark.parametrize("threshold", [0, 0.49, 1.01])
def test_rejects_threshold_out_of_range(threshold):
    with pytest.raises(ValidationError):
        Settings(confidence_threshold=threshold)


def test_real_blocking_needs_allowlist():
    with pytest.raises(ValidationError, match="allowlist is empty"):
        Settings(dry_run=False)
    assert Settings(dry_run=False, allowlist=["10.10.1.1"]).dry_run is False
