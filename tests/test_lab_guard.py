"""The attack-script guard (lab/attacks/common.sh) must refuse anything but the lab targets."""

import subprocess
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "lab" / "attacks" / "common.sh"

# The sensor image doesn't contain lab/, so these tests only run from a repo checkout.
pytestmark = pytest.mark.skipif(not COMMON.exists(), reason="lab/attacks/common.sh not present")


def run_guard(**env):
    return subprocess.run(
        ["sh", "-c", f'. "{COMMON}"; echo PASSED'],
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", **env},
        capture_output=True,
        text=True,
        check=False,  # the exit code is what the tests check
    )


@pytest.mark.parametrize(
    "env",
    [
        {"VICTIM_IP": "8.8.8.8"},  # DVWA_IP left at its lab default
        {"VICTIM_IP": "10.10.2.1"},  # Docker VM gateway
        {"VICTIM_IP": "10.10.2.2"},  # the sensor
        {"VICTIM_IP": "110.10.2.5", "DVWA_IP": "1.1.1.1"},
        {"DVWA_IP": "10.10.2.110"},
    ],
)
def test_refuses_non_lab_targets(env):
    result = run_guard(**env)
    assert result.returncode == 1
    assert "not a lab target" in result.stderr
    assert "PASSED" not in result.stdout


def test_lab_targets_pass_target_check_but_not_outside_attacker():
    # Valid targets get past the target check, then the host is refused
    # because this test doesn't run inside the attacker container.
    result = run_guard()
    assert result.returncode == 1
    assert "not a lab target" not in result.stderr
    assert "inside the lab attacker container" in result.stderr
