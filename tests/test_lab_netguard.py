"""lab/soc/netguard.sh: which resolver answers may be allowed, which host names are accepted, and
what one refresh does, with fake getent, ip and nft programs on PATH.

The script is sourced with NETGUARD_LIB=1 so only its functions load (no real nft or routes).
Each call prints ALLOW or REFUSE, so a script that fails to load can't pass a refusal test."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "lab" / "soc" / "netguard.sh"
SH = shutil.which("sh")
pytestmark = pytest.mark.skipif(SH is None, reason="needs a POSIX sh")


def _call(func: str, arg: str) -> bool:
    cmd = f'NETGUARD_LIB=1; . "{SCRIPT}" || exit 9; if {func} "$1"; then echo ALLOW; else echo REFUSE; fi'
    r = subprocess.run([SH, "-c", cmd, "sh", arg], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() in ("ALLOW", "REFUSE"), (r.returncode, r.stdout, r.stderr)
    return r.stdout.strip() == "ALLOW"


@pytest.mark.parametrize("ip", [
    "104.26.12.38", "172.67.70.74", "1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.0",
    "172.15.255.255", "172.32.0.0", "192.169.0.1", "198.17.255.255", "198.20.0.0",
    "223.255.255.255", "11.0.0.1",
])
def test_public_addresses_are_allowed(ip):
    assert _call("public_ipv4", ip)


@pytest.mark.parametrize("ip", [
    "0.0.0.0", "10.0.0.1", "10.10.2.10", "127.0.0.1", "169.254.169.254", "172.16.0.1",
    "172.31.255.255", "192.168.1.1", "100.64.0.0", "100.100.1.1", "100.127.255.255",
    "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.9",
    "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
])
def test_private_and_reserved_addresses_are_refused(ip):
    assert not _call("public_ipv4", ip)


@pytest.mark.parametrize("host", ["api.abuseipdb.com", "hooks.slack.com", "a-b.example.org", "localhost"])
def test_valid_host_names(host):
    assert _call("valid_host", host)


@pytest.mark.parametrize("host", [
    "", "*", "-x", "a.-b.com", "a-.b.com", "a..b", ".a.com", "a.com.", "a b", "a;b", "$(id)",
    "a/b", "x" * 254,
])
def test_bad_host_names_are_refused(host):
    assert not _call("valid_host", host)


# --- one refresh with fake tools ------------------------------------------------------------

FAKE_GETENT = """#!/bin/sh
# getent ahostsv4 NAME: answers from $FAKE/dns/NAME (one address per line); none = not found
f="$FAKE/dns/$2"; [ -f "$f" ] || exit 2
while read -r a; do echo "$a STREAM $2"; echo "$a DGRAM"; done < "$f"
"""
FAKE_IP = """#!/bin/sh
# Records route changes in $FAKE/routes; `ip -4 route show proto 99` lists them.
case "$*" in
  "route replace "*) a=${3%/32}; grep -qxF "$a" "$FAKE/routes" 2>/dev/null || echo "$a" >> "$FAKE/routes" ;;
  "route del "*) a=${3%/32}; grep -vxF "$a" "$FAKE/routes" > "$FAKE/r.tmp" || true; mv "$FAKE/r.tmp" "$FAKE/routes" ;;
  "-4 route show proto 99") [ -f "$FAKE/routes" ] && sed 's/$/ via 10.0.0.1 dev eth0 proto 99/' "$FAKE/routes" ;;
  *) echo "fake ip: $*" >&2; exit 1 ;;
esac
[ ! -f "$FAKE/ip_fails" ]
"""
FAKE_NFT = """#!/bin/sh
# `nft -f -` adds the addresses it is given to the named set's file ($FAKE/set for egress4,
# $FAKE/set_<name> for others); `nft list set inet socguard NAME` prints them.
file_of() { if [ "$1" = egress4 ]; then echo "$FAKE/set"; else echo "$FAKE/set_$1"; fi; }
case "$1" in
  -f) [ ! -f "$FAKE/nft_fails" ] || exit 1
      cat > "$FAKE/last_nft"
      f=$(file_of "$(awk '{print $5; exit}' "$FAKE/last_nft")")
      grep -oE '([0-9]+\\.){3}[0-9]+' "$FAKE/last_nft" >> "$f"; sort -u "$f" -o "$f" ;;
  list) f=$(file_of "$5"); echo "table inet socguard {"; echo "  set $5 {"
        printf '    elements = { %s }\\n' "$(sed 's/$/ timeout 1h expires 59m/' "$f" 2>/dev/null | paste -sd, -)"
        echo "  }"; echo "}" ;;
esac
"""


@pytest.fixture
def fake(tmp_path):
    bin_ = tmp_path / "bin"
    (tmp_path / "dns").mkdir()
    bin_.mkdir()
    for name, body in (("getent", FAKE_GETENT), ("ip", FAKE_IP), ("nft", FAKE_NFT)):
        f = bin_ / name
        f.write_text(body)
        f.chmod(0o755)
    return tmp_path


def _dns(fake, name, *addrs):
    (fake / "dns" / name).write_text("".join(f"{a}\n" for a in addrs))


def _refresh(fake, hosts):
    env = {**os.environ, "FAKE": str(fake), "PATH": f"{fake / 'bin'}:{os.environ['PATH']}"}
    cmd = (f'NETGUARD_LIB=1; . "{SCRIPT}" || exit 9; HOSTS="$1"; GW=10.0.0.1; '
           'if refresh; then echo OK; else echo FAIL; fi')
    r = subprocess.run([SH, "-c", cmd, "sh", hosts], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and r.stdout.strip().splitlines()[-1] in ("OK", "FAIL"), (r.stdout, r.stderr)
    return r.stdout.strip().splitlines()[-1] == "OK", r.stderr


def _lines(path):
    return sorted(path.read_text().split()) if path.exists() else []


def test_refresh_allows_public_answers_and_refuses_private_ones(fake):
    _dns(fake, "api.example.com", "104.26.12.38", "10.0.0.5", "104.26.13.38")
    ok, err = _refresh(fake, "api.example.com")
    assert ok
    assert _lines(fake / "set") == ["104.26.12.38", "104.26.13.38"]
    assert _lines(fake / "routes") == ["104.26.12.38", "104.26.13.38"]
    assert "ignoring non-public address 10.0.0.5" in err


def test_shared_addresses_across_hosts_go_in_once(fake):
    _dns(fake, "a.example.com", "104.26.12.38", "104.26.13.38")
    _dns(fake, "b.example.com", "104.26.13.38", "172.67.70.74")
    ok, _ = _refresh(fake, "a.example.com b.example.com")
    assert ok
    sent = (fake / "last_nft").read_text()
    assert sent.count("104.26.13.38") == 1
    assert _lines(fake / "set") == ["104.26.12.38", "104.26.13.38", "172.67.70.74"]


def test_a_host_that_fails_does_not_block_the_others(fake):
    _dns(fake, "good.example.com", "104.26.12.38")
    ok, err = _refresh(fake, "missing.example.com good.example.com")
    assert ok and _lines(fake / "set") == ["104.26.12.38"]
    assert "no public address for missing.example.com" in err


def test_nothing_resolved_or_only_private_fails_and_changes_nothing(fake):
    _dns(fake, "private.example.com", "192.168.1.10")
    ok, _ = _refresh(fake, "private.example.com missing.example.com")
    assert not ok
    assert _lines(fake / "set") == [] and _lines(fake / "routes") == []


def test_answers_are_capped_per_host(fake):
    _dns(fake, "many.example.com", *(f"104.16.0.{i}" for i in range(1, 60)))
    ok, _ = _refresh(fake, "many.example.com")
    assert ok and len(_lines(fake / "set")) == 32


def test_a_failed_nft_update_reports_failure(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    (fake / "nft_fails").write_text("")
    ok, _ = _refresh(fake, "api.example.com")
    assert not ok and _lines(fake / "set") == []


def test_routes_of_expired_addresses_are_removed(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    (fake / "routes").write_text("1.2.3.4\n")  # an address no longer in the set
    ok, _ = _refresh(fake, "api.example.com")
    assert ok and _lines(fake / "routes") == ["104.26.12.38"]


# --- the email exception: one host, one port, its own set --------------------------------------

def _refresh_all(fake, hosts, smtp_host, smtp_port="587"):
    env = {**os.environ, "FAKE": str(fake), "PATH": f"{fake / 'bin'}:{os.environ['PATH']}"}
    cmd = (f'NETGUARD_LIB=1; . "{SCRIPT}" || exit 9; HOSTS="$1"; SMTP_HOST="$2"; SMTP_PORT="$3"; '
           'GW=10.0.0.1; if refresh_all; then echo OK; else echo FAIL; fi')
    r = subprocess.run([SH, "-c", cmd, "sh", hosts, smtp_host, smtp_port], capture_output=True,
                       text=True, env=env)
    assert r.returncode == 0, (r.stdout, r.stderr)
    return r.stdout.strip().splitlines()[-1] == "OK", r.stderr


@pytest.mark.parametrize("port,ok", [("25", True), ("465", True), ("587", True), ("443", False),
                                     ("22", False), ("5870", False), ("", False), ("58 7", False)])
def test_only_mail_ports_are_accepted(port, ok):
    assert _call("valid_smtp_port", port) is ok


def test_the_mail_server_goes_in_its_own_set_not_the_https_one(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    _dns(fake, "smtp.example.com", "142.250.4.108", "10.1.1.1")
    ok, err = _refresh_all(fake, "api.example.com", "smtp.example.com")
    assert ok
    assert _lines(fake / "set") == ["104.26.12.38"]  # HTTPS set unchanged by email
    assert _lines(fake / "set_egress_smtp4") == ["142.250.4.108"]  # private answer refused
    assert _lines(fake / "routes") == ["104.26.12.38", "142.250.4.108"]  # both keep their routes
    assert "SMTP port 587 allowed to smtp.example.com" in err


def test_email_only_works_without_https_hosts(fake):
    _dns(fake, "smtp.example.com", "142.250.4.108")
    ok, _ = _refresh_all(fake, "", "smtp.example.com")
    assert ok and _lines(fake / "set") == [] and _lines(fake / "set_egress_smtp4") == ["142.250.4.108"]


def test_an_unresolvable_mail_server_does_not_hold_up_https(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    ok, err = _refresh_all(fake, "api.example.com", "missing.example.com")
    assert ok  # one set working ends the fast start-up retries
    assert _lines(fake / "set") == ["104.26.12.38"] and _lines(fake / "set_egress_smtp4") == []
    assert "mail server not resolved: missing.example.com" in err


def test_nothing_resolved_at_all_fails(fake):
    ok, _ = _refresh_all(fake, "missing.example.com", "nomail.example.com")
    assert not ok


@pytest.mark.parametrize("host,local", [("", True), ("localhost", True), ("127.0.0.1", True),
                                        ("10.10.3.5", True), ("smtp.gmail.com", False),
                                        ("142.250.4.108", False)])
def test_a_local_test_mail_server_needs_no_exception(host, local):
    assert _call("local_mail_host", host) is local


def _run(fake, script):
    env = {**os.environ, "FAKE": str(fake), "PATH": f"{fake / 'bin'}:{os.environ['PATH']}"}
    r = subprocess.run([SH, "-c", f'NETGUARD_LIB=1; . "{SCRIPT}" || exit 9; GW=10.0.0.1; {script}'],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, (r.stdout, r.stderr)
    return r.stderr


def test_an_https_refresh_keeps_the_mail_route_and_vice_versa(fake):
    _dns(fake, "api.example.com", "104.26.12.38")
    _dns(fake, "smtp.example.com", "142.250.4.108")
    (fake / "set_egress_smtp4").write_text("142.250.4.108\n")
    (fake / "routes").write_text("142.250.4.108\n")
    _run(fake, 'HOSTS=api.example.com; SMTP_HOST=smtp.example.com; refresh')
    assert _lines(fake / "routes") == ["104.26.12.38", "142.250.4.108"]
    _run(fake, 'HOSTS=api.example.com; SMTP_HOST=smtp.example.com; '
               'refresh_set egress_smtp4 SMTP smtp.example.com')
    assert _lines(fake / "routes") == ["104.26.12.38", "142.250.4.108"]


def test_a_stale_mail_route_is_removed_and_a_shared_one_kept(fake):
    _dns(fake, "smtp.example.com", "142.250.4.108")
    (fake / "set").write_text("104.26.12.38\n")  # also an HTTPS address
    (fake / "routes").write_text("104.26.12.38\n9.9.9.9\n")  # 9.9.9.9 is in no set
    _run(fake, 'HOSTS=""; SMTP_HOST=smtp.example.com; refresh_set egress_smtp4 SMTP smtp.example.com')
    assert _lines(fake / "routes") == ["104.26.12.38", "142.250.4.108"]


def test_the_allowed_log_line_is_written_once(fake):
    _dns(fake, "smtp.example.com", "142.250.4.108")
    err = _run(fake, 'HOSTS=""; SMTP_HOST=smtp.example.com; SMTP_PORT=587; '
                     'refresh_all; refresh_all')
    assert err.count("SMTP port 587 allowed") == 1


@pytest.mark.parametrize("host,local", [("foo.localhost", True), ("1.2", False), ("::1", False)])
def test_more_local_host_cases(host, local):
    # Not local: "1.2" is resolved like a name and every answer is checked by public_ipv4; "::1"
    # is then refused by valid_host in the main section (email stays blocked, the SOC starts).
    assert _call("local_mail_host", host) is local


# --- extra sensors on the mutual-TLS port 8444 (C4: the cloud collector) ----------------------

def _extra(value):
    env = {**os.environ}
    env.pop("SOC_EXTRA_SENSOR_ADDRS", None)
    if value is not None:
        env["SOC_EXTRA_SENSOR_ADDRS"] = value
    cmd = f'NETGUARD_LIB=1; . "{SCRIPT}" || exit 9; extra_sensor_addrs; echo DONE'
    r = subprocess.run([SH, "-c", cmd], capture_output=True, text=True, env=env)  # noqa: PLW1510
    lines = r.stdout.split()
    assert r.returncode == 0 and lines[-1] == "DONE", (r.stdout, r.stderr)
    return lines[:-1], r.stderr


def test_no_extra_sensor_by_default():
    assert _extra(None) == ([], "")
    assert _extra("") == ([], "")
    assert _extra(" , ,") == ([], "")


def test_the_collector_address_is_accepted():
    assert _extra("10.10.3.3")[0] == ["10.10.3.3"]
    assert _extra(" 10.10.3.3 , 10.10.3.4,10.10.3.3")[0] == ["10.10.3.3", "10.10.3.4"]


@pytest.mark.parametrize("bad", [
    "10.10.3.1",        # the Docker gateway
    "10.10.3.10",       # the SOC itself
    "10.10.3.0", "10.10.3.255", "10.10.3.256", "10.10.3.03", "10.10.3",
    "10.10.2.10",       # the victim
    "10.10.1.10",       # the attacker
    "10.10.4.30",       # cloud_net
    "10.10.3.0/24", "0.0.0.0", "any", "10.10.3.3/32", "10.10.3.3;ls", "$(id)", "*", "8.8.8.8",
    "10.10.30.3", "110.10.3.3", "tcp",
])
def test_bad_extra_sensor_entries_are_ignored_and_logged(bad):
    out, err = _extra(bad)
    assert out == []
    assert "ignoring SOC_EXTRA_SENSOR_ADDRS entry" in err


def test_a_bad_entry_does_not_cancel_a_good_one():
    out, err = _extra("10.10.2.10,10.10.3.3")
    assert out == ["10.10.3.3"] and "10.10.2.10" in err


def test_at_most_four_extra_sensors():
    out, _ = _extra(",".join(f"10.10.3.{n}" for n in range(3, 10)))
    assert out == [f"10.10.3.{n}" for n in range(3, 7)]


FULL_NFT = """#!/bin/sh
# Records every call; `-f -` also records the rule set it is given.
echo "nft $*" >> "$FAKE/calls"
[ "$1" = -f ] && cat >> "$FAKE/calls"
exit 0
"""
FULL_IP = """#!/bin/sh
case "$*" in
  "-4 route show default") echo "default via 10.0.0.1 dev eth0" ;;
  "route") ;;                              # no default route left
esac
exit 0
"""
FULL_SLEEP = """#!/bin/sh
kill -TERM "$PPID"   # ends the script's idle loop (its trap exits 0)
"""
FULL_TOUCH = """#!/bin/sh
echo "touch $*" >> "$FAKE/calls"
"""


def _run_script(tmp_path, extra):
    """Run the whole script with fake nft/ip/sleep/touch (nothing real is changed)."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name, body in (("nft", FULL_NFT), ("ip", FULL_IP), ("sleep", FULL_SLEEP),
                       ("touch", FULL_TOUCH)):
        f = bin_ / name
        f.write_text(body)
        f.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOC_")}
    env.update(FAKE=str(tmp_path), PATH=f"{bin_}:{os.environ['PATH']}")
    if extra is not None:
        env["SOC_EXTRA_SENSOR_ADDRS"] = extra
    r = subprocess.run([SH, str(SCRIPT)], capture_output=True, text=True, env=env, timeout=30)  # noqa: PLW1510
    assert r.returncode == 0, (r.stdout, r.stderr)
    return (tmp_path / "calls").read_text(), r.stderr


def test_default_rules_are_unchanged(tmp_path):
    """Nothing set: exactly today's input rules, no extra `nft add rule`."""
    calls, err = _run_script(tmp_path, None)
    assert "ip saddr 10.10.3.2 tcp dport 8444 accept" in calls
    assert "tcp dport 8443 accept" in calls
    assert "nft add rule" not in calls
    assert "touch /tmp/ready" in calls
    assert "also open" not in err


def test_the_collector_gets_8444_and_nothing_else(tmp_path):
    calls, err = _run_script(tmp_path, "10.10.3.3")
    added = [ln for ln in calls.splitlines() if ln.startswith("nft add rule")]
    assert added == ["nft add rule inet socguard input ip saddr 10.10.3.3 tcp dport 8444 accept"]
    assert "ip saddr 10.10.3.2 tcp dport 8444 accept" in calls  # the sensor keeps its rule
    assert "10.10.3.3" in err


def test_a_rejected_entry_adds_no_rule_but_the_soc_still_starts(tmp_path):
    calls, err = _run_script(tmp_path, "10.10.2.10")
    assert "nft add rule" not in calls and "touch /tmp/ready" in calls
    assert "ignoring SOC_EXTRA_SENSOR_ADDRS entry '10.10.2.10'" in err
