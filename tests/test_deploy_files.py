"""Step 12: static checks of the deployment files. The compose files are normalised by
`docker compose config` (skipped when Docker is not installed); the rest needs nothing."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
INSTALL = (DEPLOY / "install.sh").read_text()
DOCKER = shutil.which("docker") or shutil.which(
    "docker", path="/Applications/Docker.app/Contents/Resources/bin")


def _compose(name: str, env: dict[str, str]) -> dict:
    if DOCKER is None:
        pytest.skip("docker is not installed")
    envfile = DEPLOY / f".env.test-{os.getpid()}"
    envfile.write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    try:
        r = subprocess.run([DOCKER, "compose", "--profile", "tools", "--env-file", str(envfile), "-f",
                            str(DEPLOY / f"compose/{name}.yml"), "-p", "idps-pkg-lint", "config",
                            "--format", "json"], capture_output=True, text=True, timeout=60)
    finally:
        envfile.unlink(missing_ok=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


SOC_ENV = {"IDPS_TAG": "0.2.0", "IDPS_SITE": "localhost"}


@pytest.fixture(scope="module")
def soc():
    return _compose("soc", SOC_ENV)


@pytest.fixture(scope="module")
def sensor():
    return _compose("sensor", {"IDPS_TAG": "0.2.0", "IDPS_SOC_URL": "https://soc:8444",
                               "IDPS_INTERFACE": "eth0", "IDPS_MODEL_FILE": "m.joblib"})


def _published(service: dict) -> list[int]:
    return [int(p["target"]) for p in service.get("ports", [])]


def test_main_port_8000_is_never_published(soc):
    for name, svc in soc["services"].items():
        assert 8000 not in _published(svc), name
        assert 8000 not in [int(p["published"]) for p in svc.get("ports", [])], name
    assert "8000" in soc["services"]["soc"]["expose"]


def test_database_is_not_published_and_uses_a_secret_file(soc):
    db = soc["services"]["db"]
    assert "ports" not in db
    assert "POSTGRES_PASSWORD" not in db["environment"]
    assert db["environment"]["POSTGRES_PASSWORD_FILE"] == "/run/secrets/db_password"
    assert db["healthcheck"]["test"]


def test_sensor_port_is_published_by_the_soc_and_mtls_is_required_by_default(soc):
    s = soc["services"]["soc"]
    assert _published(s) == [8444]
    assert s["environment"]["IDPS_SOC_SENSOR_MTLS_REQUIRED"] == "true"
    assert s["depends_on"]["db"]["condition"] == "service_healthy"
    assert s["read_only"] is True and s["cap_drop"] == ["ALL"]


def test_secrets_are_files_and_no_secret_value_is_inline(soc):
    assert set(soc["secrets"]) == {"db_password", "jwt_secret", "mfa_key"}
    for spec in soc["secrets"].values():
        assert "/deploy/secrets/" in spec["file"]
    text = (DEPLOY / "compose/soc.yml").read_text()
    for pattern in (r"JWT_SECRET\s*:", r"MFA_KEY\s*:", r"DATABASE_URL\s*:", r"POSTGRES_PASSWORD\s*:",
                    r"postgresql\+psycopg://\w+:[^@\s]*@"):
        assert not re.search(pattern, text), pattern
    for name in ("soc", "soc-admin"):
        assert {"jwt_secret", "mfa_key", "db_password"} <= {
            s["source"] for s in soc["services"][name]["secrets"]}
    for name, svc in soc["services"].items():  # nothing secret-looking in any environment
        for key, value in svc.get("environment", {}).items():
            assert not re.search(r"(SECRET|PASSWORD|KEY)$", key) or key.endswith("_FILE"), (name, key)


def test_services_restart_have_limits_and_named_volumes(soc):
    for name in ("db", "soc", "proxy"):
        svc = soc["services"][name]
        assert svc["restart"] == "unless-stopped", name
        assert int(svc["deploy"]["resources"]["limits"]["memory"]) > 0, name
    assert {"pgdata", "pki", "caddy_data"} <= set(soc["volumes"])
    assert "caddy_data" in [v["source"] for v in soc["services"]["proxy"]["volumes"]]
    vol = soc["services"]["soc"]["volumes"]
    assert [(v["source"], v["read_only"]) for v in vol] == [("pki", True)]  # certificates only
    # the CA private keys are in a volume that only the soc-admin service mounts
    for name, svc in soc["services"].items():
        mounted = {v["source"] for v in svc.get("volumes", [])}
        assert ("cakeys" in mounted) == (name == "soc-admin"), name
    assert soc["services"]["soc-admin"]["profiles"] == ["tools"]


def test_proxy_ports_come_from_the_environment_with_standard_defaults(soc):
    assert sorted(int(p["published"]) for p in soc["services"]["proxy"]["ports"]) == [80, 443]
    text = (DEPLOY / "compose/soc.yml").read_text()
    assert "${IDPS_HTTP_PORT:-80}:80" in text and "${IDPS_HTTPS_PORT:-443}:443" in text
    custom = _compose("soc", {**SOC_ENV, "IDPS_HTTP_PORT": "18080", "IDPS_HTTPS_PORT": "18443",
                              "IDPS_SENSOR_PORT": "18444"})
    assert sorted(int(p["published"]) for p in custom["services"]["proxy"]["ports"]) == [18080, 18443]
    assert [int(p["published"]) for p in custom["services"]["soc"]["ports"]] == [18444]


def test_images_are_tagged_from_the_environment(soc, sensor):
    assert soc["services"]["soc"]["image"] == "idps-soc:0.2.0"
    assert soc["services"]["soc-admin"]["image"] == "idps-soc:0.2.0"
    assert soc["services"]["proxy"]["image"] == "idps-proxy:0.2.0"
    assert sensor["services"]["sensor"]["image"] == "idps-sensor:0.2.0"


def test_sensor_compose_host_network_capabilities_and_read_only_mounts(sensor):
    s = sensor["services"]["sensor"]
    assert s["network_mode"] == "host"
    assert set(s["cap_add"]) == {"NET_ADMIN", "NET_RAW"} and s["cap_drop"] == ["ALL"]
    assert "DAC_READ_SEARCH" not in s["cap_add"]  # open_by_handle_at: container escape
    assert s["read_only"] is True
    mounts = {v["target"]: v for v in s["volumes"]}
    assert mounts["/models"]["type"] == "bind" and mounts["/models"]["read_only"]
    assert mounts["/enrol"]["type"] == "volume" and mounts["/enrol"]["read_only"]
    assert not s.get("ports")
    loader = sensor["services"]["sensor-load"]
    assert loader["network_mode"] == "none" and loader["cap_drop"] == ["ALL"]
    assert not loader.get("cap_add")
    text = (DEPLOY / "compose/sensor.yml").read_text() + (DEPLOY / "compose/soc.yml").read_text()
    assert "DAC_READ_SEARCH" not in (DEPLOY / "compose/sensor.yml").read_text().replace("No DAC_READ_SEARCH", "")
    del text


def test_proxy_caddyfiles():
    for mode in ("internal", "domain"):
        text = (DEPLOY / f"proxy/Caddyfile.{mode}").read_text()
        assert "handle_path /api/*" in text and "reverse_proxy {$IDPS_UPSTREAM:soc:8000}" in text
        assert "max_size 11MiB" in text
        assert "X-Frame-Options DENY" in text
        assert "frame-ancestors 'none'" in text and "default-src 'self'" in text
        assert "try_files {path} /index.html" in text
        assert "redir https://" in text
        # nothing outside the app's own origin may load: no hosts in the policy
        csp = re.search(r'Content-Security-Policy "([^"]*)"', text).group(1)
        assert "http" not in csp and "*" not in csp and "unsafe-eval" not in csp
        assert "script-src 'self';" in csp
    assert "Strict-Transport-Security" in (DEPLOY / "proxy/Caddyfile.domain").read_text()
    assert "Strict-Transport-Security" not in (DEPLOY / "proxy/Caddyfile.internal").read_text()
    assert "tls internal" in (DEPLOY / "proxy/Caddyfile.internal").read_text()
    assert "tls internal" not in (DEPLOY / "proxy/Caddyfile.domain").read_text()


def test_dashboard_loads_nothing_from_other_origins():
    """The CSP above has no external hosts: the sources must not name any either."""
    src = ROOT / "soc/web/src"
    for path in list(src.rglob("*.ts")) + list(src.rglob("*.tsx")):
        if "test" in path.parts:
            continue
        text = path.read_text()
        for m in re.finditer(r"""(?:src|href|url\()\s*[=:]?\s*["'`]?(https?://[^"'`)\s]+)""", text):
            pytest.fail(f"{path}: external resource {m.group(1)}")


def test_dockerfiles():
    for name in ("soc", "proxy", "sensor"):
        text = (DEPLOY / f"docker/{name}.Dockerfile").read_text()
        assert "ARG VERSION" in text and "ARG GIT_SHA" in text
        for label in ("org.opencontainers.image.version", "org.opencontainers.image.revision"):
            assert label in text, (name, label)
        assert text.count("FROM ") >= 2, "multi-stage"
    soc = (DEPLOY / "docker/soc.Dockerfile").read_text()
    assert "USER 10001" in soc and "HEALTHCHECK" in soc and "--no-deps" in soc
    assert "-c requirements.lock" in soc
    sensor = (DEPLOY / "docker/sensor.Dockerfile").read_text()
    assert not re.search(r"^COPY\s+(\S+\s+)*models", sensor, re.M)  # models are mounted, not baked in


def test_soc_image_installs_the_same_packages_as_the_cloud_template():
    tpl = (ROOT / "infra/templates/soc-user-data.sh.tftpl").read_text()
    wanted = re.search(r"pip install --no-cache-dir -c /repo/requirements.lock\s+(.*?)\s+&&", tpl, re.S)
    cloud = set(re.sub(r"['\"]", "", wanted.group(1)).split())
    soc = (DEPLOY / "docker/soc.Dockerfile").read_text()
    block = re.search(r"-c requirements.lock \\\n(.*?)\n(?:COPY|RUN|FROM)", soc, re.S).group(1)
    image = set(re.sub(r"['\"\\]", "", block).split())
    # the cloud list plus pandas: soc.api imports idps.features, which needs it (numpy comes along)
    assert image == cloud | {"pandas"}


def test_entrypoint_reads_secrets_from_files():
    text = (DEPLOY / "soc/entrypoint.sh").read_text()
    for name in ("jwt_secret", "mfa_key", "db_password"):
        assert f"read_secret {name}" in text
    assert "IDPS_SOC_JWT_SECRET" in text and "IDPS_SOC_DATABASE_URL" in text and "IDPS_SOC_MFA_KEY" in text
    assert "python -m soc.api.serve" in text
    assert not re.search(r"\becho\b[^\n]*\$(DB_PASSWORD|IDPS_SOC_JWT_SECRET|IDPS_SOC_MFA_KEY)", text)


def test_version_is_0_2_0_everywhere():
    import json

    assert re.search(r'^version = "0\.2\.0"', (ROOT / "pyproject.toml").read_text(), re.M)
    assert json.loads((ROOT / "soc/web/package.json").read_text())["version"] == "0.2.0"


def test_install_sh_never_prints_secrets():
    secret_vars = r"(DB_PASSWORD|JWT_SECRET|MFA_KEY|ADMIN_PASSWORD|admin_pw|password|token)"
    for n, line in enumerate(INSTALL.splitlines(), 1):
        code = line.split("#", 1)[0]
        if re.search(r"\b(echo|printf)\b", code) and re.search(r"\$\{?" + secret_vars + r"\b", code, re.I):
            pytest.fail(f"install.sh:{n} prints a secret variable: {line.strip()}")
    for n, line in enumerate(INSTALL.splitlines(), 1):
        # a secret file is never cat-ed to the terminal or put on a command line
        assert not re.search(r"\bcat\b[^|<>\n]*secrets/", line), n
        assert "set -x" not in line, n
    assert "set -eu" in INSTALL
    assert "umask 077" in INSTALL


def test_install_sh_is_valid_posix_sh_and_help_works():
    assert subprocess.run(["sh", "-n", str(DEPLOY / "install.sh")]).returncode == 0
    r = subprocess.run(["sh", str(DEPLOY / "install.sh"), "--help"], capture_output=True, text=True)
    assert r.returncode == 0 and "install.sh soc" in r.stdout
    for script in ("soc/entrypoint.sh", "soc/init-pki.sh", "soc/add-sensor.sh",
                   "sensor/entrypoint.sh", "proxy/entrypoint.sh", "tests/fresh-install.sh",
                   "tests/upgrade.sh"):
        path = DEPLOY / script
        if path.exists():
            assert subprocess.run(["sh", "-n", str(path)]).returncode == 0, script


def test_install_sh_rejects_bad_input_before_touching_docker(tmp_path):
    def run(*args):
        return subprocess.run(["sh", str(DEPLOY / "install.sh"), *args], capture_output=True,
                              text=True, env={"PATH": "/usr/bin:/bin"})

    assert run("soc", "--domain", "a.example", "--host", "b").returncode != 0
    assert "not a valid host" in run("soc", "--host", "a b;rm").stderr
    assert "bad --https-port" in run("soc", "--https-port", "70000").stderr
    assert "80 and 443" in run("soc", "--domain", "a.example", "--https-port", "8443").stderr
    assert run("nonsense").returncode == 2


def test_gitignore_and_dockerignore_cover_the_deploy_secrets():
    for ignore in (".gitignore", ".dockerignore"):
        text = (ROOT / ignore).read_text()
        for path in ("deploy/.env", "deploy/secrets", "deploy/sensors", "deploy/sensor-data"):
            assert path in text, (ignore, path)


def test_install_sensor_writes_the_files_and_validates_compose(tmp_path):
    """`install.sh sensor --no-start` on a copy of deploy/ with a fake bundle and model."""
    if DOCKER is None:
        pytest.skip("docker is not installed")
    images = subprocess.run([DOCKER, "image", "ls", "idps-sensor", "--format", "{{.Tag}}"],
                            capture_output=True, text=True, check=False).stdout.split()
    if not images:
        pytest.skip("no local idps-sensor image (build one: install.sh sensor --build)")
    tag = images[0]
    project = "idps-pkg-pytest"
    env = {**os.environ, "PATH": f"{Path(DOCKER).parent}:{os.environ['PATH']}"}
    home = tmp_path / "host"
    shutil.copytree(DEPLOY, home / "deploy", ignore=shutil.ignore_patterns(
        "secrets", "sensors", "sensor-data", ".env*", "__pycache__"))
    shutil.copy(ROOT / "pyproject.toml", home / "pyproject.toml")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for name, text in (("token", "tok-secret-value"), ("client.pem", "CERT"), ("client.key", "KEY"),
                       ("ca.pem", "CA"), ("sensor.env", "IDPS_SOC_URL=https://soc.example:8444\n")):
        (bundle / name).write_text(text)
    model = tmp_path / "m.joblib"
    model.write_bytes(b"model")
    for ext in (".sha256", ".sig"):
        (tmp_path / f"m.joblib{ext}").write_text("x")
    pub = tmp_path / "pub.pem"
    pub.write_text("PUB")
    try:
        r = subprocess.run(["sh", str(home / "deploy/install.sh"), "sensor", "--bundle", str(bundle),
                            "--interface", "eth0", "--model", str(model), "--public-key", str(pub),
                            "--image-tag", tag, "--project", project, "--no-start"],
                           capture_output=True, text=True, env=env, check=False)
        assert r.returncode == 0, r.stderr
        assert "tok-secret-value" not in r.stdout + r.stderr
        data = home / "deploy/sensor-data"
        assert not (data / "enrol").exists()  # the bundle is only in the volume
        assert sorted(p.name for p in (data / "models").iterdir()) == [
            "m.joblib", "m.joblib.sha256", "m.joblib.sig"]
        assert oct((data / "models").stat().st_mode & 0o777) == "0o755"
        assert oct((data / "models/m.joblib").stat().st_mode & 0o777) == "0o644"
        env_text = (home / "deploy/.env.sensor").read_text()
        assert f"IDPS_TAG={tag}" in env_text and "IDPS_SOC_URL=https://soc.example:8444" in env_text
        assert "IDPS_INTERFACE=eth0" in env_text and "IDPS_MODEL_FILE=m.joblib" in env_text
        assert oct((home / "deploy/.env.sensor").stat().st_mode & 0o777) == "0o600"
        assert "tok-secret" not in env_text
        # the volume holds the bundle, owned by root, keys 0600
        ls = subprocess.run([DOCKER, "run", "--rm", "--network", "none", "--cap-drop", "ALL",
                             "-v", f"{project}_sensor_enrol:/e:ro", "--entrypoint", "sh",
                             f"idps-sensor:{tag}", "-c", "stat -c '%a %U %n' /e/*"],
                            capture_output=True, text=True, check=False)
        lines = sorted(ls.stdout.split("\n"))
        assert "600 root /e/token" in lines and "600 root /e/client.key" in lines, ls.stdout
        assert "644 root /e/model-signing.pub" in lines
    finally:
        subprocess.run([DOCKER, "compose", "-p", project, "--profile", "tools", "down", "--volumes",
                        "--remove-orphans"], capture_output=True, check=False, env=env)
        subprocess.run([DOCKER, "volume", "rm", f"{project}_sensor_enrol", f"{project}_sensor_state"],
                       capture_output=True, check=False, env=env)


def test_install_sensor_refuses_an_incomplete_bundle(tmp_path):
    bundle = tmp_path / "b"
    bundle.mkdir()
    (bundle / "token").write_text("x")
    model = tmp_path / "m.joblib"
    model.write_bytes(b"m")
    r = subprocess.run(["sh", str(DEPLOY / "install.sh"), "sensor", "--bundle", str(bundle),
                        "--interface", "eth0", "--model", str(model), "--no-start"],
                       capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert r.returncode != 0 and "missing" in r.stderr


def test_proxy_has_a_fixed_address_and_only_it_may_set_forwarded_for(soc):
    net = soc["networks"]["default"]["ipam"]["config"][0]["subnet"]
    proxy_ip = soc["services"]["proxy"]["networks"]["default"]["ipv4_address"]
    import ipaddress

    assert ipaddress.ip_address(proxy_ip) in ipaddress.ip_network(net)
    assert soc["services"]["soc"]["environment"]["IDPS_FORWARDED_ALLOW_IPS"] == proxy_ip
    assert "*" not in (DEPLOY / "soc/entrypoint.sh").read_text().split("forwarded-allow-ips")[1].split("\n")[0]


def test_db_image_is_pulled_by_the_installer_when_missing():
    assert "IDPS_DB_IMAGE:-postgres:16-alpine" in (DEPLOY / "compose/soc.yml").read_text()
    assert "ensure_db_image" in INSTALL and "docker pull" in INSTALL
    assert INSTALL.index("ensure_db_image\n  check_network\n  info \"starting the database") > 0


def test_redirect_uses_the_configured_site_not_the_clients_host():
    for mode in ("internal", "domain"):
        text = (DEPLOY / f"proxy/Caddyfile.{mode}").read_text()
        assert "redir https://{$IDPS_SITE}" in text and "{host}" not in text


def test_install_has_restore_rollback_renew_and_no_unchecked_env_rewrite():
    for cmd in ("restore)", "rollback)", "renew-sensor)", "upgrade)"):
        assert cmd in INSTALL
    assert '> "$ENV_FILE.tmp.$$" &&' not in INSTALL
    assert "-previous" in INSTALL and "dc_tag" in INSTALL


def test_images_pin_caddy_and_have_no_placeholder_source_label():
    assert re.search(r"^FROM caddy:2\.\d+\.\d+$", (DEPLOY / "docker/proxy.Dockerfile").read_text(), re.M)
    for n in ("soc", "proxy", "sensor"):
        assert "image.source" not in (DEPLOY / f"docker/{n}.Dockerfile").read_text()


def test_install_has_the_safety_checks():
    assert "--no-safety-copy" in INSTALL and "restore_abort" in INSTALL
    # the SOC is stopped before the safety copy, and the safety copy is not just a warning
    assert INSTALL.index('info "stopping the SOC"') < INSTALL.index("safety copy of the current database")
    assert "continuing: you asked to replace it" not in INSTALL
    assert "known_revision" in INSTALL and "does not know the database" in INSTALL
    assert "KEEP_TAG" in INSTALL and "check_network" in INSTALL
    assert "force-recreate sensor" in INSTALL and "sdc stop sensor" in INSTALL
    assert INSTALL.index("unset IDPS_DB_IMAGE IDPS_TAG") < INSTALL.index("DEPLOY_DIR=")
    assert "no-unknown-keyword" in (DEPLOY / "compose/sensor.yml").read_text()
    renew = (DEPLOY / "soc/renew-sensor.sh").read_text()
    assert "revoked" in renew and "SensorToken" in renew
    # restore calls ensure_db_image before touching volumes
    body = INSTALL[INSTALL.index("cmd_restore() {"):]
    assert body.index("ensure_db_image") < body.index("docker volume rm")


def test_install_rejects_a_version_that_is_not_a_valid_tag(tmp_path):
    if DOCKER is None:
        pytest.skip("docker is not installed")
    home = tmp_path / "h"
    shutil.copytree(DEPLOY, home / "deploy", ignore=shutil.ignore_patterns(
        "secrets", "sensors", "sensor-data", ".env*", "__pycache__"))
    (home / "pyproject.toml").write_text('[project]\nversion = "0.2.0+x"\n')
    env = {**os.environ, "PATH": f"{Path(DOCKER).parent}:{os.environ['PATH']}"}
    r = subprocess.run(["sh", str(home / "deploy/install.sh"), "soc", "--project", "idps-pkg-pytest2"],
                       capture_output=True, text=True, env=env, check=False)
    assert r.returncode != 0 and "not valid" in r.stderr


def test_sensor_only_host_uninstall(tmp_path):
    if DOCKER is None:
        pytest.skip("docker is not installed")
    images = subprocess.run([DOCKER, "image", "ls", "idps-sensor", "--format", "{{.Tag}}"],
                            capture_output=True, text=True, check=False).stdout.split()
    if not images:
        pytest.skip("no local idps-sensor image")
    project = "idps-pkg-pytest3"
    env = {**os.environ, "PATH": f"{Path(DOCKER).parent}:{os.environ['PATH']}"}
    home = tmp_path / "h"
    shutil.copytree(DEPLOY, home / "deploy", ignore=shutil.ignore_patterns(
        "secrets", "sensors", "sensor-data", ".env*", "__pycache__"))
    shutil.copy(ROOT / "pyproject.toml", home / "pyproject.toml")
    bundle = tmp_path / "b"
    bundle.mkdir()
    for name in ("token", "client.pem", "client.key", "ca.pem"):
        (bundle / name).write_text("x")
    (bundle / "sensor.env").write_text("IDPS_SOC_URL=https://soc.example:8444\n")
    model = tmp_path / "m.joblib"
    model.write_bytes(b"m")
    run = lambda *a: subprocess.run(["sh", str(home / "deploy/install.sh"), *a],  # noqa: E731
                                    capture_output=True, text=True, env=env, check=False)
    try:
        assert run("sensor", "--bundle", str(bundle), "--interface", "eth0", "--model", str(model),
                   "--image-tag", images[0], "--project", project, "--no-start").returncode == 0
        assert not (home / "deploy/.env").exists()  # a sensor-only host
        r = run("uninstall", "--yes")  # keeps the data
        assert r.returncode == 0, r.stderr
        assert (home / "deploy/.env.sensor").exists() and (home / "deploy/sensor-data").exists()
        vols = subprocess.run([DOCKER, "volume", "ls", "--format", "{{.Name}}"], capture_output=True,
                              text=True, check=False, env=env).stdout.split()
        assert f"{project}_sensor_enrol" in vols
        r = run("uninstall", "--delete-data", "--yes")
        assert r.returncode == 0, r.stderr
        assert not (home / "deploy/.env.sensor").exists() and not (home / "deploy/sensor-data").exists()
        vols = subprocess.run([DOCKER, "volume", "ls", "--format", "{{.Name}}"], capture_output=True,
                              text=True, check=False, env=env).stdout.split()
        assert f"{project}_sensor_enrol" not in vols
        assert run("uninstall", "--yes").returncode != 0  # nothing left to uninstall
    finally:
        subprocess.run([DOCKER, "volume", "rm", f"{project}_sensor_enrol", f"{project}_sensor_state"],
                       capture_output=True, check=False, env=env)
