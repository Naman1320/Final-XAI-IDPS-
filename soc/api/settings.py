"""SOC API settings, overridable with IDPS_SOC_* environment variables."""

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, IPvAnyNetwork, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

MIN_SECRET_LENGTH = 32

SEVERITIES = ("low", "medium", "high", "critical")

# Base severity per predicted class (matched case-insensitively). Anything not listed gets
# `default_severity`. Override with IDPS_SOC_SEVERITY_BY_CLASS='{"Bot": "critical"}'.
DEFAULT_SEVERITY_BY_CLASS = {
    "portscan": "low",
    "dos": "high", "ddos": "critical", "bot": "high", "infiltration": "critical",
    "heartbleed": "critical", "web attack": "high", "ftp-patator": "medium",
    "ssh-patator": "medium", "brute force": "medium", "sql injection": "high", "xss": "medium",
    # Families of rule (Suricata) alerts, see idps/rules/eve.py; "Rule match" gets default_severity.
    "scan": "low", "malware": "high", "exploit": "high", "policy": "low",
}


# Integration secrets can come from a file instead of the environment: IDPS_SOC_<NAME>_FILE=path
# (Docker/Kubernetes secrets). Blank values (docker compose passes "" for an unset ${VAR:-}) mean
# "not set" for every integration setting.
SECRET_FIELDS = ("webhook_url", "webhook_secret", "slack_webhook_url", "smtp_password",
                 "abuseipdb_key", "mfa_key", "oidc_client_secret")
INTEGRATION_PREFIXES = ("notify_", "webhook_", "slack_", "smtp_", "email_", "syslog_",
                        "abuseipdb_", "oidc_", "mfa_", "sensor_mtls_", "privacy_", "report_")
# Settings where a blank value (docker compose passes "" for an unset ${VAR:-}) also means unset.
BLANK_IS_UNSET = ("alert_retention_days", "alert_retention_keep_labelled", "audit_retention_days",
                  "assistant_retention_days", "closed_case_retention_days", "auto_migrate",
                  "access_log_retention_days", "login_history_retention_days", "demo_token", "c6_token",
                  "cloud_endpoint_url")
_EMAIL = re.compile(r"^[^@\s<>,;\"]+@[^@\s<>,;\"]+$")


class SocSettings(BaseSettings):
    # hide_input_in_errors: a rejected value (an address list, a URL, a secret) is never echoed
    # into the validation error, which ends up in logs.
    model_config = SettingsConfigDict(env_prefix="IDPS_SOC_", hide_input_in_errors=True)

    # SQLite for local development; PostgreSQL in deployment, e.g.
    # postgresql+psycopg://user:pass@host/idps
    database_url: str = "sqlite:///./soc.db"
    # Signs login tokens. Required: there is deliberately no default, so a forgotten
    # setting can't leave the SOC running with a guessable key.
    # Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"
    jwt_secret: SecretStr
    access_token_minutes: int = Field(default=30, ge=5, le=24 * 60)
    # Failed logins allowed per (username, client IP) before a lockout, and per client IP.
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_max_failures_per_ip: int = Field(default=20, ge=1, le=1000)
    login_lockout_minutes: int = Field(default=15, ge=1, le=24 * 60)
    # --- MFA (soc/api/mfa.py, docs/soc.md "MFA") ------------------------------------------------
    # Admins must use an authenticator app: an admin without one is asked to enrol at login and
    # gets no access token until they do. Analysts may turn it on themselves.
    mfa_required_for_admins: bool = True
    # Encrypts the stored TOTP secrets and keys the recovery-code hashes. Optional: derived from
    # the JWT secret when unset (then changing IDPS_SOC_JWT_SECRET means everyone enrols again).
    mfa_key: SecretStr | None = None
    mfa_issuer: str = Field(default="IDPS SOC", min_length=1, max_length=40,
                            pattern=r"^[A-Za-z0-9 ._-]+$")  # the name shown in the app
    mfa_challenge_minutes: int = Field(default=10, ge=1, le=60)  # time to type the code
    mfa_max_failures: int = Field(default=5, ge=1, le=100)  # wrong codes per user per lockout
    # --- mutual TLS for sensors (soc/api/serve.py, docs/soc.md "Sensor certificates") -----------
    # When on, sensor endpoints only accept requests that came in on the mutual-TLS listener with
    # a client certificate whose common name is the sensor's name; anything else gets 401.
    sensor_mtls_required: bool = False
    # --- single sign-on with OpenID Connect (soc/api/oidc.py). Off unless issuer is set. ------
    oidc_issuer: str | None = None  # e.g. https://login.example.com/realms/soc (https only)
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    # Where the identity provider sends the browser back: the dashboard's /auth/callback page.
    oidc_redirect_uri: str | None = None
    oidc_scopes: str = "openid profile email"
    # The ID token claim matched to an existing SOC username the first time; after that the
    # account is linked to the provider's subject id and only that is used. Nobody gets an
    # account by signing in: an admin creates it first.
    oidc_username_claim: str = Field(default="preferred_username", pattern=r"^[A-Za-z0-9_.:-]+$")
    oidc_button_label: str = Field(default="Sign in with single sign-on", max_length=60)
    oidc_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    # DEV/LAB ONLY: allow an http:// issuer (a local test provider).
    oidc_allow_http: bool = False
    # Severity = base severity of the class, lowered one level when the model is unsure.
    severity_by_class: dict[str, str] = Field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_BY_CLASS))
    default_severity: str = "medium"
    low_confidence_below: float = Field(default=0.6, ge=0, le=1)
    # Maximum simultaneous /ws/alerts connections, and each one's queue of unsent alerts
    # (a client that falls this far behind is disconnected rather than slowing ingest).
    ws_max_connections: int = Field(default=50, ge=1, le=10_000)
    ws_queue_size: int = Field(default=200, ge=1, le=100_000)
    # Serve /docs and /openapi.json. Off by default: they would be the only unauthenticated
    # routes besides /health and /auth/login.
    enable_docs: bool = False
    # Cloud management (soc/api/cloud): unset (the default) = the MOCK provider, a demo inventory
    # in the SOC's own database. Set it to the URL of the LOCAL Moto emulator, for example
    # http://127.0.0.1:4566, to read from the emulator instead (read-only, fake credentials,
    # account 000000000000). Only a loopback or private http address is accepted; anything else
    # is refused and /cloud answers 503. It never talks to real AWS.
    cloud_endpoint_url: str | None = Field(default=None, max_length=200)
    # Live demo (soc/api/routes/demo.py, docs/soc.md "Live demo"): the shared secret the host-side
    # demo runner sends in X-Demo-Token. Unset or blank = demo mode off (the runner endpoints answer
    # 404 and an admin can't start a run). At least 32 characters; generate one with
    # python -c "import secrets; print(secrets.token_urlsafe(32))"
    demo_token: SecretStr | None = None
    c6_token: SecretStr | None = None  # separate host evidence worker credential
    # Addresses and networks the SOC must never ask a sensor to block: the gateways, DNS servers,
    # the SOC host, the sensors and the analysts' machines. REQUIRED for blocking: while it is
    # empty, every block request is refused (503), so a forgotten setting fails closed.
    # From the environment: IDPS_SOC_BLOCK_ALLOWLIST=10.10.1.1,10.10.2.1,192.168.1.0/24
    block_allowlist: Annotated[list[IPvAnyNetwork], NoDecode] = Field(default_factory=list)
    # Dry-run "would block" records older than this are deleted (see routes/blocks.py). Real
    # blocks are never pruned.
    would_block_retention_days: int = Field(default=7, ge=1, le=365)
    # Schema migrations at start-up (docs/soc.md, "Database"): when on (default), the SOC brings
    # an older database to the current schema itself; when off, it refuses to start unless the
    # database is already at the current revision (run `python -m soc.api db upgrade` first).
    auto_migrate: bool = True
    # Retention (soc/api/retention.py), run in the background once an hour. 0 = keep forever.
    alert_retention_days: int = Field(default=180, ge=0, le=36_500)
    # Alerts an analyst judged (confirmed / false_positive) that carry model features are the
    # training rows for export_feedback and retraining: kept past alert_retention_days when on.
    # Privacy trade-off: their IP addresses and features then stay until you turn this off.
    alert_retention_keep_labelled: bool = True
    audit_retention_days: int = Field(default=365, ge=0, le=36_500)
    assistant_retention_days: int = Field(default=90, ge=0, le=36_500)  # by last update
    closed_case_retention_days: int = Field(default=0, ge=0, le=36_500)  # by last update
    # The access log (who looked at personal data, soc/api/access_log.py).
    access_log_retention_days: int = Field(default=365, ge=0, le=36_500)
    login_history_retention_days: int = Field(default=365, ge=0, le=36_500)  # by attempt time
    # --- privacy notice (GET /privacy/notice, docs/privacy.md) and weekly report -----------------
    # All optional: blank = unset. The notice names whoever is responsible for the data.
    privacy_controller_name: str | None = Field(default=None, max_length=200)
    privacy_contact_email: str | None = None
    privacy_grievance_officer: str | None = Field(default=None, max_length=300)
    # Weekly PDF report (soc/api/reports.py). Masking hides the last octet of the addresses shown.
    report_mask_ips: bool = False
    # Emailing it (off by default) once a week through the SMTP settings below. The weekday is
    # 0 = Monday, the hour is UTC; the report is of the last complete ISO week. Recipients default
    # to smtp_to.
    report_email_enabled: bool = False
    report_email_weekday: int = Field(default=0, ge=0, le=6)
    report_email_hour_utc: int = Field(default=6, ge=0, le=23)
    report_email_to: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Attack world map. GeoLite2 City database path (free MaxMind account needed); without it,
    # public addresses can't be placed. geo_demo gives lab (private) addresses made-up,
    # clearly labelled locations for demonstrations. home_* is where the protected site is.
    geoip_db: str | None = None
    geo_demo: bool = False
    home_lat: float | None = Field(default=None, ge=-90, le=90)
    home_lon: float | None = Field(default=None, ge=-180, le=180)
    home_label: str = Field(default="Protected site", max_length=64)
    # SOC assistant (Claude). Needs Anthropic credentials in the API's environment
    # (ANTHROPIC_API_KEY); without them the assistant is switched off and the rest works.
    assistant_model: str = "claude-opus-5-5"
    assistant_effort: str = Field(default="medium", pattern="^(low|medium|high|xhigh|max)$")
    # Cost and abuse limits: messages per user per 10 minutes, and turns per conversation.
    assistant_rate_per_10min: int = Field(default=20, ge=1, le=1000)
    assistant_max_turns: int = Field(default=30, ge=1, le=200)
    # Replies running at once across all users (each holds a model call open).
    assistant_max_concurrent: int = Field(default=4, ge=1, le=100)
    # Browser origins allowed to call the API (the dashboard's dev server by default).
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"])

    # --- Integrations (docs/soc.md, "Integrations") -----------------------------------------
    # Every channel is optional and configured ONLY here (environment or *_FILE secret files),
    # never through the API; the API never returns or logs these values.
    # Base address of the dashboard, for links to an alert in notifications (blank: no link).
    public_url: str | None = None
    notify_enabled: bool = True  # kill switch for every channel
    # Notify for new alerts at or above this severity (a channel's own *_MIN_SEVERITY overrides).
    notify_min_severity: str = "high"
    # DEV/LAB ONLY. Webhook destinations must be https and public; these let a lab test use a
    # local receiver. (Slack and webhook URLs go through the same check.)
    notify_allow_private: bool = False
    notify_allow_http: bool = False
    notify_queue_size: int = Field(default=500, ge=1, le=100_000)  # per channel
    notify_max_attempts: int = Field(default=3, ge=1, le=6)
    notify_backoff_seconds: float = Field(default=1.0, ge=0, le=60)  # doubles each retry
    notify_rate_per_minute: int = Field(default=20, ge=1, le=10_000)  # per channel, then a digest
    notify_dedupe_seconds: int = Field(default=300, ge=0, le=86_400)  # 0 = off
    notify_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    # Generic webhook: JSON POST, optional HMAC-SHA256 of the body in X-IDPS-Signature.
    webhook_url: SecretStr | None = None
    webhook_secret: SecretStr | None = None
    webhook_min_severity: str | None = None
    webhook_include_rules: bool = True
    # Slack incoming webhook.
    slack_webhook_url: SecretStr | None = None
    slack_min_severity: str | None = None
    slack_include_rules: bool = True
    # Email over SMTP. smtp_security "none" is for a local test receiver only.
    smtp_host: str | None = None
    smtp_port: int | None = Field(default=None, ge=1, le=65535)  # 465 for ssl, else 587
    smtp_security: Literal["starttls", "ssl", "none"] = "starttls"
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_to: Annotated[list[str], NoDecode] = Field(default_factory=list)
    email_min_severity: str | None = None
    email_include_rules: bool = True
    # Syslog/CEF export for a SIEM. Every alert by default (low and up), no dedupe, no rate limit
    # (a SIEM wants the whole stream); blocks are sent too.
    syslog_host: str | None = None
    syslog_port: int = Field(default=514, ge=1, le=65535)
    syslog_protocol: Literal["udp", "tcp", "tls"] = "udp"
    syslog_ca_file: str | None = None  # TLS: CA that signed the receiver's certificate
    syslog_min_severity: str = "low"
    syslog_include_rules: bool = True
    syslog_include_blocks: bool = True
    syslog_idle_seconds: float = Field(default=60, gt=0, le=3600)  # reconnect a TCP/TLS link idle this long
    syslog_rate_per_minute: int = Field(default=0, ge=0, le=1_000_000)  # 0 = unlimited
    # AbuseIPDB reputation of an alert's source address (looked up only when an analyst opens
    # it). This sends that public IP to a third party; see docs/soc.md.
    abuseipdb_key: SecretStr | None = None
    abuseipdb_cache_hours: float = Field(default=24, gt=0, le=24 * 30)
    abuseipdb_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    abuseipdb_max_per_minute: int = Field(default=30, ge=1, le=10_000)  # uncached lookups
    abuseipdb_max_per_day: int = Field(default=900, ge=1, le=1_000_000)  # free tier: 1000

    @property
    def report_recipients(self) -> list[str]:
        return list(self.report_email_to or self.smtp_to)

    @property
    def smtp_port_effective(self) -> int:
        return self.smtp_port or (465 if self.smtp_security == "ssl" else 587)

    @model_validator(mode="before")
    @classmethod
    def _integration_inputs(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        for key in list(data):
            blank = isinstance(data[key], str) and not data[key].strip()
            if blank and (key.startswith(INTEGRATION_PREFIXES) or key == "public_url"
                          or key in BLANK_IS_UNSET):
                del data[key]  # blank = unset (the default applies)
        for name in SECRET_FIELDS:
            path = os.environ.get(f"IDPS_SOC_{name.upper()}_FILE", "").strip()
            if path and name not in data:
                try:
                    value = Path(path).read_text(encoding="utf-8").strip()
                except OSError as exc:  # never echo the path's content; the path is not secret
                    raise ValueError(f"IDPS_SOC_{name.upper()}_FILE cannot be read") from exc
                if value:
                    data[name] = value
        return data

    @field_validator("notify_min_severity", "syslog_min_severity", "webhook_min_severity",
                     "slack_min_severity", "email_min_severity")
    @classmethod
    def _severity_name(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip().casefold()
            if value not in SEVERITIES:
                raise ValueError(f"severity must be one of {SEVERITIES}")
        return value

    @field_validator("public_url")
    @classmethod
    def _public_url(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip().rstrip("/")
            if not re.match(r"^https?://[^\s/?#]+(/[^\s?#]*)?$", value):
                raise ValueError("IDPS_SOC_PUBLIC_URL must be an http(s) address without a query")
        return value

    @field_validator("smtp_to", "report_email_to", mode="before")
    @classmethod
    def _split_recipients(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("smtp_to", "report_email_to")
    @classmethod
    def _recipients_valid(cls, value: list[str]) -> list[str]:
        if len(value) > 20 or not all(_EMAIL.match(v) for v in value):
            raise ValueError("the recipient list must be up to 20 plain email addresses")
        return value

    @field_validator("privacy_contact_email")
    @classmethod
    def _contact_valid(cls, value: str | None) -> str | None:
        if value is not None and not _EMAIL.match(value.strip()):
            raise ValueError("IDPS_SOC_PRIVACY_CONTACT_EMAIL must be a plain email address")
        return None if value is None else value.strip()

    @field_validator("privacy_controller_name", "privacy_grievance_officer")
    @classmethod
    def _notice_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if any(not c.isprintable() for c in value):
            raise ValueError("privacy notice text must be plain, printable text")
        return value or None

    @field_validator("smtp_from")
    @classmethod
    def _sender_valid(cls, value: str | None) -> str | None:
        if value is not None and not _EMAIL.match(value.strip()):
            raise ValueError("IDPS_SOC_SMTP_FROM must be a plain email address")
        return None if value is None else value.strip()

    @field_validator("mfa_key")
    @classmethod
    def _mfa_key_long_enough(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < MIN_SECRET_LENGTH:
            raise ValueError(f"IDPS_SOC_MFA_KEY must be at least {MIN_SECRET_LENGTH} characters")
        return value

    @field_validator("demo_token", "c6_token")
    @classmethod
    def _demo_token_valid(cls, value: SecretStr | None, info) -> SecretStr | None:
        if value is None:
            return None
        secret = value.get_secret_value().strip()
        if len(secret) < MIN_SECRET_LENGTH or len(secret) > 256 or not secret.isascii() \
                or not secret.isprintable():
            raise ValueError(f"IDPS_SOC_{info.field_name.upper()} must be {MIN_SECRET_LENGTH} to 256 printable "
                             "ASCII characters")
        normalized = SecretStr(secret)
        if info.field_name == "c6_token" and normalized == info.data.get("demo_token"):
            raise ValueError("Use separate credentials for C6 and the Live Demo runner")
        return normalized

    @model_validator(mode="after")
    def _oidc_complete(self) -> "SocSettings":
        if self.oidc_issuer is None:
            return self
        self.oidc_issuer = self.oidc_issuer.strip().rstrip("/")
        scheme = ("https://", "http://") if self.oidc_allow_http else ("https://",)
        if not self.oidc_issuer.startswith(scheme) or any(c in self.oidc_issuer for c in "?# "):
            raise ValueError("IDPS_SOC_OIDC_ISSUER must be an https:// address without a query")
        missing = [n for n in ("oidc_client_id", "oidc_client_secret", "oidc_redirect_uri")
                   if getattr(self, n) is None]
        if missing:
            raise ValueError("single sign-on needs " + ", ".join(
                f"IDPS_SOC_{n.upper()}" for n in missing))
        if not re.match(r"^https?://[^\s?#]+$", self.oidc_redirect_uri or ""):
            raise ValueError("IDPS_SOC_OIDC_REDIRECT_URI must be an http(s) address")
        if "openid" not in self.oidc_scopes.split():
            raise ValueError("IDPS_SOC_OIDC_SCOPES must include openid")
        return self

    @property
    def mfa_master_key(self) -> str:
        return (self.mfa_key or self.jwt_secret).get_secret_value()

    @field_validator("jwt_secret")
    @classmethod
    def _secret_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SECRET_LENGTH:
            raise ValueError(f"IDPS_SOC_JWT_SECRET must be at least {MIN_SECRET_LENGTH} characters")
        return value

    @field_validator("severity_by_class", mode="before")
    @classmethod
    def _normalise_severity_map(cls, value: object) -> object:
        if isinstance(value, dict):
            value = {str(k).strip().casefold(): v for k, v in value.items()}
            bad = {v for v in value.values() if v not in SEVERITIES}
            if bad:
                raise ValueError(f"severities must be one of {SEVERITIES}, got {sorted(bad)}")
        return value

    @field_validator("default_severity")
    @classmethod
    def _default_severity_valid(cls, value: str) -> str:
        if value not in SEVERITIES:
            raise ValueError(f"default_severity must be one of {SEVERITIES}")
        return value

    @field_validator("geoip_db", "home_lat", "home_lon", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        # docker compose passes "" for an unset ${VAR:-}: that means "not configured".
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("home_label", mode="before")
    @classmethod
    def _blank_label_is_default(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return "Protected site"
        return value

    @field_validator("block_allowlist", mode="before")
    @classmethod
    def _split_allowlist(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value


@lru_cache
def get_settings() -> SocSettings:
    return SocSettings()
