"""Settings of the live loop (IDPS_LIVE_* and the shared IDPS_SOC_* variables)."""

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from idps.soc_client import validate_token


class LiveSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDPS_LIVE_", populate_by_name=True)

    # Alerts below this confidence are not sent. Blocking has its own, stricter threshold
    # (IDPS_CONFIDENCE_THRESHOLD) and is not affected by this floor.
    min_alert_confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    # A micro-batch is scored when it has batch_size flows or batch_seconds have passed since
    # its first flow, whichever comes first.
    batch_size: int = Field(default=64, ge=1, le=10_000)
    batch_seconds: float = Field(default=2.0, gt=0.0, le=60.0)

    # SHAP: features per explanation, and how many alerts per batch get one (the rest are sent
    # without; the SHAP budget is < 50 ms per alert, so a flood must not turn into seconds).
    top_k: int = Field(default=5, ge=1, le=20)
    max_explanations_per_batch: int = Field(default=50, ge=0, le=1_000)
    # How many of the first BENIGN flows are kept as background for explainers that need one.
    background_size: int = Field(default=50, ge=1, le=500)

    # SOC outbox (only used when a SOC is configured): in memory, saved to outbox_file.
    outbox_max_alerts: int = Field(default=5_000, ge=1, le=1_000_000)
    outbox_file: str = "data/processed/live_outbox.json"
    # Rule (Suricata) alerts have their own cap, on top of the one above: a rule flood drops the oldest
    # RULE alerts and never a model alert.
    outbox_max_rule_alerts: int = Field(default=1_000, ge=1, le=1_000_000)
    # Without a SOC, alerts are appended here as JSON lines.
    alerts_file: str = "data/processed/live_alerts.jsonl"

    # How often the sensor asks the SOC for analyst actions (block_ip / unblock_ip); backs off
    # while the SOC is unreachable. Only used when a SOC is configured.
    action_poll_seconds: float = Field(default=5.0, ge=1.0, le=300.0)

    # How often the sensor reports its status (mode, policy, health) to the SOC; also once at
    # start. Only used when a SOC is configured.
    status_seconds: float = Field(default=30.0, ge=5.0, le=3600.0)

    # Drift monitor: how many of the latest scored flows (all of them) are compared with the
    # training data's distribution (needs `<model>.drift.json`, see idps.detect.drift).
    # Send each alert's model features and model identity, and the model sha256/version and drift
    # in the status. Switch off ONLY to run a new sensor against an older SOC, which refuses
    # unknown fields (upgrade the SOC first, then sensors; see docs/live.md).
    send_features: bool = True
    drift_window: int = Field(default=5000, ge=100, le=1_000_000)

    metrics_seconds: float = Field(default=10.0, gt=0.0)

    soc_url: str | None = Field(default=None, validation_alias=AliasChoices("IDPS_SOC_URL"))
    # IDPS_SOC_SENSOR_TOKEN is what the cloud collector and `soc.api create-sensor` use;
    # IDPS_SOC_TOKEN is accepted as a short alias.
    soc_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("IDPS_SOC_SENSOR_TOKEN", "IDPS_SOC_TOKEN"))
    soc_ca_file: str | None = Field(
        default=None, validation_alias=AliasChoices("IDPS_SOC_CA_FILE"))
    # Mutual TLS (a SOC with a sensor listener, soc/api/serve.py): this sensor's certificate,
    # whose common name is the sensor's name at the SOC, and its private key.
    soc_client_cert: str | None = Field(
        default=None, validation_alias=AliasChoices("IDPS_SOC_CLIENT_CERT"))
    soc_client_key: str | None = Field(
        default=None, validation_alias=AliasChoices("IDPS_SOC_CLIENT_KEY"))
    # Signed models (idps.detect.signing): the public key models must be signed with. When set,
    # the sensor refuses a model without a valid `<model>.sig` from that key.
    model_public_key: str | None = Field(
        default=None, validation_alias=AliasChoices("IDPS_MODEL_PUBLIC_KEY"))

    @field_validator("soc_token", mode="before")
    @classmethod
    def _clean_token(cls, value: object) -> object:
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if isinstance(value, str) and value.strip():
            return validate_token(value)  # ValueError text never contains the token
        return value

    @field_validator("soc_url", "soc_ca_file", "soc_token", "soc_client_cert", "soc_client_key",
                     "model_public_key", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def soc_configured(self) -> bool:
        return bool(self.soc_url and self.soc_token)

    @property
    def soc_half_configured(self) -> bool:
        return bool(self.soc_url) != bool(self.soc_token)

