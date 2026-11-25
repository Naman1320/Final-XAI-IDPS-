"""Runtime settings for the IDPS, overridable with IDPS_* environment variables."""

from typing import Annotated

from pydantic import Field, IPvAnyNetwork, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDPS_")

    interface: str = "eth0"
    model_path: str = "models/model.joblib"
    # How long a block lasts: at least 1 minute, at most 1 day, so a bad value
    # can never mean "block forever" or "block for 0 seconds".
    block_ttl_seconds: int = Field(default=900, ge=60, le=86_400)
    # Below 0.5 the model is more unsure than sure; a threshold of 0 would block everything.
    confidence_threshold: float = Field(default=0.9, ge=0.5, le=1.0)
    # Log what would be blocked instead of touching nftables.
    dry_run: bool = True
    # After an analyst unblocks an address, the automatic policy leaves it alone for this long
    # (alerts are still produced). An analyst block of the address ends the grace period.
    # At most a year: the SOC's status report accepts no more (soc/api/routes/sensors.py).
    unblock_grace_seconds: int = Field(default=3600, ge=0, le=31_536_000)
    # At most this many analyst blocks active on the sensor at once (further ones are refused).
    max_analyst_blocks: int = Field(default=1000, ge=1, le=100_000)
    # Optional: the JSON written by `python -m idps.explain faithfulness`. The live sensor reports
    # its model-level numbers in its status (the dashboard's "Can I trust it?" card).
    faithfulness_report: str | None = None
    # Addresses or networks that must never be blocked: gateway, DNS, SOC host, analyst AND the
    # servers being protected (a flow's source can be a server's reply, so the allowlist is the
    # real safeguard for them).
    # From the environment: IDPS_ALLOWLIST=10.10.1.1,10.10.2.0/24
    allowlist: Annotated[list[IPvAnyNetwork], NoDecode] = Field(default_factory=list)

    @field_validator("allowlist", mode="before")
    @classmethod
    def _split_allowlist(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @model_validator(mode="after")
    def _require_allowlist_when_blocking(self) -> "Settings":
        if not self.dry_run and not self.allowlist:
            raise ValueError(
                "dry_run is off but the allowlist is empty: set IDPS_ALLOWLIST "
                "(gateway, DNS, SOC host, analyst) before enabling real blocking"
            )
        return self


def get_settings() -> Settings:
    return Settings()
