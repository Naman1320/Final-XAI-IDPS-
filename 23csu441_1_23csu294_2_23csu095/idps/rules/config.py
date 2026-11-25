"""Settings of the rule forwarder (IDPS_RULES_*). Off unless IDPS_RULES_EVE names Suricata's eve.json."""

from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class RulesSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDPS_RULES_", populate_by_name=True)

    # The eve.json Suricata writes (the lab's `suricata` service shares it read-only with the
    # sensor). Unset: the forwarder is off and nothing about rules is sent.
    eve: str | None = None
    # Informational alerts (ET INFO / ET POLICY / GPL ICMP_INFO ..., idps.rules.eve) are dropped
    # unless this is on.
    include_info: bool = False
    # The same (sid, src, dst, dst port) within this many seconds is ONE alert plus, when it
    # repeated, one follow-up with the count. 0 sends every event.
    dedupe_seconds: float = Field(default=60.0, ge=0.0, le=3600.0)
    # Rules (Suricata signature ids) whose alerts may trigger an automatic block, through the same
    # policy, allowlist and dry-run as the model's detections. Empty: rules never block.
    block_sids: Annotated[list[int], NoDecode] = Field(default_factory=list)
    # At most this many rule alerts are queued per minute (first events and follow-ups alike); the rest
    # are dropped and counted as `rate_limited`. 0 = no limit. Blocking is not affected.
    max_per_minute: int = Field(default=120, ge=0, le=100_000)
    # The networks you protect. A rule hit whose SOURCE is inside one is never handed to the response
    # engine (a forged or reflected packet must not get a server blocked), in addition to
    # IDPS_ALLOWLIST. Comma list; empty = no extra check. The lab sets 10.10.2.0/24 (lab/sensor/live.sh).
    protected_nets: Annotated[list[IPv4Network | IPv6Network], NoDecode] = Field(default_factory=list)
    # Read an existing eve file from its start instead of its end (replays history; for tests).
    from_start: bool = False
    poll_seconds: float = Field(default=0.5, ge=0.05, le=30.0)

    @field_validator("eve", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("block_sids", mode="before")
    @classmethod
    def _split_sids(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("protected_nets", mode="before")
    @classmethod
    def _split_nets(cls, value: object) -> object:
        if isinstance(value, str):
            return [ip_network(part.strip(), strict=False) for part in value.split(",") if part.strip()]
        return value

    @field_validator("block_sids")
    @classmethod
    def _sids_valid(cls, value: list[int]) -> list[int]:
        if any(not 1 <= s <= 2**32 for s in value):
            raise ValueError("IDPS_RULES_BLOCK_SIDS must be Suricata signature ids (positive integers)")
        return sorted(set(value))

    @property
    def enabled(self) -> bool:
        return bool(self.eve)
