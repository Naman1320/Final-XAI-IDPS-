"""The cloud module's clock, in one place so tests can pin it."""

from datetime import UTC, datetime


def now() -> datetime:
    return datetime.now(UTC)
