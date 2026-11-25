"""Shared pieces of the cloud routes: the request context, response envelope, field types,
the activity + audit record, and the transaction helper."""

import contextlib
import logging
import re
from collections.abc import Callable, Iterator
from functools import cached_property
from typing import Annotated, Generic, TypeVar

from fastapi import Depends, HTTPException, Path, Query, Request, status
from pydantic import AfterValidator, BaseModel, Field
from sqlalchemy.orm import Session

from soc.api.cloud import catalog, clock
from soc.api.cloud.provider import (
    EmulatedAwsProvider,
    MockProvider,
    ProviderUnavailable,
)
from soc.api.common import audit, plain_text
from soc.api.db import get_db, serialize_writes
from soc.api.iam import engine
from soc.api.iam.deps import require_permission
from soc.api.models import CloudActivity, CloudVpc, User

log = logging.getLogger("soc.cloud")
T = TypeVar("T")

# --- permissions ------------------------------------------------------------------------------
VIEW = "cloud.view"
INSTANCES = "cloud.instances.write"
STORAGE = "cloud.storage.write"
NETWORK = "cloud.network.write"
ALERTS = "cloud.alerts.manage"


# --- response envelope --------------------------------------------------------------------------

class Sourced(BaseModel):
    """Every response that returns inventory, metrics or cost says where it came from."""

    data_source: str
    data_source_label: str
    note: str | None = None  # on a change: what it did and did not touch


class Paged(Sourced, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


Limit = Annotated[int, Query(ge=1, le=catalog.MAX_PAGE)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
ResourceId = Annotated[str, Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")]


def page(items: list, limit: int, offset: int) -> tuple[list, int]:
    return items[offset:offset + limit], len(items)


# --- field types ------------------------------------------------------------------------------

def _plain(value: str) -> str:
    return plain_text(value)


Name = Annotated[str, Field(min_length=1, max_length=63, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
                 AfterValidator(_plain)]
Description = Annotated[str, Field(max_length=255), AfterValidator(_plain)]
_TAG_KEY = re.compile(r"^[A-Za-z0-9 _.:/=+@-]{1,64}$")


def _tags(value: dict[str, str]) -> dict[str, str]:
    if len(value) > catalog.MAX_TAGS:
        raise ValueError(f"at most {catalog.MAX_TAGS} tags")
    for k, v in value.items():
        if not _TAG_KEY.match(k):
            raise ValueError("a tag key is 1 to 64 letters, digits or _ . : / = + @ - or space")
        if len(v) > 128:
            raise ValueError("a tag value is at most 128 characters")
        plain_text(v)
    return value


Tags = Annotated[dict[str, str], AfterValidator(_tags)]


# --- the request context ----------------------------------------------------------------------

class Ctx:
    """The signed-in user, the session and (built on first use, so a refused request never
    touches the inventory) the provider."""

    def __init__(self, request: Request, user: User, db: Session) -> None:
        self.request, self.user, self.db = request, user, db

    def ready(self) -> None:
        """Build the provider now: the first authorised request seeds the demo data, before any
        handler reads a table (an unauthorised one never gets this far)."""
        _ = self.provider

    @cached_property
    def provider(self):
        url = self.request.app.state.settings.cloud_endpoint_url
        try:
            if url:
                cached = getattr(self.request.app.state, "cloud_emulated", None)
                if cached is None:
                    cached = EmulatedAwsProvider.from_endpoint(url)
                    self.request.app.state.cloud_emulated = cached
                return cached
            mock = MockProvider(self.db)
            mock.prepare()
            return mock
        except ProviderUnavailable as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    @cached_property
    def mock(self) -> MockProvider:
        """The provider for a change: only the mock accepts them."""
        provider = self.provider
        if not isinstance(provider, MockProvider):
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "the emulated AWS provider is read-only; changes are only "
                                "possible on the mock inventory")
        return provider

    def require_mock(self) -> MockProvider:
        return self.mock

    def sourced(self) -> dict:
        p = self.provider
        return {"data_source": p.data_source, "data_source_label": p.data_source_label}

    def changed(self) -> dict:
        from soc.api.cloud.provider import MOCK_NOTE

        return {**self.sourced(), "note": MOCK_NOTE}

    def allowed_on(self, permission: str, resource: str) -> None:
        """403 if a policy scoped to this resource takes `permission` away from the user here
        (the route's own check asks about "any resource")."""
        if not engine.allows(self.db, self.user, permission, resource):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"a policy denies {permission} on {resource}")


def reader() -> Callable[..., Ctx]:
    check = require_permission(VIEW)

    def dependency(request: Request, user: Annotated[User, Depends(check)],
                   db: Annotated[Session, Depends(get_db)]) -> Ctx:
        ctx = Ctx(request, user, db)
        ctx.ready()
        return ctx

    return dependency


def writer(*permissions: str) -> Callable[..., Ctx]:
    """The user must hold ALL `permissions`; writes are limited per user per minute (429)."""
    check = require_permission(*permissions)

    def dependency(request: Request, user: Annotated[User, Depends(check)],
                   db: Annotated[Session, Depends(get_db)]) -> Ctx:
        limiter = getattr(request.app.state, "cloud_limiter", None)
        if limiter is not None and not limiter.allow(user.id):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "too many changes; slow down", headers={"Retry-After": "60"})
        ctx = Ctx(request, user, db)
        ctx.require_mock()
        serialize_writes(db, CloudVpc)
        return ctx

    return dependency


Read = Annotated[Ctx, Depends(reader())]
WriteInstances = Annotated[Ctx, Depends(writer(INSTANCES))]
WriteStorage = Annotated[Ctx, Depends(writer(STORAGE))]
WriteNetwork = Annotated[Ctx, Depends(writer(NETWORK))]
ManageAlerts = Annotated[Ctx, Depends(writer(ALERTS))]
WriteAll = Annotated[Ctx, Depends(writer(INSTANCES, STORAGE, NETWORK, ALERTS))]


# --- changes ---------------------------------------------------------------------------------------

def record(db: Session, user: User, action: str, rtype: str, rid: str,
           details: dict | None = None) -> None:
    """The cloud activity row AND the audit row of one change, added to the session (committed
    with the change, so neither exists without it). Never put a secret in `details`."""
    details = {"data_source": "mock", **(details or {})}
    db.add(CloudActivity(at=clock.now(), actor=user.username, action=action, resource_type=rtype,
                         resource_id=rid, details=details))
    audit(db, user, "cloud_" + action.replace(".", "_"), f"{rtype}:{rid}", details)


@contextlib.contextmanager
def atomic(db: Session) -> Iterator[None]:
    """Commit at the end; roll everything back if anything raises."""
    try:
        yield
        db.commit()
    except BaseException:
        db.rollback()
        raise


def not_found(what: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")


def conflict(message: str) -> HTTPException:
    return HTTPException(status.HTTP_409_CONFLICT, message)


def unprocessable(message: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, message)
