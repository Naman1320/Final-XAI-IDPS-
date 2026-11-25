"""Helpers for the cloud tests: a pinned clock, users with chosen permissions, lookups."""

from datetime import UTC, datetime

import pytest
from iam_helpers import add_policy, add_user, headers

from soc.api.cloud import clock

T0 = datetime(2026, 3, 15, 12, 0, 30, tzinfo=UTC)
ALL_WRITES = ["cloud.instances.write", "cloud.storage.write", "cloud.network.write",
              "cloud.alerts.manage"]


class Clock:
    def __init__(self, now):
        self.value = now

    def set(self, now):
        self.value = now


@pytest.fixture
def pinned(monkeypatch):
    """The cloud clock stops at T0; `pinned.set(...)` moves it."""
    c = Clock(T0)
    monkeypatch.setattr(clock, "now", lambda: c.value)
    return c


def user_with(client, app, name, perms=()):
    add_user(app, name, perms=list(perms))
    return headers(client, name)


def denied_user(client, app, name="nocloud"):
    """An analyst whose cloud.* permissions are all taken away by a deny policy."""
    uid = add_user(app, name)
    with app.state.session_factory() as db:
        add_policy(db, f"deny cloud {name}", "deny", ["cloud.*"], attach=[("user", uid)])
    return headers(client, name)


def by_name(client, h, name):
    items = client.get("/cloud/instances", headers=h, params={"limit": 200}).json()["items"]
    return next(i for i in items if i["name"] == name)


def activity(client, h, **params):
    r = client.get("/cloud/activity", headers=h, params={"limit": 200, **params})
    assert r.status_code == 200, r.text
    return r.json()["items"]
