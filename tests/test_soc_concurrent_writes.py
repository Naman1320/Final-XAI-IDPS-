"""Exercise cross-session check-and-write invariants on a file DB (or the test PostgreSQL DB)."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from conftest import ADMIN_PW, login
from fastapi.testclient import TestClient

from soc.api import auth
from soc.api.main import create_app
from soc.api.models import Role


def test_simultaneous_name_checks_and_address_allocation(soc_settings, tmp_path):
    if soc_settings.database_url == "sqlite://":
        soc_settings = soc_settings.model_copy(update={"database_url": f"sqlite:///{tmp_path}/soc.db"})
    app = create_app(soc_settings)
    with app.state.session_factory() as db:
        auth.create_user(db, "admin", ADMIN_PW, Role.ADMIN)
    with TestClient(app) as client:
        headers = login(client, "admin", ADMIN_PW)
        subnet = next(s for s in client.get("/cloud/network/subnets", headers=headers).json()["items"]
                      if s["public"])
        sg = next(g for g in client.get("/cloud/network/security-groups", headers=headers).json()["items"]
                  if g["vpc_id"] == subnet["vpc_id"])

        def race(path, bodies):
            gate = Barrier(len(bodies))

            def submit(body):
                gate.wait(timeout=10)
                return client.post(path, headers=headers, json=body)

            with ThreadPoolExecutor(max_workers=len(bodies)) as pool:
                return list(pool.map(submit, bodies))

        roles = race("/iam/roles", [{"name": "Operators"}, {"name": "OPERATORS"}])
        assert sorted(r.status_code for r in roles) == [201, 409]
        body = {"name": "new", "subnet_id": subnet["id"], "instance_type": "t3.micro",
                "security_group_ids": [sg["id"]]}
        instances = race("/cloud/instances", [body, body])
        assert all(r.status_code == 201 for r in instances)
        for field in ("private_ip", "public_ip"):
            assert len({r.json()[field] for r in instances}) == 2
