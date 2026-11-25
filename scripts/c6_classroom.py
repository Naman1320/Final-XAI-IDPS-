"""Serve the built dashboard and a fresh local SOC for a recorded C6 classroom demonstration."""
import getpass
import os
import secrets
import signal
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from soc.api import auth, pki, security
from soc.api.main import create_app
from soc.api.models import Role
from soc.api.settings import SocSettings

DIST = Path(__file__).resolve().parents[1] / "soc/web/dist"
PORT = 8766


def main():
    if not (DIST / "index.html").is_file():
        sys.exit("Build the dashboard with npm --prefix soc/web run build first.")
    password = getpass.getpass("Choose a temporary classroom admin password (12+ characters): ")
    security.check_password_policy(password)
    # This process owns a temporary SOC. Never inherit production integrations or DB settings.
    for name in list(os.environ):
        if name.startswith(("IDPS_SOC_", "ANTHROPIC_")):
            del os.environ[name]
    token = secrets.token_urlsafe(40)
    with TemporaryDirectory(prefix="idps-c6-classroom-") as directory:
        tmp = Path(directory)
        settings = SocSettings(database_url=f"sqlite:///{tmp/'classroom.db'}", c6_token=token,
                               jwt_secret=secrets.token_urlsafe(48), mfa_required_for_admins=False)
        soc = create_app(settings)
        with soc.state.session_factory() as db:
            auth.create_user(db, "admin", password, Role.ADMIN)
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        app.mount("/api", soc)
        app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

        @app.get("/{page:path}")
        def dashboard(page: str):
            return FileResponse(DIST / "index.html")

        ca_key, ca_cert = pki.make_ca("C6 temporary local CA", days=1)
        key, cert = pki.issue_server_cert(ca_key, ca_cert, "localhost", ["localhost", "127.0.0.1"], days=1)
        pki.write_private(tmp / "key.pem", pki.key_pem(key))
        pki.write_public(tmp / "cert.pem", pki.cert_pem(cert))
        pki.write_public(tmp / "ca.pem", pki.cert_pem(ca_cert))
        origin = f"https://127.0.0.1:{PORT}"
        worker = subprocess.Popen([sys.executable, "-m", "scripts.c6_worker", "--soc-url",
                                   origin + "/api", "--ca-file", str(tmp / "ca.pem")],
                                  env={**os.environ, "IDPS_SOC_C6_TOKEN": token})
        print(f"Classroom dashboard {origin}/c6  |  username admin", flush=True)
        try:
            uvicorn.run(app, host="127.0.0.1", port=PORT, ssl_keyfile=str(tmp/"key.pem"),
                        ssl_certfile=str(tmp/"cert.pem"), access_log=False)
        finally:
            worker.send_signal(signal.SIGINT)
            worker.wait()


if __name__ == "__main__":
    main()
