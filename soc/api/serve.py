"""Run the SOC API with a second, mutual-TLS listener for sensors (roadmap step 11).

    python -m soc.api.serve --port 8443 --ssl-keyfile K --ssl-certfile C \\
        --sensor-port 8444 --sensor-ca sensor-ca.pem

Without --ssl-keyfile/--ssl-certfile the main listener serves plain HTTP, for a deployment behind a
TLS-terminating proxy (deploy/, docs/deploy.md; add --proxy-headers and --forwarded-allow-ips).
The sensor listener always needs TLS: --sensor-ssl-keyfile/--sensor-ssl-certfile (default: the
main ones; an error when neither pair is given).

Both listeners serve ONE application in ONE process (the live feed and the throttles are
in-process). The sensor listener:

- requires a client certificate signed by --sensor-ca (the TLS handshake fails without one, so
  a client with no certificate never reaches the application);
- serves only the sensor endpoints (/ingest/..., /sensor/..., /health): 404 for the rest;
- passes the certificate's common name and SHA-256 fingerprint to the application, which checks
  the common name is the name of the sensor whose token came with the request (auth.py). So a
  stolen token is useless without that sensor's private key, and one sensor's certificate cannot
  speak for another sensor.

With IDPS_SOC_SENSOR_MTLS_REQUIRED=true the sensor endpoints on the main listener refuse every
request, so all sensors must use this one.

uvicorn does not pass client certificates to the application, so the sensor listener uses
MtlsH11Protocol, a small subclass of uvicorn's h11 protocol that adds them to each request's
scope under extensions["idps.client_cert"] (a client cannot set extensions). It depends on
uvicorn's h11 protocol assigning `self.scope` per request (true for uvicorn 0.30 to 0.54);
tests/test_soc_mtls.py runs a real server and fails if that changes.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import ssl
import sys

import uvicorn
from cryptography import x509
from cryptography.x509.oid import NameOID
from uvicorn.protocols.http.h11_impl import H11Protocol

CERT_EXTENSION = "idps.client_cert"
SENSOR_PATHS = ("/ingest/", "/sensor/")
SENSOR_EXACT = ("/health",)
log = logging.getLogger("soc.serve")


def cert_identity(der: bytes | None) -> dict | None:
    """{"cn", "sha256"} of a DER certificate (None for no certificate or no single CN)."""
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(names) != 1:
        return {"cn": None, "sha256": hashlib.sha256(der).hexdigest()}
    return {"cn": str(names[0].value), "sha256": hashlib.sha256(der).hexdigest()}


class MtlsH11Protocol(H11Protocol):
    """uvicorn's h11 protocol, plus the verified client certificate in every request's scope."""

    _idps_cert: dict | None = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        self._idps_cert = cert_identity(der)

    @property
    def scope(self):  # type: ignore[override]
        return self.__dict__.get("_idps_scope")

    @scope.setter
    def scope(self, value) -> None:
        if isinstance(value, dict):
            value.setdefault("extensions", {})[CERT_EXTENSION] = (
                dict(self._idps_cert) if self._idps_cert else None)
        self.__dict__["_idps_scope"] = value


class SensorOnly:
    """ASGI wrapper for the sensor listener: only the sensor endpoints, and never a WebSocket."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if scope["type"] != "http" or not (path in SENSOR_EXACT or path.startswith(SENSOR_PATHS)):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            body = b'{"detail":"not found"}'
            await send({"type": "http.response.start", "status": 404, "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


def sensor_config(app, host: str, port: int, keyfile: str, certfile: str, ca: str,
                  **kw) -> uvicorn.Config:
    return uvicorn.Config(
        SensorOnly(app), host=host, port=port, http=MtlsH11Protocol, ws="none",
        lifespan="off",  # the main listener runs the app's start-up and shut-down
        ssl_keyfile=keyfile, ssl_certfile=certfile, ssl_ca_certs=ca,
        ssl_cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLS_SERVER,
        # sensors connect directly: never trust X-Forwarded-For from them (it would let a sensor
        # choose the address the SOC records)
        **{"proxy_headers": False, **kw})


def make_servers(main_cfg: uvicorn.Config,
                 sensor_cfg: uvicorn.Config | None) -> list[uvicorn.Server]:
    return [uvicorn.Server(main_cfg)] + ([uvicorn.Server(sensor_cfg)] if sensor_cfg else [])


async def serve(main_cfg: uvicorn.Config, sensor_cfg: uvicorn.Config | None,
                servers: list[uvicorn.Server] | None = None) -> None:
    """Run both listeners until either stops (set `should_exit` on one to stop both)."""
    servers = servers or make_servers(main_cfg, sensor_cfg)
    tasks = [asyncio.create_task(s.serve()) for s in servers]
    # When either stops (a signal, or a failed start such as a port in use), stop the other.
    done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for s in servers:
        s.should_exit = True
    await asyncio.gather(*tasks, return_exceptions=True)
    for t in done:
        if t.exception() is not None:
            raise t.exception()
    if any(not s.started for s in servers):
        raise SystemExit(1)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate the command line (exit status 2 with one line on a bad combination)."""
    p = argparse.ArgumentParser(prog="python -m soc.api.serve")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--ssl-keyfile", default=None,
                   help="TLS private key of the main listener (omit both --ssl-* options to serve "
                        "plain HTTP, only behind a TLS-terminating proxy such as Caddy)")
    p.add_argument("--ssl-certfile", default=None)
    p.add_argument("--sensor-port", type=int, default=None,
                   help="mutual-TLS listener for sensors (off when not given)")
    p.add_argument("--sensor-ca", default=None,
                   help="CA certificate (PEM) that signs the sensors' client certificates")
    p.add_argument("--sensor-ssl-keyfile", default=None,
                   help="TLS private key of the sensor listener (default: --ssl-keyfile)")
    p.add_argument("--sensor-ssl-certfile", default=None,
                   help="TLS certificate of the sensor listener (default: --ssl-certfile)")
    p.add_argument("--ws-max-size", type=int, default=65536)
    p.add_argument("--proxy-headers", action="store_true",
                   help="trust X-Forwarded-For/-Proto from --forwarded-allow-ips (main listener)")
    p.add_argument("--forwarded-allow-ips", default=None,
                   help="comma-separated proxy addresses whose forwarded headers are trusted "
                        "(uvicorn's default: 127.0.0.1). '*' trusts every peer: only when the "
                        "port is reachable by the proxy alone")
    args = p.parse_args(argv)
    if (args.ssl_keyfile is None) != (args.ssl_certfile is None):
        p.error("--ssl-keyfile and --ssl-certfile go together")
    if (args.sensor_port is None) != (args.sensor_ca is None):
        p.error("--sensor-port and --sensor-ca go together")
    if (args.sensor_ssl_keyfile is None) != (args.sensor_ssl_certfile is None):
        p.error("--sensor-ssl-keyfile and --sensor-ssl-certfile go together")
    if args.sensor_port is None and args.sensor_ssl_keyfile is not None:
        p.error("--sensor-ssl-keyfile/--sensor-ssl-certfile need --sensor-port")
    if args.sensor_port is not None:
        if args.sensor_ssl_keyfile is None:
            args.sensor_ssl_keyfile, args.sensor_ssl_certfile = args.ssl_keyfile, args.ssl_certfile
        if args.sensor_ssl_keyfile is None:  # the sensor listener never runs without TLS
            p.error("--sensor-port needs a TLS certificate: give --sensor-ssl-keyfile and "
                    "--sensor-ssl-certfile (or --ssl-keyfile and --ssl-certfile)")
    return args


def build_configs(args: argparse.Namespace, app) -> tuple[uvicorn.Config, uvicorn.Config | None]:
    """uvicorn configs for the main listener (TLS only when a certificate is given) and, when
    --sensor-port is set, the sensor listener (always TLS with a required client certificate)."""
    kw: dict = {}
    if args.ssl_keyfile:
        kw.update(ssl_keyfile=args.ssl_keyfile, ssl_certfile=args.ssl_certfile)
    if args.forwarded_allow_ips is not None:
        kw["forwarded_allow_ips"] = args.forwarded_allow_ips
    main_cfg = uvicorn.Config(app, host=args.host, port=args.port, ws_max_size=args.ws_max_size,
                              proxy_headers=args.proxy_headers, **kw)
    sensor_cfg = None
    if args.sensor_port is not None:
        sensor_cfg = sensor_config(app, args.host, args.sensor_port, args.sensor_ssl_keyfile,
                                   args.sensor_ssl_certfile, args.sensor_ca)
    return main_cfg, sensor_cfg


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    from soc.api.main import create_app

    app = create_app()
    if app.state.settings.sensor_mtls_required and args.sensor_port is None:
        print("error: IDPS_SOC_SENSOR_MTLS_REQUIRED is on but no --sensor-port is given",
              file=sys.stderr)
        return 1
    main_cfg, sensor_cfg = build_configs(args, app)
    if not args.ssl_keyfile:
        log.warning("the main listener serves plain HTTP: keep it behind a TLS proxy")
    asyncio.run(serve(main_cfg, sensor_cfg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
