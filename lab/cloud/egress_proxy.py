"""Emulator-only HTTP proxy for Terraform (docs/cloud-plan.md, step C1).

lab/cloud/tf.sh starts it on 127.0.0.1 and sets HTTP_PROXY/HTTPS_PROXY for plan/apply/destroy.
It does two jobs:

1. S3 Control puts the account id in front of the endpoint's host name
   (http://000000000000.localhost:4566/...). Nothing resolves that name, so the provider can't
   read bucket tags. The proxy sends any *.localhost:4566 request to the emulator instead.
2. It is a second fence after the billing guard: plain-HTTP requests for any other host get
   403, and HTTPS tunnels (CONNECT) are always refused, so Terraform can't reach real AWS even
   if an endpoint were left unset.

    python lab/cloud/egress_proxy.py --port 0 --upstream 127.0.0.1:4566
Prints the port it listens on as the first line of stdout.
"""

from __future__ import annotations

import argparse
import http.client
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MAX_BODY = 64 * 1024 * 1024  # far above any Terraform request to the emulator
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def allowed(host: str | None, port: int | None, emulator_port: int) -> bool:
    """True only for the emulator: 127.0.0.1, localhost or *.localhost on the emulator port."""
    if not host or port != emulator_port:
        return False
    host = host.lower().rstrip(".")
    return host in ("127.0.0.1", "localhost") or host.endswith(".localhost")


class Handler(BaseHTTPRequestHandler):
    upstream_host = "127.0.0.1"
    upstream_port = 4566
    protocol_version = "HTTP/1.1"
    timeout = 30  # a client that stops sending mid-request can't hold a thread forever

    def log_message(self, fmt: str, *args) -> None:  # quiet; refusals are logged below
        pass

    def _refuse(self, why: str) -> None:
        sys.stderr.write(f"egress proxy: refused {self.command} {self.path} ({why})\n")
        body = f"refused by the emulator-only proxy: {why}\n".encode()
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_CONNECT(self) -> None:
        self._refuse("HTTPS tunnels are never allowed")

    def _bad_request(self, why: str) -> None:
        sys.stderr.write(f"egress proxy: bad request {self.command} {self.path} ({why})\n")
        self.send_error(400, why)
        self.close_connection = True

    def _body(self) -> bytes:
        """The request body; ValueError for a malformed or negative length or a short read."""
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            out = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                if size < 0 or len(out) + size > MAX_BODY:
                    raise ValueError("bad chunk size")
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass  # trailers
                    return bytes(out)
                chunk = self.rfile.read(size)
                if len(chunk) != size:
                    raise ValueError("body ended early")
                out += chunk
                self.rfile.readline()
        lengths = self.headers.get_all("Content-Length") or []
        if len({v.strip() for v in lengths}) > 1:
            raise ValueError("conflicting Content-Length headers")
        length = int(lengths[0]) if lengths else 0
        if length < 0 or length > MAX_BODY:
            raise ValueError("bad Content-Length")
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            raise ValueError("body ended early")
        return body

    def _forward(self) -> None:
        url = urlsplit(self.path)
        if url.scheme != "http":
            self._refuse("only absolute http:// URLs are proxied")
            return
        try:
            port = url.port
        except ValueError:
            port = None
        if not allowed(url.hostname, port, self.upstream_port):
            self._refuse(f"{url.hostname}:{port} is not the emulator")
            return
        try:
            body = self._body()
        except ValueError as exc:
            self._bad_request(str(exc))
            return
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        conn = http.client.HTTPConnection(self.upstream_host, self.upstream_port, timeout=60)
        try:
            # Headers are passed through in order, repeats kept, the Host header unchanged (it
            # is part of the SigV4 signature). Framing headers are rebuilt from the body read.
            conn.putrequest(self.command, path, skip_host=True, skip_accept_encoding=True)
            for key, value in self.headers.items():
                if key.lower() not in HOP_BY_HOP and key.lower() != "content-length":
                    conn.putheader(key, value)
            if body or self.command in ("POST", "PUT", "PATCH"):
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body or None)
            resp = conn.getresponse()
            data = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            self.send_error(502, f"emulator unreachable: {exc}")
            return
        finally:
            conn.close()
        self.send_response_only(resp.status, resp.reason)
        for key, value in resp.getheaders():
            if key.lower() not in HOP_BY_HOP and key.lower() != "content-length":
                self.send_header(key, value)
        if self.command == "HEAD":
            # A HEAD reply has no body but reports the size the GET would have.
            if resp.getheader("Content-Length") is not None:
                self.send_header("Content-Length", resp.getheader("Content-Length"))
        elif resp.status not in (204, 304) and not 100 <= resp.status < 200:
            self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD" and resp.status not in (204, 304):
            self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _forward


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=0, help="listen port on 127.0.0.1 (0 = any free)")
    ap.add_argument("--upstream", default="127.0.0.1:4566", help="emulator host:port")
    args = ap.parse_args()
    host, _, port = args.upstream.rpartition(":")
    Handler.upstream_host, Handler.upstream_port = host, int(port)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(server.server_address[1], flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
