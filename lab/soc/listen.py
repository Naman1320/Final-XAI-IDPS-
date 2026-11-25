"""Lab-only receivers for trying the SOC's integrations (docs/soc.md, "Integrations").

The lab SOC can't open outbound connections (lab/soc/netguard.sh), so it can't reach Slack, a mail
server or a SIEM. Run these inside the SOC's own network namespace and point the integrations at
127.0.0.1:

    docker compose exec soc python /opt/idps/lab/soc/listen.py http 9000
    docker compose exec soc python /opt/idps/lab/soc/listen.py syslog 5514
    docker compose exec soc python /opt/idps/lab/soc/listen.py smtp 2525

http: prints each POST and whether its X-IDPS-Signature (HMAC over "<X-IDPS-Timestamp>.<body>")
matches LISTEN_HMAC_SECRET (if set) and the timestamp is within 5 minutes.
syslog: listens on UDP and TCP (octet-counted frames) on the same port.
smtp: accepts any mail without authentication and prints it.
"""

import hashlib
import hmac
import os
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"  # never listen beyond the container's loopback


class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        secret = os.environ.get("LISTEN_HMAC_SECRET", "").encode()
        sig = self.headers.get("X-IDPS-Signature")
        stamp = self.headers.get("X-IDPS-Timestamp", "")
        check = ""
        if secret:
            # signature = HMAC-SHA256(secret, "<timestamp>." + body); reject stale timestamps
            good = "sha256=" + hmac.new(secret, stamp.encode() + b"." + body,
                                        hashlib.sha256).hexdigest()
            fresh = stamp.isdigit() and abs(time.time() - int(stamp)) <= 300
            ok = bool(sig) and hmac.compare_digest(sig, good)
            check = f"  signature {'OK' if ok else 'WRONG'}, timestamp {'fresh' if fresh else 'STALE'}"
        print(f"POST {self.path.split('?')[0]}{check}\n{body.decode('utf-8', 'replace')}\n",
              flush=True)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def http(port: int) -> None:
    ThreadingHTTPServer((HOST, port), Hook).serve_forever()


class SyslogTcp(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            length = b""
            while (c := self.rfile.read(1)) not in (b" ", b""):
                length += c
            if not length.isdigit():
                return
            print("TCP", self.rfile.read(int(length)).decode("utf-8", "replace"), flush=True)


def syslog(port: int) -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((HOST, port))

    def loop():
        while True:
            print("UDP", udp.recvfrom(65535)[0].decode("utf-8", "replace"), flush=True)

    threading.Thread(target=loop, daemon=True).start()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer((HOST, port), SyslogTcp).serve_forever()


class Smtp(socketserver.StreamRequestHandler):
    def handle(self):
        def say(text):
            self.wfile.write(text.encode() + b"\r\n")

        say("220 lab-listener")
        while line := self.rfile.readline():
            cmd = line.decode().strip()
            if cmd.upper() == "DATA":
                say("354 end with a dot")
                data = []
                while (row := self.rfile.readline()) not in (b".\r\n", b""):
                    data.append(row.decode("utf-8", "replace"))
                print("MAIL\n" + "".join(data), flush=True)
                say("250 queued")
            elif cmd.upper() == "QUIT":
                say("221 bye")
                return
            else:
                say("250 ok")


def smtp(port: int) -> None:
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer((HOST, port), Smtp).serve_forever()


if __name__ == "__main__":
    kinds = {"http": http, "syslog": syslog, "smtp": smtp}
    if len(sys.argv) != 3 or sys.argv[1] not in kinds or not sys.argv[2].isdigit():
        sys.exit(__doc__)
    print(f"listening on {HOST}:{sys.argv[2]} ({sys.argv[1]})", flush=True)
    kinds[sys.argv[1]](int(sys.argv[2]))
