"""The delivery channels. Each knows how to send one item (an event, a digest or a test) and
nothing about queues, retries or limits (manager.py). Errors raised are `DeliveryError`s whose
text never holds a URL, a secret or an address."""

from __future__ import annotations

import hashlib
import hmac
import json
import select
import smtplib
import socket
import ssl
import threading
import time
from email.message import EmailMessage
from urllib.parse import urlsplit

from soc.api.integrations import formats, netguard
from soc.api.integrations.formats import Item
from soc.api.integrations.netguard import DeliveryError, UnsafeDestination, Watchdog
from soc.api.settings import SocSettings

CHANNEL_NAMES = ("webhook", "slack", "email", "syslog")


class Channel:
    name = ""
    accepts_blocks = False
    use_limits = True  # dedupe and rate limit/digest (off for the SIEM stream by default)

    def __init__(self, settings: SocSettings) -> None:
        self.s = settings
        self.rate_per_minute = settings.notify_rate_per_minute
        self.dedupe_seconds = settings.notify_dedupe_seconds

    # configured / hint / thresholds -------------------------------------------------------
    @property
    def configured(self) -> bool:
        raise NotImplementedError

    @property
    def min_severity(self) -> str:
        raise NotImplementedError

    @property
    def include_rules(self) -> bool:
        return True

    def target_hint(self) -> str | None:
        return None

    def secrets(self) -> list[str]:
        """Secret strings to scrub from any error text, as a last line of defence."""
        return []

    def send(self, item: Item) -> None:
        raise NotImplementedError

    def close(self) -> None:
        return None


class _HttpChannel(Channel):
    def _url(self) -> str:
        raise NotImplementedError

    def _target(self) -> netguard.Target:
        try:
            return netguard.resolve_target(
                self._url(), allow_private=self.s.notify_allow_private,
                allow_http=self.s.notify_allow_http, resolver=self.resolver)
        except UnsafeDestination as exc:
            raise DeliveryError(f"destination refused: {exc}", retryable=False) from exc

    resolver = staticmethod(socket.getaddrinfo)
    ssl_context: ssl.SSLContext | None = None  # tests trust a throwaway CA here

    def _post(self, body: bytes, extra: dict[str, str] | None = None) -> None:
        headers = {"Content-Type": "application/json", "User-Agent": "idps-soc",
                   "Content-Length": str(len(body))} | (extra or {})
        netguard.check_status(netguard.post(self._target(), body, headers,
                                            self.s.notify_timeout_seconds, self.ssl_context))

    def target_hint(self) -> str | None:
        url = self._url()
        try:
            return urlsplit(url).hostname  # the host only: the path/token is the secret
        except ValueError:
            return None

    def secrets(self) -> list[str]:
        return [self._url()]


class WebhookChannel(_HttpChannel):
    name = "webhook"

    @property
    def configured(self) -> bool:
        return self.s.webhook_url is not None

    @property
    def min_severity(self) -> str:
        return self.s.webhook_min_severity or self.s.notify_min_severity

    @property
    def include_rules(self) -> bool:
        return self.s.webhook_include_rules

    def _url(self) -> str:
        return self.s.webhook_url.get_secret_value() if self.s.webhook_url else ""

    def secrets(self) -> list[str]:
        return super().secrets() + ([self.s.webhook_secret.get_secret_value()]
                                    if self.s.webhook_secret else [])

    def send(self, item: Item) -> None:
        body = json.dumps(formats.webhook_payload(item, self.s.public_url),
                          separators=(",", ":"), ensure_ascii=False).encode()
        extra = {}
        if self.s.webhook_secret:
            # Signature over "<timestamp>.<body>": a receiver rejects a stale timestamp, so a
            # captured message cannot be replayed later.
            key = self.s.webhook_secret.get_secret_value().encode()
            stamp = str(int(time.time()))
            extra["X-IDPS-Timestamp"] = stamp
            extra["X-IDPS-Signature"] = "sha256=" + hmac.new(
                key, stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        self._post(body, extra)


class SlackChannel(_HttpChannel):
    name = "slack"

    @property
    def configured(self) -> bool:
        return self.s.slack_webhook_url is not None

    @property
    def min_severity(self) -> str:
        return self.s.slack_min_severity or self.s.notify_min_severity

    @property
    def include_rules(self) -> bool:
        return self.s.slack_include_rules

    def _url(self) -> str:
        return self.s.slack_webhook_url.get_secret_value() if self.s.slack_webhook_url else ""

    def send(self, item: Item) -> None:
        body = json.dumps(formats.slack_payload(item, self.s.public_url),
                          separators=(",", ":"), ensure_ascii=False).encode()
        self._post(body)


class EmailChannel(Channel):
    name = "email"

    @property
    def configured(self) -> bool:
        return bool(self.s.smtp_host and self.s.smtp_from and self.s.smtp_to)

    @property
    def min_severity(self) -> str:
        return self.s.email_min_severity or self.s.notify_min_severity

    @property
    def include_rules(self) -> bool:
        return self.s.email_include_rules

    def target_hint(self) -> str | None:
        domains = sorted({a.rsplit("@", 1)[-1] for a in self.s.smtp_to})
        return (f"{self.s.smtp_host}:{self.s.smtp_port_effective} to "
                + ", ".join(f"***@{d}" for d in domains))

    def secrets(self) -> list[str]:
        return [self.s.smtp_password.get_secret_value()] if self.s.smtp_password else []

    def send(self, item: Item) -> None:
        s = self.s
        msg = formats.build_email(item, s.smtp_from, s.smtp_to, s.public_url)
        send_email(s, msg, list(s.smtp_to))


def send_email(s: SocSettings, msg: EmailMessage, recipients: list[str],
               timeout: float | None = None,
               attachment: tuple[str, str, bytes] | None = None) -> None:
    """Send one prepared message through the configured SMTP server (the alert channel and the
    weekly report both use this). Raises DeliveryError, whose text never holds an address or a
    secret. `timeout` bounds each socket operation and, through the watchdog, the whole
    conversation; the default is notify_timeout_seconds (a report with an attachment passes more).
    `attachment`: one file as (filename, "type/subtype", content), added to `msg`."""
    if s.smtp_username and s.smtp_security == "none":
        raise DeliveryError("refusing to send a password without TLS "
                            "(IDPS_SOC_SMTP_SECURITY is none)", retryable=False)
    timeout = timeout or s.notify_timeout_seconds
    if attachment is not None:
        name, mime, data = attachment
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    client = None
    # `timeout` is per socket operation; the watchdog bounds the whole conversation.
    with Watchdog(timeout) as dog:
        try:
            # Created unconnected so the watchdog can cut the connection (and a slow
            # greeting) short: connect() assigns the socket before it reads the greeting.
            if s.smtp_security == "ssl":
                client = smtplib.SMTP_SSL(timeout=timeout, context=ssl.create_default_context())
            else:
                client = smtplib.SMTP(timeout=timeout)
            dog.target = client
            # smtplib only records the host name when it is given to the constructor, and both
            # STARTTLS and SMTP_SSL read it (self._host) as the name the server's certificate
            # must match; without it TLS fails with "check_hostname requires server_hostname".
            # It is always the configured host, never anything the server says.
            client._host = s.smtp_host
            try:
                client.connect(s.smtp_host, s.smtp_port_effective)
                client.ehlo()
                if s.smtp_security == "starttls":
                    # Not offered: starttls() raises. No plaintext fallback, ever.
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                if s.smtp_username:
                    client.login(s.smtp_username,
                                 s.smtp_password.get_secret_value() if s.smtp_password else "")
                client.send_message(msg, from_addr=s.smtp_from, to_addrs=list(recipients))
                try:  # sent: a failed goodbye changes nothing
                    client.quit()
                except (OSError, smtplib.SMTPException):
                    pass
            finally:
                # Not `with client:`: its QUIT on the way out of an error would replace the
                # real error with a confusing one (e.g. "SMTP error -1" after a TLS failure).
                client.close()
        except smtplib.SMTPNotSupportedError as exc:
            raise DeliveryError("the server does not offer STARTTLS; refusing to send "
                                "without TLS", retryable=False) from exc
        except smtplib.SMTPAuthenticationError as exc:
            raise DeliveryError("SMTP login refused", retryable=False) from exc
        except smtplib.SMTPRecipientsRefused as exc:
            raise DeliveryError("SMTP: recipients refused", retryable=False) from exc
        except smtplib.SMTPResponseException as exc:
            if dog.expired:
                raise DeliveryError("timed out") from exc
            if exc.smtp_code < 0:  # smtplib's code for a reply it could not read
                raise DeliveryError("SMTP: unreadable reply from the server",
                                    retryable=False) from exc
            # 4xx replies are transient (try again); 5xx are permanent.
            raise DeliveryError(f"SMTP error {exc.smtp_code}",
                                retryable=exc.smtp_code < 500) from exc
        except ssl.SSLError as exc:
            if dog.expired:
                raise DeliveryError("timed out") from exc
            raise DeliveryError(
                "TLS error (certificate not trusted or handshake failed)") from exc
        except (OSError, smtplib.SMTPException) as exc:
            if dog.expired or isinstance(exc, TimeoutError):
                raise DeliveryError("timed out") from exc
            raise DeliveryError(f"SMTP connection failed ({type(exc).__name__})") from exc


class SyslogChannel(Channel):
    name = "syslog"
    accepts_blocks = True

    def __init__(self, settings: SocSettings) -> None:
        super().__init__(settings)
        self.use_limits = settings.syslog_rate_per_minute > 0
        self.rate_per_minute = settings.syslog_rate_per_minute
        self.dedupe_seconds = 0
        self._sock: socket.socket | None = None
        self._last_used = 0.0
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return bool(self.s.syslog_host)

    @property
    def min_severity(self) -> str:
        return self.s.syslog_min_severity

    @property
    def include_rules(self) -> bool:
        return self.s.syslog_include_rules

    @property
    def include_blocks(self) -> bool:
        return self.s.syslog_include_blocks

    def target_hint(self) -> str | None:
        return f"{self.s.syslog_protocol}://{self.s.syslog_host}:{self.s.syslog_port}"

    def _connect(self) -> socket.socket:
        s = self.s
        raw = socket.create_connection((s.syslog_host, s.syslog_port),
                                       timeout=s.notify_timeout_seconds)
        if s.syslog_protocol != "tls":
            return raw
        try:
            ctx = ssl.create_default_context(cafile=s.syslog_ca_file or None)
            return ctx.wrap_socket(raw, server_hostname=s.syslog_host)
        except Exception:
            raw.close()
            raise

    def _drop(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def _stale(self, sock: socket.socket) -> bool:
        """True if the kept-open link should not be used: idle too long, or the peer has closed
        it (a FIN is only noticed by reading; a write into it would succeed and be lost)."""
        if time.monotonic() - self._last_used > self.s.syslog_idle_seconds:
            return True
        try:
            readable, _, _ = select.select([sock], [], [], 0)
            if not readable:
                return False
            if isinstance(sock, ssl.SSLSocket):
                return True  # a receiver never sends: close_notify, an alert or an error
            data = sock.recv(1, socket.MSG_PEEK)
            if data == b"":
                return True
            sock.recv(4096)  # unexpected data from the receiver: discard it, link still fine
            return False
        except (OSError, ValueError):
            return True

    def _udp(self, plain: bytes) -> None:
        s = self.s
        family, _, _, _, addr = socket.getaddrinfo(
            s.syslog_host, s.syslog_port, type=socket.SOCK_DGRAM)[0]
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(s.notify_timeout_seconds)
            sock.sendto(plain, addr)

    def send(self, item: Item) -> None:
        plain, counted = formats.syslog_frame(item)
        s = self.s
        try:
            if s.syslog_protocol == "udp":
                self._udp(plain)
                return
            with self._lock, Watchdog(s.notify_timeout_seconds) as dog:
                try:
                    for attempt in (0, 1):  # a dead kept-open link gets one fresh try
                        try:
                            if self._sock is not None and self._stale(self._sock):
                                self._drop()
                            if self._sock is None:
                                self._sock = self._connect()
                            dog.target = self._sock
                            self._sock.sendall(counted)
                            self._last_used = time.monotonic()
                            return
                        except OSError:
                            self._drop()
                            if attempt or dog.expired:
                                raise
                except OSError as exc:
                    if dog.expired:
                        raise TimeoutError from exc
                    raise
        except TimeoutError as exc:
            raise DeliveryError("timed out") from exc
        except ssl.SSLError as exc:
            raise DeliveryError("TLS error (certificate not trusted or handshake failed)") from exc
        except OSError as exc:
            raise DeliveryError(f"connection failed ({type(exc).__name__})") from exc

    def close(self) -> None:
        # Never wait for a send that is stuck: take the lock for a moment, else close anyway.
        got = self._lock.acquire(timeout=0.5)
        try:
            self._drop()
        finally:
            if got:
                self._lock.release()


def build_channels(settings: SocSettings) -> dict[str, Channel]:
    return {c.name: c for c in (WebhookChannel(settings), SlackChannel(settings),
                                EmailChannel(settings), SyslogChannel(settings))}
