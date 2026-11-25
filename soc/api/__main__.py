"""Admin CLI for the SOC API.

    python -m soc.api create-user <username> --role admin|analyst   (asks for the password)
    python -m soc.api create-user <username> --role admin|analyst --password-file PATH
                                     (scripted: reads the password from PATH, never prints it)
    python -m soc.api create-sensor <name>                           (prints the token once)
    python -m soc.api sensor-ca --out-dir DIR                (mutual TLS: a CA for sensor certs)
    python -m soc.api server-cert --dir DIR [--ca-dir CADIR] --san NAME_OR_IP [--san ...]
                                     (the TLS certificate of the sensor port, from its own CA kept
                                     in CADIR (default DIR); reused while valid)
    python -m soc.api sensor-cert <name> --ca-dir DIR --out-dir OUT   (a sensor's certificate)
    python -m soc.api mfa-reset <username>          (lost phone and recovery codes; logs them out)
    python -m soc.api mfa-enrol <username> --secret-file PATH   (scripted accounts: writes the
                                     TOTP secret to PATH, mode 0600, and never prints it)
    python -m soc.api db upgrade | current | check   [--database-url URL]
    python -m soc.api prune [--dry-run]              [--database-url URL]   (retention, once)
    python -m soc.api backup OUT.jsonl.gz            [--database-url URL]
    python -m soc.api restore IN.jsonl.gz            [--database-url URL]   (empty database only)

--database-url defaults to IDPS_SOC_DATABASE_URL (then the SOC's default). Exit status: 0 ok,
1 refused or failed (one line on stderr), 2 bad usage.
"""

import argparse
import getpass
import os
import sys

from soc.api import auth
from soc.api.db import init_db, make_engine, make_session_factory
from soc.api.models import Role
from soc.api.security import PasswordPolicyError
from soc.api.settings import get_settings


def _session():
    settings = get_settings()
    engine = make_engine(settings.database_url)
    init_db(engine, settings.auto_migrate)
    return make_session_factory(engine)()


def _create_user(args) -> int:
    if args.password_file:
        try:
            with open(args.password_file, encoding="utf-8") as fh:
                # one trailing newline is the file's, not the password's
                password = fh.read().removesuffix("\n")
        except OSError as exc:  # the path is not secret; the content never is printed
            print(f"error: cannot read {args.password_file}: {exc.strerror}", file=sys.stderr)
            return 1
    else:
        password = getpass.getpass(f"Password for {args.username}: ")
        if password != getpass.getpass("Repeat password: "):
            print("passwords don't match", file=sys.stderr)
            return 1
    with _session() as db:
        try:
            auth.create_user(db, args.username, password, Role(args.role))
        except (ValueError, PasswordPolicyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    print(f"created {args.role} {args.username!r}")
    return 0


def _create_sensor(args) -> int:
    with _session() as db:
        try:
            token = auth.create_sensor_token(db, args.name)
        except Exception as exc:  # noqa: BLE001  e.g. duplicate name
            print(f"error: {exc}", file=sys.stderr)
            return 1
    print("Sensor token (shown once; store it in the sensor's IDPS_SOC_SENSOR_TOKEN):")
    print(token)
    return 0


def _mfa_reset(args) -> int:
    from sqlalchemy import select

    from soc.api.common import audit
    from soc.api.models import User

    with _session() as db:
        user = db.scalar(select(User).where(User.username == args.username))
        if user is None:
            print(f"error: no user {args.username!r}", file=sys.stderr)
            return 1
        auth.clear_mfa(user)
        db.add(user)
        audit(db, user, "user_mfa_reset", f"user:{user.username}", {"by": "cli"})
        db.commit()
    print(f"MFA removed for {args.username!r}; they enrol again at their next login")
    return 0


def _mfa_enrol(args) -> int:
    """Enrol an account used by scripts (the lab's check user): the secret goes to a new file
    only. The recovery codes are not kept (the account can be reset with mfa-reset)."""
    from sqlalchemy import select

    from soc.api import mfa
    from soc.api.common import audit
    from soc.api.models import User

    settings = get_settings()
    keys = mfa.MfaKeys(settings.mfa_master_key)
    with _session() as db:
        user = db.scalar(select(User).where(User.username == args.username))
        if user is None:
            print(f"error: no user {args.username!r}", file=sys.stderr)
            return 1
        if user.mfa_enabled and not args.replace:
            print(f"error: MFA is already on for {args.username!r} (--replace to change it)",
                  file=sys.stderr)
            return 1
        secret = mfa.new_secret()
        try:
            fd = os.open(args.secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        except OSError as exc:
            print(f"error: cannot write {args.secret_file}: {exc.strerror}", file=sys.stderr)
            return 1
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(secret + "\n")
        user.totp_secret = keys.encrypt(secret, user.id)
        user.totp_pending = None
        user.totp_last_step = None
        user.recovery_codes = []
        user.mfa_enabled = True
        user.token_version += 1
        audit(db, user, "mfa_enable", f"user:{user.username}", {"by": "cli"})
        db.commit()
    print(f"MFA on for {args.username!r}; secret written to {args.secret_file}")
    return 0


def _sensor_ca(args) -> int:
    from pathlib import Path

    from soc.api import pki

    out = Path(args.out_dir)
    if (out / "sensor-ca.key").exists():
        print(f"error: {out / 'sensor-ca.key'} exists; refusing to replace a CA", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    key, cert = pki.make_ca(days=args.days)
    pki.write_private(out / "sensor-ca.key", pki.key_pem(key))
    pki.write_public(out / "sensor-ca.pem", pki.cert_pem(cert))
    print(f"sensor CA written to {out}: give sensor-ca.pem to the SOC (--sensor-ca); keep "
          "sensor-ca.key offline")
    return 0


def _server_cert(args) -> int:
    """The sensor port's TLS certificate, signed by a CA of its own that stays in --dir (sensors
    trust server-ca.pem). Reused while it covers exactly the given names and has 30+ days left."""
    from datetime import UTC, datetime, timedelta
    from pathlib import Path

    from cryptography import x509

    from soc.api import pki

    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    ca_dir = Path(args.ca_dir) if args.ca_dir else out
    ca_dir.mkdir(parents=True, exist_ok=True)
    sans = list(dict.fromkeys(args.san))
    try:
        if (ca_dir / "server-ca.key").exists():
            ca_key, ca_cert = pki.load_ca(ca_dir, "server-ca")
        else:
            ca_key, ca_cert = pki.make_ca("IDPS SOC server CA", days=3650)
            pki.write_private(ca_dir / "server-ca.key", pki.key_pem(ca_key))
            pki.write_public(ca_dir / "server-ca.pem", pki.cert_pem(ca_cert))
        if ca_dir != out:  # the certificate (public) goes next to the server key
            pki.write_public(out / "server-ca.pem", pki.cert_pem(ca_cert))
        try:
            cur = x509.load_pem_x509_certificate((out / "server.pem").read_bytes())
            if ((out / "server.key").exists() and cur.issuer == ca_cert.subject
                    and pki.cert_sans(cur) == set(sans)
                    and cur.not_valid_after_utc - datetime.now(UTC) > timedelta(days=30)):
                print(f"server certificate in {out} is current")
                return 0
        except (OSError, ValueError):
            pass
        key, cert = pki.issue_server_cert(ca_key, ca_cert, sans[0], sans, days=args.days)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    pki.write_private(out / "server.key", pki.key_pem(key))
    pki.write_public(out / "server.pem", pki.cert_pem(cert))
    print(f"server certificate for {', '.join(sans)} written to {out}")
    return 0


def _sensor_cert(args) -> int:
    from pathlib import Path

    from soc.api import pki

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    try:
        ca_key, ca_cert = pki.load_ca(Path(args.ca_dir))
        key, cert = pki.issue_client_cert(ca_key, ca_cert, args.name, days=args.days)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    pki.write_private(out / f"{args.name}.key", pki.key_pem(key))
    pki.write_public(out / f"{args.name}.pem", pki.cert_pem(cert))
    print(f"certificate for sensor {args.name!r} written to {out} (IDPS_SOC_CLIENT_CERT/KEY)")
    return 0


def _url(args) -> str:
    if args.database_url:
        return args.database_url
    from soc.api.settings import SocSettings

    return os.environ.get("IDPS_SOC_DATABASE_URL") or SocSettings.model_fields[
        "database_url"].default


def _engine(args):
    return make_engine(_url(args))


def _guarded(fn):
    """Turn failures into one stderr line and exit status 1 (a shell script's contract). The
    database URL (it holds a password) is never printed."""
    def run(args) -> int:
        from soc.api.backup import BackupError
        from soc.api.migrate import SchemaError

        try:
            return fn(args)
        except (BackupError, SchemaError) as exc:
            print(f"error: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            text = (str(exc).splitlines() or [""])[0][:300]
            print(f"error: {type(exc).__name__}: {text}", file=sys.stderr)
        return 1
    return run


def _db(args) -> int:
    from soc.api import migrate

    engine = _engine(args)
    if args.db_cmd == "upgrade":
        migrate.ensure_schema(engine, auto_migrate=True)  # empty / adopt / upgrade, under the lock
        print(f"database is at {migrate.head_revision()}")
        return 0
    if args.db_cmd == "current":
        with engine.connect() as conn:
            print(migrate.current_revision(conn) or "(none)")
            conn.rollback()
        return 0
    problems = migrate.check(engine)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if not problems:
        print("ok: the database is at head and matches the models")
    return 1 if problems else 0


def _prune(args) -> int:
    from soc.api import migrate, retention
    from soc.api.settings import MIN_SECRET_LENGTH, SocSettings

    url = _url(args)
    # The JWT secret is not needed to prune: a placeholder satisfies the settings model (the
    # retention values still come from the IDPS_SOC_* environment).
    settings = SocSettings(jwt_secret="x" * MIN_SECRET_LENGTH, database_url=url)
    engine = make_engine(url)
    problems = migrate.check(engine)
    if problems:
        raise migrate.SchemaError(
            f"the database is not ready ({problems[0]}): run `python -m soc.api db upgrade` first")
    with make_session_factory(engine)() as db:
        counts: dict[str, int] = {}
        gave_up: list[str] = []
        error = None
        try:
            # pause between batches (as the background runner does): on SQLite each batch holds
            # the write lock, and back-to-back batches would starve the SOC's own writers
            retention.prune(db, settings, dry_run=args.dry_run, counts=counts,
                            pause=retention.PAUSE_SECONDS, problems=gave_up)
            if gave_up:
                error = "; ".join(gave_up)
                print(f"warning: {error}", file=sys.stderr)
        except Exception as exc:
            error = type(exc).__name__ + " (see the message above)"
            raise
        finally:
            if not args.dry_run and sum(counts.values()):
                try:  # what was deleted before a failure is audited too
                    retention._audit(make_session_factory(engine), counts, error)
                except Exception:
                    if error is None:
                        raise  # the prune worked but could not be recorded: say so
                    print("warning: the audit entry could not be written", file=sys.stderr)
    print(("would delete" if args.dry_run else "deleted") + ":")
    for table, n in counts.items():
        print(f"  {table}: {n}")
    return 0


def _backup(args) -> int:
    from soc.api import backup

    engine = _engine(args)
    print(f"backing up {engine.url.render_as_string(hide_password=True)}", file=sys.stderr)
    backup.backup(engine, args.file)
    return 0


def _restore(args) -> int:
    from soc.api import backup

    engine = _engine(args)
    print(f"restoring into {engine.url.render_as_string(hide_password=True)}", file=sys.stderr)
    backup.restore(engine, args.file)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m soc.api")
    sub = parser.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("create-user")
    u.add_argument("username")
    u.add_argument("--role", choices=[r.value for r in Role], required=True)
    u.add_argument("--password-file", metavar="PATH", default=None,
                   help="read the password from this file instead of asking")
    u.set_defaults(fn=_create_user)
    s = sub.add_parser("create-sensor")
    s.add_argument("name")
    s.set_defaults(fn=_create_sensor)
    ca = sub.add_parser("sensor-ca", help="make a CA for sensor client certificates")
    ca.add_argument("--out-dir", required=True)
    ca.add_argument("--days", type=int, default=3650)
    ca.set_defaults(fn=_sensor_ca)
    sv = sub.add_parser("server-cert", help="TLS certificate for the sensor port")
    sv.add_argument("--dir", required=True)
    sv.add_argument("--ca-dir", default=None, help="where the CA key lives (default: --dir)")
    sv.add_argument("--san", action="append", required=True, metavar="NAME_OR_IP")
    sv.add_argument("--days", type=int, default=365)
    sv.set_defaults(fn=_server_cert)
    sc = sub.add_parser("sensor-cert", help="issue a sensor's client certificate")
    sc.add_argument("name", help="the sensor's name at the SOC")
    sc.add_argument("--ca-dir", required=True)
    sc.add_argument("--out-dir", required=True)
    sc.add_argument("--days", type=int, default=365)
    sc.set_defaults(fn=_sensor_cert)
    m = sub.add_parser("mfa-reset", help="remove a user's MFA")
    m.add_argument("username")
    m.set_defaults(fn=_mfa_reset)
    e = sub.add_parser("mfa-enrol", help="turn MFA on for a scripted account")
    e.add_argument("username")
    e.add_argument("--secret-file", required=True)
    e.add_argument("--replace", action="store_true")
    e.set_defaults(fn=_mfa_enrol)
    d = sub.add_parser("db", help="schema migrations")
    d.add_argument("db_cmd", choices=["upgrade", "current", "check"])
    d.set_defaults(fn=_guarded(_db))
    pr = sub.add_parser("prune", help="run the retention policy once")
    pr.add_argument("--dry-run", action="store_true", help="only count what would be deleted")
    pr.set_defaults(fn=_guarded(_prune))
    b = sub.add_parser("backup", help="portable logical backup (gzip JSON lines)")
    b.add_argument("file", metavar="OUT.jsonl.gz")
    b.set_defaults(fn=_guarded(_backup))
    r = sub.add_parser("restore", help="restore a backup into an empty database")
    r.add_argument("file", metavar="IN.jsonl.gz")
    r.set_defaults(fn=_guarded(_restore))
    for cmd in (d, pr, b, r):
        cmd.add_argument("--database-url", default=None,
                         help="SQLAlchemy URL (default: IDPS_SOC_DATABASE_URL)")
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
