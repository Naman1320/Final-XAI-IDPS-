"""Email sign-in codes for accounts with an operator-assigned mailbox."""

import hmac
import logging
import secrets
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Literal

from sqlalchemy import or_, update
from sqlalchemy.orm import Session

from soc.api.integrations.channels import send_email
from soc.api.integrations.netguard import DeliveryError
from soc.api.models import User
from soc.api.settings import SocSettings

LIFETIME = timedelta(minutes=5)
SEND_INTERVAL = timedelta(minutes=1)


def _digest(settings: SocSettings, mailbox: str, challenge: str, code: str) -> str:
    message = f"email-mfa-v1\0{mailbox}\0{challenge}\0{code}".encode()
    return hmac.digest(settings.mfa_master_key.encode(), message, "sha256").hex()


def deliver(db: Session, settings: SocSettings, user: User, challenge: str
            ) -> Literal["sent", "cooldown", "unavailable"]:
    mailbox = user.mfa_email
    if not (mailbox and settings.smtp_host and settings.smtp_from
            and settings.smtp_security in {"ssl", "starttls"}):
        return "unavailable"
    now = datetime.now(UTC)
    code = f"{secrets.randbelow(100_000_000):08d}"
    digest = _digest(settings, mailbox, challenge, code)
    account = update(User).where(User.id == user.id, User.mfa_email == mailbox,
                                 User.mfa_enabled.is_(True), User.disabled.is_(False),
                                 User.token_version == user.token_version)
    reserved = db.execute(account.where(or_(User.email_sent_at.is_(None),
                                            User.email_sent_at <= now - SEND_INTERVAL))
                          .values(email_sent_at=now, email_code_hash=digest)
                          .execution_options(synchronize_session=False))
    db.commit()
    if reserved.rowcount != 1:
        return "cooldown"

    msg = EmailMessage()
    msg["From"], msg["To"] = settings.smtp_from, mailbox
    msg["Subject"] = "Your Lab SOC sign-in code"
    msg.set_content(f"Your sign-in code is {code}. Enter it in the tab where you signed in. "
                    "It expires in five minutes. If you did not request it, you can ignore this email.")
    try:
        send_email(settings, msg, [mailbox], timeout=20)
    except DeliveryError as exc:
        logging.getLogger(__name__).warning("MFA email delivery failed: %s", exc)
        db.execute(account.where(User.email_code_hash == digest).values(email_code_hash=None))
        db.commit()
        return "unavailable"
    return "sent"


def consume(db: Session, settings: SocSettings, user: User, challenge: str, code: str) -> bool:
    if not user.mfa_email:
        return False
    digest = _digest(settings, user.mfa_email, challenge, code)
    used = db.execute(update(User).where(
        User.id == user.id, User.disabled.is_(False), User.mfa_enabled.is_(True),
        User.token_version == user.token_version, User.mfa_email == user.mfa_email,
        User.email_code_hash == digest, User.email_sent_at > datetime.now(UTC) - LIFETIME,
    ).values(email_code_hash=None).execution_options(synchronize_session=False))
    db.commit()
    return used.rowcount == 1
