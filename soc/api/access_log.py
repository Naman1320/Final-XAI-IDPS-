"""Access log: who looked at personal data (docs/privacy.md).

A row is written when an individual address is looked at through the API or the assistant: an
alert's detail, a search of alerts, blocks or would-blocks by address, an alert's reputation, a
case and its alerts, the assistant's read tools, the training export, a report download (the
addresses it prints) and an erasure preview. List views that are not filtered by address (the
alert, block, case and action lists, metrics, topology, the live feed) are NOT logged: they
show many addresses at once and logging each would bury the log. One row per subject address, and
the address itself is never stored: `subject_fp` is a keyed HMAC-SHA256 of the normalised address.
It is pseudonymous, not anonymous: whoever holds the database but not the SOC's key cannot turn a
fingerprint back into an address or test a guess, but whoever has the key can recompute it for any
address (IPv4 is only 2^32 of them). An admin can ask "who looked at 203.0.113.7?" because the
server fingerprints the address in the question.

The key is derived with HKDF from IDPS_SOC_MFA_KEY, or the JWT secret when that is not set (the
same master as soc/api/mfa.py, a different purpose label). Changing that secret changes every
fingerprint: older rows stay in the log but no longer match a lookup.

Fail closed: the log rows are committed (together with anything else pending in the request's
session, such as its audit entry) before the answer is returned. If writing them fails, the
request fails with 500 and nothing is returned. The one gap: a response is built before it is
logged, so a crash between the two serves nothing, but a client that already got the answer of an
earlier request is of course not affected.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
from collections.abc import Iterable
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException
from sqlalchemy.orm import Session

from soc.api.models import AccessLog, User
from soc.api.settings import SocSettings

log = logging.getLogger("soc.access_log")

KEY_INFO = b"access-log-subject-v1"
KEY_SALT = b"idps-soc-access-log"
MAX_SUBJECTS = 100  # distinct addresses logged for one request (a case with many alerts)


def normalise_ip(value: str) -> str:
    """The canonical text of an address: IPv6 compressed and lower case, an IPv4-mapped IPv6
    address as the IPv4 one. ValueError when it is not an address (a CIDR is not one)."""
    addr = ipaddress.ip_address(value.strip())
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


@lru_cache(maxsize=8)
def _key(master: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=KEY_SALT,
                info=KEY_INFO).derive(master.encode())


def fingerprint(settings: SocSettings, ip: str) -> str:
    """64 hex characters: HMAC-SHA256 of the normalised address under the derived key."""
    return hmac.new(_key(settings.mfa_master_key), normalise_ip(ip).encode(),
                    hashlib.sha256).hexdigest()


def log_access(db: Session, settings: SocSettings, user: User, action: str, *,
               target_type: str = "", target: str = "", ips: Iterable[str] = (),
               without_subject: bool = False) -> None:
    """Write the access rows and COMMIT them (together with anything else already pending in the
    session, e.g. an audit entry). Call it after the answer is built and before returning it.

    `ips`: the addresses the request exposed or searched for; one row per distinct address (at
    most MAX_SUBJECTS). With none, one row without a subject is written; `without_subject` adds
    that row as well when there are addresses (a case: the case itself, then its alerts' addresses).

    Raises HTTPException 500 when the rows cannot be written; the session is rolled back."""
    try:
        subjects: dict[str, None] = {}  # ordered, de-duplicated fingerprints
        for ip in ips:
            if len(subjects) >= MAX_SUBJECTS:
                break
            subjects[fingerprint(settings, ip)] = None
        fps: list[str | None] = list(subjects)
        if not fps or without_subject:
            fps.insert(0, None)
        for fp in fps:
            db.add(AccessLog(user_id=user.id, username=user.username, action=action,
                             target_type=target_type, target=target, subject_fp=fp))
        db.commit()
    except Exception:
        db.rollback()
        log.exception("could not write the access log; refusing the request")
        raise HTTPException(500, "the access log could not be written; request refused") from None
