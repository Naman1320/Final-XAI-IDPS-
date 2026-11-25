"""Packet capture: read a PCAP or sniff an interface, then group packets into flows.

Both entry points go through the same extractor and yield the same `Flow` record, so
features computed from a dataset PCAP and from live traffic are identical.
"""

import logging
import os
from collections.abc import Iterator

from idps.capture.flow import FLOW_FIELDS, Flow

__all__ = ["FLOW_FIELDS", "Flow", "check_timeouts", "flows_from_interface", "flows_from_pcap",
           "select_backend"]

# Flow timeouts in seconds. 120 s matches the CICFlowMeter setting used for CIC-IDS2017.
DEFAULT_IDLE_TIMEOUT = 120.0
DEFAULT_ACTIVE_TIMEOUT = 120.0


log = logging.getLogger(__name__)


def select_backend(name: str | None = None) -> str:
    """Return "nfstream" or "scapy".

    `name` (or the IDPS_EXTRACTOR environment variable) picks one; the default is "nfstream",
    and it fails loudly if NFStream can't be imported rather than silently switching.
    "scapy" must be asked for explicitly. "auto" (NFStream if it imports, else scapy) is
    allowed but logs a warning, because training and live detection must use the same one.
    """
    name = (name or os.environ.get("IDPS_EXTRACTOR") or "nfstream").lower()
    if name not in {"auto", "nfstream", "scapy"}:
        raise ValueError(f"unknown extractor {name!r}: use nfstream, scapy or auto")
    if name == "auto":
        from idps.capture import nfstream_flows

        chosen = "nfstream" if nfstream_flows.available() else "scapy"
        log.warning("extractor 'auto' chose %s; pin IDPS_EXTRACTOR so training and live match",
                    chosen)
        return chosen
    if name == "nfstream":
        from idps.capture import nfstream_flows

        if not nfstream_flows.available():
            raise RuntimeError("NFStream was requested but cannot be imported on this machine")
    return name


def check_timeouts(idle_timeout: float, active_timeout: float) -> None:
    """Timeouts must be positive whole seconds: NFStream only accepts whole seconds, so any
    fraction would make the two backends split flows differently."""
    for name, value in (("idle_timeout", idle_timeout), ("active_timeout", active_timeout)):
        if value <= 0 or float(value) != int(value):
            raise ValueError(f"{name} must be a positive whole number of seconds, got {value!r}")


def _flows(source: str, *, live: bool, backend: str | None, idle_timeout: float,
           active_timeout: float, bpf_filter: str | None, max_flows: int | None,
           duration: float | None) -> Iterator[Flow]:
    """The single code path behind both public functions."""
    check_timeouts(idle_timeout, active_timeout)
    chosen = select_backend(backend)
    if chosen == "nfstream":
        from idps.capture import nfstream_flows

        return nfstream_flows.flows_from_source(
            source, idle_timeout, active_timeout, bpf_filter, max_flows)
    from idps.capture import scapy_flows

    if live:
        return scapy_flows.flows_from_interface_scapy(
            source, idle_timeout, active_timeout, bpf_filter, max_flows, duration)
    return scapy_flows.flows_from_pcap_scapy(source, idle_timeout, active_timeout)


def flows_from_pcap(path: str | os.PathLike, *, backend: str | None = None,
                    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
                    active_timeout: float = DEFAULT_ACTIVE_TIMEOUT) -> Iterator[Flow]:
    """Yield the flows in a PCAP file."""
    path = os.fspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return _flows(path, live=False, backend=backend, idle_timeout=idle_timeout,
                  active_timeout=active_timeout, bpf_filter=None, max_flows=None, duration=None)


def flows_from_interface(name: str, *, backend: str | None = None,
                         idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
                         active_timeout: float = DEFAULT_ACTIVE_TIMEOUT,
                         bpf_filter: str | None = None, max_flows: int | None = None,
                         duration: float | None = None) -> Iterator[Flow]:
    """Yield flows from a live interface as they expire (needs root / CAP_NET_RAW).

    Stops after `max_flows` flows, or after `duration` seconds (scapy backend only; NFStream
    blocks until a flow expires, so combine it with a short `idle_timeout` and `max_flows`).
    """
    return _flows(name, live=True, backend=backend, idle_timeout=idle_timeout,
                  active_timeout=active_timeout, bpf_filter=bpf_filter, max_flows=max_flows,
                  duration=duration)
