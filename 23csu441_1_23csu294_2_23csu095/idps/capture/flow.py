"""Backend-neutral flow record.

Every extractor backend (NFStream, scapy) fills in exactly this record, so everything
downstream (features, labels, detection) never needs to know which backend ran.

Conventions (identical for every backend):
- "fwd" is the direction of the first packet seen for the flow (the initiator), "bwd" the reply.
- Times are milliseconds since the Unix epoch (UTC). Inter-arrival times (iat_*) are in ms.
- Packet sizes and byte counts are whole frames as captured, including the Ethernet header.
- Standard deviations are sample standard deviations (n-1); 0.0 when fewer than 2 values.
"""

from dataclasses import dataclass, fields


@dataclass(frozen=True, slots=True)
class Flow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int  # IP protocol number: 6 TCP, 17 UDP, 1 ICMP
    start_ms: int
    end_ms: int

    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int

    pkt_len_min: float
    pkt_len_max: float
    pkt_len_mean: float
    pkt_len_std: float
    fwd_pkt_len_min: float
    fwd_pkt_len_max: float
    fwd_pkt_len_mean: float
    fwd_pkt_len_std: float
    bwd_pkt_len_min: float
    bwd_pkt_len_max: float
    bwd_pkt_len_mean: float
    bwd_pkt_len_std: float

    iat_min: float
    iat_max: float
    iat_mean: float
    iat_std: float
    fwd_iat_min: float
    fwd_iat_max: float
    fwd_iat_mean: float
    fwd_iat_std: float
    bwd_iat_min: float
    bwd_iat_max: float
    bwd_iat_mean: float
    bwd_iat_std: float

    syn_count: int
    fin_count: int
    rst_count: int
    psh_count: int
    ack_count: int
    urg_count: int
    cwr_count: int
    ece_count: int


FLOW_FIELDS: tuple[str, ...] = tuple(f.name for f in fields(Flow))
