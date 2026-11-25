"""Build tiny synthetic PCAPs with scapy (no files needed in the repo)."""

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

T0 = 1_700_000_000.0  # fixed start so tests are deterministic
CLIENT, SERVER = "10.10.1.5", "10.10.2.10"
PAYLOAD_REQ, PAYLOAD_RESP = 100, 500


def _pkt(layer, t):
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / layer
    p.time = t
    return p


def tcp_session(sport=40000, dport=80, t0=T0):
    """Handshake, one request, one response, FIN close. 10 packets total.

    client->server: SYN, ACK, data(100), ACK, FIN, ACK  = 6 packets
    server->client: SYN-ACK, data(500), FIN-ACK         = 3 ... plus ACK of data = see below
    """
    c = lambda flags, seq, ack, load=b"": IP(src=CLIENT, dst=SERVER) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack
    ) / load
    s = lambda flags, seq, ack, load=b"": IP(src=SERVER, dst=CLIENT) / TCP(
        sport=dport, dport=sport, flags=flags, seq=seq, ack=ack
    ) / load
    seq = [
        (c("S", 1000, 0), 0.00),
        (s("SA", 5000, 1001), 0.01),
        (c("A", 1001, 5001), 0.02),
        (c("PA", 1001, 5001, b"a" * PAYLOAD_REQ), 0.03),
        (s("A", 5001, 1101), 0.04),
        (s("PA", 5001, 1101, b"b" * PAYLOAD_RESP), 0.05),
        (c("A", 1101, 5501), 0.06),
        (c("FA", 1101, 5501), 0.07),
        (s("FA", 5501, 1102), 0.08),
        (c("A", 1102, 5502), 0.09),
    ]
    return [_pkt(layer, t0 + dt) for layer, dt in seq]


def udp_exchange(sport=50000, dport=53, t0=T0 + 1.0):
    """Two queries (30 B payload) and two replies (80 B payload), 0.1 s apart."""
    out = []
    for i in range(2):
        out.append(_pkt(IP(src=CLIENT, dst="10.10.2.53") / UDP(sport=sport, dport=dport) / (b"q" * 30), t0 + i * 0.2))
        out.append(_pkt(IP(src="10.10.2.53", dst=CLIENT) / UDP(sport=dport, dport=sport) / (b"r" * 80), t0 + i * 0.2 + 0.1))
    return out


def write_pcap(path, packets):
    wrpcap(str(path), sorted(packets, key=lambda p: float(p.time)))
    return path


def ping(t0=T0 + 5.0):
    return [_pkt(IP(src=CLIENT, dst=SERVER) / ICMP() / (b"x" * 20), t0)]
