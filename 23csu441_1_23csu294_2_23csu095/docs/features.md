# Feature pipeline

PCAP or live interface -> flows -> feature table -> (training only) labels joined.

```
python -m idps.features extract capture.pcap -o flows.parquet [--backend nfstream|scapy]
python -m idps.features label flows.parquet MondayWorkingHours.pcap_ISCX.csv -o labelled.parquet \
       --utc-offset-hours -3 --tolerance-ms 1000
```

Code: `idps/capture` (PCAP/interface -> `Flow`), `idps/features` (`Flow` -> `to_frame()`,
`FEATURE_COLUMNS`), `idps/features/labels.py` (`join_labels`).

## Extractor choice

One extractor serves PCAPs and live interfaces. `flows_from_pcap(path)` and
`flows_from_interface(name)` call the same internal function and yield the same `Flow` record.
`select_backend()` picks, in order:

1. **NFStream 6.6.0** (preferred). Reasons: it is a maintained C meter with a Python API and
   handles a PCAP path and a live interface through the same `NFStreamer(source=...)` call, so the
   two paths cannot drift apart. It ships manylinux wheels for aarch64 (checked: cp312 aarch64
   wheel exists for 6.6.0), so it installs in the arm64 sensor container without a compiler. It
   installs and runs on macOS arm64 too.
2. **scapy flow builder** (`idps/capture/scapy_flows.py`, about 150 lines). Used when NFStream
   cannot be imported, and only when asked for explicitly. It follows the same rules as NFStream
   6.6.0 (checked by tests that run both on the same PCAPs): 5-tuple flows, first packet = forward,
   timestamps truncated to whole ms, a flow ends when a gap is >= the idle timeout or its age is
   >= the active timeout, IPv6 extension headers skipped, only the first fragment of a fragmented
   packet counted, VLAN id in the flow key, non-decreasing packet time, whole-frame sizes, sample
   std. Expiry costs O(log n) per packet, open flows are
   capped at 500,000 (the least recently seen flow is ended early beyond that, with a warning) and
   the live packet queue is bounded (drops are counted and logged), so floods can't exhaust memory.
3. **cicflowmeter** was considered and is not used. Its Python port is a sniffer-to-CSV tool with
   its own fixed feature set and no flow-record API, so it cannot share a code path with a
   second extractor; it also needs scapy anyway, so the scapy builder covers the same fallback need.

Training and live detection must use the same backend. The default is `nfstream`, and it fails
loudly if NFStream can't be imported instead of silently switching. `scapy` must be chosen
explicitly (`IDPS_EXTRACTOR=scapy` or `--backend scapy`); `auto` still exists but logs a warning.
Timeouts must be whole seconds (NFStream only supports whole seconds).

Every feature file records how it was made: `write_features()` stores the extractor, timeouts and
column list in the parquet metadata (or a `.meta.json` file next to a CSV), `read_features()`
returns them, and `check_same_extraction(train_meta, live_meta)` raises if they differ.

Extractor rules both backends follow (the tests run NFStream and scapy on the same PCAPs and
assert equal frames; a 40-case random fuzz of out-of-order, multi-flow, multi-VLAN captures also
agreed):
- **VLAN id is part of the flow key.** The same 5-tuple on different VLANs is a different flow.
  NFStream keys on the INNERMOST 802.1Q tag (with stacked tags `Dot1Q(100)/Dot1Q(5)` the id is 5,
  not the outermost 100), and VLAN 0 is the same as untagged. Frames with an 802.1ad (0x88a8) outer
  tag are not parsed by NFStream at all (no flow), so scapy skips them too.
- **Packet time never goes backwards.** NFStream treats a packet stamped earlier than the latest
  time seen so far in the capture (across all flows, ARP and other non-flow frames do not count)
  as arriving at that latest time. Hence: `start_ms` is the first packet in capture order,
  `end_ms` the latest time, `duration_ms` is never negative, and every inter-arrival time
  (`iat`, `fwd_iat`, `bwd_iat`) is `max(0, t - latest)` and so never negative. The scapy builder
  reproduces this (it used to compute negative IATs and a negative duration on such captures).

Known backend differences (both are documented, tested behaviours, not bugs):
- Timestamps are whole milliseconds, truncated (NFStream's behaviour; the scapy builder matches).
- Flows end on idle/active timeout (default 120 s each, the CICFlowMeter setting) or end of
  capture, not on FIN/RST. A reused 5-tuple within the idle timeout merges into one flow.
- `fwd` = direction of the first packet captured. If a capture starts mid-connection the "forward"
  side may be the server.
- Sizes include the Ethernet header (a bare TCP ACK is 54 bytes). Live capture on an
  interface with a different link layer (e.g. `any`, tun) would shift sizes.
- ICMP flows have ports 0.
- Live: NFStream only notices expired flows when a later packet arrives (observed on the sensor:
  with a single curl and then silence nothing was emitted until it was killed; with ongoing
  background traffic flows came out after the idle/active timeout). On a quiet link a finished
  flow can therefore be delayed; the live detection loop (week 7) must account for that. The
  scapy backend polls its own clock and emits idle flows on time. `duration` only applies to the
  scapy backend; for NFStream sample with `max_flows` and traffic running.
- Live check done on the sensor's `lab_attack` interface (curl + ping from the attacker
  container): both backends produced 47 columns identical to the PCAP path.

## Columns

`FEATURE_COLUMNS` (47 columns, fixed order; saved models depend on it). The first 7 are identity and
timing columns used for joining and alert display. `MODEL_FEATURES` = `dst_port`, `protocol` and the
40 columns after `end_ms`; train on that list.

Identity:

| Column | Meaning |
|---|---|
| src_ip, src_port | Initiator (first packet) address and port |
| dst_ip, dst_port | Responder address and port |
| protocol | IP protocol number (6 TCP, 17 UDP, 1 ICMP) |
| start_ms, end_ms | First and last packet time, epoch milliseconds UTC |

Features:

| Column | Meaning |
|---|---|
| duration_ms | end_ms - start_ms |
| fwd_packets, bwd_packets | Packets initiator->responder / responder->initiator |
| fwd_bytes, bwd_bytes | Frame bytes in each direction |
| bytes_per_s, packets_per_s | Total bytes / packets divided by duration (0 if duration is 0) |
| down_up_ratio | bwd_bytes / fwd_bytes (0 if no forward bytes) |
| pkt_len_min/max/mean/std | Frame size statistics over all packets |
| fwd_pkt_len_min/max/mean/std | Same, forward packets only |
| bwd_pkt_len_min/max/mean/std | Same, backward packets only |
| iat_min/max/mean/std | Inter-arrival time (ms) between consecutive packets of either direction |
| fwd_iat_min/max/mean/std | Inter-arrival time (ms) between consecutive forward packets |
| bwd_iat_min/max/mean/std | Inter-arrival time (ms) between consecutive backward packets |
| syn_count | Packets with the TCP SYN flag (both directions) |
| fin_count | Packets with FIN |
| rst_count | Packets with RST |
| psh_count | Packets with PSH |
| ack_count | Packets with ACK |
| urg_count | Packets with URG |
| cwr_count | Packets with CWR |
| ece_count | Packets with ECE |

Statistics use the sample standard deviation and are 0 when there are fewer than 2 values.
These are CIC-style features, not an exact copy of the CIC-IDS2017 CSV columns (which were
produced by Java CICFlowMeter); that is deliberate, see the key rule in PLAN.md section 2.
Not included yet: bulk/subflow/idle-active features and TCP window sizes.

## Label joining

`join_labels(flows_df, labels_df, tolerance_ms=1000)` (label window and resolution: see "Matching
rule") returns a copy of the flows with
`label`, `label_matched` and `label_ambiguous`. `summarize_matches(joined)` gives flows, matched,
unmatched, `match_rate`, ambiguous count and per-label counts. `load_cic_labels(paths,
utc_offset_hours)` reads CIC-IDS2017 label CSVs (`TrafficLabelling/*.csv`), one file at a time.

For training, use `training_rows(joined)` (matched, non-ambiguous rows only) or
`training_xy(joined)` (`MODEL_FEATURES` and the label). Don't filter on `label` yourself:
`UNMATCHED` is a string too, so `label != "BENIGN"` would count it as an attack. The `label`
CLI writes only training-safe rows unless `--keep-unmatched` is given, and exits with code 2 when
the match rate is below `--min-match-rate` (default 0.5).

Timestamps (`parse_cic_timestamps`): dates are read **day first** (`3/7/2017` is 3 July 2017),
with or without seconds. A file with no hour above 12 is treated as a 12-hour clock without
AM/PM, and hours 1-7 become afternoon (`3:56` is 15:56); hour 12 stays noon. This is a heuristic
based on the lab's working hours (about 8:00-17:00): check the match rate for every day file.

Matching rule: a flow matches a label row if

1. the protocol is equal;
2. the pair of (ip, port) endpoints is equal in either direction (labels use CICFlowMeter's own
   direction, which can differ from ours);
3. the time windows overlap: label window
   `[start_ms - tol, end_ms + ts_resolution_ms + tol]` against flow `[start_ms, end_ms]`.

`ts_resolution_ms` is a per-row column made by `normalize_cic_labels`: 60000 when the raw timestamp
has no seconds (`9:03`), 1000 when it has (`9:03:41`). A minute-only timestamp means the true
start is anywhere in `[ts, ts + 60 s)`, so the window widens forward only (the true start is
never earlier than the printed minute) by the resolution. `tol` (default 1000 ms) is the extra
slack on both sides for clock and flow-boundary differences. A label frame without the column
counts as resolution 0, so older callers behave as before. Checked on the real
`TrafficLabelling` CSVs: Monday is 1000, the other seven files are 60000.

With several candidates the largest overlap wins (ties: earliest label start). If the candidates
carry different labels the flow is flagged `label_ambiguous` (so you can drop or inspect it).
Flows with no candidate get `label == "UNMATCHED"` and `label_matched == False`; do not train on
them as if they were benign.

Known limits (to be checked against the real data once downloaded, and the match rate reported):
- **Timezone and resolution of CIC timestamps.** The CSV timestamps are local time without a zone.
  Pass the correct `utc_offset_hours` (check one known flow). Minute-only files are handled by
  `ts_resolution_ms` (above), so keep `tolerance_ms` small; a wide window raises ambiguity on
  busy 5-tuples. Every label file records `utc_offset_hours` and `match_summary` in its metadata,
  and training refuses low-match or mixed-offset files (see docs/training.md).
- **Different flow boundaries.** CICFlowMeter ends flows on FIN and splits differently from our
  timeouts, so one label row can overlap several of our flows (all get the label) and our flow can
  span several label rows (best overlap wins).
- **Port reuse.** Repeated connections on the same 5-tuple (DoS tools, scans) are distinguished
  only by time, so tolerance matters there.
- **NAT / address rewriting and mismatched PCAP segments** (the day PCAPs are large and the
  label CSVs were generated from them) can leave flows unmatched. A low match rate on one day is
  a signal to inspect, not to ignore.
- Known label-quality issues in CIC-IDS2017 (duplicated and mislabelled rows) are not corrected here.
- The join is tested on synthetic data. Only the timestamp resolution has been checked against
  the real CSVs; the day-first and 12-hour-clock handling and the real match rates still need to
  be checked against the matching PCAPs.
