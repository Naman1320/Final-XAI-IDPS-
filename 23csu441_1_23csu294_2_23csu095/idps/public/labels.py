"""Common label scheme and feature names shared by CIC-IDS2017 and CSE-CIC-IDS2018.

Both datasets come from the Canadian Institute for Cybersecurity and spell their labels and
CICFlowMeter columns differently. Every spelling is listed in LABEL_TABLE and FEATURE_NAMES so
nothing is matched by guesswork: an unknown label or a missing column is an error.
"""

import re

import pandas as pd

BENIGN = "BENIGN"
# The label the models learn. PortScan covers reconnaissance (only CIC-IDS2017 has it).
COMMON_CLASSES = (
    "BENIGN",
    "Bot",
    "BruteForce",
    "DDoS",
    "DoS",
    "Heartbleed",
    "Infiltration",
    "PortScan",
    "WebAttack",
)

# (common label, CIC-IDS2017 spelling, CSE-CIC-IDS2018 spelling); None = not in that dataset.
LABEL_TABLE: tuple[tuple[str, str | None, str | None], ...] = (
    ("BENIGN", "BENIGN", "Benign"),
    ("DoS", "DoS Hulk", "DoS attacks-Hulk"),
    ("DoS", "DoS GoldenEye", "DoS attacks-GoldenEye"),
    ("DoS", "DoS slowloris", "DoS attacks-Slowloris"),
    ("DoS", "DoS Slowhttptest", "DoS attacks-SlowHTTPTest"),
    ("DDoS", "DDoS", "DDoS attacks-LOIC-HTTP"),
    ("DDoS", None, "DDOS attack-HOIC"),
    ("DDoS", None, "DDOS attack-LOIC-UDP"),
    ("PortScan", "PortScan", None),
    ("BruteForce", "FTP-Patator", "FTP-BruteForce"),
    ("BruteForce", "SSH-Patator", "SSH-Bruteforce"),
    ("WebAttack", "Web Attack – Brute Force", "Brute Force -Web"),
    ("WebAttack", "Web Attack – XSS", "Brute Force -XSS"),
    ("WebAttack", "Web Attack – Sql Injection", "SQL Injection"),
    ("Bot", "Bot", "Bot"),
    ("Infiltration", "Infiltration", "Infilteration"),  # the 2018 files misspell it
    ("Heartbleed", "Heartbleed", "Heartbleed"),
)


def label_key(raw: str) -> str:
    """Lower-case letters and digits only, so spacing, dashes (the 2017 files use an en dash, or
    Windows-1252 byte 0x96 when read as latin-1) and case do not matter:
    "Brute Force -Web" -> "bruteforceweb"."""
    return re.sub(r"[^a-z0-9]", "", str(raw).lower())


def _build_keys() -> dict[str, str]:
    keys: dict[str, str] = {}
    spellings = [(c, s) for c, a, b in LABEL_TABLE for s in (a, b) if s]
    for common, spelling in spellings:
        key = label_key(spelling)
        if keys.setdefault(key, common) != common:
            raise ValueError(f"label spelling {spelling!r} maps to two classes")
    return keys


_KEYS = _build_keys()


def common_label(raw: str) -> str:
    """The common class of a CIC-IDS2017 or CSE-CIC-IDS2018 label; unknown labels raise."""
    try:
        return _KEYS[label_key(raw)]
    except KeyError:
        raise ValueError(
            f"unknown label {str(raw)!r}: add it to LABEL_TABLE in idps/public/labels.py"
        ) from None


def map_labels(raw: pd.Series) -> pd.Series:
    """Common class per row. All unknown labels are listed in one error."""
    names = raw.astype(str).str.strip()
    table, unknown = {}, []
    for name in names.unique():
        try:
            table[name] = common_label(name)
        except ValueError:
            unknown.append(name)
    if unknown:
        raise ValueError(
            f"unknown label(s) {sorted(unknown)}: add them to LABEL_TABLE in idps/public/labels.py"
        )
    return names.map(table)


def label_table_markdown() -> str:
    rows = ["| Common class | CIC-IDS2017 label | CSE-CIC-IDS2018 label |", "|---|---|---|"]
    rows += [
        f"| {c} | {a or '(not in dataset)'} | {b or '(not in dataset)'} |"
        for c, a, b in LABEL_TABLE
    ]
    return "\n".join(rows)


# --- columns -----------------------------------------------------------------------------------

DST_PORT = "Dst Port"
TIMESTAMP = "Timestamp"
LABEL = "Label"
# Columns that name hosts, flows or time: never features (they identify the lab machines or let
# a model memorise who attacked whom and when).
ID_COLUMNS_2018 = ("Flow ID", "Src IP", "Src Port", "Dst IP")
# (2018 name, 2017 name) of every CICFlowMeter feature the two datasets share. The 2018 name is
# the one used in memory. Both files have 78 such columns; the 2017 file lists
# "Fwd Header Length" twice (identical copies) and only the first is used.
FEATURE_NAMES: tuple[tuple[str, str], ...] = (
    ("Dst Port", "Destination Port"),
    ("Protocol", "Protocol"),
    ("Flow Duration", "Flow Duration"),
    ("Tot Fwd Pkts", "Total Fwd Packets"),
    ("Tot Bwd Pkts", "Total Backward Packets"),
    ("TotLen Fwd Pkts", "Total Length of Fwd Packets"),
    ("TotLen Bwd Pkts", "Total Length of Bwd Packets"),
    ("Fwd Pkt Len Max", "Fwd Packet Length Max"),
    ("Fwd Pkt Len Min", "Fwd Packet Length Min"),
    ("Fwd Pkt Len Mean", "Fwd Packet Length Mean"),
    ("Fwd Pkt Len Std", "Fwd Packet Length Std"),
    ("Bwd Pkt Len Max", "Bwd Packet Length Max"),
    ("Bwd Pkt Len Min", "Bwd Packet Length Min"),
    ("Bwd Pkt Len Mean", "Bwd Packet Length Mean"),
    ("Bwd Pkt Len Std", "Bwd Packet Length Std"),
    ("Flow Byts/s", "Flow Bytes/s"),
    ("Flow Pkts/s", "Flow Packets/s"),
    ("Flow IAT Mean", "Flow IAT Mean"),
    ("Flow IAT Std", "Flow IAT Std"),
    ("Flow IAT Max", "Flow IAT Max"),
    ("Flow IAT Min", "Flow IAT Min"),
    ("Fwd IAT Tot", "Fwd IAT Total"),
    ("Fwd IAT Mean", "Fwd IAT Mean"),
    ("Fwd IAT Std", "Fwd IAT Std"),
    ("Fwd IAT Max", "Fwd IAT Max"),
    ("Fwd IAT Min", "Fwd IAT Min"),
    ("Bwd IAT Tot", "Bwd IAT Total"),
    ("Bwd IAT Mean", "Bwd IAT Mean"),
    ("Bwd IAT Std", "Bwd IAT Std"),
    ("Bwd IAT Max", "Bwd IAT Max"),
    ("Bwd IAT Min", "Bwd IAT Min"),
    ("Fwd PSH Flags", "Fwd PSH Flags"),
    ("Bwd PSH Flags", "Bwd PSH Flags"),
    ("Fwd URG Flags", "Fwd URG Flags"),
    ("Bwd URG Flags", "Bwd URG Flags"),
    ("Fwd Header Len", "Fwd Header Length"),
    ("Bwd Header Len", "Bwd Header Length"),
    ("Fwd Pkts/s", "Fwd Packets/s"),
    ("Bwd Pkts/s", "Bwd Packets/s"),
    ("Pkt Len Min", "Min Packet Length"),
    ("Pkt Len Max", "Max Packet Length"),
    ("Pkt Len Mean", "Packet Length Mean"),
    ("Pkt Len Std", "Packet Length Std"),
    ("Pkt Len Var", "Packet Length Variance"),
    ("FIN Flag Cnt", "FIN Flag Count"),
    ("SYN Flag Cnt", "SYN Flag Count"),
    ("RST Flag Cnt", "RST Flag Count"),
    ("PSH Flag Cnt", "PSH Flag Count"),
    ("ACK Flag Cnt", "ACK Flag Count"),
    ("URG Flag Cnt", "URG Flag Count"),
    ("CWE Flag Count", "CWE Flag Count"),
    ("ECE Flag Cnt", "ECE Flag Count"),
    ("Down/Up Ratio", "Down/Up Ratio"),
    ("Pkt Size Avg", "Average Packet Size"),
    ("Fwd Seg Size Avg", "Avg Fwd Segment Size"),
    ("Bwd Seg Size Avg", "Avg Bwd Segment Size"),
    ("Fwd Byts/b Avg", "Fwd Avg Bytes/Bulk"),
    ("Fwd Pkts/b Avg", "Fwd Avg Packets/Bulk"),
    ("Fwd Blk Rate Avg", "Fwd Avg Bulk Rate"),
    ("Bwd Byts/b Avg", "Bwd Avg Bytes/Bulk"),
    ("Bwd Pkts/b Avg", "Bwd Avg Packets/Bulk"),
    ("Bwd Blk Rate Avg", "Bwd Avg Bulk Rate"),
    ("Subflow Fwd Pkts", "Subflow Fwd Packets"),
    ("Subflow Fwd Byts", "Subflow Fwd Bytes"),
    ("Subflow Bwd Pkts", "Subflow Bwd Packets"),
    ("Subflow Bwd Byts", "Subflow Bwd Bytes"),
    ("Init Fwd Win Byts", "Init_Win_bytes_forward"),
    ("Init Bwd Win Byts", "Init_Win_bytes_backward"),
    ("Fwd Act Data Pkts", "act_data_pkt_fwd"),
    ("Fwd Seg Size Min", "min_seg_size_forward"),
    ("Active Mean", "Active Mean"),
    ("Active Std", "Active Std"),
    ("Active Max", "Active Max"),
    ("Active Min", "Active Min"),
    ("Idle Mean", "Idle Mean"),
    ("Idle Std", "Idle Std"),
    ("Idle Max", "Idle Max"),
    ("Idle Min", "Idle Min"),
)
FEATURES_2018: list[str] = [a for a, _ in FEATURE_NAMES]  # incl. Dst Port; the in-memory names
FEATURES_NOPORT: list[str] = [f for f in FEATURES_2018 if f != DST_PORT]
NAMES_2017_TO_2018: dict[str, str] = {b: a for a, b in FEATURE_NAMES}
if len(NAMES_2017_TO_2018) != len(FEATURE_NAMES) or len(set(FEATURES_2018)) != len(FEATURES_2018):
    raise ValueError("FEATURE_NAMES has a duplicated name")

# Timestamp formats exactly as published. CSE-CIC-IDS2018: "01/03/2018 08:17:11" (day/month/year,
# whole seconds, the HOUR ON A 12-HOUR CLOCK WITHOUT AM/PM: hours 1-7 are afternoon, see
# idps/public/cse2018.py). The clock/timezone is the dataset's own and is not converted: the
# values are only used to order flows and to cut the time split. CIC-IDS2017's are parsed by
# idps.features.labels.parse_cic_timestamps (minute resolution, 12-hour quirks).
TIMESTAMP_FORMAT_2018 = "%d/%m/%Y %H:%M:%S"


def rename_2017(columns) -> tuple[dict[str, str], list[str], list[str]]:
    """How to rename a CIC-IDS2017 header to the common names.

    Returns (rename {raw 2017 column -> 2018 name}, unmatched 2017 columns that are not
    identifiers, 2018 features no 2017 column maps to). Leading/trailing spaces are ignored; the
    second of two identically named columns is left alone."""
    rename, seen = {}, set()
    skip = {"Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp", "Label"}
    unmatched = []
    for raw in columns:
        name = str(raw).strip()
        target = NAMES_2017_TO_2018.get(name)
        if target is not None and target not in seen:
            rename[raw] = target
            seen.add(target)
        elif name not in skip and not re.fullmatch(r".+\.\d+", name):
            unmatched.append(name)
    return rename, unmatched, [f for f in FEATURES_2018 if f not in seen]


# --- UNSW-NB15 -----------------------------------------------------------------------------------
# UNSW-NB15 (Argus/Bro features, a 2015 testbed) has its own nine attack categories. They do NOT map
# onto the CIC classes above (CIC-IDS has no Fuzzers, Exploits, Generic, Shellcode, Worms or Analysis;
# CIC's "DoS" is a different traffic generator than UNSW's), so they stay their own class names and
# no CIC <-> UNSW class mapping is made. Only spelling variants of the same UNSW class are merged.

UNSW_BENIGN_ORIGINAL = "Normal"  # the dataset's name for the class; its attack_cat field is blank
UNSW_CLASSES = (
    "BENIGN",
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
)
# (our class, attack_cat spelling found in the files or on the dataset's page)
UNSW_LABEL_TABLE: tuple[tuple[str, str], ...] = (
    ("BENIGN", "Normal"),
    ("Analysis", "Analysis"),
    ("Backdoor", "Backdoor"),  # the files use both spellings
    ("Backdoor", "Backdoors"),  # the dataset page and the paper write the plural
    ("DoS", "DoS"),
    ("Exploits", "Exploits"),
    ("Fuzzers", "Fuzzers"),  # also stored as " Fuzzers " and " Fuzzers" (padded with blanks)
    ("Generic", "Generic"),
    ("Reconnaissance", "Reconnaissance"),  # also " Reconnaissance "
    ("Shellcode", "Shellcode"),  # also " Shellcode "
    ("Worms", "Worms"),
)


def _build_unsw_keys() -> dict[str, str]:
    keys: dict[str, str] = {}
    for common, spelling in UNSW_LABEL_TABLE:
        if keys.setdefault(label_key(spelling), common) != common:
            raise ValueError(f"label spelling {spelling!r} maps to two classes")
    return keys


_UNSW_KEYS = _build_unsw_keys()


def unsw_label(raw: str) -> str:
    """Our class of a UNSW-NB15 attack_cat value (blanks around it are ignored, and so are case and
    punctuation); an unknown value raises. A blank value is NOT mapped here: the loader decides it
    from the Label column (blank + Label 0 = Normal, blank + Label 1 = a contradiction)."""
    try:
        return _UNSW_KEYS[label_key(raw)]
    except KeyError:
        raise ValueError(
            f"unknown UNSW-NB15 attack_cat {str(raw)!r}: add it to UNSW_LABEL_TABLE in "
            "idps/public/labels.py"
        ) from None


def unsw_label_table_markdown() -> str:
    rows = ["| Class (this project) | UNSW-NB15 attack_cat spelling |", "|---|---|"]
    rows += [f"| {c} | {s} |" for c, s in UNSW_LABEL_TABLE]
    return "\n".join(rows)
