"""UNSW-NB15 loader: four header-less CSVs + the feature-name file -> one clean, memory-bounded
float32 frame.

The data (Moustafa and Slay, MilCIS 2015) is `UNSW-NB15_1.csv` .. `_4.csv` (49 fields per row, no
header row, CRLF line ends, Latin-1-safe) and `NUSW-NB15_features.csv` (No., Name, Type, Description:
the 49 column names in order). Quirks found in the real files (counts are in the report):
- file 1 starts with a UTF-8 byte order mark, which sits inside the first field (srcip, unused);
- the last row of each file is repeated as the first row of the next file (3 rows): the four files
  hold 2,540,047 rows, the dataset page says 2,540,044;
- the feature file names one column "ct_src_ ltm" (a blank inside); names are cleaned (see
  `clean_name`) and the mapping is recorded;
- attack_cat is blank for normal traffic and padded with blanks (" Fuzzers ", " Fuzzers",
  " Reconnaissance ", " Shellcode ") or spelled two ways ("Backdoor" and "Backdoors");
- sport / dsport hold hex strings (0x000c, 0xcc09, 0x20205321: ICMP/ESP rows) and "-";
- ct_flw_http_mthd, is_ftp_login and ct_ftp_cmd are blank (ct_ftp_cmd: a single space) in over half
  of the rows, and is_ftp_login holds 2 and 4 besides 0/1;
- the rows are in order of Ltime (record end), not Stime; Stime has 1 s resolution;
- the two captures are 26 days apart (22-23 Jan and 18 Feb 2015, UTC); a calendar-day key would
  cut the first one at midnight, so rows are grouped into capture SESSIONS (gap over one day).

Steps, with the class counts after each one in the report:
1. `raw`: rows read that have a usable label (not a repeated header, Label 0/1, attack_cat
   consistent with Label); a contradictory row is dropped and counted, an unknown attack_cat is an
   error;
2. `after_file_overlap`: minus the rows repeated across a file boundary;
3. `valid_timestamp`: rows with a Stime that is a number inside 2015;
4. `sampled`: at most `caps` rows per (capture session, attack_cat), evenly spaced in time
   (idps.public.sampling); applied before step 5, so a group can end a little under its cap;
5. `finite`: rows whose features all parse; blank is_ftp_login / ct_ftp_cmd / ct_flw_http_mthd
   become 0 and is_ftp_login is clipped to 0/1 (both counted), hex ports are read as hex and
   "-" ports become -1 (counted); any other unparseable, infinite or float32-overflowing cell drops
   the whole row (counted per column). Nothing is silently filled in.
Exact duplicates are removed later, inside each split (see idps.public.pipeline).

The CSVs are read twice, in batches (never all rows): pass 1 reads Stime, Ltime, attack_cat and Label
of every row to choose the sample; pass 2 reads the feature columns of the chosen rows.
"""

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from idps.public.labels import UNSW_BENIGN_ORIGINAL, unsw_label
from idps.public.sampling import Caps, select_rows

DATASET = "UNSW-NB15"
FEATURES_FILE = "NUSW-NB15_features.csv"
CHECKSUMS_FILE = "checksums.json"
BATCH_ROWS = 262_144
ENCODING = "latin-1"  # every byte value is a character; the files are ASCII apart from the BOM
UTF8_BOM = b"\xef\xbb\xbf"
# Stime is epoch seconds; the capture was in 2015. Anything else is a bad timestamp.
MIN_SECONDS = 1420070400  # 2015-01-01 00:00:00 UTC
MAX_SECONDS = 1451606400  # 2016-01-01 00:00:00 UTC
MAX_BAD_TIMESTAMP_SHARE = 0.05
SESSION_GAP_S = 86_400  # more than a day without any flow = a new capture session
FLOAT32_MAX = float(np.finfo(np.float32).max)
NO_PORT = -1.0  # sport/dsport "-" or blank

# The 49 columns in file order, after clean_name(). "label" is the 0/1 column: it is called
# label_binary here so that it cannot be mixed up with `label`, the class the models learn.
ALL_COLUMNS: tuple[str, ...] = (
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl",
    "dttl", "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts", "swin", "dwin",
    "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "sjit", "djit", "stime",
    "ltime", "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
    "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat",
    "label_binary",
)  # fmt: skip
ID_COLUMNS = ("srcip", "dstip", "stime", "ltime")  # hosts and time: never features
LABEL_COLUMNS = ("attack_cat", "label_binary")
PORT_COLUMNS = ("sport", "dsport")
CATEGORICAL = ("proto", "state", "service")
BLANK_TO_ZERO = ("ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd")
BINARY_FLAGS = ("is_ftp_login",)  # 2 and 4 occur: clipped to 1 ("the session was logged in")
# Features in file order. Categorical columns appear as integer codes (CategoryEncoder).
FEATURES_UNSW: list[str] = [c for c in ALL_COLUMNS if c not in (*ID_COLUMNS, *LABEL_COLUMNS)]
FEATURES_UNSW_NOPORT: list[str] = [c for c in FEATURES_UNSW if c not in PORT_COLUMNS]
NUMERIC_FEATURES: list[str] = [c for c in FEATURES_UNSW if c not in CATEGORICAL]  # incl. ports
_PURE_NUMERIC = [c for c in NUMERIC_FEATURES if c not in PORT_COLUMNS]


def clean_name(raw: str) -> str:
    """Deterministic column name: all whitespace removed (inside too: "ct_src_ ltm" ->
    "ct_src_ltm"), then lower-case ("Sload" -> "sload", "Stime" -> "stime"). The 0/1 column
    "Label" becomes "label_binary". The feature file's own spelling is kept in the report."""
    name = re.sub(r"\s+", "", str(raw)).lower()
    return "label_binary" if name == "label" else name


def read_feature_names(data_dir: str | Path) -> tuple[list[str], dict]:
    """(the 49 clean column names in order, report) from NUSW-NB15_features.csv. The names must
    equal ALL_COLUMNS: a different feature file is an error, never guessed at."""
    path = Path(data_dir) / FEATURES_FILE
    if not path.exists():
        raise FileNotFoundError(f"{path} not found (the file that names the 49 columns)")
    table = pd.read_csv(path, encoding=ENCODING, dtype=str, keep_default_na=False)
    table.columns = [str(c).strip() for c in table.columns]
    if "Name" not in table.columns:
        raise ValueError(f"{path.name} has no 'Name' column; found {list(table.columns)}")
    raw = [str(n) for n in table["Name"]]
    names = [clean_name(n) for n in raw]
    if names != list(ALL_COLUMNS):
        diff = sorted(set(names) ^ set(ALL_COLUMNS)) or "same names, different order"
        raise ValueError(
            f"{path.name} lists {len(names)} columns that differ from the expected 49: {diff}"
        )
    types = [str(t).strip() for t in table.get("Type", table.iloc[:, 2])]
    mapping = [
        {"file_name": r, "name": n, "type": t, "renamed": r != n}
        for r, n, t in zip(raw, names, types, strict=True)
    ]
    return names, {"file": path.name, "n_columns": len(names), "columns": mapping}


def list_files(data_dir: str | Path, only: list[str] | None = None) -> list[Path]:
    """UNSW-NB15_<n>.csv in numeric order (the order of the capture). `only`: keep files whose
    name contains one of these (for example "_1" "_2")."""
    data_dir = Path(data_dir)
    files = sorted(
        (
            p
            for p in data_dir.glob("UNSW-NB15_*.csv")
            if re.fullmatch(r"UNSW-NB15_\d+\.csv", p.name)
        ),
        key=_file_no,
    )
    if only:
        files = [f for f in files if any(o in f.name for o in only)]
    if not files:
        raise ValueError(f"no UNSW-NB15_<n>.csv files found in {data_dir}")
    return files


def _file_no(path: Path) -> int:
    """n of UNSW-NB15_<n>.csv"""
    return int(re.fullmatch(r"UNSW-NB15_(\d+)", path.stem).group(1))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_checksums(data_dir: Path, files: list[Path]) -> dict:
    """Compare the files with checksums.json (written when the data was fetched), if it exists.
    A file that no longer matches is an error. Returns {file: {"rows": n, "sha256_ok": True}}."""
    path = data_dir / CHECKSUMS_FILE
    if not path.exists():
        return {}
    known = json.loads(path.read_text())
    out = {}
    for f in files:
        entry = known.get(f.name)
        if not isinstance(entry, dict) or "sha256" not in entry:
            continue
        if _sha256(f) != entry["sha256"]:
            raise ValueError(f"{f.name} does not match its SHA-256 in {CHECKSUMS_FILE}")
        out[f.name] = {"rows": entry.get("rows"), "sha256_ok": True}
    return out


def edge_lines(path: Path) -> tuple[str, str, bool]:
    """(first line, last line, starts with a UTF-8 BOM) of a CSV: the BOM and the line end are
    removed. Used to find the row that one file repeats from the end of the previous file."""
    with open(path, "rb") as f:
        first = f.readline()
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 65_536))
        tail = f.read()
    bom = first.startswith(UTF8_BOM)
    if bom:
        first = first[len(UTF8_BOM) :]
    lines = [x for x in tail.splitlines() if x.strip()]
    last = lines[-1] if lines else b""
    return (
        first.decode(ENCODING).rstrip("\r\n"),
        last.decode(ENCODING).rstrip("\r\n"),
        bom,
    )


def assign_sessions(ts: np.ndarray, gap_s: int = SESSION_GAP_S) -> tuple[np.ndarray, list[dict]]:
    """(session id per row, description). A new session starts after `gap_s` seconds in which no
    flow starts: UNSW-NB15's two captures are 26 days apart. Ids are 0, 1, ... in time order."""
    if len(ts) == 0:
        return np.zeros(0, dtype=np.int32), []
    order = np.sort(ts)
    cuts = order[1:][np.diff(order) > gap_s]  # the first Stime of every later session
    sid = np.searchsorted(cuts, ts, side="right").astype(np.int32)
    starts = np.concatenate([[order[0]], cuts])
    ends = np.concatenate([order[np.searchsorted(order, cuts, side="left") - 1], [order[-1]]])
    info = [
        {
            "session": i,
            "first_stime": pd.Timestamp(int(s), unit="s").isoformat(),
            "last_stime": pd.Timestamp(int(e), unit="s").isoformat(),
            "rows": int((sid == i).sum()),
        }
        for i, (s, e) in enumerate(zip(starts, ends, strict=True))
    ]
    return sid, info


# --- cell parsing --------------------------------------------------------------------------------


def _numbers(col: pd.Series) -> np.ndarray:
    """Text -> float64; anything unparseable is NaN ("inf" stays inf: it is caught as non-finite)."""
    return pd.to_numeric(col, errors="coerce").to_numpy(dtype="float64", na_value=np.nan)


def parse_ports(col: pd.Series) -> tuple[np.ndarray, dict[str, int]]:
    """Port text -> float64 and counts of what was coerced. Decimal ("80") is read as is; hex
    ("0xcc09", the ICMP/ESP rows) as its value; "-" and blank become NO_PORT (-1); anything else is
    NaN, which makes the loader drop the row. Counts: decimal, hex, dash_or_blank, unparseable."""
    s = col.astype(str).str.strip()
    dec = s.str.fullmatch(r"\d+").to_numpy(dtype=bool)
    hexm = s.str.fullmatch(r"0[xX][0-9a-fA-F]+").to_numpy(dtype=bool)
    none = s.isin(["-", ""]).to_numpy(dtype=bool)
    out = np.full(len(s), np.nan)
    out[dec] = s[dec].astype("float64").to_numpy()
    out[hexm] = [float(int(v, 16)) for v in s[hexm]]
    out[none] = NO_PORT
    counts = {
        "decimal": int(dec.sum()),
        "hex": int(hexm.sum()),
        "dash_or_blank": int(none.sum()),
        "unparseable": int((~(dec | hexm | none)).sum()),
    }
    return out, counts


def parse_features(raw: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, dict]:
    """A batch of text columns -> (float32 matrix, one column per NUMERIC_FEATURES; finite mask per
    row; coercion counts). Rows with a False mask are dropped by the caller."""
    mat = np.empty((len(raw), len(NUMERIC_FEATURES)), dtype=np.float64)
    co = {"blank_to_zero": Counter(), "flag_clipped": Counter(), "hex_port": Counter(),
          "dash_or_blank_port": Counter()}  # fmt: skip
    for j, name in enumerate(NUMERIC_FEATURES):
        col = raw[name]
        if name in PORT_COLUMNS:
            mat[:, j], c = parse_ports(col)
            co["hex_port"][name] += c["hex"]
            co["dash_or_blank_port"][name] += c["dash_or_blank"]
            continue
        if name in BLANK_TO_ZERO:
            blank = col.astype(str).str.strip().eq("").to_numpy(dtype=bool)
            col = col.where(~blank, "0")
            co["blank_to_zero"][name] += int(blank.sum())
        mat[:, j] = _numbers(col)
        if name in BINARY_FLAGS:
            over = mat[:, j] > 1
            co["flag_clipped"][name] += int(over.sum())
            mat[over, j] = 1.0
    finite = np.isfinite(mat).all(axis=1) & (np.abs(mat) <= FLOAT32_MAX).all(axis=1)
    bad = {
        NUMERIC_FEATURES[j]: int(
            (~(np.isfinite(mat[:, j]) & (np.abs(mat[:, j]) <= FLOAT32_MAX))).sum()
        )
        for j in range(mat.shape[1])
    }
    co["nonfinite_by_column"] = Counter({k: v for k, v in bad.items() if v})
    with np.errstate(invalid="ignore"):
        return mat.astype(np.float32), finite, co


# --- categorical encoding, fitted on the TRAIN split only ---------------------------------------

OTHER_CODE = 0
DEFAULT_MAX_CATEGORIES = 30


class CategoryEncoder:
    """proto / state / service as integer codes, with the categories fixed from the TRAINING split.

    Per column the `max_categories` most frequent training values get the codes 1, 2, ... in order
    of decreasing training frequency (ties alphabetical); every other value, and every value that
    only occurs in validation/test data, gets the reserved code 0 ("other"). Because the mapping
    is built from training rows alone, no information about the held-out data reaches it: a value
    unseen in training cannot even be told apart from another unseen one. The ranking by training
    frequency gives the codes a stable, documented order (no alphabetical accident), and the
    model keeps one feature per original column, so SHAP/LIME still explain "proto", "service",
    "state". `to_dict()` goes into the model bundle, so inference reproduces the encoding."""

    def __init__(self, mapping: dict[str, dict[str, int]], max_categories: int, train_rows: int):
        self.mapping, self.max_categories, self.train_rows = mapping, max_categories, train_rows

    @classmethod
    def fit(
        cls, train: pd.DataFrame, columns=CATEGORICAL, max_categories=DEFAULT_MAX_CATEGORIES
    ) -> "CategoryEncoder":
        if max_categories < 1:
            raise ValueError("max_categories must be at least 1")
        mapping = {}
        for col in columns:
            counts = train[col].astype(str).value_counts()
            ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:max_categories]
            mapping[col] = {value: i + 1 for i, (value, _) in enumerate(ranked)}
        return cls(mapping, max_categories, len(train))

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """A copy of df whose categorical columns are float32 codes (unseen values: OTHER_CODE)."""
        out = df.copy()
        for col, table in self.mapping.items():
            codes = df[col].astype(str).map(table).fillna(OTHER_CODE)
            out[col] = codes.to_numpy(dtype=np.float32)
        return out

    def describe(self, parts: dict[str, pd.DataFrame] | None = None) -> dict:
        """The mapping, and (given the raw splits) the share of rows each split sends to 'other'."""
        out = {
            "scheme": "ordinal code by training-set frequency; 0 = other / unseen in training",
            "max_categories_per_column": self.max_categories,
            "fitted_on_rows": self.train_rows,
            "other_code": OTHER_CODE,
            "categories": self.mapping,
        }
        if parts is not None:
            out["share_other_by_split"] = {
                name: {
                    col: float((~df[col].astype(str).isin(table)).mean()) if len(df) else 0.0
                    for col, table in self.mapping.items()
                }
                for name, df in parts.items()
            }
            out["values_coded_other_by_split"] = {
                name: {
                    col: sorted(set(df[col].astype(str)) - set(table))
                    for col, table in self.mapping.items()
                }
                for name, df in parts.items()
                if name != "train"
            }
        return out

    def to_dict(self) -> dict:
        return {
            "mapping": self.mapping,
            "max_categories": self.max_categories,
            "train_rows": self.train_rows,
            "other_code": OTHER_CODE,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CategoryEncoder":
        return cls(d["mapping"], d["max_categories"], d["train_rows"])


# --- the loader ----------------------------------------------------------------------------------


def _read_csv(path: Path, names: list[str], usecols: list[str], n: int | None):
    """Batches of the CSV as text (header-less file, explicit names). A BOM only touches srcip,
    which is never read."""
    return pd.read_csv(
        path,
        header=None,
        names=names,
        usecols=usecols,
        dtype=str,
        keep_default_na=False,
        encoding=ENCODING,
        chunksize=BATCH_ROWS,
        nrows=n,
    )


def _scan(path: Path, names: list[str], n: int | None) -> dict:
    """Pass 1: Stime, Ltime and labels of the first n rows (all if None), plus the counts of the odd
    cell values over ALL of those rows (the sampled rows' counts are in the pass-2 coercions)."""
    ts_parts, code_parts, ok_parts = [], [], []
    originals: dict[str, int] = {}
    raw_values: Counter = Counter()
    unknown: set[str] = set()
    c = Counter()
    quirks: Counter = Counter()
    quirk_cols = ["stime", "ltime", "attack_cat", "label_binary", *PORT_COLUMNS, *BLANK_TO_ZERO]
    for df in _read_csv(path, names, quirk_cols, n):
        for name in PORT_COLUMNS:
            _, pc = parse_ports(df[name])
            quirks[f"{name}_hex"] += pc["hex"]
            quirks[f"{name}_dash_or_blank"] += pc["dash_or_blank"]
            quirks[f"{name}_unparseable"] += pc["unparseable"]
        for name in BLANK_TO_ZERO:
            quirks[f"{name}_blank"] += int(df[name].str.strip().eq("").sum())
        quirks["is_ftp_login_over_1"] += int((_numbers(df["is_ftp_login"]) > 1).sum())
        stime, ltime = _numbers(df["stime"]), _numbers(df["ltime"])
        binary = df["label_binary"].str.strip()
        hdr = (binary.str.lower() == "label_binary") | (binary.str.lower() == "label")
        hdr = (hdr | (df["stime"].str.strip().str.lower() == "stime")).to_numpy(dtype=bool)
        raw_values.update(df["attack_cat"].value_counts().to_dict())
        cat = df["attack_cat"].str.strip()
        is_normal = (binary == "0").to_numpy(dtype=bool)
        orig = cat.where(cat != "", np.where(is_normal, UNSW_BENIGN_ORIGINAL, ""))
        bad_label = ~binary.isin(["0", "1"]).to_numpy(dtype=bool) & ~hdr
        blank = (orig == "").to_numpy(dtype=bool)
        cls = np.full(len(df), "", dtype=object)
        for value in orig[~blank].unique():
            try:
                cls[(orig == value).to_numpy(dtype=bool)] = unsw_label(value)
            except ValueError:
                unknown.add(value)
        contradiction = ~hdr & ~bad_label & (blank | ((cls == "BENIGN") != is_normal))
        usable = ~hdr & ~bad_label & ~contradiction
        ts_ok = np.isfinite(stime) & (stime >= MIN_SECONDS) & (stime < MAX_SECONDS)
        c["header_rows"] += int(hdr.sum())
        c["bad_label"] += int(bad_label.sum())
        c["label_contradictions"] += int(contradiction.sum())
        c["bad_timestamp"] += int((usable & ~ts_ok).sum())
        c["ltime_before_stime"] += int((usable & ts_ok & (ltime < stime)).sum())
        c["flows_longer_than_120s"] += int((usable & ts_ok & ((ltime - stime) > 120)).sum())
        codes = np.full(len(df), -1, dtype=np.int32)
        for value in orig[usable].unique():
            codes[(orig == value).to_numpy(dtype=bool) & usable] = originals.setdefault(
                value, len(originals)
            )
        ts_parts.append(np.where(ts_ok, np.nan_to_num(stime), 0).astype(np.int64))
        code_parts.append(codes)
        ok_parts.append(ts_ok)
    if unknown:
        raise ValueError(
            f"{path.name}: unknown attack_cat value(s) {sorted(unknown)}: add them to "
            "UNSW_LABEL_TABLE in idps/public/labels.py"
        )
    empty = np.zeros(0, dtype=np.int64)
    return {
        "ts": np.concatenate(ts_parts) if ts_parts else empty,
        "code": np.concatenate(code_parts) if code_parts else empty.astype(np.int32),
        "ts_ok": np.concatenate(ok_parts) if ok_parts else empty.astype(bool),
        "names": list(originals),
        "raw_attack_cat": raw_values,
        "quirks": quirks,
        **{k: c[k] for k in (
            "header_rows", "bad_label", "label_contradictions", "bad_timestamp",
            "ltime_before_stime", "flows_longer_than_120s")},
    }  # fmt: skip


def _iso(seconds) -> str:
    return pd.Timestamp(int(seconds), unit="s").isoformat()


def _count(codes: np.ndarray, common_of: list[str]) -> dict[str, int]:
    counts = np.bincount(codes[codes >= 0], minlength=len(common_of))
    out: Counter = Counter()
    for cls, k in zip(common_of, counts, strict=True):
        out[cls] += int(k)
    return {k: v for k, v in out.items() if v}


def load_unsw(
    data_dir: str | Path,
    caps: Caps | None = None,
    seed: int = 42,
    max_rows: int | None = None,
    only: list[str] | None = None,
) -> tuple[pd.DataFrame, dict]:
    """The UNSW-NB15 CSVs of data_dir -> (one frame, report).

    Frame columns: NUMERIC_FEATURES (float32, ports included), proto / state / service (text, the
    categories are encoded later from the train split only), `start_ms` (Stime x 1000, read as
    UTC), `session` (capture session), `label` (our class), `label_original` (attack_cat without
    its blanks; "Normal" for the blank attack_cat of Label 0 rows) and `source` (file name).
    `max_rows`: read only the first rows of every file (smoke tests)."""
    caps = caps or Caps()
    data_dir = Path(data_dir)
    names, name_report = read_feature_names(data_dir)
    files = list_files(data_dir, only)
    checksums = check_checksums(data_dir, files)

    # pass 1: every file's timestamps and labels (small arrays), then ONE global sample, because a
    # (session, attack_cat) group runs across file boundaries
    scans = [_scan(f, names, max_rows) for f in files]
    original_names: list[str] = []
    for s in scans:
        for x in s["names"]:
            if x not in original_names:
                original_names.append(x)
    index = {x: i for i, x in enumerate(original_names)}
    common_of = [unsw_label(x) for x in original_names]
    lens = [len(s["ts"]) for s in scans]
    offsets = np.concatenate([[0], np.cumsum(lens)]).astype(np.int64)
    ts = np.concatenate([s["ts"] for s in scans])
    ts_ok = np.concatenate([s["ts_ok"] for s in scans])
    code = np.concatenate(
        [np.array([*(index[x] for x in s["names"]), -1], dtype=np.int32)[s["code"]] for s in scans]
    )  # local label codes -> global ones (-1 stays -1: it indexes the appended -1)
    n_bad_ts = sum(s["bad_timestamp"] for s in scans)
    if len(ts) and n_bad_ts > MAX_BAD_TIMESTAMP_SHARE * len(ts):
        raise ValueError(
            f"{n_bad_ts} of {len(ts)} Stime values are not epoch seconds inside 2015; "
            "check the file format"
        )

    # a row repeated across a file boundary: first line of file k+1 == last line of file k
    edges = {f.name: edge_lines(f) for f in files}
    overlap = np.zeros(len(code), dtype=bool)
    boundary = []
    for k in range(1, len(files)):
        consecutive = _file_no(files[k]) == _file_no(files[k - 1]) + 1
        if consecutive and lens[k] and edges[files[k].name][0] == edges[files[k - 1].name][1]:
            overlap[offsets[k]] = True
            boundary.append({"file": files[k].name, "repeats_last_row_of": files[k - 1].name})
    raw_codes = code
    after_overlap = np.where(overlap, -1, code)
    usable = (after_overlap >= 0) & ts_ok
    usable_codes = np.where(usable, code, -1)
    idx = np.flatnonzero(usable)
    session, session_info = assign_sessions(ts[idx])
    sess_all = np.zeros(len(code), dtype=np.int32)
    sess_all[idx] = session
    original = (
        np.array(original_names, dtype=object)[code[idx]] if len(idx) else np.array([], object)
    )
    cap_of = {x: caps.for_class(c) for x, c in zip(original_names, common_of, strict=True)}
    keep = select_rows(session, original, ts[idx], cap_of.__getitem__, seed)
    selected = np.zeros(len(code), dtype=bool)
    selected[idx[keep]] = True
    sampled_codes = np.where(selected, code, -1)
    groups = pd.DataFrame({"session": session, "label_original": original})
    available = groups.value_counts().rename("available")
    picked = groups[keep].value_counts().rename("sampled")

    # pass 2: the feature columns of the chosen rows only
    feature_cols = [*NUMERIC_FEATURES, *CATEGORICAL]
    frames, finite_codes = [], []
    co = {"blank_to_zero": Counter(), "flag_clipped": Counter(), "hex_port": Counter(),
          "dash_or_blank_port": Counter(), "nonfinite_by_column": Counter()}  # fmt: skip
    per_file = []
    for k, path in enumerate(files):
        base, n_file = int(offsets[k]), lens[k]
        sel_file = selected[base : base + n_file]
        kept_here = 0
        dropped_here = 0
        offset = 0
        file_frames = []
        for raw in _read_csv(path, names, feature_cols, max_rows):
            sel = sel_file[offset : offset + len(raw)]
            if sel.any():
                part = raw[sel]
                mat, finite, c = parse_features(part)
                for key, counter in c.items():
                    co[key].update(counter)
                pos = np.flatnonzero(sel) + offset + base
                finite_codes.append(code[pos[finite]])
                dropped_here += int((~finite).sum())
                pos = pos[finite]
                frame = pd.DataFrame(mat[finite], columns=NUMERIC_FEATURES)
                for col in CATEGORICAL:
                    frame[col] = part[col].str.strip().to_numpy()[finite]
                frame["start_ms"] = ts[pos] * 1000
                frame["session"] = sess_all[pos]
                frame["label_original"] = np.array(original_names, dtype=object)[code[pos]]
                file_frames.append(frame)
                kept_here += len(frame)
            offset += len(raw)
        if file_frames:
            whole = pd.concat(file_frames, ignore_index=True)
            whole["source"] = path.name
            frames.append(whole)
        s = scans[k]
        per_file.append(
            {
                "file": path.name,
                "bom": edges[path.name][2],
                "rows_read": n_file,
                "rows_in_checksums_json": checksums.get(path.name, {}).get("rows"),
                "sha256_ok": checksums.get(path.name, {}).get("sha256_ok"),
                "header_rows": s["header_rows"],
                "bad_label": s["bad_label"],
                "label_contradictions": s["label_contradictions"],
                "bad_timestamp": s["bad_timestamp"],
                "ltime_before_stime": s["ltime_before_stime"],
                "flows_longer_than_120s": s["flows_longer_than_120s"],
                "rows_selected": int(sel_file.sum()),
                "nonfinite_dropped": dropped_here,
                "rows_kept": kept_here,
            }
        )
    out = (
        pd.concat(frames, ignore_index=True)
        if frames
        else pd.DataFrame(
            columns=[
                *NUMERIC_FEATURES,
                *CATEGORICAL,
                "start_ms",
                "session",
                "label_original",
                "source",
            ]
        )
    )
    out["label"] = out["label_original"].map(dict(zip(original_names, common_of, strict=True)))
    finite_all = np.concatenate(finite_codes) if finite_codes else np.zeros(0, dtype=np.int32)
    steps = {
        "raw": _count(raw_codes, common_of),
        "after_file_overlap": _count(after_overlap, common_of),
        "valid_timestamp": _count(usable_codes, common_of),
        "sampled": _count(sampled_codes, common_of),
        "finite": _count(finite_all, common_of),
    }
    raw_attack_cat: Counter = Counter()
    raw_quirks: Counter = Counter()
    for s in scans:
        raw_attack_cat.update(s["raw_attack_cat"])
        raw_quirks.update(s["quirks"])
    report = {
        "dataset": f"{DATASET} (UNSW-NB15_1..4.csv, Moustafa and Slay, MilCIS 2015)",
        "feature_names": name_report,
        "timestamp_note": "Stime = epoch seconds (1 s resolution), as published; start_ms = "
        "Stime x 1000 read as UTC. The rows are ordered by Ltime, not Stime.",
        "sessions": session_info,
        "sessions_note": f"capture sessions: a gap of more than {SESSION_GAP_S} s without any flow "
        "starts a new one (the day key of the split and of the caps)",
        "caps": caps.as_dict(),
        "caps_scope": "per (capture session, attack_cat), before the unparseable-number drop",
        "seed": seed,
        "max_rows_per_file": max_rows,
        "files": per_file,
        "file_boundary_overlap": boundary,
        "file_boundary_overlap_rows": int(overlap.sum()),
        "attack_cat_raw_values": {repr(k): int(v) for k, v in sorted(raw_attack_cat.items())},
        "odd_values_all_rows": dict(sorted(raw_quirks.items())),
        "coercions": {
            "scope": "the sampled rows only; odd_values_all_rows counts every row read",
            "rule": "blank ct_flw_http_mthd / is_ftp_login / ct_ftp_cmd -> 0; is_ftp_login > 1 -> 1; "
            "hex sport/dsport -> its value; '-' or blank port -> -1; any other unparseable, "
            "infinite or float32-overflowing cell drops the row",
            **{k: dict(v) for k, v in co.items()},
        },
        "n_features": len(FEATURES_UNSW),
        "steps": {k: {a: int(b) for a, b in sorted(v.items())} for k, v in steps.items()},
        "groups": [
            {
                "session": int(d),
                "label_original": lab,
                "label": unsw_label(lab),
                "cap": cap_of[lab],
                "available": int(av),
                "sampled": int(picked.get((d, lab), 0)),
            }
            for (d, lab), av in available.items()
        ],
        "rows_total": len(out),
    }
    return out, report
