"""Fetch CSE-CIC-IDS2018's "Processed Traffic Data for ML Algorithms" CSVs as Parquet.

Plan: docs/training-dataset1.md. Source: the dataset's public AWS open-data bucket, read
anonymously over plain HTTPS (no AWS account, no credentials, nothing billed to us).
Cite: Sharafaldin, Habibi Lashkari, Ghorbani, ICISSP 2018; https://registry.opendata.aws/cse-cic-ids2018/

The disk is small, so one file at a time:
1. refuse to start a file unless at least --keep-free GB would stay free while its CSV is on disk;
2. stream it to a temporary .part file, check its size and S3 ETag (plain or multipart MD5);
3. convert it to Parquet (zstd) with EVERY column read as text, so nothing is lost or guessed
   (the files repeat their header row mid-file and the Tuesday 20-02 file has 4 extra columns;
   cleaning is the loader's job, not this script's);
4. record size, ETag, SHA-256, rows and columns in manifest.json, then delete the CSV.
Re-running skips files already in the manifest whose Parquet file exists.

    .venv/bin/python scripts/fetch_cse_cic_ids2018.py            # all 10 files
    .venv/bin/python scripts/fetch_cse_cic_ids2018.py --list     # sizes only
"""

from __future__ import annotations

import argparse
import csv
import errno
import hashlib
import json
import os
import re
import shutil
import ssl
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from xml.etree import ElementTree

import certifi
import pyarrow as pa
import pyarrow.csv as pacsv
import pyarrow.parquet as pq

BUCKET_URL = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com"
PREFIX = "Processed Traffic Data for ML Algorithms/"
S3_NS = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO / "data" / "raw" / "cse-cic-ids2018"
CHUNK = 1024 * 1024
# python.org builds of Python ship no CA certificates; use certifi's bundle (never skip checks).
TLS = ssl.create_default_context(cafile=certifi.where())
# Part sizes S3 clients commonly use, tried first; any other part size is derived from the
# multipart ETag's part count (the part size P must satisfy ceil(size / P) == parts).
PART_SIZES_MIB = (8, 16, 5, 15, 32, 64, 100)
MIB = 1024 * 1024
PARQUET_SHARE = 0.35  # Parquet (zstd, text columns) came out at 25-30% of the CSV so far
DOWNLOAD_TRIES = 3


def list_files() -> list[dict]:
    """The CSV objects under PREFIX: key, size and ETag, from the anonymous bucket listing."""
    query = urllib.parse.urlencode({"list-type": "2", "prefix": PREFIX})
    with urllib.request.urlopen(f"{BUCKET_URL}/?{query}", timeout=60, context=TLS) as resp:
        root = ElementTree.fromstring(resp.read())
    if root.findtext("s3:IsTruncated", namespaces=S3_NS) == "true":
        raise RuntimeError("bucket listing is truncated; pagination is not implemented")
    files = []
    for item in root.findall("s3:Contents", S3_NS):
        key = item.findtext("s3:Key", namespaces=S3_NS)
        if not key.lower().endswith(".csv"):
            continue
        files.append(
            {
                "key": key,
                "size": int(item.findtext("s3:Size", namespaces=S3_NS)),
                "etag": item.findtext("s3:ETag", namespaces=S3_NS).strip('"'),
            }
        )
    return files


def candidate_part_sizes(size: int, parts: int) -> list[int]:
    """Part sizes (bytes) that give exactly `parts` parts for a file of `size` bytes."""
    if parts == 1:
        return [size]
    lo = -(-size // parts)  # smallest P with ceil(size / P) <= parts
    hi = (size - 1) // (parts - 1)  # largest P with ceil(size / P) >= parts
    sizes = [m * MIB for m in PART_SIZES_MIB if lo <= m * MIB <= hi]
    first, last = -(-lo // MIB), hi // MIB
    sizes += [m * MIB for m in range(first, min(last, first + 64) + 1) if m * MIB not in sizes]
    return sizes


def etag_matches(path: Path, etag: str) -> bool:
    """True if the file's MD5 (single upload) or multipart MD5 (some part size) equals etag."""
    if "-" not in etag:
        md5 = hashlib.md5(usedforsecurity=False)
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(CHUNK), b""):
                md5.update(block)
        return md5.hexdigest() == etag
    want_hash, want_parts = etag.split("-")
    for part in candidate_part_sizes(path.stat().st_size, int(want_parts)):
        digests = hashlib.md5(usedforsecurity=False)
        outer = b""
        with path.open("rb") as fh:
            for block in iter(lambda part=part, fh=fh: fh.read(part), b""):
                outer += hashlib.md5(block, usedforsecurity=False).digest()
        digests.update(outer)
        if digests.hexdigest() == want_hash:
            return True
    return False


def free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def download(key: str, dest: Path, size: int) -> None:
    """Stream the object to dest. A dropped connection resumes with a Range request; a full
    disk is never retried."""
    url = f"{BUCKET_URL}/{urllib.parse.quote(key)}"
    start, last = time.monotonic(), 0.0
    for attempt in range(1, DOWNLOAD_TRIES + 1):
        got = dest.stat().st_size if dest.exists() else 0
        if got == size:
            return
        request = urllib.request.Request(url)
        if got:
            request.add_header("Range", f"bytes={got}-")
        try:
            with urllib.request.urlopen(request, timeout=60, context=TLS) as resp:
                if got and resp.status != 206:
                    got = 0  # the server ignored the range: start over
                with dest.open("ab" if got else "wb") as out:
                    for block in iter(lambda: resp.read(CHUNK), b""):
                        out.write(block)
                        got += len(block)
                        now = time.monotonic()
                        if now - last > 15:
                            rate = got / max(now - start, 1e-6) / 1e6
                            print(
                                f"    {got / 1e6:8.1f} / {size / 1e6:.1f} MB  ({rate:.1f} MB/s)",
                                flush=True,
                            )
                            last = now
        except OSError as exc:
            if exc.errno == errno.ENOSPC or attempt == DOWNLOAD_TRIES:
                raise
            print(
                f"    connection problem ({exc}); retrying ({attempt}/{DOWNLOAD_TRIES})", flush=True
            )
            time.sleep(5 * attempt)
            continue
        if dest.stat().st_size == size:
            return
        print(f"    got {dest.stat().st_size} of {size} bytes; resuming", flush=True)
    raise RuntimeError(f"{key}: still short after {DOWNLOAD_TRIES} tries")


def read_header(csv_path: Path) -> list[str]:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
        return next(csv.reader(fh))


def atomic_write(path: Path, text: str) -> None:
    """Write text so that a crash or a full disk never leaves a truncated file at `path`."""
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(path)


def to_parquet(csv_path: Path, parquet_path: Path) -> dict:
    """Stream the CSV into Parquet with every column as string. Returns rows, columns, sha256.

    Raises, and leaves no Parquet file behind, unless every line of the CSV is accounted for:
    rows written + rows set aside = lines in the file - 1 (header).
    """
    sha = hashlib.sha256()
    newlines, last_byte = 0, b"\n"
    with csv_path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            sha.update(block)
            newlines += block.count(b"\n")
            last_byte = block[-1:]
    lines = newlines + (0 if last_byte == b"\n" else 1)
    columns = read_header(csv_path)
    # Duplicate names would break Parquet; keep them all, made unique, and record both lists.
    seen: dict[str, int] = {}
    unique = []
    for name in columns:
        n = seen.get(name, 0)
        unique.append(name if n == 0 else f"{name}__{n}")
        seen[name] = n + 1
    read_opts = pacsv.ReadOptions(
        column_names=unique, skip_rows=1, block_size=64 * 1024 * 1024, encoding="utf8"
    )
    convert_opts = pacsv.ConvertOptions(
        column_types={c: pa.string() for c in unique},
        strings_can_be_null=False,
        quoted_strings_can_be_null=False,
    )
    # Rows with a different number of fields (if any) are kept as raw text in a side file,
    # never silently dropped.
    bad_rows: list[str] = []

    def on_invalid(row) -> str:
        where = f"line {row.number}: " if row.number is not None else ""
        bad_rows.append(
            f"{where}expected {row.expected_columns} fields, got {row.actual_columns}: {row.text}"
        )
        return "skip"

    parse_opts = pacsv.ParseOptions(invalid_row_handler=on_invalid, ignore_empty_lines=False)
    rows = 0
    tmp = parquet_path.with_suffix(".parquet.part")
    badrows_path = parquet_path.with_suffix(".badrows.txt")
    try:
        reader = pacsv.open_csv(
            csv_path, read_options=read_opts, parse_options=parse_opts, convert_options=convert_opts
        )
        with pq.ParquetWriter(tmp, reader.schema, compression="zstd") as writer:
            for batch in reader:
                writer.write_batch(batch)
                rows += batch.num_rows
        if rows + len(bad_rows) != lines - 1:
            raise RuntimeError(
                f"{csv_path.name}: {lines - 1:,} data lines but {rows:,} rows written and "
                f"{len(bad_rows):,} set aside (embedded newlines or a parsing problem?)"
            )
        if pq.ParquetFile(tmp).metadata.num_rows != rows:
            raise RuntimeError(f"{parquet_path.name}: Parquet row count differs from rows written")
        with tmp.open("rb") as fh:
            os.fsync(fh.fileno())
        tmp.replace(parquet_path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    if bad_rows:
        atomic_write(badrows_path, "\n".join(bad_rows) + "\n")
    else:
        badrows_path.unlink(missing_ok=True)
    return {
        "rows": rows,
        "columns": columns,
        "unique_columns": unique,
        "csv_sha256": sha.hexdigest(),
        "csv_lines": lines - 1,
        "bad_rows": len(bad_rows),
    }


def load_manifest(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{path} is damaged ({exc}). The Parquet files next to it are intact: move the "
            "manifest aside and run again, which re-downloads every file."
        ) from exc


def already_done(entry: dict | None, f: dict, parquet_path: Path) -> bool:
    """True if the manifest, the file listing and the Parquet file on disk all agree."""
    if not entry or entry.get("etag") != f["etag"] or entry.get("size") != f["size"]:
        return False
    try:
        return parquet_path.stat().st_size == entry.get("parquet_bytes") and pq.ParquetFile(
            parquet_path
        ).metadata.num_rows == entry.get("rows")
    except (OSError, pa.ArrowInvalid):
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--keep-free", type=float, default=5.0, help="GB that must stay free")
    ap.add_argument("--list", action="store_true", help="only list the files and sizes")
    ap.add_argument("--only", help="regex: fetch only keys matching it")
    args = ap.parse_args()

    files = list_files()
    if args.only:
        files = [f for f in files if re.search(args.only, f["key"])]
    total = sum(f["size"] for f in files)
    for f in files:
        print(f"{f['size'] / 1e6:9.1f} MB  {Path(f['key']).name}")
    print(f"{len(files)} files, {total / 1e9:.2f} GB as CSV")
    if args.list:
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest.setdefault(
        "_source",
        {
            "bucket": BUCKET_URL,
            "prefix": PREFIX,
            "citation": "Sharafaldin, Habibi Lashkari, Ghorbani, ICISSP 2018",
            "note": "all columns stored as text; header repeats and odd rows kept for the loader",
        },
    )

    failed: list[str] = []
    # Smallest first: if space runs short, as much as possible is already done.
    for f in sorted(files, key=lambda f: f["size"]):
        name = Path(f["key"]).name
        parquet_path = args.out / (Path(name).stem + ".parquet")
        if already_done(manifest.get(name), f, parquet_path):
            print(f"skip {name} (already fetched)")
            continue
        # Peak use is the CSV plus the Parquet being written next to it.
        need = f["size"] * (1 + PARQUET_SHARE) + args.keep_free * 1e9
        if free_bytes(args.out) < need:
            print(
                f"STOP before {name}: {free_bytes(args.out) / 1e9:.1f} GB free, "
                f"need {need / 1e9:.1f} GB ({f['size'] / 1e9:.1f} GB file + "
                f"{f['size'] * PARQUET_SHARE / 1e9:.1f} GB for the Parquet + {args.keep_free} GB "
                "kept free). Free some space and run again; finished files are kept.",
                file=sys.stderr,
            )
            return 3
        part = args.out / (name + ".part")
        part.unlink(missing_ok=True)  # a leftover from a killed run can't be trusted
        print(f"get  {name} ({f['size'] / 1e6:.1f} MB)", flush=True)
        try:
            download(f["key"], part, f["size"])
            if not etag_matches(part, f["etag"]):
                raise RuntimeError(f"{name}: checksum does not match the bucket's ETag")
            print("    checksum ok; converting to Parquet", flush=True)
            info = to_parquet(part, parquet_path)
        except Exception as exc:  # noqa: BLE001 - report, keep going with the other files
            print(f"FAILED {name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            failed.append(name)
            continue
        finally:
            part.unlink(missing_ok=True)
        manifest[name] = {
            "key": f["key"],
            "size": f["size"],
            "etag": f["etag"],
            "parquet": parquet_path.name,
            "parquet_bytes": parquet_path.stat().st_size,
            **info,
        }
        atomic_write(manifest_path, json.dumps(manifest, indent=2) + "\n")
        print(
            f"    {info['rows']:,} rows, {len(info['columns'])} columns, "
            f"{parquet_path.stat().st_size / 1e6:.1f} MB Parquet"
            + (f", {info['bad_rows']} odd rows kept aside" if info["bad_rows"] else ""),
            flush=True,
        )
    if failed:
        print(f"{len(failed)} file(s) failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"done: {manifest_path}")
    return 0


if __name__ == "__main__":
    os.umask(0o022)
    sys.exit(main())
