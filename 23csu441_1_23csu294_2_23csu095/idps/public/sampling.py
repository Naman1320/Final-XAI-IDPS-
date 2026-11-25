"""Memory-bounded, time-stratified sampling of a public dataset, per (day, attack name).

CSE-CIC-IDS2018 has 16 million flows and our machine 8 GB of RAM, so the loader keeps at most
`cap` flows of every (day, original label) group. The kept flows are evenly spaced in time order
(systematic sampling with a seeded random start), so the sample covers the whole attack window
and the 60/20/20 time split afterwards still has early and late flows of every group. Groups at
or under their cap are kept whole. The same input and seed always give the same sample.
"""

import zlib
from collections.abc import Callable
from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd

from idps.public.labels import BENIGN

DAY_SECONDS = 86_400
DEFAULT_CAP_BENIGN = 250_000
DEFAULT_CAP_ATTACK = 150_000


@dataclass(frozen=True)
class Caps:
    """Most flows kept per (day, original label) group."""

    benign: int = DEFAULT_CAP_BENIGN
    attack: int = DEFAULT_CAP_ATTACK

    def __post_init__(self):
        if self.benign < 1 or self.attack < 1:
            raise ValueError("caps must be at least 1")

    def for_class(self, common: str) -> int:
        return self.benign if common == BENIGN else self.attack

    def as_dict(self) -> dict:
        return asdict(self)


def select_rows(
    day: np.ndarray, label: np.ndarray, ts: np.ndarray, cap_for: Callable[[str], int], seed: int
) -> np.ndarray:
    """Boolean mask of the rows to keep.

    `day`, `label` (original label strings) and `ts` (seconds) have one value per row.
    `cap_for(label)` is the cap of that label's groups. Within a group the rows are put in time
    order (ties keep their input order) and `cap` evenly spaced ones are taken, starting at a
    random offset drawn from (seed, day, label) alone: the pick of one group does not depend on
    the other groups.
    """
    keep = np.zeros(len(ts), dtype=bool)
    groups = pd.DataFrame({"day": day, "label": label}).groupby(["day", "label"], sort=True)
    for (d, lab), rows in groups.indices.items():
        cap = cap_for(lab)
        if len(rows) <= cap:
            keep[rows] = True
            continue
        order = rows[np.argsort(ts[rows], kind="stable")]
        rng = np.random.default_rng([seed, int(d) % (2**32), zlib.crc32(str(lab).encode())])
        pos = np.floor((np.arange(cap) + rng.random()) * (len(rows) / cap)).astype(np.int64)
        keep[order[pos]] = True
    return keep
