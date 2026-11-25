"""POST /cloud/demo-data/reset: wipe the MOCK inventory and seed the demo data again."""

from fastapi import APIRouter

from soc.api.cloud import seed
from soc.api.cloud.common import Sourced, WriteAll, atomic, record

router = APIRouter(prefix="/cloud", tags=["cloud"])


class ResetResult(Sourced):
    demo_data: bool = True
    created: dict[str, int]


@router.post("/demo-data/reset", response_model=ResetResult)
def reset_demo_data(ctx: WriteAll):
    """Needs every cloud write permission: it replaces the whole mock inventory, its alerts, its
    activity timeline and its cost history with freshly generated DEMO data."""
    ctx.require_mock()
    with atomic(ctx.db):
        seed.wipe(ctx.db)
        counts = seed.seed(ctx.db)
        ctx.db.flush()
        record(ctx.db, ctx.user, "demo_data.reset", "demo_data", "*", {"created": counts})
    return ResetResult(**ctx.changed(), created=counts)
