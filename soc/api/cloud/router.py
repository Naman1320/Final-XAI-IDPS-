"""All /cloud routes, assembled for soc.api.main."""

from fastapi import APIRouter

from soc.api.cloud import activity, alerts, demo, instances, monitoring, network, storage

router = APIRouter()
for module in (monitoring, instances, storage, network, alerts, activity, demo):
    router.include_router(module.router)
