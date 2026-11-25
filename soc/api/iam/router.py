"""All /iam routes, assembled for soc.api.main."""

from fastapi import APIRouter

from soc.api.iam import groups, logs, policies, roles, users

router = APIRouter()
for module in (roles, users, groups, policies, logs):
    router.include_router(module.router)
