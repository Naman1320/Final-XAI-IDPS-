"""SOC API application.

Run (after setting IDPS_SOC_JWT_SECRET and creating an admin with `python -m soc.api create-user`):
    uvicorn soc.api.main:app --ws-max-size 65536 --reload

Run a single process (no --workers): the live alert feed is an in-process broadcaster.
See docs/soc.md for settings, endpoints and the auth model.
"""

import contextlib
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from soc.api import auth, oidc, privacy, reports
from soc.api.broadcast import AlertBroadcaster
from soc.api.cloud.router import router as cloud_router
from soc.api.db import init_db, make_engine, make_session_factory
from soc.api.geo import GeoLocator
from soc.api.iam.deps import WriteLimiter
from soc.api.iam.router import router as iam_router
from soc.api.integrations.manager import NotificationManager
from soc.api.integrations.reputation import ReputationService
from soc.api.limits import BodyLimitMiddleware
from soc.api.reports import ReportRunner
from soc.api.retention import RetentionRunner
from soc.api.routes import (
    actions,
    admin,
    alerts,
    assistant,
    blocks,
    c6,
    cases,
    demo,
    geo,
    integrations,
    live,
    metrics,
    sensors,
    training,
)
from soc.api.routes.demo import DemoState, new_token_throttle
from soc.api.routes.sensors import SensorAuditState
from soc.api.security import LoginThrottle
from soc.api.settings import SocSettings, get_settings


def create_app(settings: SocSettings | None = None) -> FastAPI:
    settings = settings or get_settings()
    # The interactive docs are unauthenticated, so they are off unless IDPS_SOC_ENABLE_DOCS=true.
    docs = {} if settings.enable_docs else {"docs_url": None, "redoc_url": None,
                                           "openapi_url": None}

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.retention.start()  # first pass shortly after start, then hourly
        app.state.report_runner.start()  # only runs when weekly report email is on
        yield
        app.state.report_runner.stop()
        app.state.retention.stop()
        app.state.notifier.close()  # stop the notification workers

    app = FastAPI(title="IDPS SOC API", lifespan=lifespan, **docs)
    app.state.settings = settings
    engine = make_engine(settings.database_url)
    init_db(engine, settings.auto_migrate)
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.state.retention = RetentionRunner(app.state.session_factory, settings)
    app.state.report_runner = ReportRunner(app.state.session_factory, settings)
    app.state.geo = GeoLocator(settings.geoip_db, settings.geo_demo)
    # The assistant is off (None) when no Anthropic credentials are configured.
    from soc.assistant.llm import make_llm

    app.state.assistant_llm = make_llm(settings.assistant_model, settings.assistant_effort)
    app.state.assistant_limiter = None
    app.state.assistant_slots = None
    # Outbound integrations (notifications, syslog, reputation); all optional, env-configured.
    app.state.notifier = NotificationManager(settings)
    app.state.reputation = ReputationService(settings)
    app.state.sensor_audit = SensorAuditState()  # throttles sensor-status audit rows
    app.state.iam_limiter = WriteLimiter()  # writes per user per minute on /iam
    app.state.cloud_limiter = WriteLimiter()  # writes per user per minute on /cloud
    app.state.c6 = c6.Slot()
    app.state.demo = DemoState()  # the live demo's one run slot (routes/demo.py), in memory
    app.state.demo_token_throttle = new_token_throttle()  # wrong X-Demo-Token values per address
    app.state.broadcaster = AlertBroadcaster(settings.ws_max_connections, settings.ws_queue_size)
    app.state.login_throttle = LoginThrottle(
        settings.login_max_failures, settings.login_max_failures_per_ip,
        settings.login_lockout_minutes * 60)
    # Single sign-on (soc/api/oidc.py): None unless IDPS_SOC_OIDC_ISSUER is set.
    app.state.oidc = oidc.OidcClient(settings) if settings.oidc_issuer else None
    app.state.oidc_log = logging.getLogger("soc.oidc")
    # Wrong MFA codes, per user (see auth._CodeAttempt).
    app.state.mfa_throttle = LoginThrottle(
        settings.mfa_max_failures, settings.mfa_max_failures, settings.login_lockout_minutes * 60)

    # Added before CORS so the CORS headers are on its 413s too (the last one added is outermost).
    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"])

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default echoes each bad input back. That fails to serialise for NaN
        # (a 500) and would send a rejected 16 KB explanation straight back, so leave it out.
        detail = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]}
                  for e in exc.errors()]
        return JSONResponse({"detail": detail}, status_code=422)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth.router)
    app.include_router(oidc.router)
    for module in (alerts, live, blocks, actions, cases, metrics, geo, assistant, admin, sensors,
                   training, integrations, privacy, reports, demo, c6):
        app.include_router(module.router)
    app.include_router(iam_router)
    app.include_router(cloud_router)
    return app


def __getattr__(name: str):
    # `uvicorn soc.api.main:app` builds the app on first access, so importing this module
    # (e.g. in tests) doesn't require IDPS_SOC_JWT_SECRET to be set.
    if name == "app":
        globals()["app"] = application = create_app()
        return application
    raise AttributeError(name)
