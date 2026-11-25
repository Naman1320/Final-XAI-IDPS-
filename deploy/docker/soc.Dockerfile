# idps-soc: the SOC API only (no ML stack). Build from the repo root:
#   docker build -f deploy/docker/soc.Dockerfile --build-arg VERSION=0.2.0 --build-arg GIT_SHA=abc1234 .
# (deploy/install.sh does this for you with --build.)
FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY requirements.lock pyproject.toml README.md ./
# The API's packages only (the list in infra/templates/soc-user-data.sh.tftpl, checked by
# tests/test_deploy_files.py), versions pinned by requirements.lock. pandas is added to that
# list: soc.api.routes.alerts imports idps.features, which needs pandas and numpy.
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --retries 10 --timeout 60 \
        -c requirements.lock \
        fastapi uvicorn websockets sqlalchemy pydantic pydantic-settings pyjwt anthropic geoip2 \
        argon2-cffi 'psycopg[binary]' alembic cryptography segno pandas reportlab
COPY idps ./idps
COPY soc ./soc
RUN /opt/venv/bin/pip install --retries 10 --timeout 60 --no-deps .

FROM python:3.12-slim
ARG VERSION=0.0.0
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.title="idps-soc" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.description="IDPS SOC API"
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    IDPS_VERSION=${VERSION}
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin idps
COPY --from=build /opt/venv /opt/venv
# The volumes for certificates, CA keys and backups start out owned by the service user (a named
# volume copies this). The CA keys volume is mounted only into the soc-admin service.
RUN mkdir -p /var/lib/idps-pki /var/lib/idps-cakeys /var/lib/idps-backups \
    && chown 10001:10001 /var/lib/idps-pki /var/lib/idps-cakeys /var/lib/idps-backups \
    && chmod 0700 /var/lib/idps-pki /var/lib/idps-cakeys /var/lib/idps-backups
COPY deploy/soc/entrypoint.sh /usr/local/bin/idps-entrypoint
COPY deploy/soc/init-pki.sh /usr/local/bin/idps-init-pki
COPY deploy/soc/add-sensor.sh /usr/local/bin/idps-add-sensor
COPY deploy/soc/renew-sensor.sh /usr/local/bin/idps-renew-sensor
RUN chmod 0755 /usr/local/bin/idps-entrypoint /usr/local/bin/idps-init-pki /usr/local/bin/idps-add-sensor /usr/local/bin/idps-renew-sensor
USER 10001:10001
WORKDIR /tmp
EXPOSE 8000 8444
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=6 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["/usr/local/bin/idps-entrypoint"]
CMD ["serve"]
