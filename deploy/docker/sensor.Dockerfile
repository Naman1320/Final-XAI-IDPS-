# idps-sensor: live capture and detection. No model is baked in: models are mounted (/models).
#   docker build -f deploy/docker/sensor.Dockerfile --build-arg VERSION=0.2.0 --build-arg GIT_SHA=abc1234 .
FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY requirements.lock pyproject.toml README.md ./
COPY idps ./idps
COPY soc ./soc
# The full pinned set (as lab/sensor/Dockerfile does), so shap/numpy/xgboost do not drift apart.
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --retries 10 --timeout 60 \
        -c requirements.lock . \
    # CPU-only: the GPU runtime wheels that xgboost lists on Linux are not needed (~GBs)
    && (/opt/venv/bin/pip list --format=freeze | sed -n 's/^\(nvidia-[A-Za-z0-9_-]*\)==.*/\1/p' \
        | xargs -r /opt/venv/bin/pip uninstall -y)

FROM python:3.12-slim
ARG VERSION=0.0.0
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.title="idps-sensor" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.description="IDPS sensor (live flow capture, detection, response)"
# libpcap: packet capture (NFStream); libgomp1: xgboost; nftables/iproute2: blocking.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 libgomp1 nftables iproute2 \
    && rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    IDPS_VERSION=${VERSION}
COPY --from=build /opt/venv /opt/venv
COPY deploy/sensor/entrypoint.sh /usr/local/bin/idps-sensor
RUN chmod 0755 /usr/local/bin/idps-sensor && mkdir -p /var/lib/idps-sensor
# Runs as root inside the container (raw capture and nftables need capabilities that a non-root
# user does not keep across exec); the compose file drops every capability but the three it needs.
WORKDIR /var/lib/idps-sensor
ENTRYPOINT ["/usr/local/bin/idps-sensor"]
