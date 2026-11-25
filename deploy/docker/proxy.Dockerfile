# idps-proxy: Caddy + the built dashboard. Build from the repo root:
#   docker build -f deploy/docker/proxy.Dockerfile --build-arg VERSION=0.2.0 --build-arg GIT_SHA=abc1234 .
FROM node:22-alpine AS web
WORKDIR /web
COPY soc/web/package.json soc/web/package-lock.json ./
RUN npm ci --no-audit --no-fund --fetch-retries=5 --fetch-retry-mintimeout=5000
COPY soc/web/ ./
RUN npm run build

# Pinned to the release that was tested (digest pinning, FROM caddy@sha256:..., is a stricter option).
FROM caddy:2.11.9
ARG VERSION=0.0.0
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.title="idps-proxy" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.description="IDPS SOC dashboard and TLS reverse proxy"
COPY --from=web /web/dist /srv
COPY deploy/proxy/Caddyfile.internal deploy/proxy/Caddyfile.domain /etc/caddy/
COPY deploy/proxy/entrypoint.sh /usr/local/bin/idps-proxy
RUN chmod 0755 /usr/local/bin/idps-proxy
EXPOSE 80 443
HEALTHCHECK --interval=10s --timeout=4s --start-period=10s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:80/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/idps-proxy"]
