# Holds the network namespace for one lab endpoint (attacker, victim or dvwa).
# The endpoint joins it with network_mode: service:<name> and has no NET_ADMIN,
# so nothing running in the endpoint can change routes or firewall rules.
FROM alpine:3.20
RUN apk add --no-cache iproute2 nftables
COPY setup.sh /setup.sh
RUN chmod +x /setup.sh
HEALTHCHECK --interval=2s --timeout=2s --retries=15 CMD test -f /tmp/ready
ENTRYPOINT ["/setup.sh"]
