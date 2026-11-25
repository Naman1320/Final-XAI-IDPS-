FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap hydra hping3 sqlmap curl iproute2 slowhttptest iputils-ping tcpreplay \
        openssh-client sshpass procps \
    && rm -rf /var/lib/apt/lists/* \
    # nmap ships with file capabilities incl. cap_net_admin, which this container does not get,
    # so exec fails. Root already has cap_net_raw, so drop the file capabilities (if a later
    # nmap package ships without them, there is nothing to drop and setcap -r would fail).
    && if [ -n "$(getcap /usr/lib/nmap/nmap)" ]; then setcap -r /usr/lib/nmap/nmap; fi
# Build context is lab/ (see docker-compose.yml).
COPY attacker/entrypoint.sh /entrypoint.sh
COPY attacks /attacks
RUN chmod +x /entrypoint.sh /attacks/*.sh
ENTRYPOINT ["/entrypoint.sh"]
