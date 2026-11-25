FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server nginx iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd
RUN useradd -m -s /bin/bash labuser
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
