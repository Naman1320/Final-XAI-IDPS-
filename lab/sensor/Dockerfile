FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv tcpdump tcpreplay nftables iproute2 iputils-ping openssl \
    && rm -rf /var/lib/apt/lists/*

# Build context is the repo root (see lab/docker-compose.yml); .dockerignore keeps
# data, secrets and git history out of the image.
WORKDIR /opt/idps
COPY pyproject.toml README.md requirements.lock ./
COPY 23csu441_1_23csu294_2_23csu095/idps ./idps
COPY soc ./soc
COPY 23csu441_1_23csu294_2_23csu095/docs/playbooks ./docs/playbooks
# Trained models are copied in because bind mounts of ~/Desktop are blocked on macOS.
COPY models ./models
# The public key models must be signed with, if you made one (lab/keys/README.md).
COPY lab/keys ./keys

# Install the project into a venv (Ubuntu 24.04 blocks system-wide pip installs).
# requirements.lock pins exact versions so shap/numpy/xgboost don't drift apart.
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -c /opt/idps/requirements.lock '/opt/idps[postgres]'
ENV PATH="/opt/venv/bin:$PATH"
# Capture on the attack-side interface; start.sh gives it this fixed name.
ENV IDPS_INTERFACE=lab_attack

COPY lab/sensor/nftables.conf /etc/idps-lab/nftables.conf
COPY lab/sensor/start.sh /start.sh
# The same image runs the lab SOC (lab/soc/start.sh) with a different command.
COPY lab/sensor/live.sh /usr/local/bin/live.sh
COPY lab/soc ./lab/soc
RUN chmod +x /start.sh /usr/local/bin/live.sh ./lab/soc/start.sh
HEALTHCHECK --interval=2s --timeout=2s --retries=15 CMD test -f /tmp/ready
CMD ["/start.sh"]
