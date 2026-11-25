# The lab's Suricata sidecar: the pinned image from roadmap step 6 plus a minimal alert-only
# configuration and a log cap. The repo is copied in rather than bind-mounted (macOS blocks Docker
# from mounting folders under ~/Desktop), like the sensor.
FROM jasonish/suricata:7.0.10
COPY suricata.yaml /etc/idps/suricata.yaml
COPY run.sh /usr/local/bin/idps-suricata-run.sh
ENTRYPOINT ["/usr/local/bin/idps-suricata-run.sh"]
