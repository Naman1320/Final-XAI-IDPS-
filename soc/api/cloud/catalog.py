"""Fixed catalogs and thresholds of the cloud module (constants, not stored)."""

REGION = "eu-west-1"
ACCOUNT_ID = "000000000000"  # the emulator's account; the mock uses it too
PENDING_SECONDS = 10  # a new or started instance is "pending" this long, then "running"

# instance type: (vcpus, memory GiB, USD per running hour; illustrative on-demand style prices)
INSTANCE_TYPES: dict[str, tuple[int, float, float]] = {
    "t3.micro": (2, 1.0, 0.0104),
    "t3.small": (2, 2.0, 0.0208),
    "t3.medium": (2, 4.0, 0.0416),
    "t3.large": (2, 8.0, 0.0832),
    "m5.large": (2, 8.0, 0.0960),
    "m5.xlarge": (4, 16.0, 0.1920),
    "c5.large": (2, 4.0, 0.0850),
    "c5.xlarge": (4, 8.0, 0.1700),
    "r5.large": (2, 16.0, 0.1260),
}
OPERATING_SYSTEMS = ("Ubuntu 22.04", "Ubuntu 24.04", "Debian 12", "Amazon Linux 2023",
                     "Windows Server 2022")
VOLUME_TYPES = ("gp3", "gp2", "io1", "st1")
INSTANCE_STATES = ("running", "stopped", "pending", "terminated")
VOLUME_STATES = ("available", "in-use")
ALERT_SEVERITIES = ("info", "warning", "critical")
ALERT_STATUSES = ("open", "acknowledged", "resolved")
COST_SERVICES = ("compute", "storage", "network", "other")

# Health thresholds (percent): value >= degraded is "degraded", >= critical is "critical".
HEALTH_THRESHOLDS: dict[str, tuple[float, float]] = {
    "cpu_pct": (80.0, 95.0),
    "memory_pct": (85.0, 95.0),
    "disk_pct": (80.0, 90.0),
}

# Limits (a demo inventory, not a datacentre).
MAX_INSTANCES = 100  # not counting terminated ones
MAX_VOLUMES = 200
MAX_BUCKETS = 50
MAX_SECURITY_GROUPS = 50
MAX_RULES_PER_GROUP = 60
MAX_TAGS = 20
MAX_PAGE = 200
SENSITIVE_PORTS = (22, 3389)  # not to be opened to the world without an explicit confirmation
