"""Rules next to the model: Suricata alerts read from its eve.json and sent to the SOC as rule alerts.

    eve.py      parsing and classification of eve alert events, and the mapping to a SOC alert
    tail.py     follow a growing file (rotation, truncation, partial lines)
    forward.py  the sensor's forwarder: filter, de-duplicate, send, and (only if allowed) block

See docs/live.md, "Rules next to ML".
"""
