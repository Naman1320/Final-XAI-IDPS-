#!/bin/sh
# Routes and firewall rules are set by the attacker-net container, whose network
# namespace this container shares. Nothing to do here but idle.
exec sleep infinity
