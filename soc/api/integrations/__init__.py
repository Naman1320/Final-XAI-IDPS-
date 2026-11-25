"""Outbound integrations: notifications (webhook, Slack, email), syslog/CEF export, reputation.

Nothing here runs on the ingest request path except `NotificationManager.submit_*`, which only
filters and puts small objects on bounded in-memory queues. Sending happens on one worker thread
per channel. See docs/soc.md, "Integrations".
"""
