#!/usr/bin/env python3
"""Tail Suricata eve.json and send Telegram alerts for IDS events."""

import json
import os
import sys
import time

import requests

DEFAULT_EVE_PATH = "/var/log/suricata/eve.json"
POLL_SECONDS = 1
SEND_TIMEOUT_SECONDS = 10


def format_alert(event):
    """Build the Telegram text for one eve.json object.

    Returns None when the event is not an alert.
    """
    if not isinstance(event, dict) or event.get("event_type") != "alert":
        return None

    alert = event.get("alert")
    if not isinstance(alert, dict):
        alert = {}

    category = alert.get("category") or "Unknown Category"
    signature = alert.get("signature") or "Unknown Signature"
    src_ip = event.get("src_ip") or "Unknown IP"
    priority = _priority(alert.get("priority", 3))

    if priority == 1:
        header = "HIGH SEVERITY ALERT"
    elif priority == 2:
        header = "MEDIUM SEVERITY ALERT"
    else:
        header = "LOW PRIORITY NOTICE"

    return (
        f"{header}\n"
        f"Priority: {priority}\n"
        f"Type: {category}\n"
        f"Signature: {signature}\n"
        f"Source IP: {src_ip}"
    )


def parse_event_line(line):
    """Parse one eve.json line into an alert message.

    Blank lines and invalid JSON are skipped.
    """
    if not isinstance(line, str):
        return None
    text = line.strip()
    if not text:
        return None
    try:
        event = json.loads(text)
    except json.JSONDecodeError:
        return None
    return format_alert(event)


def send_alert(token, chat_id, message):
    """POST one message to the Telegram Bot API."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        response = requests.post(
            url,
            data={"chat_id": chat_id, "text": message},
            timeout=SEND_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        # Avoid printing the exception text: requests includes the request
        # URL, and that URL contains the bot token.
        detail = exc.__class__.__name__
        response = getattr(exc, "response", None)
        if response is not None:
            detail = f"{detail} (HTTP {response.status_code})"
        print(f"Failed to send Telegram message: {detail}", flush=True)


def follow_log(path):
    """Yield lines appended to path, starting at the current end.

    Reopens the file from the beginning when it is replaced or truncated
    so alerts written after log rotation are still delivered.
    """
    try:
        handle, inode = _open_log(path, from_end=True)
    except FileNotFoundError:
        print(f"Error: Could not find the log file at {path}", flush=True)
        sys.exit(1)

    try:
        while True:
            line = handle.readline()
            if line:
                yield line
                continue

            time.sleep(POLL_SECONDS)
            try:
                stat = os.stat(path)
            except OSError:
                handle.close()
                handle, inode = _reopen_when_present(path)
                continue

            replaced = stat.st_ino != inode
            truncated = stat.st_size < handle.tell()
            if replaced or truncated:
                handle.close()
                handle, inode = _reopen_when_present(path)
    finally:
        handle.close()


def load_config():
    """Read required Telegram settings and the optional log path."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        print(
            "Error: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set.",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)

    path = os.environ.get("SURICATA_EVE_PATH", DEFAULT_EVE_PATH).strip()
    return token, chat_id, path or DEFAULT_EVE_PATH


def main():
    token, chat_id, path = load_config()
    print(f"Pi Guard Bot online. Monitoring {path}", flush=True)
    for line in follow_log(path):
        message = parse_event_line(line)
        if message:
            send_alert(token, chat_id, message)


def _priority(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 3


def _open_log(path, from_end):
    handle = open(path, "r", encoding="utf-8", errors="replace")
    if from_end:
        handle.seek(0, os.SEEK_END)
    return handle, os.fstat(handle.fileno()).st_ino


def _reopen_when_present(path):
    while True:
        try:
            return _open_log(path, from_end=False)
        except FileNotFoundError:
            print(f"Waiting for log file {path}", flush=True)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
