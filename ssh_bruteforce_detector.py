#!/usr/bin/env python3
"""
ssh_bruteforce_detector.py

Parses Linux authentication logs (auth.log on Debian/Ubuntu, or
`journalctl -u ssh` output on systemd/journald systems) to detect
repeated failed SSH login attempts from the same source IP within a
sliding time window (a classic brute-force signature), and raises
alerts.

Part of Week 3 (Log Monitoring & Automation Scripting) of the
Enterprise Infrastructure Hardening & Vulnerability Management
Pipeline project.

Usage:
    # One-shot scan of a static log file
    python3 ssh_bruteforce_detector.py --logfile /var/log/auth.log

    # Continuously tail a live log (like `tail -f`)
    python3 ssh_bruteforce_detector.py --logfile /var/log/auth.log --follow

    # Tune detection sensitivity
    python3 ssh_bruteforce_detector.py --logfile /var/log/auth.log \
        --threshold 5 --window 60

    # Write alerts to a file as well as stdout
    python3 ssh_bruteforce_detector.py --logfile /var/log/auth.log \
        --alert-log /var/log/ssh_bruteforce_alerts.log

Exit codes:
    0 - ran cleanly (one-shot mode) with no unhandled errors
    1 - fatal error (e.g. log file not found / not readable)
"""

import argparse
import logging
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Log line patterns
# --------------------------------------------------------------------------
# Classic syslog-style auth.log line (Debian/Ubuntu, OpenSSH):
#   Aug 15 10:22:31 host sshd[1234]: Failed password for root from 10.0.2.4 port 51514 ssh2
#   Aug 15 10:22:33 host sshd[1234]: Failed password for invalid user admin from 10.0.2.4 port 51515 ssh2
#   Aug 15 10:22:40 host sshd[1234]: Invalid user test from 10.0.2.4 port 51520
FAILED_PASSWORD_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) "
    r"port \d+ ssh2"
)
INVALID_USER_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)

# journald / journalctl -o short-iso style timestamp variant:
#   2026-08-15T10:22:31+0100 host sshd[1234]: Failed password for root from 10.0.2.4 port 51514 ssh2
FAILED_PASSWORD_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) "
    r"port \d+ ssh2"
)

CURRENT_YEAR = datetime.now().year


def parse_line(line: str):
    """
    Try each known log format against a line.
    Returns (datetime, ip, user) on a match, or None.
    """
    for pattern, iso in (
        (FAILED_PASSWORD_RE, False),
        (INVALID_USER_RE, False),
        (FAILED_PASSWORD_ISO_RE, True),
    ):
        m = pattern.match(line)
        if not m:
            continue
        ip = m.group("ip")
        user = m.group("user")
        ts_raw = m.group("ts")
        try:
            if iso:
                ts = datetime.strptime(ts_raw, "%Y-%m-%dT%H:%M:%S")
            else:
                # syslog format has no year; assume current year.
                ts = datetime.strptime(f"{CURRENT_YEAR} {ts_raw}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        return ts, ip, user
    return None


class BruteForceDetector:
    """
    Tracks failed-login timestamps per source IP in a sliding window
    and fires an alert once an IP crosses the threshold.
    """

    def __init__(self, threshold: int, window_seconds: int, alert_cb):
        self.threshold = threshold
        self.window = window_seconds
        self.alert_cb = alert_cb
        self._attempts = defaultdict(deque)   # ip -> deque[datetime]
        self._already_alerted = defaultdict(lambda: None)  # ip -> last alert time
        # re-alert cooldown so a sustained attack doesn't spam one alert per line
        self.realert_cooldown = window_seconds

    def record(self, ts, ip, user):
        dq = self._attempts[ip]
        dq.append(ts)

        # drop attempts outside the sliding window
        cutoff = ts.timestamp() - self.window
        while dq and dq[0].timestamp() < cutoff:
            dq.popleft()

        if len(dq) >= self.threshold:
            last_alert = self._already_alerted[ip]
            if last_alert is None or (ts.timestamp() - last_alert) >= self.realert_cooldown:
                self._already_alerted[ip] = ts.timestamp()
                self.alert_cb(ip=ip, user=user, count=len(dq), window=self.window, ts=ts)


def make_alert_callback(alert_logger):
    def _alert(ip, user, count, window, ts):
        msg = (
            f"[ALERT] Possible SSH brute-force from {ip} — "
            f"{count} failed logins in {window}s (last attempt user='{user}' at {ts:%Y-%m-%d %H:%M:%S})"
        )
        alert_logger.warning(msg)
    return _alert


def setup_alert_logger(alert_log_path: str | None):
    logger = logging.getLogger("ssh_bruteforce_alerts")
    logger.setLevel(logging.WARNING)
    logger.propagate = False

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console)

    if alert_log_path:
        file_handler = logging.FileHandler(alert_log_path)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(file_handler)

    return logger


def scan_static_file(path: Path, detector: BruteForceDetector):
    with path.open("r", errors="replace") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                ts, ip, user = parsed
                detector.record(ts, ip, user)


def follow_file(path: Path, detector: BruteForceDetector, poll_interval: float = 1.0):
    """
    Behaves like `tail -f`: seeks to end of file, then reads new lines
    as they're appended. Handles log rotation (file truncated/replaced).
    """
    with path.open("r", errors="replace") as f:
        f.seek(0, 2)  # jump to EOF
        inode = path.stat().st_ino
        while True:
            line = f.readline()
            if line:
                parsed = parse_line(line)
                if parsed:
                    ts, ip, user = parsed
                    detector.record(ts, ip, user)
                continue

            time.sleep(poll_interval)

            # detect log rotation
            try:
                if path.stat().st_ino != inode:
                    f.close()
                    f = path.open("r", errors="replace")
                    inode = path.stat().st_ino
            except FileNotFoundError:
                time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(
        description="Detect repeated failed SSH login attempts (brute-force activity) in auth logs."
    )
    parser.add_argument(
        "--logfile", required=True,
        help="Path to the auth log to scan (e.g. /var/log/auth.log, or a journalctl export).",
    )
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Number of failed attempts from one IP within the window to trigger an alert (default: 5).",
    )
    parser.add_argument(
        "--window", type=int, default=60,
        help="Sliding time window in seconds to count attempts within (default: 60).",
    )
    parser.add_argument(
        "--follow", action="store_true",
        help="Continuously monitor the log file for new entries, like `tail -f`.",
    )
    parser.add_argument(
        "--alert-log", default=None,
        help="Optional path to also write alerts to a dedicated log file.",
    )
    args = parser.parse_args()

    path = Path(args.logfile)
    if not path.exists():
        print(f"ERROR: log file not found: {path}", file=sys.stderr)
        sys.exit(1)

    alert_logger = setup_alert_logger(args.alert_log)
    detector = BruteForceDetector(
        threshold=args.threshold,
        window_seconds=args.window,
        alert_cb=make_alert_callback(alert_logger),
    )

    if args.follow:
        print(f"Monitoring {path} (threshold={args.threshold} attempts / {args.window}s)... Ctrl+C to stop.")
        try:
            follow_file(path, detector)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        scan_static_file(path, detector)


if __name__ == "__main__":
    main()
