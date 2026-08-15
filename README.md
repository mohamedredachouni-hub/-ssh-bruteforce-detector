# Week 3 — Log Monitoring & Automation Scripting

Part of the **Enterprise Infrastructure Hardening & Vulnerability Management Pipeline** project.

**Goal:** understand security monitoring and automate detection of brute-force SSH activity.

Lab context: Ubuntu scanner VM (VirtualBox, host-only network `192.168.56.0/24`) monitoring
its own auth log / a simulated target's SSH activity, as used in Weeks 1–2 of this project.

---

## 1. Centralized log collection setup

### 1a. System logging with rsyslog

On the Ubuntu scanner VM, `rsyslog` already writes authentication events to
`/var/log/auth.log` by default via the `auth`/`authpriv` facility. To confirm and, if needed,
make that explicit:

```bash
sudo apt update && sudo apt install -y rsyslog
sudo systemctl enable --now rsyslog

# Confirm the auth facility is routed to auth.log
grep -R "auth" /etc/rsyslog.d/50-default.conf
# Expect a line like:
# auth,authpriv.*                /var/log/auth.log
```

To forward these logs to a **centralized log collector** (e.g. a Wazuh manager or a
lightweight Elastic/Splunk instance running on another lab VM), add a forwarding rule:

```bash
# /etc/rsyslog.d/60-forward.conf
auth,authpriv.* @@<log-collector-ip>:514   # @@ = TCP, @ = UDP
```

```bash
sudo systemctl restart rsyslog
```

On systemd-based systems, the same auth events are also queryable directly via `journald`:

```bash
journalctl -u ssh --since "1 hour ago"
journalctl -u ssh -f          # live tail, journald equivalent of tail -f auth.log
```

### 1b. Centralized collector (lightweight Wazuh option)

For this lab, **Wazuh** (free, built specifically for security/log monitoring rather than
general-purpose search like Splunk/Elastic) is the fastest path to a working SIEM-style
collector:

```bash
# On a dedicated "SIEM" VM in the lab network
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash wazuh-install.sh -a          # installs indexer + server + dashboard (all-in-one)
```

Then install the lightweight agent on the scanner VM and point it at the manager:

```bash
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_amd64.deb
sudo WAZUH_MANAGER='<siem-vm-ip>' dpkg -i ./wazuh-agent_4.9.0-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

Wazuh ships a built-in SSH brute-force detection rule set out of the box (rule group
`authentication_failures`) — the custom Python script below is the "build it yourself"
version of the same detection logic, which is the actual Week 3 task deliverable.

---

## 2. Brute-force detection script

`ssh_bruteforce_detector.py` parses SSH authentication log lines (`Failed password ...`,
`Invalid user ...`) from either:
- a static `auth.log`-style file (syslog timestamp format), or
- a `journalctl -o short-iso` export (ISO-8601 timestamp format)

For each source IP, it keeps a sliding window of failed-attempt timestamps. Once an IP
crosses a configurable threshold of failed attempts inside that window, it raises an alert
(printed to stdout, and optionally written to a dedicated alert log file). A cooldown
prevents the same sustained attack from re-alerting on every single subsequent line.

### Usage

```bash
# One-shot scan of an existing log
python3 ssh_bruteforce_detector.py --logfile /var/log/auth.log

# Live monitoring, like `tail -f`
python3 ssh_bruteforce_detector.py --logfile /var/log/auth.log --follow

# Tune sensitivity: alert at 5+ failures from one IP within 60s (defaults shown)
python3 ssh_bruteforce_detector.py --logfile /var/log/auth.log --threshold 5 --window 60

# Also persist alerts to their own log file
python3 ssh_bruteforce_detector.py --logfile /var/log/auth.log \
    --alert-log /var/log/ssh_bruteforce_alerts.log
```

### Running it as an automated job

For continuous coverage without babysitting the process, either:

- Run it under `systemd` as a small service unit with `Restart=on-failure`, or
- Add `--follow` to a `systemd` service so it behaves like a lightweight IDS daemon.

Example unit file:

```ini
# /etc/systemd/system/ssh-bruteforce-detector.service
[Unit]
Description=SSH brute-force log monitor
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/security-tools/ssh_bruteforce_detector.py \
    --logfile /var/log/auth.log --follow --alert-log /var/log/ssh_bruteforce_alerts.log
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now ssh-bruteforce-detector
```

---

## 3. Test demo

`sample_auth.log` is a small synthetic log included in this repo for a reproducible demo
without needing a live attack. It contains:

- Two legitimate `Accepted publickey` logins (should **not** alert)
- **5 failed attempts from `192.168.56.101`** within ~10 seconds (should alert — this is the
  lab's own Metasploitable-range host simulating a credential-stuffing attempt)
- **3 failed attempts from `203.0.113.55`** (below the default threshold of 5 — should
  **not** alert, demonstrating the script isn't just flagging any failure)
- 1 isolated failure from `198.51.100.9` (should not alert)

Run the demo:

```bash
python3 ssh_bruteforce_detector.py --logfile sample_auth.log --threshold 5 --window 60
```

Expected output:

```
[ALERT] Possible SSH brute-force from 192.168.56.101 — 5 failed logins in 60s (last attempt user='root' at 2026-08-15 10:22:14)
```

Only one alert fires, for the IP that actually crossed the threshold — confirming both the
detection logic and the false-positive control (203.0.113.55's 3 attempts stay silent).

Live-tail mode was also verified by appending new `Failed password` lines to a copy of the
log while the script ran with `--follow`, confirming it picks up new attacks in real time
without needing to restart the process.

---

## Repo structure

```
week3-ssh-bruteforce-detector/
├── README.md
├── ssh_bruteforce_detector.py
└── sample_auth.log
```

## Next steps (Week 4+)

- Wire the alert callback to an actual notification channel (email via `smtplib`, or a
  webhook into Wazuh/Slack) instead of just stdout/file.
- Add IP reputation lookups (e.g. AbuseIPDB) to enrich alerts.
- Feed detected IPs into an automated block (e.g. `fail2ban` or a UFW rule) as a response
  action, closing the loop from detection to remediation.
