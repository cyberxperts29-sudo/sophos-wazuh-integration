# Sophos Firewall + Wazuh: decoders, rules and auto-block

Wazuh decoders and rules for **Sophos Firewall's current "Standard syslog protocol" log format** (formerly Central Reporting Format), plus a **Wazuh Active Response that blocks attackers on Sophos automatically** through its XML API.

![Pipeline](docs/images/pipeline.png)

## Why

Sophos Firewall has two syslog formats:

| Format | Log starts with | Wazuh support |
| --- | --- | --- |
| Device standard (legacy) | `device="Sophos-Firewall" date=...` | Built-in `sophos-fw` decoder, header fields only |
| **Standard syslog protocol** (current) | `device_name="Sophos-Firewall" timestamp="..."` | **None** — events arrive and produce no alerts |

This repo adds that missing support.

## What's inside

| Path | What it does |
| --- | --- |
| `decoders/sophos_standard_syslog_decoders.xml` | Parent `sophos-std` decoder + sibling decoders for ~20 fields (srcip, dstip, ports, user, status, message, country, IPS signature, URL) |
| `rules/sophos_standard_syslog_rules.xml` | 15 rules (110000–110031), MITRE ATT&CK mapped |
| `active-response/sophos-block.py` | Adds the attacker IP to a Sophos IP host group that a Drop rule blocks |
| `active-response/sophos_api.conf.example` | Config template (credentials stay out of the script) |
| `active-response/ossec.conf.snippet.xml` | Syslog listener + Active Response wiring |

## Detection rules

| Rule | Level | Detects | MITRE |
| --- | --- | --- | --- |
| 110011 | 3 | Successful admin login | T1078 |
| 110013 | 5 | Failed admin login | T1110 |
| 110014 | 10 | 5 failed logins from one IP in 2 min | T1110.001 |
| 110015 | 5 | Configuration change | T1562.004 |
| 110016 | 8 | Log settings modified | T1562.006 |
| 110017 | 12 | Syslog server deleted (log tampering) | T1562.006 |
| 110020 | 3 | Traffic denied | — |
| 110021 | 5 | Probe on Telnet/SMB/RDP/VNC/MSSQL/MySQL | T1046 |
| 110022 | 10 | Port scan: 15 ports in 60 s from one IP | T1046 |
| 110030 | 10 | Attacker IP auto-blocked on Sophos | — |
| 110031 | 7 | Auto-block attempt failed | — |

## Install

Tested on **Wazuh 4.14.x** and **Sophos Firewall SFOS v22**.

### 1. Sophos: send logs to Wazuh

*System services → Log settings → Syslog servers → Add*

- Server: Wazuh manager IP, port `514`, facility `DAEMON`, severity `Information`
- Format: **Standard syslog protocol**
- Tick the categories you need (Firewall rules, Local ACLs, IPS, ATP, Web filter, Admin events, Authentication)

### 2. Wazuh: decoders and rules

```bash
sudo cp decoders/sophos_standard_syslog_decoders.xml /var/ossec/etc/decoders/
sudo cp rules/sophos_standard_syslog_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/sophos_standard_syslog_decoders.xml /var/ossec/etc/rules/sophos_standard_syslog_rules.xml
sudo chmod 660 /var/ossec/etc/decoders/sophos_standard_syslog_decoders.xml /var/ossec/etc/rules/sophos_standard_syslog_rules.xml
```

Add the `<remote>` block from `active-response/ossec.conf.snippet.xml` to `ossec.conf`, restart, and test:

```bash
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-logtest
```

### 3. Optional: auto-block

On Sophos:

1. *Hosts and services → IP host group* → create `Wazuh-Blocked-IPs` (empty).
2. *Rules and policies* → firewall rule at the **top**: source `Wazuh-Blocked-IPs`, action **Drop**.
3. *Administration → Device access* → **Local service ACL exception rule**: source zone WAN, source `Wazuh-Blocked-IPs`, action **Drop** (firewall rules do not cover traffic to the firewall itself).
4. *Administration → API access* (SFOS v22; older versions: *Backup & firmware → API*) → enable, allow the Wazuh manager as an IP host.

On Wazuh:

```bash
sudo cp active-response/sophos-block.py /var/ossec/active-response/bin/
sudo chown root:wazuh /var/ossec/active-response/bin/sophos-block.py
sudo chmod 750 /var/ossec/active-response/bin/sophos-block.py

sudo cp active-response/sophos_api.conf.example /var/ossec/etc/sophos_api.conf
sudo nano /var/ossec/etc/sophos_api.conf      # fill in your values
sudo chown root:wazuh /var/ossec/etc/sophos_api.conf
sudo chmod 640 /var/ossec/etc/sophos_api.conf
```

Add the `<command>` and `<active-response>` blocks from the snippet, then restart the manager.

![Active Response log](docs/images/active-response-log.png)

## Safety

- Private IPs and anything in `whitelist` are never blocked.
- `check_keys` handshake: one IP is processed once even when many alerts fire.
- Existing hosts are updated instead of failing (`code 502` → `operation="update"`).
- Every block or failed block becomes a Wazuh alert (110030 / 110031).

**Before production:** use a dedicated least-privilege API account, a trusted TLS certificate (`verify_tls=yes`), never expose port 4444 to the internet, and review or expire auto-blocks.

## Write-up

Full walkthrough on Medium: *Building a Self-Defending Firewall: Sophos + Wazuh* — MEDIUM_LINK

## Author

Muhammad Ahmad Abid — SOC Analyst. Feedback, issues and PRs welcome.

## License

GPL-2.0, the same licence as the Wazuh ruleset.
