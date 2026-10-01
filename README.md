# Splunk SOC Projects

Hands-on SOC analyst projects built in Splunk Enterprise. Each project investigates a different angle of the logs, documents the steps with screenshots, and ends with findings, limitations and recommendations.

> **Note:** all projects use the Splunk Tutorial Data, a training dataset. They are lab exercises to practice log analysis and detection, not real production incidents.

## Projects

| # | Project | Log source | Focus |
|---|---|---|---|
| 1 | [SSH Brute Force Detection](01-ssh-bruteforce-detection/README.md) | `secure.log` (sshd) | Failed logins, distributed password guessing, MITRE T1110 |
| 2 | [Web Server Log Analysis](02-web-log-analysis/README.md) | `access.log` (web store) | Traffic baseline, HTTP errors, suspicious client behavior |
| 3 | [Threat Hunting: Suspicious IPs Across Logs](03-threat-hunting/README.md) | `access.log` + `secure.log` | Hypothesis-driven hunt, one IP tracked across web and SSH logs |

## Skills Demonstrated

- Searching and filtering logs with SPL (`timechart`, `top`, field filters)
- Identifying brute-force activity and indicators of compromise (IOC)
- Baselining normal traffic and spotting anomalies
- Hypothesis-driven threat hunting across several log sources
- Mapping findings to MITRE ATT&CK
- Writing clear findings and recommendations

## Tools

Splunk Enterprise (Free license), SPL, MITRE ATT&CK.
