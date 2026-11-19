# Security Log Analysis Report

- **Generated:** 2026-10-03T00:00:00Z
- **Tool:** seclog 1.0.0
- **Input:** `samples/auth.log`
- **Events analysed:** 2026-03-14T02:00:05 to 2026-03-14T12:40:17 (timestamps as written in the log, no time-zone conversion)
- **Hosts:** web01

> This report was produced by an automated script. Findings are leads for an analyst to
> verify, not verdicts. Read the limitations at the end before acting on them.

## 1. Summary

| Metric | Value |
|---|---|
| Log lines read | 353 |
| Security events parsed | 135 |
| Lines ignored (valid line, not security relevant) | 218 |
| Malformed lines (no recognisable header) | 0 |
| Lines outside the requested time range | 0 |
| Events skipped because the source is excluded | 0 |
| Findings | 11 (high: 6, medium: 4, low: 1) |

Event types seen:

| Event type | Count |
|---|---|
| ssh_failed | 68 |
| ssh_invalid_user | 54 |
| sudo_command | 4 |
| ssh_accepted | 3 |
| group_member_added | 1 |
| password_changed | 1 |
| su_failed | 1 |
| su_success | 1 |
| sudo_not_in_sudoers | 1 |
| user_created | 1 |

Analysis parameters: 

- `failed_threshold` = `5`
- `window_minutes` = `10`
- `enum_threshold` = `5`
- `since` = `-`
- `until` = `-`
- `year` = `2026`
- `exclude_ips` = `-`

## 2. Findings

| Time | Severity | Rule | Subject | Events | MITRE ATT&CK | What happened |
|---|---|---|---|---|---|---|
| 2026-03-14T07:00:19 | medium | SL-001 | 10.10.30.60 | 7 | T1110.001 | **SSH brute force.** 7 failed logins from 10.10.30.60 (peak 7 within 10 minutes, 1 distinct usernames tried) |
| 2026-03-14T09:05:12 | medium | SL-006 | labadmin | 1 | T1548.003 | **Sensitive command run with sudo.** labadmin ran '/usr/sbin/visudo -c' (account management tool) 1 time(s), last at 2026-03-14T09:05:12 |
| 2026-03-14T10:02:25 | medium | SL-001 | 203.0.113.45 | 59 | T1110.001 | **SSH brute force.** 59 failed logins from 203.0.113.45 (peak 59 within 10 minutes, 13 distinct usernames tried) |
| 2026-03-14T10:02:28 | low | SL-002 | 203.0.113.45 | 10 | T1110 | **SSH username enumeration.** 10 distinct non-existent usernames were tried from 203.0.113.45 |
| 2026-03-14T10:06:41 | high | SL-003 | svc-backup | 1 | T1078.003 | **SSH login succeeded after a brute-force burst.** svc-backup logged in with password from 203.0.113.45 after 59 failed attempts in the last 10 minutes |
| 2026-03-14T10:08:05 | medium | SL-005 | svc-backup | 1 | T1548.003 | **sudo request denied.** 1 denied sudo attempt(s) by svc-backup, 1 of them 'not in sudoers' (first command: /usr/bin/bash) |
| 2026-03-14T10:08:40 | high | SL-008 | svc-backup | 1 | T1078.003 | **Privilege activity by a suspect account.** svc-backup failed to switch user with su to labadmin. svc-backup logged in from 203.0.113.45 after a brute-force burst |
| 2026-03-14T10:09:30 | high | SL-008 | svc-backup | 1 | T1078.003 | **Privilege activity by a suspect account.** svc-backup switched user with su to labadmin. svc-backup logged in from 203.0.113.45 after a brute-force burst |
| 2026-03-14T10:10:02 | high | SL-008 | labadmin | 1 | T1078.003 | **Privileged command by a suspect account.** labadmin ran '/bin/bash' as root [shell]. svc-backup logged in from 203.0.113.45 after a brute-force burst |
| 2026-03-14T10:11:20 | high | SL-007 | support01 | 1 | T1136.001 | **New local account created.** account support01 was created (4 minutes after a suspicious login: svc-backup logged in from 203.0.113.45 after a brute-force burst) |
| 2026-03-14T10:11:50 | high | SL-007 | support01 | 1 | T1098 | **Account added to a privileged group.** account support01 was added to the privileged group sudo (5 minutes after a suspicious login: svc-backup logged in from 203.0.113.45 after a brute-force burst) |

## 3. Failed SSH logins by source

Top 3 of 3 source(s), ordered by failed logins.

| Source | Failed | Distinct usernames | Non-existent usernames | Peak in window | First seen | Last seen | Successful logins | Brute force flagged |
|---|---|---|---|---|---|---|---|---|
| 203.0.113.45 | 59 | 13 | 10 | 59 | 2026-03-14T10:02:11 | 2026-03-14T10:06:20 | 1 | yes |
| 10.10.30.60 | 7 | 1 | 1 | 7 | 2026-03-14T07:00:03 | 2026-03-14T07:00:27 | 0 | yes |
| 10.10.30.5 | 2 | 1 | 0 | 2 | 2026-03-14T08:30:12 | 2026-03-14T08:30:19 | 1 | no |

## 4. sudo and privilege activity

| User | sudo commands | Denied | Not in sudoers | First seen | Last seen |
|---|---|---|---|---|---|
| labadmin | 4 | 0 | 0 | 2026-03-14T08:35:02 | 2026-03-14T12:40:17 |
| svc-backup | 0 | 1 | 1 | 2026-03-14T10:08:05 | 2026-03-14T10:08:05 |

## 5. Suggested next steps

- **SL-001:** Check whether the source is expected (scanner, VPN, office). If not, block it at the firewall and review other logs for the same address.
- **SL-002:** Many unknown usernames usually mean automated scanning. Confirm that password authentication is disabled where possible and that no valid account was guessed.
- **SL-003:** Treat the account as compromised until proven otherwise: reset its credentials, review what it did after the login and look for new keys or accounts.
- **SL-005:** Find out why the account tried to use sudo. A service account that is not meant to use sudo is a strong signal when combined with other findings.
- **SL-006:** Confirm with the administrator that the command was intended. Shells, account tools and sudoers edits are normal for admins but also what attackers do.
- **SL-007:** Verify that the account change was requested. Remove unauthorised accounts, and check authorized_keys and cron for persistence.
- **SL-008:** Follow the chain: review everything the listed accounts did after the first suspicious login (auditd 'auid' shows the original login user).

## 6. Limitations

- Detection is rule based and uses simple thresholds. It can produce false positives (for example an authorised scanner) and can miss slow or distributed attacks.
- Only the supported event formats of OpenSSH, sudo, su and the account tools are parsed. Other lines are counted as ignored.
- Timestamps are compared as written. Logs from several time zones, or syslog timestamps without a year, can place events incorrectly (use `--year`).
- `useradd` and `usermod` do not log who ran them, so account changes cannot be attributed from this log alone. Use auditd (`auid`) for that.
- The MITRE ATT&CK technique IDs are a best-effort label to help triage, not a classification.
