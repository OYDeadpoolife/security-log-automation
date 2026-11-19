# Detection rules

`seclog` uses a few simple rules whose logic you can explain in one sentence. Every finding carries a rule ID, a
severity and a MITRE ATT&CK technique ID. **The technique IDs are a best-effort label to help triage, not a verdict**,
and a finding is a lead for an analyst, never proof of compromise.

Default thresholds can be changed with `--failed-threshold`, `--window-minutes` and `--enum-threshold`.

| Rule | Name | Severity | Technique |
|---|---|---|---|
| SL-001 | SSH brute force | medium | T1110.001 Password Guessing |
| SL-002 | SSH username enumeration | low | T1110 Brute Force |
| SL-003 | SSH login succeeded after a brute-force burst | high | T1078.003 Valid Accounts: Local Accounts |
| SL-004 | Direct root SSH login | medium | T1021.004 Remote Services: SSH |
| SL-005 | sudo request denied | medium | T1548.003 Sudo and Sudo Caching |
| SL-006 | Sensitive command run with sudo | medium | T1548.003 Sudo and Sudo Caching |
| SL-007 | New local account / account added to a privileged group | high | T1136.001 Create Account: Local Account, T1098 Account Manipulation |
| SL-008 | Privilege activity by a suspect account | high | T1078.003 Valid Accounts: Local Accounts |

## SL-001 SSH brute force

* **Logic:** five (`--failed-threshold`) or more `Failed password/publickey` events from one source within ten
  (`--window-minutes`) minutes. The window is a sliding window and is inclusive: five failures exactly ten minutes
  apart count, a failure 601 seconds after the first does not. The finding time is the moment the threshold was reached.
* **Why it matters:** automated password guessing is the most common first step against an exposed SSH service.
* **False positives:** authorised vulnerability scanners, monitoring that checks SSH with wrong credentials, users behind
  one NAT address who mistype passwords, an automation job with an expired password. Use `--exclude-ips` for known sources.
* **Misses:** "low and slow" guessing below the threshold, guessing spread over many source addresses, and attacks that use
  keys or other services.

## SL-002 SSH username enumeration

* **Logic:** five or more *distinct* non-existent usernames (`Invalid user …`) from one source.
* **Why it matters:** attackers try common names (`admin`, `oracle`, `pi`) before guessing passwords.
* **False positives:** a misconfigured client trying several saved usernames. Low severity on its own.

## SL-003 SSH login succeeded after a brute-force burst

* **Logic:** an `Accepted …` login from a source whose failed logins in the last window are at or above the SL-001 threshold.
* **Why it matters:** this is the moment a guess worked. It is the strongest signal in the tool, and the account is marked
  *suspect* for two hours (see SL-008).
* **False positives:** a legitimate user who forgot the password and then remembered it, from a source that also
  failed many times (for example a shared jump host). Check the source address and the login method: a service account
  that normally uses a key and now logs in with a password is suspicious.

## SL-004 Direct root SSH login

* **Logic:** any accepted SSH login for `root`.
* **Why it matters:** root logins are not attributable to a person; most hardening guides set `PermitRootLogin no`.
* **False positives:** deliberate root access on some appliances or backup setups.

## SL-005 sudo request denied

* **Logic:** `user NOT in sudoers`, `N incorrect password attempts`, or a failed sudo password prompt. Grouped per user.
* **Why it matters:** an account that is not meant to use sudo trying it is a sign of privilege escalation attempts.
* **False positives:** a user who mistypes their password once; a user who is missing from the sudoers file by mistake.

## SL-006 Sensitive command run with sudo

* **Logic:** a `sudo` command that opens a shell (`bash`, `sh`, …), runs `su`, runs an account tool (`useradd`, `usermod`,
  `passwd`, `visudo`, …) or mentions `/etc/shadow`, `/etc/sudoers` or `/etc/passwd`. Identical commands by the same user
  are grouped into one finding with a count.
* **False positives:** administrators do these things routinely (the sample log contains a legitimate `visudo -c`).
  The rule only asks "is this expected?". It stays quiet for accounts already reported by SL-008, which has more context.

## SL-007 New local account or privileged group change

* **Logic:** `useradd` creates a user, or `usermod`/`gpasswd` adds an account to `sudo`, `admin`, `wheel`, `root`, `adm`,
  `shadow`, `docker` or `lxd`. If it happens within two hours of an SL-003 login on the same host, the finding says so.
* **Why it matters:** creating an account with sudo rights is a classic persistence step.
* **Limitation:** these tools do not log who ran them, so attribution needs auditd (`auid`).
* **False positives:** planned onboarding. Compare with your change tickets.

## SL-008 Privilege activity by a suspect account

* **Logic:** after SL-003, `su` (successful or failed) and `sudo` commands by the compromised account are reported. A
  successful `su` makes the target account suspect too, so the chain continues. The suspicion lasts two hours.
* **Why it matters:** it connects separate log lines into one narrative: *who got in, whom they became, what they did*.
* **False positives:** the real user of the account doing normal work after a legitimate login that happened to
  follow a burst of failures. Always check SL-003 first.

## What the rules deliberately do not do

No machine learning, no reputation lookups and no network access. Everything is deterministic and local, so the same
input always gives the same output and you can explain every finding by pointing at log lines.
