# Glossary (plain language)

If you are new to security terms, this page explains the words used in this repository.

| Term | Meaning |
|---|---|
| Log | A file in which a computer records what happened, one line per event. |
| `auth.log` | The Linux log of logins, `sudo` use and account changes. It is the input of `seclog`. |
| SSH | The standard way to log in to a Linux server over the network. Attackers often try to guess SSH passwords. |
| Brute force | Trying many passwords, one after another, until one works. In a log it looks like many failed logins from one address in a short time. |
| Failed / successful login | One log line per attempt. A success right after many failures is suspicious, because the guesses may have worked. |
| `sudo` / `su` | Commands that let a user act with administrator ("root") powers. Using them in unusual ways is worth a look. |
| Privilege escalation | Getting more powers than you had, for example by adding an account to the `sudo` group. |
| Finding | One thing the tool flags as suspicious, with a rule ID and a severity. |
| Rule ID (SL-001 ... SL-008) | The name of one detection rule in this project. [detection-rules.md](detection-rules.md) explains each one. |
| MITRE ATT&CK | A public catalogue of attacker techniques. Each finding carries a tag such as T1110.001 (password guessing) so the technique can be looked up. |
| False positive | An alert about something harmless, for example an administrator who mistyped a password several times. |
| JSON / CSV | Two plain-text file formats that other programs and spreadsheets can read. |
| awk | A small text-processing language that ships with Linux and macOS. The tool uses it to read the log. |
| cron | The Linux scheduler. `scripts/run_daily.sh` is meant to be started by it. |
| Synthetic data | Made-up data. All the example logs in this repository are synthetic. |
