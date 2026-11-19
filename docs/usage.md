# Usage

## Commands

```text
seclog analyze --input PATH [options]     analyse your own logs
seclog demo [--output-dir DIR]            analyse the bundled synthetic sample
seclog --help | --version
```

## Options for `analyze`

| Option | Meaning | Default |
|---|---|---|
| `-i, --input PATH` | Log file, directory (regular files directly inside it) or `-` for standard input. Repeatable. `*.gz` files are decompressed while reading. | required |
| `-o, --output-dir DIR` | Where results are written. The tool refuses to overwrite existing result files. | `./seclog-output/<command>-<date>-<time>` |
| `--since TIME` | Ignore events before TIME. `2026-03-14`, `2026-03-14 10:30` or `2026-03-14T10:30:15`. A date alone means 00:00:00. | none |
| `--until TIME` | Ignore events after TIME. A date alone means 23:59:59 of that day. | none |
| `--year YYYY` | Year for syslog timestamps (they contain none). | current year, or the previous year for a month still in the future |
| `--failed-threshold N` | Failed SSH logins from one source inside the window that raise SL-001 and make SL-003 possible. | 5 |
| `--window-minutes N` | Length of that sliding window. | 10 |
| `--enum-threshold N` | Distinct non-existent usernames from one source that raise SL-002. | 5 |
| `--exclude-ips LIST` | Comma-separated trusted sources (addresses or host names) to ignore for the SSH rules. | none |
| `--fail-on-findings` | Exit with status 10 when at least one *high* finding exists (for scripts and cron). | off |
| `--dry-run` | Validate options and inputs, print the plan, write nothing. | off |
| `-q, --quiet` | Print only the summary and errors. | off |
| `--no-color` | Disable colours. The `NO_COLOR` environment variable is honoured too. | colour when stdout is a terminal |

### Exit status

| Code | Meaning |
|---|---|
| 0 | Success (findings do not change this unless `--fail-on-findings` is given) |
| 1 | Runtime failure (for example a missing `awk`, or a stage that failed) |
| 2 | Invalid command line: unknown option, bad value, output would overwrite earlier results |
| 3 | Input problem: file missing, unreadable, empty directory, corrupt `.gz` |
| 10 | `--fail-on-findings` and a high severity finding exists |

### Environment variables

| Variable | Purpose |
|---|---|
| `NO_COLOR` | Disable colours |
| `SECLOG_AWK` | Use a specific awk program (`gawk`, `mawk`, `original-awk`); used by the CI matrix |
| `SECLOG_FIXED_TIME` | Testing aid: fixes the `generated_at` time so output can be compared byte for byte |

## Result files

All files are created with permissions `0600` (owner only) in a directory with `0700`, because they contain
user names and addresses from the logs.

### `summary.json`

One document with these top-level keys: `tool`, `generated_at`, `inputs`, `parameters`, `parse`, `time_range`, `hosts`,
`event_types`, `summary`, `findings`, `failed_login_sources`, `sudo_users`. Each finding has `rule_id`, `severity`,
`time`, `host`, `subject`, `event_count`, `mitre_technique`, `title` and `details`.

`parse` explains where every input line went: `lines_total = lines_blank + lines_malformed + lines_out_of_range +
lines_ignored + events` (`lines_truncated` counts lines longer than 4096 characters that were cut).

### `events.csv`

`timestamp, host, program, event_type, user, source, target, detail` — every security event, in time order.
Event types: `ssh_failed`, `ssh_invalid_user`, `ssh_accepted`, `sudo_command`, `sudo_denied`, `sudo_not_in_sudoers`,
`sudo_auth_failure`, `su_success`, `su_failed`, `user_created`, `group_member_added`, `password_changed`, `user_deleted`.

### `findings.csv`

`time, rule_id, severity, host, subject, event_count, mitre_technique, title, details` — one row per detection.

### `sources.csv`

`source, failed_logins, distinct_usernames, invalid_usernames, peak_in_window, first_seen, last_seen, accepted_logins,
flagged_brute_force` — one row per source address with failures, most failures first.

### `report.md`

Summary table, findings table, top sources, sudo users, suggested next steps for the rules that fired, and limitations.

CSV cells that start with `=`, `+`, `-` or `@` get a leading apostrophe so a spreadsheet cannot execute them as formulas.
Log text is reduced to printable ASCII; other bytes become `?`.

## Examples

```bash
# 1. Safe first run
./bin/seclog demo

# 2. Look at a rotated, compressed log without unpacking it first
./bin/seclog analyze -i /var/log/auth.log.2.gz --year 2026

# 3. Pipe from another tool
zcat /var/log/auth.log.*.gz | ./bin/seclog analyze --input - --year 2026

# 4. Use the exit status in a script
./bin/seclog analyze -i /var/log/auth.log -q --fail-on-findings
echo "exit status: $?"    # 10 means a high severity finding exists

# 5. Work with the JSON
jq '.findings[] | select(.severity=="high") | {time, rule_id, subject}' seclog-output/*/summary.json
```

Command 5 needs [`jq`](https://jqlang.org/), which `seclog` itself does not require.
