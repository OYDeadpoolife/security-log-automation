# Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `seclog: error: file is not readable: /var/log/auth.log` (exit 3) | Your account may not read the log | On Debian/Ubuntu an administrator can add you to the `adm` group. `seclog` never changes permissions. As a test, copy the log to a place you can read. |
| `input does not exist` (exit 3) | Wrong path, or the log was rotated | `ls -l /var/log/auth.log*`; use the rotated names, for example `auth.log.1` or `auth.log.2.gz`. |
| `no readable files found in directory` | A directory input contains no regular files, or only unreadable ones | Pass the file names, or check permissions. Symbolic links inside the directory are skipped. |
| `refusing to overwrite …; choose a new --output-dir` (exit 2) | Results already exist there | Pick a new directory or leave `-o` out: the default directory name contains the date and time. |
| `could not read the input (a .gz file may be corrupt)` (exit 3) | Truncated or not a gzip file | `gzip -t file.gz` to test it. |
| `0 events parsed` but the log is not empty | The log format is not recognised, or `--since/--until` excluded everything | Look at `parse` in `summary.json`: `lines_malformed` means the header was not recognised; `lines_out_of_range` means the time filter removed the lines; `lines_ignored` means valid lines that are not security events. |
| Events appear in the wrong year | Syslog timestamps have no year | Pass `--year YYYY`. |
| Timestamps look off by hours | Time zone differences | `seclog` compares timestamps as written. Analyse logs from one time zone at a time. |
| `required program not found: awk` (exit 1) | No awk in `PATH`, or `SECLOG_AWK` names a program that does not exist | Install `gawk` or `mawk`, or unset `SECLOG_AWK`. |
| A scanner or monitoring system causes SL-001 findings | It really does fail logins | Use `--exclude-ips ADDRESS`. |
| `Permission denied` when running `./bin/seclog` | The file lost its executable bit (this happens when files are uploaded through GitHub's web page) | `chmod +x bin/seclog scripts/run_daily.sh`, or run `bash bin/seclog ...` |
| Terminal shows strange characters like `[1;31m` | The terminal does not understand colours | Use `--no-color` or set `NO_COLOR=1`. |
| The cron job produces no output | Cron's minimal `PATH`, or no permission to read the log | Use absolute paths (see `examples/cron/seclog.cron`) and check `$HOME/seclog-reports/cron.log`. |
| `run_daily.sh: another run is in progress` | A previous run is still running or was killed | Check `ls -d "${TMPDIR:-/tmp}"/seclog-run-daily.*.lock`; remove the folder only if no run is active. |
| Tests fail on Linux but pass on macOS | An awk implementation difference | Run `SECLOG_AWK=gawk python3 -m pytest` and `SECLOG_AWK=mawk …`, then open an issue with the failing test name. |

## How to look inside a run

The stages are plain text. To see what each one does, run the parser alone:

```bash
LC_ALL=C awk -v year=2026 -v cur_year=2026 -v cur_month=10 -v since= -v until= \
    -f lib/awk/parse_auth.awk < samples/auth.log | head
```

Standard output shows the normalized events (tab-separated); standard error shows the `STAT` lines.
