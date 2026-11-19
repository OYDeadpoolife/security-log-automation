# Test results — security-log-automation (`seclog` 1.0.0)

Last full local run: **2026-10-03**. Result: **134 passed, 0 failed, 0 skipped** (`python3 -m pytest`, about 5 seconds).
First GitHub Actions run: **2026-11-19**. Result: **134 passed in all four jobs** (Ubuntu with mawk, gawk and original-awk; macOS). See below.

## Environment of that run

| Item | Value |
|---|---|
| Operating system | macOS 15.7.4 (arm64) |
| Bash | GNU bash 3.2.57 (the macOS default, the oldest version the project supports) |
| awk | BWK awk 20200816 (the macOS default) |
| Python / pytest | Python 3.9.6, pytest 8.4.2 |
| ShellCheck / shfmt | ShellCheck 0.11.0, shfmt 3.14.1 (installed with pip in an isolated virtual environment) |

## PASS — executed and successful

| Area | Tests | What was verified |
|---|---|---|
| Command line (`tests/test_cli.py`) | 38 | `--help`, `--version`, 13 invalid-usage cases with exit status 2, missing input / empty directory / unreadable file / corrupt `.gz` with exit status 3, `demo`, `--dry-run` writes nothing, results are never overwritten, **paths with spaces and Hebrew characters**, standard input, gzip, directories of rotated files, files without a final newline, no temporary files left behind, result files are `0600`, only the output directory is written, symlinked launcher, `--fail-on-findings` exit status 10 |
| Parsing (`tests/test_parse.py`) | 25 | Epoch calculation compared with Python for leap years, 2000, 2100, 1970 and 2038; impossible dates; ISO and syslog formats; year guessing and December→January rollover; inclusive time range; every event type; host names as sources; malformed, empty, blank, binary, 20 000-character and CRLF input |
| Detection (`tests/test_detection.py`) | 18 | Every rule SL-001…SL-008 on the sample and on dedicated fixtures; window boundary cases (exactly 5 failures in exactly 10 minutes flagged, 601 seconds not); threshold options; `--exclude-ips`; suspect status expiring after two hours; unprivileged group changes ignored |
| Outputs (`tests/test_outputs.py`) | 11 | JSON validity and structure (parsed with Python's `json`); numbers add up (every input line accounted for once); CSV columns, row counts and order; **hostile content** (quotes, backslashes, `|`, HTML, spreadsheet formulas) cannot break JSON, CSV or Markdown; Markdown table shape; committed example output equals fresh output |
| Cron wrapper (`tests/test_cron_wrapper.py`) | 7 | Help, one dated folder per day, correct day window, second run does nothing, bad date and unknown option rejected, failure exit status, default date is yesterday |
| Repository hygiene (`tests/test_static.py`) | 35 | All required files exist; no `sudo`/package-manager/`curl`/`eval` in the code; only three allowed uses of `rm`, `rmdir` and `mv`; no secrets or local paths; sample data uses only documentation or private addresses; **ShellCheck clean; shfmt clean** |

### GitHub Actions: first run on Linux (2026-11-19)

Commit `075a625`, run: <https://github.com/OYDeadpoolife/security-log-automation/actions/runs/44527627789>. **134 passed in every job.**
This was the first time the code ran outside the author's Mac.

| Runner | Bash | awk | Python |
|---|---|---|---|
| `ubuntu-latest` | 5.3.9 | mawk 1.3.4 | 3.12.16 |
| `ubuntu-latest` | 5.3.9 | gawk 5.3.2 | 3.12.16 |
| `ubuntu-latest` | 5.3.9 | `original-awk` package (version string not captured) | 3.12.16 |
| `macos-latest` | 3.2.57 | the system BWK awk | 3.12.10 |

ShellCheck 0.11.0 ran on every runner.

### Mutation check (does the suite really catch bugs?)

Four deliberate bugs were introduced one at a time into a copy of the project, and the suite failed each time:
threshold `>=` changed to `>` (caught by `test_window_boundaries`), CSV formula protection removed (caught by
`test_csv_formula_injection_is_neutralised`), suspect window changed from 2 to 4 hours (caught by the demo test), and the
date arithmetic shifted by one day (caught by `test_epoch_matches_python`).

### Development notes (nothing hidden)

During development the suite failed three times before the final run. Two were wrong expectations in my own tests (a
miscounted number of group events; a test of the repository itself that matched its own source text), one was a test that did
not allow for the README in the example-output folder. All were fixed in the tests; no failure was hidden by skipping a test.

## FAIL — executed and failed

None in the last local run and none in the first GitHub Actions run.

## NOT TESTED — environment not available to the author when this was written

| Item | Why |
|---|---|
| Linux on a real machine or VM (Debian, Kali, a server) | Only the Ubuntu GitHub Actions runner was used (see the CI section above) |
| Bash 4.x | Bash 3.2 (macOS) and 5.3 (Ubuntu runner) were tested; no 4.x |
| A real `/var/log/auth.log` from a real server | Only the synthetic sample and hand-written fixtures were used |
| Cron daemon starting `run_daily.sh` | The wrapper was tested by calling it directly, not through cron |
| Splunk and Elastic ingestion | No SIEM was available. Only the `jq` commands in `docs/siem-integration.md` were run |

## MANUAL VERIFICATION REQUIRED — to be done on your own Linux machine

Run these on a Linux VM (for example Ubuntu or Kali) and record the outcome here.

```bash
sudo apt-get install -y gawk mawk original-awk python3-venv   # installs extra awk programs; needs your approval
git clone https://github.com/OYDeadpoolife/security-log-automation.git && cd security-log-automation
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
for awk_program in mawk gawk original-awk; do
    echo "== $awk_program"; SECLOG_AWK=$awk_program python3 -m pytest -q
done
./bin/seclog demo
./bin/seclog analyze -i /var/log/auth.log --dry-run   # needs read access to the log (member of group adm)
```

Expected: every run ends with `134 passed`. If a test fails with one awk implementation, that is a real compatibility
bug — please record the test name and the awk version.
