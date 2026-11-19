"""Parsing: formats, time handling, malformed and hostile input."""

import calendar
import datetime
import os
import subprocess

import pytest

from conftest import FIXTURES, ROOT

AWK = os.environ.get("SECLOG_AWK", "awk")
PARSER = ROOT / "lib" / "awk" / "parse_auth.awk"


def run_parser(text, year=2026, since="", until="", cur_year=2026, cur_month=10):
    """Run parse_auth.awk directly. Returns (event rows, statistics)."""
    completed = subprocess.run(
        [AWK, "-v", f"year={year}", "-v", f"cur_year={cur_year}", "-v", f"cur_month={cur_month}",
         "-v", f"since={since}", "-v", f"until={until}", "-f", str(PARSER)],
        input=text.encode("utf-8"),
        capture_output=True,
        env=dict(os.environ, LC_ALL="C"),
        check=True,
    )
    rows = [line.split("\t") for line in completed.stdout.decode().splitlines()]
    stats = {}
    for line in completed.stderr.decode().splitlines():
        _, name, value = line.split("\t")
        stats[name] = int(value)
    return rows, stats


@pytest.mark.parametrize(
    "month, day, year",
    [
        ("Jan", 1, 1970),
        ("Feb", 29, 2024),  # leap year
        ("Feb", 29, 2000),  # divisible by 400: leap year
        ("Mar", 1, 2100),  # divisible by 100 but not 400: Feb 2100 has 28 days
        ("Dec", 31, 2025),
        ("Mar", 14, 2026),
        ("Jul", 4, 2038),  # after the 32-bit time_t limit
    ],
)
def test_epoch_matches_python(month, day, year):
    rows, _ = run_parser(f"{month} {day:>2} 13:14:15 web01 sshd[1]: Accepted password for a from 192.0.2.1 port 22 ssh2\n", year=year)
    month_number = list(calendar.month_abbr).index(month)
    expected = calendar.timegm((year, month_number, day, 13, 14, 15))
    assert int(rows[0][1]) == expected


def test_impossible_calendar_dates_are_malformed():
    text = (
        "Feb 30 10:00:00 web01 sshd[1]: Accepted password for a from 192.0.2.1 port 22 ssh2\n"
        "Feb 29 10:00:00 web01 sshd[1]: Accepted password for a from 192.0.2.1 port 22 ssh2\n"
    )
    rows, stats = run_parser(text, year=2025)  # 2025 is not a leap year
    assert rows == []
    assert stats["lines_malformed"] == 2


def test_iso_timestamps_ignore_the_year_option():
    rows, stats = run_parser((FIXTURES / "iso_format.log").read_text(), year=1999)
    assert rows[0][0] == "2026-03-14T10:00:00"
    assert stats["events"] == 6


def test_year_rollover_between_december_and_january(analyze):
    result = analyze(FIXTURES / "year_rollover.log", year=2025)
    assert [row["timestamp"] for row in result.csv_rows("events.csv")] == ["2025-12-31T23:59:58", "2026-01-01T00:00:02"]


@pytest.mark.parametrize("month_name, month_number", [("Jan", 1), ("Oct", 10), ("Dec", 12)])
def test_year_is_guessed_when_not_given(month_name, month_number):
    """Without --year, a month later than the current one must belong to the previous year."""
    now = datetime.date.today()
    line = f"{month_name} 10 10:00:00 web01 sshd[1]: Accepted password for a from 192.0.2.1 port 22 ssh2\n"
    rows, _ = run_parser(line, year=0, cur_year=now.year, cur_month=now.month)
    expected_year = now.year if month_number <= now.month else now.year - 1
    assert rows[0][0].startswith(f"{expected_year}-{month_number:02d}-10")


def test_time_range_filter_is_inclusive():
    text = "".join(
        f"Mar 14 10:0{minute}:00 web01 sshd[1]: Accepted password for u{minute} from 192.0.2.1 port 22 ssh2\n" for minute in range(5)
    )
    rows, stats = run_parser(text, since="2026-03-14T10:01:00", until="2026-03-14T10:03:00")
    assert [row[5] for row in rows] == ["u1", "u2", "u3"]
    assert stats["lines_out_of_range"] == 2


def test_each_event_type_is_classified():
    rows, stats = run_parser((FIXTURES / "sudo_events.log").read_text() + (FIXTURES / "account_changes.log").read_text()
                             + (FIXTURES / "debian_su_and_root.log").read_text())
    types = [row[4] for row in rows]
    assert types.count("sudo_command") == 7
    assert types.count("sudo_denied") == 1
    assert types.count("sudo_not_in_sudoers") == 1
    assert types.count("sudo_auth_failure") == 1
    assert types.count("user_created") == 1
    assert types.count("group_member_added") == 3  # sudo, staff and admin; privilege is judged later
    assert types.count("password_changed") == 1
    assert types.count("user_deleted") == 1
    assert types.count("su_success") == 1
    assert types.count("su_failed") == 1
    assert types.count("ssh_accepted") == 2
    assert stats["lines_ignored"] == 3  # the sudo session line, "new group" and the "shadow group" line


def test_sudo_event_fields():
    rows, _ = run_parser("Mar 14 12:00:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update\n")
    _, _, host, program, event_type, user, source, target, detail = rows[0]
    assert (host, program, event_type, user, source, target, detail) == (
        "web01", "sudo", "sudo_command", "alice", "-", "root", "/usr/bin/apt update")


def test_failed_login_for_invalid_user_keeps_the_user_name():
    rows, _ = run_parser("Mar 14 10:00:00 web01 sshd[9]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2\n")
    assert rows[0][4:8] == ["ssh_failed", "admin", "203.0.113.45", "-"]
    assert rows[0][8] == "password"


def test_host_names_are_accepted_as_source():
    rows, _ = run_parser("Mar 14 10:00:00 web01 sshd[9]: Failed password for root from host.example.test port 22 ssh2\n")
    assert rows[0][6] == "host.example.test"


def test_malformed_lines_are_counted_not_fatal(analyze):
    result = analyze(FIXTURES / "malformed.log")
    assert result.returncode == 0, result.stderr
    parse = result.summary()["parse"]
    assert parse["lines_total"] == 6
    assert parse["lines_malformed"] == 5
    assert parse["events"] == 1


def test_empty_and_blank_files(analyze):
    empty = analyze(FIXTURES / "empty.log")
    assert empty.returncode == 0
    assert empty.summary()["parse"]["lines_total"] == 0
    assert empty.summary()["findings"] == []
    assert "No findings were raised" in empty.read("report.md")
    blank = analyze(FIXTURES / "blank_lines.log")
    assert blank.summary()["parse"]["lines_blank"] == 4


def test_binary_garbage_cannot_break_the_outputs(analyze, tmp_path):
    garbage = tmp_path / "garbage.log"
    garbage.write_bytes(
        b"\x00\x01\x02 binary \xff\xfe junk\n"
        b"Mar 14 10:00:00 web01 sshd[1]: Invalid user caf\xe9\xff from 192.0.2.5 port 1\n"
        b"Mar 14 10:00:01 web01 sshd[1]: Accepted password for alice from 192.0.2.5 port 22 ssh2\n"
    )
    result = analyze(garbage)
    assert result.returncode == 0, result.stderr
    summary = result.summary()  # raises if the JSON is not valid UTF-8 JSON
    assert summary["parse"]["events"] == 2
    users = [row["user"] for row in result.csv_rows("events.csv")]
    assert users == ["caf??", "alice"]  # unprintable bytes are replaced, never copied through


def test_very_long_lines_are_truncated_safely(analyze, tmp_path):
    long_user = "u" * 20000
    path = tmp_path / "long.log"
    path.write_text(f"Mar 14 10:00:00 web01 sshd[1]: Invalid user {long_user} from 192.0.2.5 port 1\n"
                    "Mar 14 10:00:01 web01 sshd[1]: Accepted password for alice from 192.0.2.5 port 22 ssh2\n")
    result = analyze(path)
    assert result.returncode == 0, result.stderr
    assert result.summary()["parse"]["lines_truncated"] == 1
    assert result.summary()["parse"]["events"] == 1  # the truncated line no longer parses as an event


def test_file_without_trailing_newline_is_fully_read(analyze):
    result = analyze(FIXTURES / "no_trailing_newline.log")
    assert result.summary()["parse"]["events"] == 1


def test_carriage_return_line_endings_are_tolerated(analyze, tmp_path):
    path = tmp_path / "windows.log"
    path.write_bytes(b"Mar 14 10:00:00 web01 sshd[1]: Accepted password for alice from 192.0.2.5 port 22 ssh2\r\n")
    result = analyze(path)
    assert result.returncode == 0
    assert result.summary()["parse"]["events"] == 1


def test_lines_from_other_programs_are_ignored(analyze, tmp_path):
    path = tmp_path / "other.log"
    path.write_text("Mar 14 10:00:00 web01 CRON[1]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)\n"
                    "Mar 14 10:00:01 web01 kernel: [  10.1] something happened\n")
    result = analyze(path)
    assert result.summary()["parse"]["lines_ignored"] == 2
    assert result.summary()["parse"]["events"] == 0
