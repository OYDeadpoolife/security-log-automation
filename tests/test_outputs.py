"""Generated files: valid JSON and CSV, consistent numbers, safe handling of hostile content."""

import re
import subprocess

from conftest import FIXTURES, ROOT, SAMPLE_LOG

EVENT_COLUMNS = ["timestamp", "host", "program", "event_type", "user", "source", "target", "detail"]
FINDING_COLUMNS = ["time", "rule_id", "severity", "host", "subject", "event_count", "mitre_technique", "title", "details"]
SOURCE_COLUMNS = ["source", "failed_logins", "distinct_usernames", "invalid_usernames", "peak_in_window",
                  "first_seen", "last_seen", "accepted_logins", "flagged_brute_force"]


def test_json_structure_and_types(analyze):
    summary = analyze(SAMPLE_LOG).summary()
    assert list(summary) == ["tool", "generated_at", "inputs", "parameters", "parse", "time_range", "hosts",
                             "event_types", "summary", "findings", "failed_login_sources", "sudo_users"]
    assert summary["tool"] == {"name": "seclog", "version": "1.0.0"}
    assert summary["generated_at"] == "2026-01-01T00:00:00Z"  # fixed by the test environment
    assert summary["parameters"]["failed_threshold"] == 5
    assert summary["hosts"] == ["web01"]
    for finding in summary["findings"]:
        assert isinstance(finding["event_count"], int)
        assert finding["severity"] in {"high", "medium", "low"}
        assert finding["rule_id"].startswith("SL-")


def test_json_numbers_are_consistent(analyze):
    summary = analyze(SAMPLE_LOG).summary()
    assert summary["summary"]["findings_total"] == len(summary["findings"])
    by_severity = {s: sum(f["severity"] == s for f in summary["findings"]) for s in ("high", "medium", "low")}
    assert {k: summary["summary"][k] for k in by_severity} == by_severity
    assert sum(summary["event_types"].values()) == summary["parse"]["events"]
    parse = summary["parse"]
    accounted = parse["lines_blank"] + parse["lines_malformed"] + parse["lines_out_of_range"] + parse["lines_ignored"] + parse["events"]
    assert accounted == parse["lines_total"]  # every input line is accounted for exactly once


def test_csv_files_match_the_json(analyze):
    result = analyze(SAMPLE_LOG)
    summary = result.summary()
    events = result.csv_rows("events.csv")
    findings = result.csv_rows("findings.csv")
    sources = result.csv_rows("sources.csv")
    assert list(events[0]) == EVENT_COLUMNS
    assert list(findings[0]) == FINDING_COLUMNS
    assert list(sources[0]) == SOURCE_COLUMNS
    assert len(events) == summary["parse"]["events"]
    assert len(findings) == len(summary["findings"])
    assert len(sources) == len(summary["failed_login_sources"])
    assert [row["timestamp"] for row in events] == sorted(row["timestamp"] for row in events)
    assert [row["rule_id"] for row in findings] == [f["rule_id"] for f in summary["findings"]]


def test_csv_header_only_for_empty_input(analyze):
    result = analyze(FIXTURES / "empty.log")
    assert result.read("events.csv").strip() == ",".join(EVENT_COLUMNS)
    assert result.read("findings.csv").strip() == ",".join(FINDING_COLUMNS)
    assert result.csv_rows("sources.csv") == []


def test_sources_are_ordered_by_failures(analyze):
    sources = analyze(SAMPLE_LOG).summary()["failed_login_sources"]
    failures = [s["failed_logins"] for s in sources]
    assert failures == sorted(failures, reverse=True)
    assert sources[0] == {
        "source": "203.0.113.45", "failed_logins": 59, "distinct_usernames": 13, "invalid_usernames": 10,
        "peak_in_window": 59, "first_seen": "2026-03-14T10:02:11", "last_seen": "2026-03-14T10:06:20",
        "accepted_logins": 1, "flagged_brute_force": True,
    }


# --- hostile content ------------------------------------------------------------------------


def test_hostile_log_content_cannot_break_json_or_csv(analyze):
    result = analyze(FIXTURES / "injection.log")
    assert result.returncode == 0, result.stderr
    summary = result.summary()
    assert "injected" not in summary  # the quote-breaking user name stayed inside its string
    rows = {row["user"]: row for row in result.csv_rows("events.csv")}
    assert '"},{"injected":true}' in rows  # round-trips exactly through CSV quoting
    assert "back\\slash" in rows
    assert "a|b|c" in rows


def test_csv_formula_injection_is_neutralised(analyze):
    users = [row["user"] for row in analyze(FIXTURES / "injection.log").csv_rows("events.csv")]
    formula_like = [u for u in users if u.lstrip("'").startswith(("=", "+", "-", "@"))]
    assert len(formula_like) == 2
    assert all(u.startswith("'") for u in formula_like)  # a leading apostrophe stops spreadsheets executing it


def test_markdown_report_neutralises_html_and_table_breaking_characters(analyze):
    report = analyze(FIXTURES / "injection.log").read("report.md")
    assert "<b>" not in report and "</b>" not in report
    assert "&lt;b&gt;" in report
    table_rows = [line for line in report.splitlines() if line.startswith("| 2026-03-14T10:00:06")]
    assert len(table_rows) == 1
    assert table_rows[0].count("|") == 8  # 7 columns; the "|" in the command was escaped
    assert "&#124;" in table_rows[0]


def test_markdown_sections_exist(analyze):
    report = analyze(SAMPLE_LOG).read("report.md")
    for heading in ("# Security Log Analysis Report", "## 1. Summary", "## 2. Findings",
                    "## 3. Failed SSH logins by source", "## 4. sudo and privilege activity",
                    "## 5. Suggested next steps", "## 6. Limitations"):
        assert heading in report
    assert "SL-003" in report and "T1078.003" in report
    assert "203.0.113.45" in report


# --- the committed example output must match what the tool produces today -----------------------


def test_example_output_is_up_to_date(tmp_path, seclog_env):
    out_dir = tmp_path / "example"
    completed = subprocess.run([str(ROOT / "bin" / "seclog"), "demo", "--output-dir", str(out_dir), "--quiet", "--no-color"],
                               capture_output=True, env=dict(seclog_env, SECLOG_FIXED_TIME="2026-10-03T00:00:00Z"))
    assert completed.returncode == 0, completed.stderr.decode()
    committed = ROOT / "examples" / "example-output"
    assert {p.name for p in out_dir.iterdir()} == {p.name for p in committed.iterdir() if p.name != "README.md"}
    for path in out_dir.iterdir():
        assert path.read_text(encoding="utf-8") == (committed / path.name).read_text(encoding="utf-8"), (
            f"{path.name} differs from examples/example-output; regenerate it with 'make example-output'")


def test_markdown_tables_have_consistent_columns(analyze):
    report = analyze(SAMPLE_LOG).read("report.md")
    table = []
    for line in report.splitlines() + [""]:
        if line.startswith("|"):
            table.append(len(re.findall(r"(?<!\\)\|", line)))
        else:
            assert len(set(table)) <= 1, f"inconsistent table rows: {table}"
            table = []
