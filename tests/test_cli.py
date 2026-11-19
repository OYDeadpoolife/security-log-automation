"""Command line behaviour: help, version, argument validation, safe file handling."""

import gzip
import os
import stat

import pytest

from conftest import FIXTURES, ROOT, SAMPLE_LOG, SECLOG

RESULT_FILES = {"events.csv", "findings.csv", "sources.csv", "summary.json", "report.md"}


def test_help_lists_commands_and_options(run_seclog):
    result = run_seclog("--help")
    assert result.returncode == 0
    for text in ("analyze", "demo", "--input", "--since", "--dry-run", "EXIT STATUS"):
        assert text in result.stdout


def test_version_is_printed(run_seclog):
    result = run_seclog("--version")
    assert result.returncode == 0
    assert result.stdout.strip() == "seclog 1.0.0"


def test_no_arguments_prints_usage_and_fails(run_seclog):
    result = run_seclog()
    assert result.returncode == 2
    assert "USAGE" in result.stderr


@pytest.mark.parametrize(
    "args, message",
    [
        (["frobnicate"], "unknown command"),
        (["analyze", "--bogus"], "unknown option"),
        (["analyze", "--input"], "needs a value"),
        (["analyze", "--since", "yesterday", "-i", "x"], "--since must look like"),
        (["analyze", "--since", "2026-02-30", "-i", "x"], "--since must look like"),
        (["analyze", "--until", "2026-03-14 25:00", "-i", "x"], "--until must look like"),
        (["analyze", "--since", "2026-03-15", "--until", "2026-03-14", "-i", "x"], "later than"),
        (["analyze", "--failed-threshold", "abc", "-i", "x"], "whole number"),
        (["analyze", "--failed-threshold", "0", "-i", "x"], "between"),
        (["analyze", "--window-minutes", "-5", "-i", "x"], "whole number"),
        (["analyze", "--year", "26", "-i", "x"], "between"),
        (["analyze", "--exclude-ips", "1.2.3.4;rm", "-i", "x"], "comma-separated list"),
        (["analyze"], "no input given"),
    ],
)
def test_invalid_usage_exits_with_status_2(run_seclog, args, message):
    result = run_seclog(*args)
    assert result.returncode == 2, result.stderr
    assert message in result.stderr


def test_missing_input_exits_with_status_3(run_seclog, tmp_path):
    result = run_seclog("analyze", "-i", tmp_path / "does-not-exist.log")
    assert result.returncode == 3
    assert "does not exist" in result.stderr


def test_empty_directory_exits_with_status_3(run_seclog, tmp_path):
    empty = tmp_path / "empty-dir"
    empty.mkdir()
    result = run_seclog("analyze", "-i", empty)
    assert result.returncode == 3
    assert "no readable files" in result.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_unreadable_input_exits_with_status_3(run_seclog, tmp_path):
    secret = tmp_path / "locked.log"
    secret.write_text("Mar 14 10:00:00 web01 sshd[1]: x\n")
    secret.chmod(0)
    result = run_seclog("analyze", "-i", secret)
    assert result.returncode == 3
    assert "not readable" in result.stderr


def test_demo_runs_and_writes_all_result_files(run_seclog, tmp_path):
    out_dir = tmp_path / "demo-out"
    result = run_seclog("demo", "--output-dir", out_dir, "--no-color", out_dir=out_dir)
    assert result.returncode == 0, result.stderr
    assert {path.name for path in out_dir.iterdir()} == RESULT_FILES
    assert "SL-003" in result.stdout
    assert result.summary()["summary"]["findings_total"] == 11


def test_demo_rejects_own_input(run_seclog):
    result = run_seclog("demo", "--input", SAMPLE_LOG)
    assert result.returncode == 2
    assert "bundled sample" in result.stderr


def test_dry_run_creates_nothing(run_seclog, tmp_path):
    out_dir = tmp_path / "never-created"
    result = run_seclog("analyze", "-i", SAMPLE_LOG, "-o", out_dir, "--dry-run")
    assert result.returncode == 0
    assert "dry run" in result.stdout
    assert str(SAMPLE_LOG) in result.stdout
    assert not out_dir.exists()
    assert list((tmp_path / "tmp").iterdir()) == []


def test_never_overwrites_existing_results(analyze, run_seclog):
    first = analyze(SAMPLE_LOG)
    assert first.returncode == 0
    second = run_seclog("analyze", "-i", SAMPLE_LOG, "-o", first.out_dir, "--year", 2026)
    assert second.returncode == 2
    assert "refusing to overwrite" in second.stderr


def test_output_path_that_is_a_file_is_rejected(run_seclog, tmp_path):
    target = tmp_path / "a-file"
    target.write_text("keep me")
    result = run_seclog("analyze", "-i", SAMPLE_LOG, "-o", target)
    assert result.returncode == 2
    assert target.read_text() == "keep me"


def test_paths_with_spaces_and_non_ascii_characters(run_seclog, tmp_path):
    folder = tmp_path / "my logs ועבודה"
    folder.mkdir()
    source = folder / "my auth.log"
    source.write_bytes(SAMPLE_LOG.read_bytes())
    out_dir = tmp_path / "result folder ✓"
    result = run_seclog("analyze", "-i", source, "-o", out_dir, "--year", 2026, "--quiet", out_dir=out_dir)
    assert result.returncode == 0, result.stderr
    summary = result.summary()  # also proves the JSON is valid UTF-8
    assert summary["inputs"] == [str(source)]
    assert summary["parse"]["events"] == 135


def test_standard_input_is_supported(analyze):
    result = analyze("-", stdin=SAMPLE_LOG.read_bytes())
    assert result.returncode == 0, result.stderr
    assert result.summary()["parse"]["events"] == 135


def test_standard_input_only_once(run_seclog):
    result = run_seclog("analyze", "-i", "-", "-i", "-")
    assert result.returncode == 2


def test_gzip_input_is_read(analyze, tmp_path):
    compressed = tmp_path / "auth.log.1.gz"
    compressed.write_bytes(gzip.compress(SAMPLE_LOG.read_bytes()))
    result = analyze(compressed)
    assert result.returncode == 0, result.stderr
    assert result.summary()["parse"]["events"] == 135


def test_corrupt_gzip_exits_with_status_3(analyze, tmp_path):
    broken = tmp_path / "broken.log.gz"
    broken.write_bytes(b"this is not gzip data")
    result = analyze(broken)
    assert result.returncode == 3
    assert not result.out_dir.exists()  # a failed run leaves no partial results


def test_directory_input_reads_every_file_in_time_order(analyze, tmp_path):
    folder = tmp_path / "rotated"
    folder.mkdir()
    (folder / "auth.log.1").write_text("Mar 14 09:00:00 web01 sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2\n")
    (folder / "auth.log").write_text("Mar 14 10:00:00 web01 sshd[2]: Accepted password for bob from 192.0.2.2 port 22 ssh2\n")
    result = analyze(folder)
    assert result.returncode == 0, result.stderr
    assert [row["user"] for row in result.csv_rows("events.csv")] == ["alice", "bob"]


def test_files_without_trailing_newline_do_not_merge(analyze, tmp_path):
    first = tmp_path / "a.log"
    second = tmp_path / "b.log"
    first.write_text("Mar 14 09:00:00 web01 sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2")
    second.write_text("Mar 14 10:00:00 web01 sshd[2]: Accepted password for bob from 192.0.2.2 port 22 ssh2")
    result = analyze(first, "--input", second)
    assert result.summary()["parse"]["events"] == 2


def test_invalid_awk_program_is_reported(analyze):
    result = analyze(SAMPLE_LOG, env_extra={"SECLOG_AWK": "definitely-not-a-program"})
    assert result.returncode == 1
    assert "required program not found" in result.stderr


def test_works_through_a_symbolic_link(run_seclog, tmp_path):
    link = tmp_path / "bin-on-path" / "seclog"
    link.parent.mkdir()
    link.symlink_to(SECLOG)
    import subprocess

    completed = subprocess.run([str(link), "--version"], capture_output=True, text=True)
    assert completed.returncode == 0
    assert completed.stdout.strip() == "seclog 1.0.0"


def test_no_temporary_files_are_left_behind(analyze, tmp_path):
    analyze(SAMPLE_LOG)
    analyze(tmp_path / "missing.log")
    assert list((tmp_path / "tmp").iterdir()) == []


def test_result_files_are_private(analyze):
    result = analyze(SAMPLE_LOG)
    for path in result.out_dir.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
    assert stat.S_IMODE(result.out_dir.stat().st_mode) == 0o700


def test_only_the_output_directory_is_written(run_seclog, tmp_path):
    work = tmp_path / "workspace"
    work.mkdir()
    before = {path.name for path in work.iterdir()}
    result = run_seclog("analyze", "-i", SAMPLE_LOG, "--year", 2026, "--quiet", cwd=work)
    assert result.returncode == 0, result.stderr
    after = {path.name for path in work.iterdir()}
    assert after - before == {"seclog-output"}  # default output lives below ./seclog-output


def test_fail_on_findings_exit_status(analyze):
    assert analyze(SAMPLE_LOG, "--fail-on-findings").returncode == 10
    assert analyze(FIXTURES / "empty.log", "--fail-on-findings").returncode == 0
    medium_only = analyze(FIXTURES / "window_edge.log", "--fail-on-findings")
    assert medium_only.returncode == 0  # only medium findings


def test_scripts_are_executable():
    assert os.access(SECLOG, os.X_OK)
    assert os.access(ROOT / "scripts" / "run_daily.sh", os.X_OK)
