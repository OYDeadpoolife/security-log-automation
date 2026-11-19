"""scripts/run_daily.sh: the wrapper meant to be started by cron."""

import os
import subprocess

from conftest import ROOT, SAMPLE_LOG

WRAPPER = ROOT / "scripts" / "run_daily.sh"


def run_wrapper(*args, tmp_path):
    env = dict(os.environ, NO_COLOR="1", TMPDIR=str(tmp_path))
    return subprocess.run([str(WRAPPER), *map(str, args)], capture_output=True, text=True, env=env, timeout=120)


def test_help():
    completed = subprocess.run([str(WRAPPER), "--help"], capture_output=True, text=True)
    assert completed.returncode == 0
    assert "--output-base" in completed.stdout


def test_analyses_one_day_into_a_dated_folder(tmp_path):
    base = tmp_path / "reports"
    completed = run_wrapper("--input", SAMPLE_LOG, "--output-base", base, "--date", "2026-03-14", tmp_path=tmp_path)
    assert completed.returncode == 0, completed.stderr
    result_dir = base / "2026-03-14"
    assert (result_dir / "summary.json").is_file()
    assert (result_dir / "report.md").is_file()


def test_the_time_window_is_the_requested_day(tmp_path):
    base = tmp_path / "reports"
    run_wrapper("--input", SAMPLE_LOG, "--output-base", base, "--date", "2026-03-13", tmp_path=tmp_path)
    import json

    summary = json.loads((base / "2026-03-13" / "summary.json").read_text())
    assert summary["parse"]["events"] == 0  # the sample only contains events from 2026-03-14


def test_second_run_for_the_same_day_does_nothing(tmp_path):
    base = tmp_path / "reports"
    first = run_wrapper("--input", SAMPLE_LOG, "--output-base", base, "--date", "2026-03-14", tmp_path=tmp_path)
    second = run_wrapper("--input", SAMPLE_LOG, "--output-base", base, "--date", "2026-03-14", tmp_path=tmp_path)
    assert first.returncode == 0 and second.returncode == 0
    assert "already exists" in second.stderr


def test_rejects_bad_date_and_unknown_option(tmp_path):
    assert run_wrapper("--date", "14-03-2026", tmp_path=tmp_path).returncode == 2
    assert run_wrapper("--frobnicate", tmp_path=tmp_path).returncode == 2


def test_missing_log_is_a_failure_cron_can_notice(tmp_path):
    completed = run_wrapper("--input", tmp_path / "nope.log", "--output-base", tmp_path / "r", "--date", "2026-03-14", tmp_path=tmp_path)
    assert completed.returncode == 3


def test_default_date_is_yesterday(tmp_path):
    completed = run_wrapper("--input", SAMPLE_LOG, "--output-base", tmp_path / "r", tmp_path=tmp_path)
    assert completed.returncode == 0, completed.stderr
    created = [p.name for p in (tmp_path / "r").iterdir()]
    assert len(created) == 1 and len(created[0]) == 10  # YYYY-MM-DD
