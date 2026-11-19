"""Shared helpers for the seclog test suite.

The tests run the real command line tool as a subprocess, exactly as a user would, and then
inspect the files it writes. Nothing is mocked.
"""

import csv
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SECLOG = ROOT / "bin" / "seclog"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLE_LOG = ROOT / "samples" / "auth.log"


class Result:
    """Outcome of one seclog run, with helpers to read the result files."""

    def __init__(self, completed, out_dir):
        self.returncode = completed.returncode
        self.stdout = completed.stdout.decode("utf-8", "replace")
        self.stderr = completed.stderr.decode("utf-8", "replace")
        self.out_dir = out_dir

    def read(self, name):
        return (self.out_dir / name).read_text(encoding="utf-8")

    def summary(self):
        return json.loads(self.read("summary.json"))

    def csv_rows(self, name):
        with (self.out_dir / name).open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    def findings(self):
        return self.summary()["findings"]

    def rule_ids(self):
        return [finding["rule_id"] for finding in self.findings()]

    def findings_for(self, rule_id):
        return [finding for finding in self.findings() if finding["rule_id"] == rule_id]


@pytest.fixture
def seclog_env(tmp_path):
    """Environment for every run: no colour, fixed report time and a private TMPDIR."""
    tmp_dir = tmp_path / "tmp"
    tmp_dir.mkdir()
    env = dict(os.environ)
    env.update(NO_COLOR="1", SECLOG_FIXED_TIME="2026-01-01T00:00:00Z", TMPDIR=str(tmp_dir))
    return env


@pytest.fixture
def run_seclog(tmp_path, seclog_env):
    """Run bin/seclog with arbitrary arguments. Returns a Result."""

    def run(*args, stdin=None, env_extra=None, cwd=None, out_dir=None):
        env = dict(seclog_env)
        env.update(env_extra or {})
        completed = subprocess.run(
            [str(SECLOG), *map(str, args)],
            input=stdin,
            capture_output=True,
            env=env,
            cwd=str(cwd or tmp_path),
            timeout=120,
        )
        return Result(completed, out_dir)

    return run


@pytest.fixture
def analyze(tmp_path, run_seclog):
    """Analyse one input with a fresh output directory; extra arguments are passed through."""
    counter = {"runs": 0}

    def run(input_path, *extra, year=2026, stdin=None, env_extra=None):
        counter["runs"] += 1
        out_dir = tmp_path / f"out-{counter['runs']}"
        args = ["analyze", "--input", input_path, "--output-dir", out_dir, "--no-color", "--quiet"]
        if year is not None:
            args += ["--year", year]
        return run_seclog(*args, *extra, stdin=stdin, env_extra=env_extra, out_dir=out_dir)

    return run
