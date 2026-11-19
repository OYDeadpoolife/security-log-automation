"""Repository hygiene: required files, no privileged or destructive code, no secrets, lint clean."""

import re
import shutil
import subprocess

import pytest

from conftest import ROOT

REQUIRED_FILES = [
    "README.md", "LICENSE", ".gitignore", ".editorconfig", "Makefile", "requirements-dev.txt", "TEST_RESULTS.md",
    "bin/seclog", "scripts/run_daily.sh",
    "lib/seclog_common.sh", "lib/seclog_validate.sh", "lib/seclog_pipeline.sh",
    "lib/awk/parse_auth.awk", "lib/awk/detect.awk", "lib/awk/to_json.awk", "lib/awk/to_csv.awk",
    "lib/awk/to_markdown.awk", "lib/awk/to_terminal.awk",
    "samples/auth.log", "examples/cron/seclog.cron", "examples/example-output/report.md",
    "docs/usage.md", "docs/architecture.md", "docs/detection-rules.md", "docs/siem-integration.md",
    "docs/troubleshooting.md", "screenshots/README.md", ".github/workflows/ci.yml",
]
# Written in pieces so that this file does not trigger its own check.
LOCAL_PATH_MARKERS = ("/Use" + "rs/", "C:\\Use" + "rs\\", "orhay" + "yosef")
SHELL_FILES = ["bin/seclog", "scripts/run_daily.sh", "lib/seclog_common.sh", "lib/seclog_validate.sh", "lib/seclog_pipeline.sh"]


def all_text_files():
    skip = {".git", ".pytest_cache", "__pycache__", "seclog-output"}
    for path in ROOT.rglob("*"):
        if path.is_file() and not skip.intersection(path.relative_to(ROOT).parts):
            yield path


@pytest.mark.parametrize("relative", REQUIRED_FILES)
def test_required_file_exists(relative):
    assert (ROOT / relative).is_file(), f"missing {relative}"


def test_code_never_installs_software_or_escalates_privileges():
    forbidden = re.compile(r"^\s*(sudo|su|apt|apt-get|yum|dnf|brew|pip3?|npm|curl|wget|chmod|chown)\b", re.MULTILINE)
    for relative in SHELL_FILES:
        code = (ROOT / relative).read_text(encoding="utf-8")
        match = forbidden.search(code)
        assert match is None, f"{relative}: unexpected command '{match.group(0).strip()}'"
        assert not re.search(r"\beval\b", code), f"{relative}: eval is not allowed"


def test_destructive_commands_are_limited_to_known_safe_uses():
    """The only deleting or moving commands are the temp-dir cleanup, the lock and publishing results."""
    allowed = ('rmdir "$lock_dir"', 'rm -rf -- "$SECLOG_WORKDIR"', 'mv -- "$SECLOG_WORKDIR/$name" "$OUTPUT_DIR/$name"')
    uses = []
    for relative in SHELL_FILES:
        for number, line in enumerate((ROOT / relative).read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\brm\b|\brmdir\b|\bmv\b|\bshred\b|\bdd\b", line) and not line.lstrip().startswith("#"):
                uses.append((relative, number, line.strip()))
    assert len(uses) == len(allowed), uses
    for _, _, line in uses:
        assert any(snippet in line for snippet in allowed), line


def test_no_secrets_or_private_data_in_the_repository():
    patterns = [r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}", r"xox[baprs]-[A-Za-z0-9-]+",
                r"(?i)api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9]{16,}"]
    for path in all_text_files():
        if path.suffix in {".gz", ".png"} or path.name.startswith(".DS_Store"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in patterns:
            assert not re.search(pattern, text), f"possible secret in {path.relative_to(ROOT)}"
        for marker in LOCAL_PATH_MARKERS:
            assert marker not in text, f"local path leaked in {path.relative_to(ROOT)}"


def test_no_backup_or_cache_files_are_present():
    names = [p.name for p in all_text_files()]
    assert not [n for n in names if n.endswith((".orig", ".bak", ".swp", ".pyc", ".DS_Store"))]


def test_samples_use_only_documentation_and_private_addresses():
    ips = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", (ROOT / "samples" / "auth.log").read_text()))
    for ip in ips:
        assert ip.startswith(("10.", "203.0.113.", "198.51.100.", "192.0.2.")), f"unexpected address {ip} in the sample"


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_shellcheck_is_clean():
    completed = subprocess.run(["shellcheck", "-x", *SHELL_FILES], cwd=ROOT, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout


@pytest.mark.skipif(shutil.which("shfmt") is None, reason="shfmt is not installed")
def test_shfmt_formatting_is_clean():
    completed = subprocess.run(["shfmt", "-d", "-i", "4", "-ci", *SHELL_FILES], cwd=ROOT, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout
