"""Detection rules SL-001 to SL-008: what fires, what must not fire, and the boundaries."""

import pytest

from conftest import FIXTURES, SAMPLE_LOG


def subjects(result, rule_id):
    return {finding["subject"] for finding in result.findings_for(rule_id)}


# --- the bundled sample tells the whole story -----------------------------------------------


def test_sample_log_produces_the_expected_findings(analyze):
    result = analyze(SAMPLE_LOG)
    assert result.returncode == 0, result.stderr
    ids = result.rule_ids()
    assert ids.count("SL-001") == 2  # the attacker and the authorised scanner (a false positive)
    assert ids.count("SL-002") == 1
    assert ids.count("SL-003") == 1
    assert ids.count("SL-005") == 1
    assert ids.count("SL-006") == 1  # the administrator's visudo
    assert ids.count("SL-007") == 2
    assert ids.count("SL-008") == 3
    assert len(ids) == 11


def test_sample_attack_chain_is_attributed_in_order(analyze):
    findings = analyze(SAMPLE_LOG).findings()
    story = [(f["rule_id"], f["subject"]) for f in findings if f["time"] >= "2026-03-14T10:00:00"]
    assert story == [
        ("SL-001", "203.0.113.45"),
        ("SL-002", "203.0.113.45"),
        ("SL-003", "svc-backup"),
        ("SL-005", "svc-backup"),
        ("SL-008", "svc-backup"),  # su that failed
        ("SL-008", "svc-backup"),  # su that worked
        ("SL-008", "labadmin"),  # sudo /bin/bash, reached through the chain
        ("SL-007", "support01"),
        ("SL-007", "support01"),
    ]


def test_sample_brute_force_numbers(analyze):
    attacker = [f for f in analyze(SAMPLE_LOG).findings_for("SL-001") if f["subject"] == "203.0.113.45"][0]
    assert attacker["event_count"] == 59
    assert attacker["severity"] == "medium"
    assert attacker["mitre_technique"] == "T1110.001"
    assert "13 distinct usernames" in attacker["details"]


def test_sample_login_below_threshold_is_not_flagged(analyze):
    result = analyze(SAMPLE_LOG)
    assert "10.10.30.5" not in subjects(result, "SL-001")  # the administrator's two typos
    assert "labadmin" not in subjects(result, "SL-003")


def test_account_changes_mention_the_suspicious_login(analyze):
    details = [f["details"] for f in analyze(SAMPLE_LOG).findings_for("SL-007")]
    assert all("after a suspicious login" in text and "svc-backup" in text for text in details)


def test_excluding_a_trusted_scanner_removes_its_finding(analyze):
    result = analyze(SAMPLE_LOG, "--exclude-ips", "10.10.30.60")
    assert subjects(result, "SL-001") == {"203.0.113.45"}
    assert result.summary()["parse"]["events"] == 135  # events are still parsed
    assert result.summary()["failed_login_sources"][-1]["source"] != "10.10.30.60"
    assert [s["source"] for s in result.summary()["failed_login_sources"]] == ["203.0.113.45", "10.10.30.5"]


def test_time_range_limits_the_findings(analyze):
    result = analyze(SAMPLE_LOG, "--since", "2026-03-14 10:07", "--until", "2026-03-14 10:10:30")
    # The suspicious login happened at 10:06:41, outside the range, so nothing is "suspect" any more:
    # the denied sudo and the root shell are reported by their own, weaker rules.
    assert result.rule_ids() == ["SL-005", "SL-006"]
    assert result.summary()["time_range"]["first_event"] >= "2026-03-14T10:07:00"
    assert result.summary()["time_range"]["last_event"] <= "2026-03-14T10:10:30"


# --- SL-001 / SL-002 boundaries -------------------------------------------------------------


def test_window_boundaries(analyze):
    fixture = FIXTURES / "window_edge.log"
    assert subjects(analyze(fixture), "SL-001") == {"192.0.2.11"}  # exactly 5 failures in exactly 10 minutes
    assert subjects(analyze(fixture, "--failed-threshold", "4"), "SL-001") == {"192.0.2.10", "192.0.2.11", "192.0.2.12"}
    assert subjects(analyze(fixture, "--window-minutes", "11"), "SL-001") == {"192.0.2.11", "192.0.2.12"}
    assert subjects(analyze(fixture, "--failed-threshold", "6"), "SL-001") == set()


def test_enumeration_counts_distinct_names_only(analyze):
    fixture = FIXTURES / "enumeration.log"
    assert subjects(analyze(fixture), "SL-002") == {"192.0.2.20"}
    assert subjects(analyze(fixture, "--enum-threshold", "2"), "SL-002") == {"192.0.2.20", "192.0.2.21"}
    assert subjects(analyze(fixture, "--enum-threshold", "6"), "SL-002") == set()


# --- SL-003 / SL-004 ------------------------------------------------------------------------


def test_success_after_brute_force_uses_the_window(analyze):
    result = analyze(FIXTURES / "iso_format.log")
    assert subjects(result, "SL-001") == {"192.0.2.70"}
    assert subjects(result, "SL-003") == {"deploy"}
    assert "5 failed attempts" in result.findings_for("SL-003")[0]["details"]


def test_success_without_prior_failures_is_not_flagged(analyze):
    result = analyze(FIXTURES / "no_trailing_newline.log")
    assert result.rule_ids() == []


def test_direct_root_login_is_reported_once(analyze):
    result = analyze(FIXTURES / "debian_su_and_root.log")
    assert subjects(result, "SL-004") == {"192.0.2.30"}
    assert len(result.findings_for("SL-004")) == 1


# --- SL-005 / SL-006 ------------------------------------------------------------------------


def test_sudo_denials_are_grouped_per_user(analyze):
    result = analyze(FIXTURES / "sudo_events.log")
    findings = {f["subject"]: f for f in result.findings_for("SL-005")}
    assert set(findings) == {"bob", "eve"}
    assert findings["bob"]["event_count"] == 2  # one PAM failure and the final "3 incorrect password attempts"
    assert "'not in sudoers'" in findings["eve"]["details"]
    users = {u["user"]: u for u in result.summary()["sudo_users"]}
    assert users["eve"]["not_in_sudoers"] == 1
    assert users["alice"]["sudo_commands"] == 7


def test_sensitive_sudo_commands_are_aggregated(analyze):
    result = analyze(FIXTURES / "sudo_events.log")
    findings = result.findings_for("SL-006")
    assert len(findings) == 4  # su, /etc/shadow, usermod and /etc/sudoers; not apt or systemctl
    shadow = [f for f in findings if "/etc/shadow" in f["details"]][0]
    assert shadow["event_count"] == 2
    categories = " ".join(f["details"] for f in findings)
    for expected in ("(su)", "(credential or sudoers file)", "(account management tool)"):
        assert expected in categories


# --- SL-007 / SL-008 ------------------------------------------------------------------------


def test_account_creation_and_privileged_groups(analyze):
    result = analyze(FIXTURES / "account_changes.log")
    findings = result.findings_for("SL-007")
    assert [(f["subject"], f["mitre_technique"]) for f in findings] == [
        ("mallory", "T1136.001"),  # created
        ("mallory", "T1098"),  # added to sudo
        ("trudy", "T1098"),  # added to admin by gpasswd
    ]
    assert "by root" in findings[2]["details"]
    assert all(f["severity"] == "high" for f in findings)


def test_unprivileged_group_changes_are_not_findings(analyze):
    result = analyze(FIXTURES / "account_changes.log")
    assert "bob" not in subjects(result, "SL-007")


def test_suspect_status_expires_after_two_hours(analyze):
    result = analyze(FIXTURES / "chain_expiry.log")
    assert subjects(result, "SL-003") == {"victim"}
    assert len(result.findings_for("SL-008")) == 1  # the su at 10:05; the one at 13:30 is too late
    assert result.findings_for("SL-008")[0]["time"] == "2026-03-14T10:05:00"
    assert len(result.findings_for("SL-006")) == 1  # the later shell is reported as a plain sensitive command


def test_ordinary_activity_raises_no_high_findings(analyze):
    result = analyze(FIXTURES / "debian_su_and_root.log")
    assert {f["severity"] for f in result.findings()} == {"medium"}
