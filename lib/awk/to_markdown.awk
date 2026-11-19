# to_markdown.awk - render the analysis records as a readable Markdown security report.
#
# Input (stdin): the records file built by lib/seclog_pipeline.sh.
# Output: Markdown on stdout.
#
# Values that came from the log are untrusted. md_cell() neutralises the characters that could
# break a table or inject HTML or Markdown into the report.

BEGIN {
    FS = "\t"
    top_sources = 10

    advice["SL-001"] = "Check whether the source is expected (scanner, VPN, office). If not, block it at the firewall and review other logs for the same address."
    advice["SL-002"] = "Many unknown usernames usually mean automated scanning. Confirm that password authentication is disabled where possible and that no valid account was guessed."
    advice["SL-003"] = "Treat the account as compromised until proven otherwise: reset its credentials, review what it did after the login and look for new keys or accounts."
    advice["SL-004"] = "Prefer 'PermitRootLogin no' and named administrator accounts with sudo, so actions are attributable."
    advice["SL-005"] = "Find out why the account tried to use sudo. A service account that is not meant to use sudo is a strong signal when combined with other findings."
    advice["SL-006"] = "Confirm with the administrator that the command was intended. Shells, account tools and sudoers edits are normal for admins but also what attackers do."
    advice["SL-007"] = "Verify that the account change was requested. Remove unauthorised accounts, and check authorized_keys and cron for persistence."
    advice["SL-008"] = "Follow the chain: review everything the listed accounts did after the first suspicious login (auditd 'auid' shows the original login user)."
}

# Escape characters that are special in a Markdown table cell or could inject HTML.
function md_cell(text,    out, i, c) {
    if (text == "") {
        return "-"
    }
    out = ""
    for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (c == "|") {
            out = out "&#124;"
        } else if (c == "<") {
            out = out "&lt;"
        } else if (c == ">") {
            out = out "&gt;"
        } else if (c == "`") {
            out = out "'"
        } else {
            out = out c
        }
    }
    return out
}

$1 == "META" {
    meta[$2] = $3
}
$1 == "INPUT" {
    input_list[++input_count] = $2
}
$1 == "PARAM" {
    param_name[++param_count] = $2
    param_value[param_count] = $3
}
$1 == "STAT" {
    stat[$2] = $3
}
$1 == "EVTYPE" {
    evtype_name[++evtype_count] = $2
    evtype_total[evtype_count] = $3
}
$1 == "FINDING" {
    f_count++
    f_rule[f_count] = $2
    f_severity[f_count] = $3
    f_time[f_count] = $4
    f_host[f_count] = $5
    f_subject[f_count] = $6
    f_events[f_count] = $7
    f_mitre[f_count] = $8
    f_title[f_count] = $9
    f_details[f_count] = $10
    severity_total[$3]++
    rule_seen[$2] = 1
}
$1 == "SOURCE" {
    s_count++
    s_ip[s_count] = $2
    s_failed[s_count] = $3
    s_users[s_count] = $4
    s_invalid[s_count] = $5
    s_peak[s_count] = $6
    s_first[s_count] = $7
    s_last[s_count] = $8
    s_accepted[s_count] = $9
    s_flagged[s_count] = $10
}
$1 == "SUDOUSER" {
    u_count++
    u_name[u_count] = $2
    u_commands[u_count] = $3
    u_denied[u_count] = $4
    u_notin[u_count] = $5
    u_first[u_count] = $6
    u_last[u_count] = $7
}

END {
    print "# Security Log Analysis Report"
    print ""
    print "- **Generated:** " meta["generated_at"]
    print "- **Tool:** seclog " meta["tool_version"]
    printf "- **Input:** "
    for (i = 1; i <= input_count; i++) {
        printf "%s`%s`", (i > 1 ? ", " : ""), md_cell(input_list[i])
    }
    print ""
    print "- **Events analysed:** " stat["first_event"] " to " stat["last_event"] " (timestamps as written in the log, no time-zone conversion)"
    print "- **Hosts:** " stat["hosts"]
    print ""
    print "> This report was produced by an automated script. Findings are leads for an analyst to"
    print "> verify, not verdicts. Read the limitations at the end before acting on them."
    print ""

    print "## 1. Summary"
    print ""
    print "| Metric | Value |"
    print "|---|---|"
    print "| Log lines read | " stat["lines_total"] " |"
    print "| Security events parsed | " stat["events"] " |"
    print "| Lines ignored (valid line, not security relevant) | " stat["lines_ignored"] " |"
    print "| Malformed lines (no recognisable header) | " stat["lines_malformed"] " |"
    print "| Lines outside the requested time range | " stat["lines_out_of_range"] " |"
    print "| Events skipped because the source is excluded | " stat["events_from_excluded_sources"] " |"
    printf "| Findings | %d (high: %d, medium: %d, low: %d) |\n", f_count, severity_total["high"], severity_total["medium"], severity_total["low"]
    print ""
    if (evtype_count > 0) {
        print "Event types seen:"
        print ""
        print "| Event type | Count |"
        print "|---|---|"
        for (i = 1; i <= evtype_count; i++) {
            print "| " md_cell(evtype_name[i]) " | " evtype_total[i] " |"
        }
        print ""
    }

    print "Analysis parameters: "
    print ""
    for (i = 1; i <= param_count; i++) {
        print "- `" md_cell(param_name[i]) "` = `" md_cell(param_value[i]) "`"
    }
    print ""

    print "## 2. Findings"
    print ""
    if (f_count == 0) {
        print "No findings were raised for this input."
        print ""
    } else {
        print "| Time | Severity | Rule | Subject | Events | MITRE ATT&CK | What happened |"
        print "|---|---|---|---|---|---|---|"
        for (i = 1; i <= f_count; i++) {
            print "| " md_cell(f_time[i]) " | " md_cell(f_severity[i]) " | " md_cell(f_rule[i]) " | " md_cell(f_subject[i]) " | " md_cell(f_events[i]) " | " md_cell(f_mitre[i]) " | **" md_cell(f_title[i]) ".** " md_cell(f_details[i]) " |"
        }
        print ""
    }

    print "## 3. Failed SSH logins by source"
    print ""
    if (s_count == 0) {
        print "No failed SSH logins were found."
        print ""
    } else {
        shown = (s_count < top_sources ? s_count : top_sources)
        print "Top " shown " of " s_count " source(s), ordered by failed logins."
        print ""
        print "| Source | Failed | Distinct usernames | Non-existent usernames | Peak in window | First seen | Last seen | Successful logins | Brute force flagged |"
        print "|---|---|---|---|---|---|---|---|---|"
        for (i = 1; i <= shown; i++) {
            print "| " md_cell(s_ip[i]) " | " s_failed[i] " | " s_users[i] " | " s_invalid[i] " | " s_peak[i] " | " md_cell(s_first[i]) " | " md_cell(s_last[i]) " | " s_accepted[i] " | " s_flagged[i] " |"
        }
        print ""
    }

    print "## 4. sudo and privilege activity"
    print ""
    if (u_count == 0) {
        print "No sudo activity was found."
        print ""
    } else {
        print "| User | sudo commands | Denied | Not in sudoers | First seen | Last seen |"
        print "|---|---|---|---|---|---|"
        for (i = 1; i <= u_count; i++) {
            print "| " md_cell(u_name[i]) " | " u_commands[i] " | " u_denied[i] " | " u_notin[i] " | " md_cell(u_first[i]) " | " md_cell(u_last[i]) " |"
        }
        print ""
    }

    print "## 5. Suggested next steps"
    print ""
    shown_advice = 0
    n = split("SL-001 SL-002 SL-003 SL-004 SL-005 SL-006 SL-007 SL-008", rules, " ")
    for (i = 1; i <= n; i++) {
        if (rules[i] in rule_seen) {
            print "- **" rules[i] ":** " advice[rules[i]]
            shown_advice = 1
        }
    }
    if (!shown_advice) {
        print "- No rule fired, so there is nothing specific to follow up. Keep monitoring."
    }
    print ""

    print "## 6. Limitations"
    print ""
    print "- Detection is rule based and uses simple thresholds. It can produce false positives (for example an authorised scanner) and can miss slow or distributed attacks."
    print "- Only the supported event formats of OpenSSH, sudo, su and the account tools are parsed. Other lines are counted as ignored."
    print "- Timestamps are compared as written. Logs from several time zones, or syslog timestamps without a year, can place events incorrectly (use `--year`)."
    print "- `useradd` and `usermod` do not log who ran them, so account changes cannot be attributed from this log alone. Use auditd (`auid`) for that."
    print "- The MITRE ATT&CK technique IDs are a best-effort label to help triage, not a classification."
}
