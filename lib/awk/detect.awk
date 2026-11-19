# detect.awk - apply the detection rules to normalized events and aggregate statistics.
#
# Input  (stdin):  events from parse_auth.awk, sorted by epoch (column 2)
#                    1 timestamp  2 epoch  3 host  4 program  5 event_type
#                    6 user       7 source 8 target 9 detail
# Output (stdout): tab-separated records, the first column is the record type:
#                    EVTYPE   event_type  count
#                    SOURCE   source failures distinct_users invalid_users peak_in_window
#                             first_seen last_seen accepted flagged
#                    SUDOUSER user commands denied not_in_sudoers first_seen last_seen
#                    FINDING  rule severity time host subject count mitre title details
#                    STAT     name value
#
# Variables passed with -v:
#   failed_threshold  failed SSH logins from one source inside the window that raise SL-001
#   window_seconds    length of the sliding window
#   enum_threshold    distinct non-existent usernames from one source that raise SL-002
#   chain_seconds     how long an account stays "suspect" after a login that followed a brute force
#   exclude           comma-separated sources (for example a trusted scanner) to ignore
#
# Rules (see docs/detection-rules.md for the reasoning and false positives):
#   SL-001 SSH brute force            SL-005 sudo denied
#   SL-002 SSH username enumeration   SL-006 sensitive command run with sudo
#   SL-003 login success after SL-001 SL-007 new account / privileged group change
#   SL-004 direct root SSH login      SL-008 privilege activity by a suspect account

BEGIN {
    FS = "\t"
    OFS = "\t"
    max_findings = 1000

    n = split(exclude, excluded_list, ",")
    for (i = 1; i <= n; i++) {
        if (excluded_list[i] != "") {
            excluded[excluded_list[i]] = 1
        }
    }

    n = split("sudo admin wheel root adm shadow docker lxd", group_list, " ")
    for (i = 1; i <= n; i++) {
        privileged_group[group_list[i]] = 1
    }

    # MITRE ATT&CK technique IDs are a best-effort tag to help triage; they are not a verdict.
    mitre["SL-001"] = "T1110.001"
    mitre["SL-002"] = "T1110"
    mitre["SL-003"] = "T1078.003"
    mitre["SL-004"] = "T1021.004"
    mitre["SL-005"] = "T1548.003"
    mitre["SL-006"] = "T1548.003"
    mitre["SL-007"] = "T1136.001"
    mitre["SL-008"] = "T1078.003"
}

function add_finding(rule, severity, when, where, subject, count, technique, title, details) {
    if (finding_total >= max_findings) {
        findings_suppressed++
        return
    }
    finding_total++
    print "FINDING", rule, severity, when, where, subject, count, technique, title, details
}

# --- sliding window of failed logins per source ----------------------------------------------
# fail_at[source, n] holds the epoch of the n-th failure, fail_head[source] points to the oldest
# failure that is still inside the window.
function window_count(source,    head, tail) {
    tail = fail_tail[source] + 0
    if (tail == 0) {
        return 0
    }
    head = fail_head[source]
    while (head <= tail && fail_at[source SUBSEP head] < epoch - window_seconds) {
        head++
    }
    fail_head[source] = head
    return tail - head + 1
}

function record_failure(source) {
    fail_tail[source]++
    fail_at[source SUBSEP fail_tail[source]] = epoch
    if (fail_head[source] == "") {
        fail_head[source] = 1
    }
    return window_count(source)
}

function mark_suspect(where, account, reason) {
    suspect_at[where SUBSEP account] = epoch
    suspect_reason[where SUBSEP account] = reason
}

function is_suspect(where, account) {
    return ((where SUBSEP account) in suspect_at) && (epoch - suspect_at[where SUBSEP account] <= chain_seconds)
}

function touch_sudo_user(account) {
    if (!(account in sudo_first)) {
        sudo_first[account] = ts
        sudo_host[account] = host
    }
    sudo_last[account] = ts
}

# A command is "sensitive" when it opens a shell, switches user, edits accounts or touches the
# files that hold password hashes and sudo rules.
function sensitive_category(command) {
    if (command ~ /(^|\/)(bash|sh|zsh|dash|ksh|csh|tcsh|fish)( |$)/) {
        return "shell"
    }
    if (command ~ /(^|\/)su( |$)/) {
        return "su"
    }
    if (command ~ /\/etc\/(shadow|sudoers|passwd)/) {
        return "credential or sudoers file"
    }
    if (command ~ /(^|\/)(useradd|adduser|usermod|userdel|passwd|chpasswd|visudo|gpasswd)( |$)/) {
        return "account management tool"
    }
    return ""
}

function on_ssh_failed() {
    src_failures[source]++
    if (!(source in src_first)) {
        src_first[source] = ts
    }
    src_last[source] = ts
    if (!((source SUBSEP user) in seen_user)) {
        seen_user[source SUBSEP user] = 1
        src_users[source]++
    }
    current = record_failure(source)
    if (current > src_peak[source]) {
        src_peak[source] = current
    }
    if (current >= failed_threshold && !(source in brute_time)) {
        brute_time[source] = ts
        brute_host[source] = host
    }
}

function on_ssh_invalid_user() {
    if (!(source in src_first)) {
        src_first[source] = ts
    }
    src_last[source] = ts
    if (!((source SUBSEP user) in seen_invalid)) {
        seen_invalid[source SUBSEP user] = 1
        src_invalid[source]++
    }
    if (src_invalid[source] >= enum_threshold && !(source in enum_time)) {
        enum_time[source] = ts
        enum_host[source] = host
    }
}

function on_ssh_accepted(    failures) {
    src_accepted[source]++
    failures = window_count(source)
    if (failures >= failed_threshold) {
        add_finding("SL-003", "high", ts, host, user, 1, mitre["SL-003"], "SSH login succeeded after a brute-force burst",
            sprintf("%s logged in with %s from %s after %d failed attempts in the last %d minutes", user, detail, source, failures, window_seconds / 60))
        mark_suspect(host, user, sprintf("%s logged in from %s after a brute-force burst", user, source))
        last_suspect_at[host] = epoch
        last_suspect_reason[host] = suspect_reason[host SUBSEP user]
    }
    if (user == "root") {
        add_finding("SL-004", "medium", ts, host, source, 1, mitre["SL-004"], "Direct root SSH login",
            sprintf("root logged in with %s from %s", detail, source))
    }
}

function on_sudo_command(    category, key) {
    touch_sudo_user(user)
    sudo_commands[user]++
    category = sensitive_category(detail)
    if (is_suspect(host, user)) {
        add_finding("SL-008", "high", ts, host, user, 1, mitre["SL-008"], "Privileged command by a suspect account",
            sprintf("%s ran '%s' as %s%s. %s", user, detail, target, (category != "" ? " [" category "]" : ""), suspect_reason[host SUBSEP user]))
        return
    }
    if (category == "") {
        return
    }
    # Aggregate identical sensitive commands (same host, user and command) into one finding.
    key = host SUBSEP user SUBSEP detail
    if (!(key in sensitive_user)) {
        if (sensitive_keys >= 200) {
            return
        }
        sensitive_keys++
        sensitive_user[key] = user
        sensitive_host[key] = host
        sensitive_cmd[key] = detail
        sensitive_cat[key] = category
        sensitive_first[key] = ts
    }
    sensitive_count[key]++
    sensitive_last[key] = ts
}

function on_sudo_denied() {
    touch_sudo_user(user)
    if (type == "sudo_not_in_sudoers") {
        sudo_notin[user]++
    }
    sudo_denied[user]++
    if (!(user in denied_first)) {
        denied_first[user] = ts
        denied_host[user] = host
        denied_command[user] = detail
    }
    denied_last[user] = ts
}

function on_su(succeeded) {
    if (!is_suspect(host, user)) {
        return
    }
    add_finding("SL-008", "high", ts, host, user, 1, mitre["SL-008"], "Privilege activity by a suspect account",
        sprintf("%s %s to %s. %s", user, (succeeded ? "switched user with su" : "failed to switch user with su"), target, suspect_reason[host SUBSEP user]))
    if (succeeded) {
        # The attacker now controls the target account too, so keep following the chain.
        mark_suspect(host, target, suspect_reason[host SUBSEP user])
    }
}

function on_account_change(    title, text, minutes, technique) {
    if (type == "group_member_added" && !(detail in privileged_group)) {
        return
    }
    if (type == "user_created") {
        title = "New local account created"
        technique = mitre["SL-007"]
        text = sprintf("account %s was created", target)
    } else {
        title = "Account added to a privileged group"
        technique = "T1098"
        text = sprintf("account %s was added to the privileged group %s", target, detail)
    }
    if (user != "-") {
        text = text " by " user
    }
    if ((host in last_suspect_at) && epoch - last_suspect_at[host] <= chain_seconds) {
        minutes = int((epoch - last_suspect_at[host]) / 60)
        text = text sprintf(" (%d minutes after a suspicious login: %s)", minutes, last_suspect_reason[host])
    }
    add_finding("SL-007", "high", ts, host, target, 1, technique, title, text)
}

{
    ts = $1
    epoch = $2 + 0
    host = $3
    type = $5
    user = $6
    source = $7
    target = $8
    detail = $9

    type_count[type]++
    if (first_ts == "") {
        first_ts = ts
    }
    last_ts = ts
    hosts[host] = 1

    if (source != "-" && (source in excluded)) {
        excluded_events++
        next
    }

    if (type == "ssh_failed") {
        on_ssh_failed()
    } else if (type == "ssh_invalid_user") {
        on_ssh_invalid_user()
    } else if (type == "ssh_accepted") {
        on_ssh_accepted()
    } else if (type == "sudo_command") {
        on_sudo_command()
    } else if (type == "sudo_not_in_sudoers" || type == "sudo_denied" || type == "sudo_auth_failure") {
        on_sudo_denied()
    } else if (type == "su_success") {
        on_su(1)
    } else if (type == "su_failed") {
        on_su(0)
    } else if (type == "user_created" || type == "group_member_added") {
        on_account_change()
    }
}

END {
    # Findings that are only known after reading everything (counts, first and last time).
    for (s in brute_time) {
        add_finding("SL-001", "medium", brute_time[s], brute_host[s], s, src_failures[s], mitre["SL-001"], "SSH brute force",
            sprintf("%d failed logins from %s (peak %d within %d minutes, %d distinct usernames tried)", src_failures[s], s, src_peak[s], window_seconds / 60, src_users[s]))
    }
    for (s in enum_time) {
        add_finding("SL-002", "low", enum_time[s], enum_host[s], s, src_invalid[s], mitre["SL-002"], "SSH username enumeration",
            sprintf("%d distinct non-existent usernames were tried from %s", src_invalid[s], s))
    }
    for (u in denied_first) {
        add_finding("SL-005", "medium", denied_first[u], denied_host[u], u, sudo_denied[u], mitre["SL-005"], "sudo request denied",
            sprintf("%d denied sudo attempt(s) by %s, %d of them 'not in sudoers' (first command: %s)", sudo_denied[u], u, sudo_notin[u] + 0, denied_command[u]))
    }
    for (k in sensitive_user) {
        add_finding("SL-006", "medium", sensitive_first[k], sensitive_host[k], sensitive_user[k], sensitive_count[k], mitre["SL-006"], "Sensitive command run with sudo",
            sprintf("%s ran '%s' (%s) %d time(s), last at %s", sensitive_user[k], sensitive_cmd[k], sensitive_cat[k], sensitive_count[k], sensitive_last[k]))
    }

    for (t in type_count) {
        print "EVTYPE", t, type_count[t]
    }
    for (s in src_failures) {
        seen_source[s] = 1
    }
    for (s in src_invalid) {
        seen_source[s] = 1
    }
    for (s in seen_source) {
        print "SOURCE", s, src_failures[s] + 0, src_users[s] + 0, src_invalid[s] + 0, src_peak[s] + 0, (s in src_first ? src_first[s] : "-"), (s in src_last ? src_last[s] : "-"), src_accepted[s] + 0, ((s in brute_time) ? "yes" : "no")
    }
    for (u in sudo_first) {
        print "SUDOUSER", u, sudo_commands[u] + 0, sudo_denied[u] + 0, sudo_notin[u] + 0, sudo_first[u], sudo_last[u]
    }

    host_list = ""
    for (h in hosts) {
        host_list = host_list (host_list == "" ? "" : ",") h
    }
    print "STAT", "first_event", (first_ts == "" ? "-" : first_ts)
    print "STAT", "last_event", (last_ts == "" ? "-" : last_ts)
    print "STAT", "hosts", (host_list == "" ? "-" : host_list)
    print "STAT", "events_from_excluded_sources", excluded_events + 0
    print "STAT", "findings_suppressed", findings_suppressed + 0
}
