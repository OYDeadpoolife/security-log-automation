# parse_auth.awk - turn raw Linux authentication log lines into normalized events.
#
# Input  (stdin):  raw log lines, either traditional syslog
#                    "Mar 14 10:02:11 web01 sshd[2101]: Failed password for ..."
#                  or ISO-8601 timestamps
#                    "2026-03-14T10:02:11.123456+00:00 web01 sshd[2101]: Failed password for ..."
# Output (stdout): one tab-separated row per security-relevant event:
#                    timestamp, epoch, host, program, event_type, user, source, target, detail
#                  Missing values are written as "-".
# Output (stderr): "STAT<TAB>name<TAB>value" rows that describe what was parsed.
#
# Variables passed with -v:
#   year        4-digit year for syslog timestamps, or 0 to guess it
#   cur_year    current year  (only used when year is 0)
#   cur_month   current month 1-12 (only used when year is 0)
#   since,until normalized "YYYY-MM-DDTHH:MM:SS" bounds (inclusive), or empty
#
# Only portable awk features are used (no gensub, strftime, regex intervals or POSIX
# character classes) so the script runs the same on BWK awk (macOS), mawk and gawk.

BEGIN {
    OFS = "\t"
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", month_names, " ")
    for (i = 1; i <= 12; i++) {
        month_number[month_names[i]] = i
    }
    last_month = 0
    year_rollovers = 0
}

# Days since 1970-01-01 for a calendar date (Howard Hinnant's "days from civil" algorithm).
# Doing the arithmetic by hand avoids mktime(), which is not available in every awk.
function days_from_civil(y, m, d,    era, yoe, doy, doe) {
    if (m <= 2) {
        y = y - 1
    }
    era = int((y >= 0 ? y : y - 399) / 400)
    yoe = y - era * 400
    doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
    doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
    return era * 146097 + doe - 719468
}

function days_in_month(y, m) {
    if (m == 2) {
        return ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 29 : 28
    }
    return (m == 4 || m == 6 || m == 9 || m == 11) ? 30 : 31
}

function epoch_of(y, m, d, hh, mm, ss) {
    return days_from_civil(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss
}

function dash(value) {
    return (value == "" ? "-" : value)
}

# A source is normally an IP address, but sshd logs a hostname when UseDNS is enabled.
function clean_source(value) {
    if (value ~ /^[A-Za-z0-9:._-]+$/) {
        return value
    }
    return "-"
}

# Print one normalized event. ts, epoch_text, host and prog are set by the main block.
function emit(event_type, user, source, target, detail) {
    print ts, epoch_text, host, prog, event_type, dash(user), dash(source), dash(target), dash(substr(detail, 1, 300))
}

function parse_sshd(text,    n, w, i, user) {
    n = split(text, w, " ")
    if (w[1] == "Failed" && w[3] == "for") {
        i = 4
        if (w[i] == "invalid" && w[i + 1] == "user") {
            i += 2
        }
        user = w[i]
        if (user == "" || w[i + 1] != "from") {
            return 0
        }
        emit("ssh_failed", user, clean_source(w[i + 2]), "-", w[2])
        return 1
    }
    if (w[1] == "Invalid" && w[2] == "user" && w[4] == "from") {
        emit("ssh_invalid_user", w[3], clean_source(w[5]), "-", "-")
        return 1
    }
    if (w[1] == "Accepted" && w[3] == "for" && w[5] == "from") {
        emit("ssh_accepted", w[4], clean_source(w[6]), "-", w[2])
        return 1
    }
    return 0
}

function parse_sudo(text,    pos, user, rest, command, target) {
    pos = index(text, " : ")
    # Form 1: "<user> : TTY=... ; PWD=... ; USER=<target> ; COMMAND=<command>"
    if (pos > 1 && index(substr(text, 1, pos - 1), " ") == 0) {
        user = substr(text, 1, pos - 1)
        rest = substr(text, pos + 3)
        command = ""
        if (match(rest, /COMMAND=.*/)) {
            command = substr(rest, RSTART + 8)
        }
        target = "-"
        if (match(rest, /USER=[A-Za-z0-9._-]+/)) {
            target = substr(rest, RSTART + 5, RLENGTH - 5)
        }
        if (index(rest, "user NOT in sudoers") > 0) {
            emit("sudo_not_in_sudoers", user, "-", target, command)
            return 1
        }
        if (rest ~ /[0-9]+ incorrect password attempts?/) {
            emit("sudo_denied", user, "-", target, command)
            return 1
        }
        if (command != "") {
            emit("sudo_command", user, "-", target, command)
            return 1
        }
        return 0
    }
    # Form 2: a PAM message about a failed password prompt.
    if (text ~ /^pam_unix\(sudo:auth\): authentication failure/ && match(text, / user=[A-Za-z0-9._-]+$/)) {
        emit("sudo_auth_failure", substr(text, RSTART + 6, RLENGTH - 6), "-", "root", "-")
        return 1
    }
    return 0
}

function parse_su(text,    n, w, target) {
    # Ubuntu: "FAILED SU (to labadmin) svc-backup on pts/0" and "(to labadmin) svc-backup on pts/0"
    if (match(text, /^FAILED SU \(to [^)]+\) [^ ]+/)) {
        n = split(substr(text, RSTART, RLENGTH), w, " ")
        target = w[4]
        sub(/\)$/, "", target)
        emit("su_failed", w[5], "-", target, "-")
        return 1
    }
    if (match(text, /^\(to [^)]+\) [^ ]+ on /)) {
        n = split(substr(text, RSTART, RLENGTH), w, " ")
        target = w[2]
        sub(/\)$/, "", target)
        emit("su_success", w[3], "-", target, "-")
        return 1
    }
    # Debian: "Successful su for labadmin by svc-backup" and "FAILED su for labadmin by svc-backup"
    n = split(text, w, " ")
    if (w[1] == "Successful" && w[2] == "su" && w[3] == "for" && w[5] == "by") {
        emit("su_success", w[6], "-", w[4], "-")
        return 1
    }
    if (w[1] == "FAILED" && w[2] == "su" && w[3] == "for" && w[5] == "by") {
        emit("su_failed", w[6], "-", w[4], "-")
        return 1
    }
    return 0
}

function strip_quotes(value) {
    gsub(/'/, "", value)
    return value
}

# useradd, usermod, gpasswd, passwd and userdel log what they changed but, except for
# gpasswd, not who ran them. That is why the user column is "-" for most of these events.
function parse_account(program, text,    n, w, name) {
    n = split(text, w, " ")
    if (program == "useradd" && w[1] == "new" && w[2] == "user:") {
        name = w[3]
        sub(/^name=/, "", name)
        sub(/,$/, "", name)
        emit("user_created", "-", "-", name, "-")
        return 1
    }
    if (program == "usermod" && w[1] == "add" && w[3] == "to" && w[4] == "group") {
        emit("group_member_added", "-", "-", strip_quotes(w[2]), strip_quotes(w[5]))
        return 1
    }
    if (program == "gpasswd" && w[1] == "user" && w[3] == "added" && w[4] == "by" && w[6] == "to" && w[7] == "group") {
        emit("group_member_added", w[5], "-", w[2], w[8])
        return 1
    }
    if (program == "passwd" && text ~ /password changed for [^ ]+$/) {
        emit("password_changed", "-", "-", w[n], "-")
        return 1
    }
    if (program == "userdel" && w[1] == "delete" && w[2] == "user") {
        emit("user_deleted", "-", "-", strip_quotes(w[3]), "-")
        return 1
    }
    return 0
}

function stat_line(name, value) {
    print "STAT", name, value + 0 > "/dev/stderr"
}

{
    total++
    line = $0
    if (length(line) > 4096) {
        line = substr(line, 1, 4096)
        truncated++
    }
    # Log content is attacker-controlled. Keep printable ASCII only so the later JSON, CSV and
    # Markdown output can never contain control characters or invalid UTF-8.
    gsub(/[^ -~]/, "?", line)
    nf = split(line, f, " ")
    if (nf == 0) {
        blank++
        next
    }

    # --- header: timestamp, host, program ---------------------------------------------------
    if ((f[1] in month_number) && f[2] ~ /^[0-9][0-9]?$/ && f[3] ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) {
        is_iso = 0
        mon = month_number[f[1]]
        day = f[2] + 0
        hh = substr(f[3], 1, 2) + 0
        mi = substr(f[3], 4, 2) + 0
        ss = substr(f[3], 7, 2) + 0
        host_index = 4
        tag_index = 5
        message_index = 6
    } else if (f[1] ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) {
        is_iso = 1
        yr = substr(f[1], 1, 4) + 0
        mon = substr(f[1], 6, 2) + 0
        day = substr(f[1], 9, 2) + 0
        hh = substr(f[1], 12, 2) + 0
        mi = substr(f[1], 15, 2) + 0
        ss = substr(f[1], 18, 2) + 0
        host_index = 2
        tag_index = 3
        message_index = 4
    } else {
        malformed++
        next
    }
    if (mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mi > 59 || ss > 60 || f[tag_index] == "") {
        malformed++
        next
    }

    if (!is_iso) {
        # Syslog timestamps have no year. Use --year, otherwise assume the current year, or the
        # previous one for a month that is still in the future. A drop from December to January
        # between two consecutive lines is treated as a new year.
        if (last_month > 0 && last_month - mon >= 6) {
            year_rollovers++
        }
        last_month = mon
        if (year > 0) {
            yr = year
        } else {
            yr = (mon > cur_month ? cur_year - 1 : cur_year)
        }
        yr = yr + year_rollovers
    }

    if (day > days_in_month(yr, mon)) {
        malformed++
        next
    }

    ts = sprintf("%04d-%02d-%02dT%02d:%02d:%02d", yr, mon, day, hh, mi, ss)
    if ((since != "" && ts < since) || (until != "" && ts > until)) {
        out_of_range++
        next
    }
    epoch_text = sprintf("%.0f", epoch_of(yr, mon, day, hh, mi, ss))
    host = f[host_index]

    # --- program name without the "[pid]:" suffix -------------------------------------------
    prog = f[tag_index]
    sub(/:$/, "", prog)
    if (match(prog, /\[[0-9]+\]$/)) {
        prog = substr(prog, 1, RSTART - 1)
    }
    message = ""
    for (k = message_index; k <= nf; k++) {
        message = message (k > message_index ? " " : "") f[k]
    }

    # --- classify ---------------------------------------------------------------------------
    handled = 0
    if (prog == "sshd") {
        handled = parse_sshd(message)
    } else if (prog == "sudo") {
        handled = parse_sudo(message)
    } else if (prog == "su") {
        handled = parse_su(message)
    } else if (prog == "useradd" || prog == "usermod" || prog == "gpasswd" || prog == "passwd" || prog == "userdel") {
        handled = parse_account(prog, message)
    }
    if (handled) {
        events++
    } else {
        ignored++
    }
}

END {
    stat_line("lines_total", total)
    stat_line("lines_blank", blank)
    stat_line("lines_malformed", malformed)
    stat_line("lines_truncated", truncated)
    stat_line("lines_out_of_range", out_of_range)
    stat_line("lines_ignored", ignored)
    stat_line("events", events)
}
