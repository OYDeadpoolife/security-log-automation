# to_json.awk - render the analysis records as one JSON document.
#
# Input (stdin): the records file built by lib/seclog_pipeline.sh (META, INPUT, PARAM, STAT,
#                EVTYPE, FINDING, SOURCE and SUDOUSER rows, tab-separated).
# Output: JSON on stdout. Keys are written in a fixed order so that output is reproducible.
#
# JSON is built by hand because awk has no JSON library. Every string goes through jstr(),
# which escapes backslashes and quotes. The parse stage already removed control characters
# and non-ASCII bytes from log content, and the test suite validates the result with
# Python's json module, including lines that try to break the format.

BEGIN {
    FS = "\t"
}

function jesc(text,    out, i, c) {
    if (index(text, "\\") == 0 && index(text, "\"") == 0) {
        return text
    }
    out = ""
    for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (c == "\\") {
            out = out "\\\\"
        } else if (c == "\"") {
            out = out "\\\""
        } else {
            out = out c
        }
    }
    return out
}

function jstr(text) {
    return "\"" jesc(text) "\""
}

# Numbers are written bare, everything else as a string.
function jval(text) {
    return (text ~ /^[0-9]+$/ ? text : jstr(text))
}

function jnum(text) {
    return (text ~ /^[0-9]+$/ ? text : "0")
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
    print "{"
    print "  \"tool\": {\"name\": \"seclog\", \"version\": " jstr(meta["tool_version"]) "},"
    print "  \"generated_at\": " jstr(meta["generated_at"]) ","

    print "  \"inputs\": ["
    for (i = 1; i <= input_count; i++) {
        print "    " jstr(input_list[i]) (i < input_count ? "," : "")
    }
    print "  ],"

    print "  \"parameters\": {"
    for (i = 1; i <= param_count; i++) {
        print "    " jstr(param_name[i]) ": " jval(param_value[i]) (i < param_count ? "," : "")
    }
    print "  },"

    n = split("lines_total lines_blank lines_malformed lines_truncated lines_out_of_range lines_ignored events events_from_excluded_sources findings_suppressed", keys, " ")
    print "  \"parse\": {"
    for (i = 1; i <= n; i++) {
        print "    " jstr(keys[i]) ": " jnum(stat[keys[i]]) (i < n ? "," : "")
    }
    print "  },"

    print "  \"time_range\": {\"first_event\": " jstr(stat["first_event"]) ", \"last_event\": " jstr(stat["last_event"]) "},"

    host_count = split(stat["hosts"], host_list, ",")
    printf "  \"hosts\": ["
    for (i = 1; i <= host_count; i++) {
        printf "%s%s", (i > 1 ? ", " : ""), jstr(host_list[i])
    }
    print "],"

    print "  \"event_types\": {"
    for (i = 1; i <= evtype_count; i++) {
        print "    " jstr(evtype_name[i]) ": " jnum(evtype_total[i]) (i < evtype_count ? "," : "")
    }
    print "  },"

    printf "  \"summary\": {\"findings_total\": %d, \"high\": %d, \"medium\": %d, \"low\": %d},\n", f_count, severity_total["high"], severity_total["medium"], severity_total["low"]

    print "  \"findings\": ["
    for (i = 1; i <= f_count; i++) {
        printf "    {\"rule_id\": %s, \"severity\": %s, \"time\": %s, \"host\": %s, \"subject\": %s, \"event_count\": %s, \"mitre_technique\": %s, \"title\": %s, \"details\": %s}%s\n",
            jstr(f_rule[i]), jstr(f_severity[i]), jstr(f_time[i]), jstr(f_host[i]), jstr(f_subject[i]), jnum(f_events[i]), jstr(f_mitre[i]), jstr(f_title[i]), jstr(f_details[i]), (i < f_count ? "," : "")
    }
    print "  ],"

    print "  \"failed_login_sources\": ["
    for (i = 1; i <= s_count; i++) {
        printf "    {\"source\": %s, \"failed_logins\": %s, \"distinct_usernames\": %s, \"invalid_usernames\": %s, \"peak_in_window\": %s, \"first_seen\": %s, \"last_seen\": %s, \"accepted_logins\": %s, \"flagged_brute_force\": %s}%s\n",
            jstr(s_ip[i]), jnum(s_failed[i]), jnum(s_users[i]), jnum(s_invalid[i]), jnum(s_peak[i]), jstr(s_first[i]), jstr(s_last[i]), jnum(s_accepted[i]), (s_flagged[i] == "yes" ? "true" : "false"), (i < s_count ? "," : "")
    }
    print "  ],"

    print "  \"sudo_users\": ["
    for (i = 1; i <= u_count; i++) {
        printf "    {\"user\": %s, \"sudo_commands\": %s, \"denied\": %s, \"not_in_sudoers\": %s, \"first_seen\": %s, \"last_seen\": %s}%s\n",
            jstr(u_name[i]), jnum(u_commands[i]), jnum(u_denied[i]), jnum(u_notin[i]), jstr(u_first[i]), jstr(u_last[i]), (i < u_count ? "," : "")
    }
    print "  ]"
    print "}"
}
