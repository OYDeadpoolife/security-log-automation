# to_terminal.awk - print a short, optionally coloured summary for the person at the keyboard.
#
# Variables passed with -v (all optional):
#   c_red, c_yellow, c_green, c_bold, c_reset   ANSI colour codes; empty when colour is off
#   width                                       maximum line width (default 110)

BEGIN {
    FS = "\t"
    if (width == "") {
        width = 110
    }
}

function severity_color(severity) {
    if (severity == "high") {
        return c_red
    }
    if (severity == "medium") {
        return c_yellow
    }
    return c_green
}

function fit(text, max) {
    if (length(text) <= max) {
        return text
    }
    return substr(text, 1, max - 3) "..."
}

$1 == "META" {
    meta[$2] = $3
}
$1 == "STAT" {
    stat[$2] = $3
}
$1 == "FINDING" {
    f_count++
    f_severity[f_count] = $3
    f_time[f_count] = $4
    f_rule[f_count] = $2
    f_subject[f_count] = $6
    f_details[f_count] = $9 ": " $10
    severity_total[$3]++
}

END {
    print c_bold "seclog " meta["tool_version"] " - analysis complete" c_reset
    print "  Lines read   : " stat["lines_total"] " (ignored " stat["lines_ignored"] ", malformed " stat["lines_malformed"] ", outside time range " stat["lines_out_of_range"] ")"
    print "  Events parsed: " stat["events"] " between " stat["first_event"] " and " stat["last_event"]
    printf "  Findings     : %d (%shigh %d%s, %smedium %d%s, %slow %d%s)\n", f_count, c_red, severity_total["high"], c_reset, c_yellow, severity_total["medium"], c_reset, c_green, severity_total["low"], c_reset
    if (f_count > 0) {
        print ""
        for (i = 1; i <= f_count; i++) {
            printf "  %s%-6s%s %s  %s  %-16s %s\n", severity_color(f_severity[i]), f_severity[i], c_reset, f_time[i], f_rule[i], fit(f_subject[i], 16), fit(f_details[i], width - 62)
        }
    }
}
