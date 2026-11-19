# to_csv.awk - render events, findings or sources as RFC 4180 CSV.
#
# Variable passed with -v:
#   kind   "events"   input is the sorted events file (9 columns)
#          "findings" input is the records file; FINDING rows are written
#          "sources"  input is the records file; SOURCE rows are written
#
# Log content is attacker-controlled, and CSV files are often opened in a spreadsheet. A cell
# that starts with = + - or @ can be executed as a formula there ("CSV injection"), so such
# cells get a leading apostrophe. A "-" placeholder from the pipeline becomes an empty cell.

BEGIN {
    FS = "\t"
    if (kind == "events") {
        print "timestamp,host,program,event_type,user,source,target,detail"
    } else if (kind == "findings") {
        print "time,rule_id,severity,host,subject,event_count,mitre_technique,title,details"
    } else if (kind == "sources") {
        print "source,failed_logins,distinct_usernames,invalid_usernames,peak_in_window,first_seen,last_seen,accepted_logins,flagged_brute_force"
    } else {
        print "to_csv.awk: kind must be events, findings or sources" > "/dev/stderr"
        failed = 1
        exit 1
    }
}

function cell(text,    out, i, c) {
    if (text == "-") {
        return ""
    }
    if (text ~ /^[=+@-]/) {
        text = "'" text
    }
    if (text !~ /[",]/ && text !~ /^ / && text !~ / $/) {
        return text
    }
    # Double every quote by hand; gsub replacement strings behave differently between awks.
    out = ""
    for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        out = out (c == "\"" ? "\"\"" : c)
    }
    return "\"" out "\""
}

kind == "events" {
    print cell($1) "," cell($3) "," cell($4) "," cell($5) "," cell($6) "," cell($7) "," cell($8) "," cell($9)
}

kind == "findings" && $1 == "FINDING" {
    print cell($4) "," cell($2) "," cell($3) "," cell($5) "," cell($6) "," cell($7) "," cell($8) "," cell($9) "," cell($10)
}

kind == "sources" && $1 == "SOURCE" {
    print cell($2) "," cell($3) "," cell($4) "," cell($5) "," cell($6) "," cell($7) "," cell($8) "," cell($9) "," cell($10)
}

END {
    if (failed) {
        exit 1
    }
}
