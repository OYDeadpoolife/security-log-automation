#!/usr/bin/env bash
# shellcheck shell=bash
# The analysis pipeline. Sourced by bin/seclog after seclog_common.sh and seclog_validate.sh.
#
#   raw logs --> parse_auth.awk --> sort by time --> detect.awk --> records --+--> summary.json
#                                                                             +--> findings.csv, sources.csv
#   events (sorted) -------------------------------------------------------+--> events.csv
#   records ----------------------------------------------------------------+--> report.md
#
# Every stage is a plain text stream, so any intermediate file can be inspected with less/awk.
# All work happens in a private temporary directory; results are moved into the output
# directory only after every stage has succeeded, so a failed run never leaves partial results.
#
# Globals read: INPUT_FILES, OPT_* settings, NORMALIZED_SINCE, NORMALIZED_UNTIL, AWK_BIN,
#               AWK_DIR, SECLOG_WORKDIR, CURRENT_YEAR, CURRENT_MONTH

# Run awk with byte semantics (LC_ALL=C): faster, and log bytes are never reinterpreted as text.
run_awk() {
    LC_ALL=C "$AWK_BIN" "$@"
}

# Write all inputs to standard output, one after the other. "awk 1" prints every line with a
# trailing newline, so a file that does not end in a newline cannot merge with the next one.
read_inputs() {
    local file
    for file in "${INPUT_FILES[@]}"; do
        case $file in
            -) run_awk 1 || return 1 ;;
            *.gz) gzip -dc -- "$file" | run_awk 1 || return 1 ;;
            *) run_awk 1 <"$file" || return 1 ;;
        esac
    done
}

# Stage 1: raw lines -> normalized events (+ parse statistics on stderr).
stage_parse() {
    local events_raw=$SECLOG_WORKDIR/events_raw.tsv
    local stats=$SECLOG_WORKDIR/parse_stats.txt
    local status

    read_inputs | run_awk \
        -v year="$OPT_YEAR" -v cur_year="$CURRENT_YEAR" -v cur_month="$CURRENT_MONTH" \
        -v since="$NORMALIZED_SINCE" -v until="$NORMALIZED_UNTIL" \
        -f "$AWK_DIR/parse_auth.awk" >"$events_raw" 2>"$stats"
    status=("${PIPESTATUS[@]}")

    if ((status[0] != 0)); then
        die "$EXIT_INPUT" "could not read the input (a .gz file may be corrupt)"
    fi
    if ((status[1] != 0)); then
        cat "$stats" >&2
        die "$EXIT_RUNTIME" "the log parser failed"
    fi
    # Events from several files may be out of order. A stable numeric sort on the epoch column
    # puts them in time order and keeps the original order for equal timestamps.
    LC_ALL=C sort -s -t "$TAB" -k2,2n "$events_raw" >"$SECLOG_WORKDIR/events.tsv" ||
        die "$EXIT_RUNTIME" "sorting the events failed"
}

# Stage 2: normalized events -> detection records.
stage_detect() {
    run_awk \
        -v failed_threshold="$OPT_FAILED_THRESHOLD" -v window_seconds="$((OPT_WINDOW_MINUTES * 60))" \
        -v enum_threshold="$OPT_ENUM_THRESHOLD" -v chain_seconds=7200 -v exclude="$OPT_EXCLUDE_IPS" \
        -f "$AWK_DIR/detect.awk" <"$SECLOG_WORKDIR/events.tsv" >"$SECLOG_WORKDIR/detect_raw.tsv" ||
        die "$EXIT_RUNTIME" "the detection stage failed"
}

# Stage 3: combine metadata, parse statistics and detection results into one ordered file.
stage_records() {
    local detect=$SECLOG_WORKDIR/detect_raw.tsv
    local file
    {
        printf 'META\ttool_version\t%s\n' "$SECLOG_VERSION"
        printf 'META\tgenerated_at\t%s\n' "$(utc_now)"
        for file in "${INPUT_FILES[@]}"; do
            # Files below the tool's own directory (the bundled sample) are shown relative to it.
            printf 'INPUT\t%s\n' "$(sanitize_text "${file#"$SECLOG_ROOT"/}")"
        done
        printf 'PARAM\tfailed_threshold\t%s\n' "$OPT_FAILED_THRESHOLD"
        printf 'PARAM\twindow_minutes\t%s\n' "$OPT_WINDOW_MINUTES"
        printf 'PARAM\tenum_threshold\t%s\n' "$OPT_ENUM_THRESHOLD"
        printf 'PARAM\tsince\t%s\n' "$NORMALIZED_SINCE"
        printf 'PARAM\tuntil\t%s\n' "$NORMALIZED_UNTIL"
        printf 'PARAM\tyear\t%s\n' "$OPT_YEAR"
        printf 'PARAM\texclude_ips\t%s\n' "$(sanitize_text "$OPT_EXCLUDE_IPS")"
        grep '^STAT' "$SECLOG_WORKDIR/parse_stats.txt"
        grep '^STAT' "$detect"
        # Sort each record type the way a reader wants to see it.
        grep '^EVTYPE' "$detect" | LC_ALL=C sort -s -t "$TAB" -k3,3nr -k2,2
        grep '^FINDING' "$detect" | LC_ALL=C sort -s -t "$TAB" -k4,4 -k2,2 -k6,6
        grep '^SOURCE' "$detect" | LC_ALL=C sort -s -t "$TAB" -k3,3nr -k2,2
        grep '^SUDOUSER' "$detect" | LC_ALL=C sort -s -t "$TAB" -k3,3nr -k2,2
    } >"$SECLOG_WORKDIR/records.tsv"
    # grep exits with 1 when a record type is absent, which is normal; the group's status is ignored.
    return 0
}

# Stage 4: render the result files inside the work directory.
stage_render() {
    local work=$SECLOG_WORKDIR
    run_awk -f "$AWK_DIR/to_json.awk" <"$work/records.tsv" >"$work/summary.json" ||
        die "$EXIT_RUNTIME" "could not build summary.json"
    run_awk -v kind=events -f "$AWK_DIR/to_csv.awk" <"$work/events.tsv" >"$work/events.csv" ||
        die "$EXIT_RUNTIME" "could not build events.csv"
    run_awk -v kind=findings -f "$AWK_DIR/to_csv.awk" <"$work/records.tsv" >"$work/findings.csv" ||
        die "$EXIT_RUNTIME" "could not build findings.csv"
    run_awk -v kind=sources -f "$AWK_DIR/to_csv.awk" <"$work/records.tsv" >"$work/sources.csv" ||
        die "$EXIT_RUNTIME" "could not build sources.csv"
    run_awk -f "$AWK_DIR/to_markdown.awk" <"$work/records.tsv" >"$work/report.md" ||
        die "$EXIT_RUNTIME" "could not build report.md"
}

# Stage 5: move the finished files into the output directory.
stage_publish() {
    local name
    mkdir -p -- "$OUTPUT_DIR" || die "$EXIT_RUNTIME" "cannot create the output directory: $OUTPUT_DIR"
    check_output_dir "$OUTPUT_DIR"
    for name in "${OUTPUT_FILES[@]}"; do
        mv -- "$SECLOG_WORKDIR/$name" "$OUTPUT_DIR/$name" || die "$EXIT_RUNTIME" "cannot write $OUTPUT_DIR/$name"
    done
}

# Print the coloured summary for the person at the terminal.
print_terminal_summary() {
    local red="" yellow="" green="" bold="" reset=""
    if ((USE_COLOR_STDOUT)); then
        red="${ESC}[1;31m"
        yellow="${ESC}[1;33m"
        green="${ESC}[1;32m"
        bold="${ESC}[1m"
        reset="${ESC}[0m"
    fi
    run_awk -v c_red="$red" -v c_yellow="$yellow" -v c_green="$green" -v c_bold="$bold" -v c_reset="$reset" \
        -f "$AWK_DIR/to_terminal.awk" <"$SECLOG_WORKDIR/records.tsv"
}

# True (exit status 0) when the detection records contain a high severity finding.
has_high_severity_finding() {
    run_awk -F "$TAB" '$1 == "FINDING" && $3 == "high" { found = 1 } END { exit !found }' <"$SECLOG_WORKDIR/records.tsv"
}

run_analysis() {
    log_info "reading ${#INPUT_FILES[@]} input file(s)"
    stage_parse
    stage_detect
    stage_records
    stage_render
}
