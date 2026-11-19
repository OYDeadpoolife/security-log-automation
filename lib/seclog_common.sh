#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034
# Shared constants and helpers for seclog. This file is sourced, never executed.
# (SC2034 is disabled because the constants are used by the files that source this one.)

SECLOG_VERSION="1.0.0"
PROGRAM_NAME="seclog"

# Exit codes, documented in docs/usage.md so that cron jobs and scripts can react to them.
EXIT_OK=0
EXIT_RUNTIME=1   # unexpected failure while analysing
EXIT_USAGE=2     # wrong command line options or option values
EXIT_INPUT=3     # input file or directory is missing, unreadable or corrupt
EXIT_FINDINGS=10 # --fail-on-findings was given and at least one high severity finding exists

ESC=$'\033'
TAB=$'\t'

USE_COLOR_STDOUT=0
USE_COLOR_STDERR=0
OPT_QUIET=0 # overwritten by --quiet; log_info reads it

# Decide whether to use colour. It is off when --no-color or NO_COLOR is set, and for each
# stream that is not a terminal, so redirected output never contains escape codes.
init_color() {
    local mode=$1
    if [[ $mode == never || -n ${NO_COLOR:-} ]]; then
        return 0
    fi
    if [[ -t 1 ]]; then
        USE_COLOR_STDOUT=1
    fi
    if [[ -t 2 ]]; then
        USE_COLOR_STDERR=1
    fi
}

log_error() {
    if ((USE_COLOR_STDERR)); then
        printf '%s: %s[1;31merror%s[0m: %s\n' "$PROGRAM_NAME" "$ESC" "$ESC" "$*" >&2
    else
        printf '%s: error: %s\n' "$PROGRAM_NAME" "$*" >&2
    fi
}

log_warn() {
    if ((USE_COLOR_STDERR)); then
        printf '%s: %s[1;33mwarning%s[0m: %s\n' "$PROGRAM_NAME" "$ESC" "$ESC" "$*" >&2
    else
        printf '%s: warning: %s\n' "$PROGRAM_NAME" "$*" >&2
    fi
}

# Progress messages go to stderr so that stdout stays clean for the summary.
log_info() {
    if ((! OPT_QUIET)); then
        printf '%s: %s\n' "$PROGRAM_NAME" "$*" >&2
    fi
}

# die EXIT_CODE MESSAGE... : print an error and stop. Every failure path uses this function
# so that errors look the same and always carry a documented exit code.
die() {
    local code=$1
    shift
    log_error "$*"
    exit "$code"
}

# UTC timestamp for reports. SECLOG_FIXED_TIME exists only so tests can produce identical output.
utc_now() {
    if [[ -n ${SECLOG_FIXED_TIME:-} ]]; then
        printf '%s' "$SECLOG_FIXED_TIME"
    else
        date -u +%Y-%m-%dT%H:%M:%SZ
    fi
}

# Make a value safe to place into a tab-separated record: no tabs, newlines or control
# characters. Text that is not valid UTF-8 is reduced to printable ASCII, because invalid
# bytes would make the JSON output invalid.
sanitize_text() {
    local text
    text=$(printf '%s' "$1" | LC_ALL=C tr '\t\n\r' '   ' | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177')
    if command -v iconv >/dev/null 2>&1 && ! printf '%s' "$text" | iconv -f UTF-8 -t UTF-8 >/dev/null 2>&1; then
        text=$(printf '%s' "$text" | LC_ALL=C tr -c '\040-\176' '?')
    fi
    printf '%s' "$text"
}

# --- temporary work directory ---------------------------------------------------------------
SECLOG_WORKDIR=""

create_workdir() {
    SECLOG_WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/seclog.XXXXXX") || die "$EXIT_RUNTIME" "cannot create a temporary directory"
}

# Removes only a directory this process created: the name must start with "seclog.".
cleanup_workdir() {
    case ${SECLOG_WORKDIR##*/} in
        seclog.?*)
            if [[ -d $SECLOG_WORKDIR ]]; then
                rm -rf -- "$SECLOG_WORKDIR"
            fi
            ;;
    esac
}
