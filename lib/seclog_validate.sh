#!/usr/bin/env bash
# shellcheck shell=bash
# Input validation helpers. Sourced by bin/seclog after seclog_common.sh.
# Every function either succeeds or calls die with a clear message and exit code.

# The result files seclog writes. check_output_dir refuses to overwrite any of them.
OUTPUT_FILES=(events.csv findings.csv sources.csv summary.json report.md)

# Files that will be analysed (filled by collect_input_files).
INPUT_FILES=()

# require_integer NAME VALUE MIN MAX
require_integer() {
    local name=$1 value=$2 min=$3 max=$4
    if [[ ! $value =~ ^[0-9]{1,9}$ ]]; then
        die "$EXIT_USAGE" "$name must be a whole number, got '$value'"
    fi
    # "10#" forces base 10 so that a value such as 08 is not read as an invalid octal number.
    if ((10#$value < min || 10#$value > max)); then
        die "$EXIT_USAGE" "$name must be between $min and $max, got '$value'"
    fi
}

days_in_month() {
    local year=$((10#$1)) month=$((10#$2))
    case $month in
        1 | 3 | 5 | 7 | 8 | 10 | 12) echo 31 ;;
        4 | 6 | 9 | 11) echo 30 ;;
        2)
            if (((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)); then
                echo 29
            else
                echo 28
            fi
            ;;
    esac
}

# normalize_timestamp VALUE BOUND
# Accepts YYYY-MM-DD, "YYYY-MM-DD HH:MM", "YYYY-MM-DD HH:MM:SS" or the same with a "T".
# Prints YYYY-MM-DDTHH:MM:SS. A date without a time means the start of that day for a lower
# bound and the end of the day for an upper bound. Returns 1 for anything else.
normalize_timestamp() {
    local raw=$1 bound=$2
    local date_only='^([0-9]{4})-([0-9]{2})-([0-9]{2})$'
    local date_time='^([0-9]{4})-([0-9]{2})-([0-9]{2})[ T]([0-9]{2}):([0-9]{2})(:([0-9]{2}))?$'
    local year month day hour minute second

    if [[ $raw =~ $date_only ]]; then
        year=${BASH_REMATCH[1]}
        month=${BASH_REMATCH[2]}
        day=${BASH_REMATCH[3]}
        if [[ $bound == end ]]; then
            hour=23 minute=59 second=59
        else
            hour=00 minute=00 second=00
        fi
    elif [[ $raw =~ $date_time ]]; then
        year=${BASH_REMATCH[1]}
        month=${BASH_REMATCH[2]}
        day=${BASH_REMATCH[3]}
        hour=${BASH_REMATCH[4]}
        minute=${BASH_REMATCH[5]}
        second=${BASH_REMATCH[7]:-00}
    else
        return 1
    fi

    if ((10#$month < 1 || 10#$month > 12)); then
        return 1
    fi
    if ((10#$day < 1 || 10#$day > $(days_in_month "$year" "$month"))); then
        return 1
    fi
    if ((10#$hour > 23 || 10#$minute > 59 || 10#$second > 59)); then
        return 1
    fi
    printf '%s-%s-%sT%s:%s:%s\n' "$year" "$month" "$day" "$hour" "$minute" "$second"
}

# validate_time_option OPTION_NAME VALUE BOUND : prints the normalized timestamp or dies.
validate_time_option() {
    local name=$1 value=$2 bound=$3 normalized
    if ! normalized=$(normalize_timestamp "$value" "$bound"); then
        die "$EXIT_USAGE" "$name must look like 2026-03-14 or '2026-03-14 10:30[:00]', got '$value'"
    fi
    printf '%s' "$normalized"
}

# The exclude list ends up inside an awk variable, so only harmless characters are allowed.
validate_exclude_list() {
    local list=$1
    if [[ -n $list && ! $list =~ ^[A-Za-z0-9:._,-]+$ ]]; then
        die "$EXIT_USAGE" "--exclude-ips accepts a comma-separated list of addresses or host names, got '$list'"
    fi
}

# collect_input_files PATH... : expands directories and fills INPUT_FILES.
# "-" means standard input and may be used once.
collect_input_files() {
    local path file found stdin_count=0
    INPUT_FILES=()
    for path in "$@"; do
        if [[ $path == - ]]; then
            stdin_count=$((stdin_count + 1))
            if ((stdin_count > 1)); then
                die "$EXIT_USAGE" "standard input ('-') can only be used once"
            fi
            INPUT_FILES+=("-")
        elif [[ -d $path ]]; then
            found=0
            # find -print0 and read -d '' keep file names with spaces or newlines intact.
            while IFS= read -r -d '' file; do
                if [[ -r $file ]]; then
                    INPUT_FILES+=("$file")
                    found=1
                else
                    log_warn "skipping unreadable file: $file"
                fi
            done < <(find "$path" -maxdepth 1 -type f -print0 | LC_ALL=C sort -z)
            if ((! found)); then
                die "$EXIT_INPUT" "no readable files found in directory: $path"
            fi
        elif [[ -f $path ]]; then
            if [[ ! -r $path ]]; then
                die "$EXIT_INPUT" "file is not readable: $path"
            fi
            INPUT_FILES+=("$path")
        elif [[ -e $path ]]; then
            die "$EXIT_INPUT" "not a regular file or directory: $path"
        else
            die "$EXIT_INPUT" "input does not exist: $path"
        fi
    done
}

# check_output_dir DIR : never overwrite earlier results.
check_output_dir() {
    local dir=$1 name
    if [[ -e $dir && ! -d $dir ]]; then
        die "$EXIT_USAGE" "output path exists and is not a directory: $dir"
    fi
    for name in "${OUTPUT_FILES[@]}"; do
        if [[ -e $dir/$name ]]; then
            die "$EXIT_USAGE" "refusing to overwrite $dir/$name; choose a new --output-dir"
        fi
    done
}
