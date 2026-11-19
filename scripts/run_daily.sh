#!/usr/bin/env bash
# run_daily.sh - analyse one day of an authentication log; meant to be started by cron.
#
# It is a thin wrapper around "seclog analyze": it works out the date, picks a result
# directory named after that date and refuses to run twice for the same day.
# It only reads the log and writes below --output-base. It never needs root, but the
# account running it must be allowed to read the log (on Debian/Ubuntu: member of group adm).
set -u
set -o pipefail

SCRIPT_DIR=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || exit 1
SECLOG=$SCRIPT_DIR/../bin/seclog

usage() {
    cat <<'EOF'
Usage: run_daily.sh [--input FILE] [--output-base DIR] [--date YYYY-MM-DD] [--year YYYY] [--exclude-ips LIST]

  --input FILE         log to analyse (default: /var/log/auth.log)
  --output-base DIR    results go to DIR/<date> (default: $HOME/seclog-reports)
  --date YYYY-MM-DD    day to analyse (default: yesterday)
  --year YYYY          year of the syslog timestamps (default: year of --date)
  --exclude-ips LIST   trusted sources to ignore, comma separated
EOF
}

# Yesterday's date. GNU date (Linux) and BSD date (macOS) use different options.
yesterday() {
    if date -d yesterday +%F >/dev/null 2>&1; then
        date -d yesterday +%F
    else
        date -v-1d +%F
    fi
}

input=/var/log/auth.log
output_base=${HOME:-.}/seclog-reports
day=""
year=""
exclude=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --input) input=${2:?--input needs a value} && shift 2 ;;
        --output-base) output_base=${2:?--output-base needs a value} && shift 2 ;;
        --date) day=${2:?--date needs a value} && shift 2 ;;
        --year) year=${2:?--year needs a value} && shift 2 ;;
        --exclude-ips) exclude=${2:?--exclude-ips needs a value} && shift 2 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "run_daily.sh: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z $day ]]; then
    day=$(yesterday) || exit 1
fi
if [[ ! $day =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "run_daily.sh: --date must look like 2026-03-14, got '$day'" >&2
    exit 2
fi
if [[ -z $year ]]; then
    year=${day%%-*}
fi

result_dir=$output_base/$day
if [[ -e $result_dir ]]; then
    echo "run_daily.sh: $result_dir already exists, nothing to do." >&2
    exit 0
fi

# A lock directory stops two cron runs from overlapping (mkdir is atomic).
lock_dir=${TMPDIR:-/tmp}/seclog-run-daily.$(id -u).lock
if ! mkdir "$lock_dir" 2>/dev/null; then
    echo "run_daily.sh: another run is in progress (lock: $lock_dir)." >&2
    exit 1
fi
trap 'rmdir "$lock_dir"' EXIT

args=(analyze --input "$input" --year "$year" --since "$day" --until "$day" --output-dir "$result_dir" --quiet --no-color)
if [[ -n $exclude ]]; then
    args+=(--exclude-ips "$exclude")
fi
"$SECLOG" "${args[@]}"
