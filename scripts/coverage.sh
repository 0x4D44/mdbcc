#!/usr/bin/env bash
# scripts/coverage.sh — S1e (J-17 closure) cargo-llvm-cov wrapper.
#
# What it does:
#   1. Verifies `cargo llvm-cov` is installed (prints install instructions otherwise).
#   2. Runs `cargo llvm-cov --workspace --release --summary-only` and parses
#      the line-coverage percentage from the LLVM table.
#   3. Appends one row to `wrk_journals/coverage_history.tsv`:
#         <ISO-8601 timestamp>\t<git commit (12 hex)>\t<line-cov %>\t<region-cov %>
#   4. Prints the current line/region coverage AND the delta vs the previous row.
#
# Per the May-26 plan §6 testing charter (item 7): "Coverage drops are journal
# lines (J-17 wired during S1)." A tick journal entry should reference the
# output as `Coverage delta: X% -> Y% (+/- Z pp)`.
#
# Usage (from repo root):
#   bash scripts/coverage.sh
#
# Exit codes: 0 always (script reports drops as text but never fails CI; that
# decision is policy, not enforcement — see brief §S1e.2(b)).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HISTORY_FILE="${REPO_ROOT}/wrk_journals/coverage_history.tsv"

# 1. Pre-flight: cargo-llvm-cov present?
if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "cargo-llvm-cov is not installed."
    echo "Install it once with:"
    echo "  cargo install cargo-llvm-cov"
    echo ""
    echo "Note: cargo-llvm-cov requires the llvm-tools-preview rustup"
    echo "component. cargo-llvm-cov will prompt to install it on first run."
    exit 1
fi

# 2. Run the coverage sweep.
echo "Running cargo llvm-cov --workspace --release --summary-only ..."
RAW_OUTPUT="$(cargo llvm-cov --workspace --release --summary-only 2>&1)"
EXIT_CODE=$?
if [[ $EXIT_CODE -ne 0 ]]; then
    echo "cargo llvm-cov failed (exit $EXIT_CODE). Output:" >&2
    echo "${RAW_OUTPUT}" >&2
    exit "${EXIT_CODE}"
fi

# 3. Parse the TOTAL line and pull line / region coverage percentages.
# cargo-llvm-cov summary format ends with a TOTAL row containing several
# `NN.NN%` columns. Layout (cargo-llvm-cov 0.6.x):
#   regions  missed-regions  cover-regions%  functions  missed-fns  cover-fns%
#   lines  missed-lines  cover-lines%  ...
# We pull the bottom-most TOTAL row, extract all `(\d+\.\d+)%` matches, and
# take [0]=regions, [2]=lines (positional, matches cargo-llvm-cov stable output).
TOTAL_LINE="$(echo "${RAW_OUTPUT}" | awk '/^TOTAL[[:space:]]/ { last=$0 } END { print last }')"
if [[ -z "${TOTAL_LINE}" ]]; then
    echo "Could not find TOTAL line in cargo-llvm-cov output." >&2
    echo "Raw output (last 30 lines):" >&2
    echo "${RAW_OUTPUT}" | tail -n 30 >&2
    exit 2
fi

# Extract all percent tokens with grep -oE; tally and pick indices.
mapfile -t PCTS < <(echo "${TOTAL_LINE}" | grep -oE '[0-9]+\.[0-9]+%' | sed 's/%//')
if [[ "${#PCTS[@]}" -lt 3 ]]; then
    echo "Could not parse percentages from TOTAL line:" >&2
    echo "  ${TOTAL_LINE}" >&2
    exit 2
fi
REGION_PCT="${PCTS[0]}"
LINE_PCT="${PCTS[2]}"

# 4. Identify commit + timestamp.
COMMIT="$(git rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 5. Append to history TSV; create with header if absent.
NEW_ROW=$(printf "%s\t%s\t%s\t%s" "${TIMESTAMP}" "${COMMIT}" "${LINE_PCT}" "${REGION_PCT}")
HEADER=$(printf "timestamp\tcommit\tline_cov_pct\tregion_cov_pct")
if [[ ! -f "${HISTORY_FILE}" ]]; then
    echo "${HEADER}" > "${HISTORY_FILE}"
fi

# Find the previous (non-header) row, if any, before we append.
PREV_LINE_PCT=""
PREV_REGION_PCT=""
PREV_ROW="$(grep -v '^timestamp	' "${HISTORY_FILE}" | tail -n 1 || true)"
if [[ -n "${PREV_ROW}" ]]; then
    PREV_LINE_PCT="$(echo "${PREV_ROW}" | awk -F'\t' '{print $3}')"
    PREV_REGION_PCT="$(echo "${PREV_ROW}" | awk -F'\t' '{print $4}')"
fi

echo "${NEW_ROW}" >> "${HISTORY_FILE}"

# 6. Print summary.
echo ""
echo "Coverage summary (commit ${COMMIT}):"
printf "  line cov:   %s%%\n" "${LINE_PCT}"
printf "  region cov: %s%%\n" "${REGION_PCT}"
if [[ -n "${PREV_LINE_PCT}" ]]; then
    DELTA_LINES="$(awk "BEGIN { printf \"%.2f\", ${LINE_PCT} - ${PREV_LINE_PCT} }")"
    DELTA_REGIONS="$(awk "BEGIN { printf \"%.2f\", ${REGION_PCT} - ${PREV_REGION_PCT} }")"
    SIGN=""
    if [[ "$(awk "BEGIN { print (${DELTA_LINES} >= 0) }")" == "1" ]]; then
        SIGN="+"
    fi
    printf "  delta:      lines %s%s pp, regions %s%s pp (vs previous run)\n" \
        "${SIGN}" "${DELTA_LINES}" "${SIGN}" "${DELTA_REGIONS}"
    echo ""
    echo "Journal line for this tick:"
    printf "  Coverage delta: %s%% -> %s%% (%s%s pp)\n" \
        "${PREV_LINE_PCT}" "${LINE_PCT}" "${SIGN}" "${DELTA_LINES}"
else
    echo "  delta:      (no previous run - this is the baseline row)"
    echo ""
    echo "Journal line for this tick:"
    printf "  Coverage baseline: %s%% (line) / %s%% (region)\n" \
        "${LINE_PCT}" "${REGION_PCT}"
fi

echo ""
echo "History row appended to:"
echo "  ${HISTORY_FILE}"
