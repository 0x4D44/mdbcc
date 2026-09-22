# scripts/coverage.ps1 — S1e (J-17 closure) cargo-llvm-cov wrapper.
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
#   pwsh scripts/coverage.ps1
#
# Exit codes: 0 always (script reports drops as text but never fails CI; that
# decision is policy, not enforcement — see brief §S1e.2(b)).

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$HistoryFile = Join-Path $RepoRoot "wrk_journals\coverage_history.tsv"

# 1. Pre-flight: cargo-llvm-cov present?
$cargoLlvmCov = Get-Command "cargo-llvm-cov" -ErrorAction SilentlyContinue
if (-not $cargoLlvmCov) {
    Write-Host "cargo-llvm-cov is not installed." -ForegroundColor Yellow
    Write-Host "Install it once with:" -ForegroundColor Yellow
    Write-Host "  cargo install cargo-llvm-cov" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Note: cargo-llvm-cov requires the llvm-tools-preview rustup"
    Write-Host "component. cargo-llvm-cov will prompt to install it on first run."
    exit 1
}

# 2. Run the coverage sweep.
Write-Host "Running cargo llvm-cov --workspace --release --summary-only ..."
$rawOutput = & cargo llvm-cov --workspace --release --summary-only 2>&1
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    Write-Host "cargo llvm-cov failed (exit $exitCode). Output:" -ForegroundColor Red
    $rawOutput | ForEach-Object { Write-Host $_ }
    exit $exitCode
}

# 3. Parse the TOTAL line + the line/region percentages.
# cargo-llvm-cov summary format ends with a TOTAL row like:
#   TOTAL  ...  Regions   Missed Regions  Cover  Functions  ...  Lines  Missed Lines  Cover
# We grab the bottom-most TOTAL row and pick the line-coverage % (the LAST
# `Cover` column in the table) and the region-coverage % (the FIRST one).
$totalLine = $rawOutput | Where-Object { $_ -match '^TOTAL\s' } | Select-Object -Last 1
if (-not $totalLine) {
    Write-Host "Could not find TOTAL line in cargo-llvm-cov output." -ForegroundColor Red
    Write-Host "Raw output (last 30 lines):" -ForegroundColor Red
    $rawOutput | Select-Object -Last 30 | ForEach-Object { Write-Host $_ }
    exit 2
}

# Extract all percentage tokens (NN.NN%) from the TOTAL row. Standard layout:
#   [0] region cover %, [1] function cover %, [2] line cover %, [3] branch %?
# We take regions = first, lines = third (third one for line-cover).
$percentMatches = [regex]::Matches($totalLine, '(\d+\.\d+)%')
if ($percentMatches.Count -lt 3) {
    Write-Host "Could not parse percentages from TOTAL line:" -ForegroundColor Red
    Write-Host "  $totalLine" -ForegroundColor Red
    exit 2
}
$regionPct = [double]$percentMatches[0].Groups[1].Value
$linePct   = [double]$percentMatches[2].Groups[1].Value

# 4. Identify the commit (short hash) and ISO timestamp.
$commit = (& git rev-parse --short=12 HEAD).Trim()
$timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")

# 5. Append to history TSV; create with header if absent.
$newRow = "{0}`t{1}`t{2}`t{3}" -f $timestamp, $commit, $linePct.ToString("F2"), $regionPct.ToString("F2")
$header = "timestamp`tcommit`tline_cov_pct`tregion_cov_pct"
if (-not (Test-Path $HistoryFile)) {
    Set-Content -Path $HistoryFile -Value $header -Encoding UTF8
}

# Compute delta vs previous run (if any).
$existingRows = Get-Content $HistoryFile | Where-Object { $_ -and ($_ -notmatch '^timestamp\s') }
$prevLinePct = $null
$prevRegionPct = $null
if ($existingRows.Count -gt 0) {
    $lastRow = $existingRows | Select-Object -Last 1
    $cols = $lastRow -split "`t"
    if ($cols.Count -ge 4) {
        $prevLinePct = [double]$cols[2]
        $prevRegionPct = [double]$cols[3]
    }
}

Add-Content -Path $HistoryFile -Value $newRow -Encoding UTF8

# 6. Print summary.
Write-Host ""
Write-Host "Coverage summary (commit $commit):" -ForegroundColor Green
Write-Host ("  line cov:   {0:F2}%" -f $linePct)
Write-Host ("  region cov: {0:F2}%" -f $regionPct)
if ($null -ne $prevLinePct) {
    $deltaLines = $linePct - $prevLinePct
    $deltaRegions = $regionPct - $prevRegionPct
    $sign = if ($deltaLines -ge 0) { "+" } else { "" }
    Write-Host ("  delta:      lines {0}{1:F2} pp, regions {2}{3:F2} pp (vs previous run)" `
        -f $sign, $deltaLines, $sign, $deltaRegions)
    Write-Host ""
    Write-Host ("Journal line for this tick:" )
    Write-Host ("  Coverage delta: {0:F2}% -> {1:F2}% ({2}{3:F2} pp)" `
        -f $prevLinePct, $linePct, $sign, $deltaLines) -ForegroundColor Cyan
} else {
    Write-Host "  delta:      (no previous run — this is the baseline row)"
    Write-Host ""
    Write-Host ("Journal line for this tick:")
    Write-Host ("  Coverage baseline: {0:F2}% (line) / {1:F2}% (region)" `
        -f $linePct, $regionPct) -ForegroundColor Cyan
}

Write-Host ""
Write-Host "History row appended to:"
Write-Host "  $HistoryFile"
