# Build the mdbcc toolchain, then its BC4.52 dependency libraries.
#
# This is the canonical "build mdbcc" entry point. It first builds the
# compiler/linker/archiver/etc. (release profile), then runs build_bc45_libs to
# produce the BC4.52 dependency libraries from source for BOTH targets:
#   target/bc45-libs/{mdowl,mdstreams,mdcw32,mdbids}.lib       (Win32, -m32)
#   target/bc45-libs/win64/{mdowl,mdstreams,mdcw32,mdbids}.lib (Win64, -m64 + overlay)
# The library step self-skips (exit 0) when the BC4.52 source tree is absent, so
# this is always safe to run.
#
# Usage:  pwsh -NoProfile -File scripts/build-mdbcc.ps1
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    cargo build --release --bins
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & (Join-Path $repo "target\release\build_bc45_libs.exe")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & (Join-Path $repo "target\release\build_bc45_libs.exe") --target win64
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
