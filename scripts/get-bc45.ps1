# Download Borland C++ 4.52 and install its BC45 tree for build_bc45_libs.
#
# build_bc45_libs and the BC4.52 oracle suites need the original BC4.52 tree
# (INCLUDE, LIB, BIN and the OWL/CLASSLIB/RTL SOURCE). It is third-party and
# copyrighted, so it is never committed; this script fetches it on request.
#
# Source: the WinWorld "Borland C++ 4.52" archive, a 7z holding the run-from-CD
# ISO. The BC45 directory on that CD is a plain, uncompressed tree, so the
# script extracts it directly with 7-Zip; no installer runs. The archive is
# pinned by SHA-256 and refused on mismatch.
#
# Borland C++ is still copyrighted. Running this script, and the terms under
# which you use what it downloads, are your choice.
#
# Steps: download (or take -Archive) -> verify SHA-256 -> extract BC45 into
# -Dest -> check the directories the build needs -> run build-mdbcc.ps1 (the
# toolchain plus the Win32 and Win64 libraries) unless -SkipLibs.
# An existing, valid -Dest is left untouched and the download is skipped.
#
# Needs 7-Zip (7z.exe on PATH or in Program Files).
#
# Usage:  pwsh -NoProfile -File scripts/get-bc45.ps1
#         pwsh -NoProfile -File scripts/get-bc45.ps1 -Archive "D:\dl\Borland C++ 4.52.7z"
#         pwsh -NoProfile -File scripts/get-bc45.ps1 -Dest C:\tmp\bc45 -SkipLibs
param(
    [string]$Archive,
    [string]$Dest,
    [switch]$SkipLibs
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest is far slower with the progress bar

$repo = Split-Path -Parent $PSScriptRoot
if (-not $Dest) { $Dest = Join-Path $repo "wrk_oracle\bc452\BC45" }
$Dest = [System.IO.Path]::GetFullPath($Dest)

$sha256 = "C1E3FEF9D80C293F07C561675856705BB4CCE69106FB7E256C64317E85EBEDED"
$mirrors = @(
    "https://dl.winworldpc.com/Abandonware%20Applications/PC/Borland%20C++%204.52.7z",
    "https://dl-alt1.winworldpc.com/Abandonware%20Applications/PC/Borland%20C++%204.52.7z"
)
# What build_bc45_libs and the oracle suites read from the tree.
$required = @("INCLUDE\OWL", "LIB", "BIN\BCC32.EXE", "SOURCE\OWL", "SOURCE\CLASSLIB",
              "SOURCE\RTL\SOURCE\IOSTREAM", "SOURCE\RTL\RTLINC")

function Test-Bc45Tree([string]$root) {
    foreach ($rel in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $rel))) { return $rel }
    }
    return $null
}

function Find-7Zip {
    $cmd = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($dir in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($dir -and (Test-Path -LiteralPath (Join-Path $dir "7-Zip\7z.exe"))) {
            return Join-Path $dir "7-Zip\7z.exe"
        }
    }
    throw "7-Zip not found. Install it (e.g. 'winget install 7zip.7zip') and re-run."
}

function Invoke-7Zip([string]$sevenZip, [string[]]$arguments) {
    & $sevenZip @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z $($arguments -join ' ') failed (exit $LASTEXITCODE)" }
}

function Invoke-Libs {
    if ($SkipLibs) { return }
    # build_bc45_libs resolves MDBCC_BC45_ROOT first, so a non-default -Dest still wins.
    $env:MDBCC_BC45_ROOT = $Dest
    & pwsh -NoProfile -File (Join-Path $PSScriptRoot "build-mdbcc.ps1")
    if ($LASTEXITCODE -ne 0) { throw "build-mdbcc.ps1 failed (exit $LASTEXITCODE)" }
    foreach ($sub in @("", "win64")) {
        foreach ($lib in @("mdowl", "mdstreams", "mdcw32", "mdbids")) {
            $path = Join-Path (Join-Path $repo "target\bc45-libs\$sub") "$lib.lib"
            if (-not (Test-Path -LiteralPath $path)) { throw "expected library missing: $path" }
        }
    }
    Write-Host "Libraries built under $(Join-Path $repo 'target\bc45-libs')."
}

if (Test-Path -LiteralPath $Dest) {
    $missing = Test-Bc45Tree $Dest
    if ($missing) {
        throw "$Dest exists but lacks $missing. Move it aside (or pass -Dest) and re-run."
    }
    Write-Host "BC4.52 tree already present at $Dest; skipping download."
    Invoke-Libs
    exit 0
}

$sevenZip = Find-7Zip
$work = Join-Path ([System.IO.Path]::GetTempPath()) "mdbcc-bc45-$([guid]::NewGuid().ToString('N'))"
# Stage beside -Dest so the final Move-Item is a same-volume rename (it cannot move a directory across volumes).
$stage = "$Dest.partial-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $work | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Dest) | Out-Null
try {
    if ($Archive) {
        $Archive = (Resolve-Path -LiteralPath $Archive).Path
    } else {
        $download = Join-Path $work "bc452.7z"
        foreach ($url in $mirrors) {
            Write-Host "Downloading $url"
            try {
                Invoke-WebRequest -Uri $url -OutFile $download -UserAgent "mdbcc-get-bc45" -TimeoutSec 900
                $Archive = $download
                break
            } catch {
                Write-Warning "Download failed: $($_.Exception.Message)"
            }
        }
        if (-not $Archive) { throw "All mirrors failed. Download the archive yourself and pass -Archive." }
    }

    $actual = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash
    if ($actual -ne $sha256) {
        throw "SHA-256 mismatch for ${Archive}: expected $sha256, got $actual"
    }

    Write-Host "Extracting the CD image..."
    Invoke-7Zip $sevenZip @("e", "-y", "-o$work", $Archive, "Borland C++ 4.52\BCPP4_52.ISO")
    Invoke-7Zip $sevenZip @("x", "-y", "-o$stage", (Join-Path $work "BCPP4_52.ISO"), "BC45")
    $tree = Join-Path $stage "BC45"
    $missing = Test-Bc45Tree $tree
    if ($missing) { throw "Extracted tree lacks $missing; the archive layout is not the expected one." }

    # ISO9660 files come out read-only; clear that so the tree can be edited or removed later.
    Get-ChildItem -LiteralPath $tree -Recurse -File | Where-Object IsReadOnly | ForEach-Object { $_.IsReadOnly = $false }

    Move-Item -LiteralPath $tree -Destination $Dest
    Write-Host "Installed BC4.52 tree at $Dest."
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
}

Invoke-Libs
