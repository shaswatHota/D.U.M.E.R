# scripts/ci.ps1 — D.U.M.E.R CI Check Script
# Runs: cargo fmt --check, cargo clippy -- -D warnings, cargo test, cargo deny check, cargo audit

$ErrorActionPreference = "Stop"

# Ensure Cargo bin and 64-bit MinGW directories are in process PATH if present
$cargoBin = "$HOME\.cargo\bin"
if (Test-Path $cargoBin) {
    if ($env:PATH -split ';' -notcontains $cargoBin) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
}

$mingw64 = "C:\Users\ASUS\Downloads\gcc-16.1.0-gdb-17.2.90.20260510-binutils-2.46.0-mingw-w64-v14.0.0-ucrt\bin"
if (Test-Path $mingw64) {
    $env:PATH = "$mingw64;$($env:PATH -replace 'C:\\MinGW\\bin;?','')"
    $env:CC = "$mingw64\gcc.exe"
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   D.U.M.E.R CI Check Suite (PowerShell)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

$cargoCmd = Get-Command cargo -ErrorAction SilentlyContinue

if (-not $cargoCmd) {
    Write-Warning "[CI WARNING] 'cargo' is not installed or not found in PATH."
    Write-Warning "[CI WARNING] Skipping all cargo-dependent CI checks (fmt, clippy, test, deny, audit)."
    Write-Host "`nCI finished with warnings (tools not installed)." -ForegroundColor Yellow
    exit 0
}

Write-Host "Using cargo at: $($cargoCmd.Source)" -ForegroundColor Green

# 1. cargo fmt --check
Write-Host "`n--- [1/5] Checking code formatting (cargo fmt --check) ---" -ForegroundColor Cyan
$hasFmt = $false
try {
    $null = & cargo fmt --version 2>&1
    if ($LASTEXITCODE -eq 0) { $hasFmt = $true }
} catch {}

if ($hasFmt) {
    & cargo fmt --check
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[CI FAILURE] 'cargo fmt --check' failed."
        exit $LASTEXITCODE
    }
    Write-Host "[PASS] cargo fmt --check" -ForegroundColor Green
} else {
    Write-Warning "[CI WARNING] 'cargo fmt' component is not installed. Skipping formatting check."
}

# 2. cargo clippy -- -D warnings
Write-Host "`n--- [2/5] Running linter (cargo clippy -- -D warnings) ---" -ForegroundColor Cyan
$hasClippy = $false
try {
    $null = & cargo clippy --version 2>&1
    if ($LASTEXITCODE -eq 0) { $hasClippy = $true }
} catch {}

if ($hasClippy) {
    & cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[CI FAILURE] 'cargo clippy' failed with warnings/errors."
        exit $LASTEXITCODE
    }
    Write-Host "[PASS] cargo clippy" -ForegroundColor Green
} else {
    Write-Warning "[CI WARNING] 'cargo clippy' component is not installed. Skipping clippy check."
}

# 3. cargo test
Write-Host "`n--- [3/5] Running tests (cargo test) ---" -ForegroundColor Cyan
& cargo test --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Error "[CI FAILURE] 'cargo test' failed."
    exit $LASTEXITCODE
}
Write-Host "[PASS] cargo test" -ForegroundColor Green

# 4. cargo deny check
Write-Host "`n--- [4/5] Checking dependencies and licenses (cargo deny check) ---" -ForegroundColor Cyan
$hasDeny = $false
try {
    $null = & cargo deny --version 2>&1
    if ($LASTEXITCODE -eq 0) { $hasDeny = $true }
} catch {}

if ($hasDeny) {
    & cargo deny check
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[CI FAILURE] 'cargo deny check' failed."
        exit $LASTEXITCODE
    }
    Write-Host "[PASS] cargo deny check" -ForegroundColor Green
} else {
    Write-Warning "[CI WARNING] 'cargo-deny' is not installed. Skipping dependency/license checks."
}

# 5. cargo audit
Write-Host "`n--- [5/5] Checking security advisories (cargo audit) ---" -ForegroundColor Cyan
$hasAudit = $false
try {
    $null = & cargo audit --version 2>&1
    if ($LASTEXITCODE -eq 0) { $hasAudit = $true }
} catch {}

if ($hasAudit) {
    & cargo audit
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[CI FAILURE] 'cargo audit' failed."
        exit $LASTEXITCODE
    }
    Write-Host "[PASS] cargo audit" -ForegroundColor Green
} else {
    Write-Warning "[CI WARNING] 'cargo-audit' is not installed. Skipping vulnerability advisory check."
}

Write-Host "`n==================================================" -ForegroundColor Green
Write-Host "   CI SUITE COMPLETE: ALL ACTIVE CHECKS PASSED" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
exit 0
