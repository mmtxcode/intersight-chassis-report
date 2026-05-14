#Requires -Version 5.1
<#
.SYNOPSIS
    Launcher for the Intersight chassis inventory report.

.DESCRIPTION
    Runs four preflight checks (Python interpreter, virtual environment,
    .env file, API connection) before presenting an interactive menu.
    On preflight failure the launcher reports the specific issue and
    exits non-zero; on success it captures the Intersight account name
    so the menu can use it in output filenames.

.NOTES
    Compatible with Windows PowerShell 5.1 (built into Windows 10/11)
    and PowerShell 7+. On macOS / Linux use intersight-report.sh instead.
#>

# Keep going past non-fatal errors from external commands; we check
# $LASTEXITCODE explicitly where it matters.
$ErrorActionPreference = 'Continue'

# ---------- Constants ----------
$ScriptDir       = $PSScriptRoot
$VenvDir         = Join-Path $ScriptDir '.venv'
$VenvPython      = Join-Path $VenvDir  'Scripts\python.exe'
$VenvPip         = Join-Path $VenvDir  'Scripts\pip.exe'
$EnvFile         = Join-Path $ScriptDir '.env'
$ReqsFile        = Join-Path $ScriptDir 'requirements.txt'
$ReportScript    = Join-Path $ScriptDir 'chassis_report.py'
$PreflightScript = Join-Path $ScriptDir 'preflight.py'
$MinPyMajor      = 3
$MinPyMinor      = 10

# Script-scoped state filled in by preflight steps.
$script:HostPython     = $null
$script:HostPythonArgs = @()
$script:AccountName    = $null

# ---------- Output helpers ----------
function Write-Heading([string]$Text) {
    Write-Host ""
    Write-Host $Text -ForegroundColor Cyan
}
function Write-Ok([string]$Text)   { Write-Host "  [OK] $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "  [!]  $Text" -ForegroundColor Yellow }
function Write-Err([string]$Text)  { Write-Host "  [X]  $Text" -ForegroundColor Red }

# ---------- Preflight 1: locate Python ----------
function Find-PythonInterpreter {
    Write-Heading "[1/4] Locating Python $MinPyMajor.$MinPyMinor+ interpreter"

    # Try the Windows Python launcher (`py`) first — it's the most reliable
    # way to pick a specific version on Windows. Fall back to plain `python`
    # / `python3` if `py` isn't installed.
    $candidates = @(
        @{ Cmd = 'py';      Args = @('-3.13') }
        @{ Cmd = 'py';      Args = @('-3.12') }
        @{ Cmd = 'py';      Args = @('-3.11') }
        @{ Cmd = 'py';      Args = @('-3.10') }
        @{ Cmd = 'python';  Args = @() }
        @{ Cmd = 'python3'; Args = @() }
    )

    foreach ($c in $candidates) {
        if (-not (Get-Command $c.Cmd -ErrorAction SilentlyContinue)) {
            continue
        }

        $checkArgs = $c.Args + @('-c', "import sys; sys.exit(0 if sys.version_info >= ($MinPyMajor, $MinPyMinor) else 1)")
        & $c.Cmd @checkArgs 2>$null
        if ($LASTEXITCODE -ne 0) { continue }

        $verArgs = $c.Args + @('-c', "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
        $ver = & $c.Cmd @verArgs 2>$null

        $script:HostPython     = $c.Cmd
        $script:HostPythonArgs = $c.Args

        $display = if ($c.Args.Count -gt 0) { "$($c.Cmd) $($c.Args -join ' ')" } else { $c.Cmd }
        Write-Ok "Using $display (Python $ver)"
        return $true
    }

    Write-Err "No Python $MinPyMajor.$MinPyMinor+ found in PATH."
    Write-Err "Install from https://www.python.org/ and ensure 'Add to PATH' is selected during install, then retry."
    return $false
}

# ---------- Preflight 2: build/refresh venv ----------
function Initialize-Venv {
    Write-Heading "[2/4] Preparing virtual environment"

    if (-not (Test-Path $VenvDir)) {
        Write-Host "  Creating venv at $VenvDir ..."
        $createArgs = $script:HostPythonArgs + @('-m', 'venv', $VenvDir)
        & $script:HostPython @createArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to create virtual environment."
            return $false
        }
    }

    if (-not (Test-Path $VenvPip)) {
        Write-Err "pip not found inside venv at $VenvPip"
        return $false
    }

    Write-Host "  Installing dependencies from requirements.txt ..."
    & $VenvPip install --quiet --disable-pip-version-check --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Could not upgrade pip (continuing with existing version)."
    }
    & $VenvPip install --quiet --disable-pip-version-check -r $ReqsFile
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to install dependencies."
        return $false
    }

    Write-Ok "Dependencies installed"
    return $true
}

# ---------- Preflight 3: .env file ----------
function Test-EnvFile {
    Write-Heading "[3/4] Checking .env file"

    if (-not (Test-Path $EnvFile)) {
        Write-Err ".env not found at $EnvFile"
        Write-Err "Copy .env.example to .env and fill in INTERSIGHT_API_KEY_ID"
        Write-Err "and INTERSIGHT_API_KEY_FILE before re-running."
        return $false
    }

    Write-Ok ".env present"
    return $true
}

# ---------- Preflight 4: API connection ----------
function Test-IntersightConnection {
    Write-Heading "[4/4] Testing Intersight connection"

    # ProcessStartInfo gives us clean separation of stdout (account name on
    # success) and stderr (specific diagnostic on failure). PowerShell's
    # `& cmd 2>&1` merges them, which would make it hard to distinguish.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $VenvPython
    $psi.Arguments              = "`"$PreflightScript`""
    $psi.WorkingDirectory       = $ScriptDir
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($proc.ExitCode -eq 0) {
        $script:AccountName = $stdout.Trim()
        Write-Ok "Connected. Account: $($script:AccountName)"
        return $true
    } else {
        Write-Err $stderr.Trim()
        return $false
    }
}

# ---------- Helper: sanitize the account name for a filename ----------
function Get-SafeFilename([string]$Name) {
    return ($Name -replace '[^A-Za-z0-9._-]', '-')
}

# ---------- Chassis-report submenu ----------
function Show-ChassisInventoryMenu {
    $safeName = Get-SafeFilename $script:AccountName
    $baseName = "$safeName-chassis-report"
    $csvPath  = Join-Path $ScriptDir "$baseName.csv"
    $pdfPath  = Join-Path $ScriptDir "$baseName.pdf"

    while ($true) {
        Write-Host ""
        Write-Host "===== Chassis Inventory Report =====" -ForegroundColor White
        Write-Host "  Account     : $($script:AccountName)"
        Write-Host "  Output dir  : $ScriptDir"
        Write-Host "  File prefix : $baseName"
        Write-Host ""
        Write-Host "  1) Generate CSV"
        Write-Host "  2) Generate PDF"
        Write-Host "  3) Generate both"
        Write-Host "  0) Back to main menu"
        Write-Host ""
        $choice = Read-Host "Choose"

        switch ($choice) {
            '1' {
                Write-Host ""
                & $VenvPython $ReportScript --format csv -o $csvPath
                [void](Read-Host "`nPress Enter to continue")
            }
            '2' {
                Write-Host ""
                & $VenvPython $ReportScript --format pdf -o $pdfPath
                [void](Read-Host "`nPress Enter to continue")
            }
            '3' {
                Write-Host ""
                & $VenvPython $ReportScript --format csv -o $csvPath
                & $VenvPython $ReportScript --format pdf -o $pdfPath
                [void](Read-Host "`nPress Enter to continue")
            }
            '0' { return }
            default { Write-Warn "Invalid choice: '$choice'" }
        }
    }
}

# ---------- Main menu ----------
function Show-MainMenu {
    while ($true) {
        Write-Host ""
        Write-Host "===== Intersight Reports =====" -ForegroundColor White
        Write-Host "  1) Chassis Inventory Report"
        Write-Host "  0) Exit"
        Write-Host ""
        $choice = Read-Host "Choose"

        switch ($choice) {
            '1' { Show-ChassisInventoryMenu }
            '0' {
                Write-Host ""
                Write-Host "Goodbye."
                return
            }
            default { Write-Warn "Invalid choice: '$choice'" }
        }
    }
}

# ---------- Entry point ----------
Set-Location $ScriptDir

Write-Host ""
Write-Host "--- Intersight Report Launcher ---" -ForegroundColor Cyan

if (-not (Find-PythonInterpreter))    { exit 1 }
if (-not (Initialize-Venv))           { exit 1 }
if (-not (Test-EnvFile))              { exit 1 }
if (-not (Test-IntersightConnection)) { exit 1 }

Show-MainMenu
