#Requires -Version 5.0
<#
.SYNOPSIS
    Deploy ArmorPilot on Windows — one script, no prerequisites.

.DESCRIPTION
    Copies ArmorPilot.exe to an install directory, sets up kubeconfig,
    writes ArmorPilot.env, creates a desktop shortcut, and optionally
    registers an auto-start scheduled task (runs as SYSTEM at boot).

.PARAMETER ExePath
    Path to ArmorPilot.exe.  Defaults to ArmorPilot.exe in the same
    folder as this script, then .\dist\ArmorPilot.exe, then .\ArmorPilot.exe.

.PARAMETER InstallDir
    Installation directory.  Default: C:\ArmorPilot

.PARAMETER KubeConfig
    Path to kubeconfig.  Default: %USERPROFILE%\.kube\config

.PARAMETER Port
    Port the web server listens on.  Default: 5000

.PARAMETER BindHost
    Bind address.  Default: 0.0.0.0 (all interfaces)

.PARAMETER AutoStart
    Register a scheduled task to start ArmorPilot at system boot
    (runs as SYSTEM — no user login required).

.PARAMETER Uninstall
    Remove the scheduled task and optionally delete the install directory.

.EXAMPLE
    # Basic install (interactive prompts for credentials)
    .\deploy_windows.ps1

.EXAMPLE
    # Install + auto-start at boot
    .\deploy_windows.ps1 -ExePath .\ArmorPilot.exe -AutoStart

.EXAMPLE
    # Custom port and explicit kubeconfig
    .\deploy_windows.ps1 -Port 8080 -KubeConfig C:\k8s\config -AutoStart
#>

param(
    [string]$ExePath    = "",
    [string]$InstallDir = "C:\ArmorPilot",
    [string]$KubeConfig = "",
    [string]$Port       = "5000",
    [string]$BindHost   = "0.0.0.0",
    [switch]$AutoStart,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# ─── colour helpers ───────────────────────────────────────────────────────────
function ok   { param($m) Write-Host "[OK]   $m" -ForegroundColor Green  }
function warn { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function info { param($m) Write-Host "==> $m"    -ForegroundColor Cyan   }
function fail { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ArmorPilot Windows Deployment" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ─── Uninstall path ───────────────────────────────────────────────────────────
if ($Uninstall) {
    $TaskName = "ArmorPilot"
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        ok "Removed scheduled task '$TaskName'."
    } catch {
        warn "Scheduled task not found or already removed."
    }
    $choice = Read-Host "Delete install directory $InstallDir? [y/N]"
    if ($choice -match '^[Yy]$') {
        if (Test-Path $InstallDir) {
            Remove-Item $InstallDir -Recurse -Force
            ok "Deleted $InstallDir"
        }
    }
    Write-Host ""
    ok "Uninstall complete."
    exit 0
}

# ─── Locate exe ───────────────────────────────────────────────────────────────
if (-not $ExePath) {
    $candidates = @(
        (Join-Path $ScriptDir  "ArmorPilot.exe"),
        (Join-Path $ScriptDir  "..\dist\ArmorPilot.exe"),
        (Join-Path $PWD        "ArmorPilot.exe"),
        (Join-Path $PWD        "dist\ArmorPilot.exe")
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $ExePath = (Resolve-Path $c).Path; break }
    }
}
if (-not $ExePath -or -not (Test-Path $ExePath)) {
    fail "ArmorPilot.exe not found.`n  Provide the path:  .\deploy_windows.ps1 -ExePath C:\path\to\ArmorPilot.exe"
}
ok "Exe: $ExePath"

# ─── Create install directory ─────────────────────────────────────────────────
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    ok "Created: $InstallDir"
} else {
    ok "Install dir: $InstallDir"
}

# ─── Copy exe ─────────────────────────────────────────────────────────────────
$DestExe = Join-Path $InstallDir "ArmorPilot.exe"
Copy-Item $ExePath $DestExe -Force
ok "Copied exe to: $DestExe"

# ─── Kubeconfig ───────────────────────────────────────────────────────────────
$DefaultKube = Join-Path $env:USERPROFILE ".kube\config"
if (-not $KubeConfig -and (Test-Path $DefaultKube)) {
    $KubeConfig = $DefaultKube
    ok "Found kubeconfig: $KubeConfig"
}
if (-not $KubeConfig) {
    Write-Host ""
    warn "No kubeconfig found at $DefaultKube"
    $KubeConfig = Read-Host "  Path to kubeconfig (leave blank to skip)"
}

$EnvKubeLine = ""
if ($KubeConfig -and (Test-Path $KubeConfig)) {
    $KubeDestDir = Join-Path $InstallDir ".kube"
    New-Item -ItemType Directory -Force -Path $KubeDestDir | Out-Null
    $KubeDest = Join-Path $KubeDestDir "config"
    Copy-Item $KubeConfig $KubeDest -Force
    ok "Kubeconfig -> $KubeDest"
    $EnvKubeLine = "KUBECONFIG=$KubeDest"
} else {
    warn "Kubeconfig skipped — policy features unavailable until KUBECONFIG is set in ArmorPilot.env"
}

# ─── First-run credentials ────────────────────────────────────────────────────
$EnvFile    = Join-Path $InstallDir "ArmorPilot.env"
$AdminUser  = ""
$AdminPass  = ""

if (-not (Test-Path $EnvFile)) {
    Write-Host ""
    info "First-run setup: create the initial admin account."
    Write-Host "  (These values are written to ArmorPilot.env and used on first start.)" -ForegroundColor DarkGray
    Write-Host ""

    do {
        $AdminUser = Read-Host "  Admin username"
        if (-not $AdminUser) { Write-Host "  Username cannot be empty." -ForegroundColor Red }
    } while (-not $AdminUser)

    do {
        $SecPass  = Read-Host "  Admin password (min 12 chars)" -AsSecureString
        $AdminPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecPass))
        if ($AdminPass.Length -lt 12) {
            Write-Host "  Password must be at least 12 characters." -ForegroundColor Red
        }
    } while ($AdminPass.Length -lt 12)
    Write-Host ""
}

# ─── Write ArmorPilot.env ─────────────────────────────────────────────────────
$EnvContent = @(
    "# ArmorPilot configuration — generated by deploy_windows.ps1",
    "HOST=$BindHost",
    "PORT=$Port"
)
if ($EnvKubeLine)  { $EnvContent += $EnvKubeLine }
if ($AdminUser)    { $EnvContent += "ADMIN_USER=$AdminUser" }
if ($AdminPass)    { $EnvContent += "ADMIN_PASS=$AdminPass" }

$EnvContent | Set-Content -Path $EnvFile -Encoding utf8

# Restrict env file to current user only (remove inherited permissions)
try {
    $Acl = Get-Acl $EnvFile
    $Acl.SetAccessRuleProtection($true, $false)
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $CurrentUser, "FullControl", "Allow")
    $Acl.SetAccessRule($Rule)
    Set-Acl $EnvFile $Acl
} catch {
    warn "Could not restrict env file permissions: $_"
}
ok "Config written: $EnvFile"

# ─── Desktop shortcut ─────────────────────────────────────────────────────────
try {
    $WshShell  = New-Object -ComObject WScript.Shell
    $LnkPath   = Join-Path ([Environment]::GetFolderPath("Desktop")) "ArmorPilot.lnk"
    $Shortcut  = $WshShell.CreateShortcut($LnkPath)
    $Shortcut.TargetPath        = $DestExe
    $Shortcut.WorkingDirectory  = $InstallDir
    $Shortcut.Description       = "ArmorPilot — Kubernetes Security Console"
    $Shortcut.Save()
    ok "Desktop shortcut created."
} catch {
    warn "Could not create desktop shortcut: $_"
}

# ─── Scheduled task (auto-start at boot, runs as SYSTEM) ──────────────────────
if ($AutoStart) {
    $TaskName = "ArmorPilot"
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}

    $Action    = New-ScheduledTaskAction -Execute $DestExe -WorkingDirectory $InstallDir
    $Trigger   = New-ScheduledTaskTrigger -AtStartup
    $Settings  = New-ScheduledTaskSettingsSet `
                    -ExecutionTimeLimit 0 `
                    -RestartCount 3 `
                    -RestartInterval (New-TimeSpan -Minutes 1) `
                    -StartWhenAvailable $true
    $Principal = New-ScheduledTaskPrincipal `
                    -UserId "SYSTEM" `
                    -RunLevel Highest `
                    -LogonType ServiceAccount

    Register-ScheduledTask `
        -TaskName   $TaskName `
        -Action     $Action `
        -Trigger    $Trigger `
        -Settings   $Settings `
        -Principal  $Principal `
        -Description "ArmorPilot Kubernetes Security Console" `
        -Force | Out-Null

    ok "Scheduled task '$TaskName' registered (starts at boot, runs as SYSTEM)."
}

# ─── Summary ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Deployment complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install dir : $InstallDir"
Write-Host "  Config file : $EnvFile"
Write-Host "  URL         : http://localhost:$Port"
Write-Host ""
if ($AutoStart) {
    Write-Host "  Auto-start  : enabled (Task Scheduler / SYSTEM)" -ForegroundColor Green
    Write-Host "  To start now without rebooting:" -ForegroundColor Cyan
    Write-Host "    Start-ScheduledTask -TaskName ArmorPilot"
} else {
    Write-Host "  To start ArmorPilot:" -ForegroundColor Cyan
    Write-Host "    $DestExe"
    Write-Host ""
    Write-Host "  For auto-start at boot, re-run with -AutoStart" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  To edit settings after install:" -ForegroundColor DarkGray
Write-Host "    notepad $EnvFile" -ForegroundColor DarkGray
Write-Host "  To uninstall:" -ForegroundColor DarkGray
Write-Host "    .\deploy_windows.ps1 -Uninstall" -ForegroundColor DarkGray
Write-Host ""

# ─── Optional: launch now ─────────────────────────────────────────────────────
$Launch = Read-Host "Launch ArmorPilot now? [Y/n]"
if ($Launch -match '^[Yy]?$') {
    Start-Process $DestExe -WorkingDirectory $InstallDir
    ok "ArmorPilot started. Open http://localhost:$Port"
}
