$build = Join-Path $PSScriptRoot "build"
$exe = Join-Path $build "sniffer_gui.exe"
$exeNew = Join-Path $build "sniffer_gui.new.exe"
if ((Test-Path $exeNew) -and (!(Test-Path $exe) -or (Get-Item $exeNew).LastWriteTime -gt (Get-Item $exe).LastWriteTime)) {
    $exe = $exeNew
}
$tui = Join-Path $PSScriptRoot "build\sniffer_tui.exe"

if (-not (Test-Path $exe)) {
    Write-Host "Compilation requise: .\build.ps1" -ForegroundColor Yellow
    exit 1
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host "Relance en administrateur (capture Npcap)..." -ForegroundColor Cyan
    Start-Process -FilePath $exe -Verb RunAs
    exit
}

Start-Process -FilePath $exe
