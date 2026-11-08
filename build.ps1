$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Build = Join-Path $Root "build"
New-Item -ItemType Directory -Force -Path $Build | Out-Null
$imgDir = Join-Path $Build "image"
New-Item -ItemType Directory -Force -Path $imgDir | Out-Null
$logoSrc = Join-Path $Root "image/logo.jpg"
if (Test-Path $logoSrc) { Copy-Item $logoSrc (Join-Path $imgDir "logo.jpg") -Force }

$common = @("-O2", "-DSNIFFER_STATIC", "-I$Root/core")
$sources = @(
    "$Root/core/sniffer_core.c",
    "$Root/core/sniffer_parse.c",
    "$Root/core/sniffer_wpcap.c",
    "$Root/core/sniffer_util.c",
    "$Root/core/sniffer_console.c",
    "$Root/core/sniffer_insight.c",
    "$Root/core/sniffer_winproc.c",
    "$Root/asm/sniffer_x86.S"
)

$objs = @()
$i = 0
foreach ($src in $sources) {
    $obj = Join-Path $Build "obj_$i.o"
    & gcc @common -c $src -o $obj
    if ($LASTEXITCODE -ne 0) { throw "Compilation échouée: $src" }
    $objs += $obj
    $i++
}

$lib = Join-Path $Build "libsniffer_core.a"
& ar rcs $lib @objs
if ($LASTEXITCODE -ne 0) { throw "ar a échoué" }

& gcc -O2 -o (Join-Path $Build "sniffer_cli.exe") "$Root/cli/main.c" @common $lib -lws2_32
if ($LASTEXITCODE -ne 0) { throw "CLI échouée" }

$guiExe = Join-Path $Build "sniffer_gui.exe"
$guiNew = Join-Path $Build "sniffer_gui.new.exe"
$ErrorActionPreference = "Continue"
& taskkill /F /IM sniffer_gui.exe /T 2>$null | Out-Null
$ErrorActionPreference = "Stop"
foreach ($name in @("sniffer_gui", "SnifferGuiPro")) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 600

$guiOk = $false
& gcc -O2 -municode -mwindows -o $guiNew "$Root/gui_c/sniffer_gui.c" @common $lib -lws2_32 -lcomctl32 -lgdi32 -luxtheme -ldwmapi -liphlpapi -lpsapi -lshell32 -lgdiplus
if ($LASTEXITCODE -eq 0) {
    try {
        if (Test-Path $guiExe) { Remove-Item -Force $guiExe -ErrorAction Stop }
        Rename-Item -Path $guiNew -NewName "sniffer_gui.exe" -Force
        $guiOk = $true
    } catch {
        Write-Host "GUI: impossible de remplacer sniffer_gui.exe (fermez la fenêtre Sniffer puis relancez build.ps1)." -ForegroundColor Yellow
        if (Test-Path $guiNew) {
            Write-Host "  Binaire alternatif: $guiNew" -ForegroundColor Yellow
            $guiOk = $true
        }
    }
}
if (-not $guiOk) { throw "GUI Win32 échouée (compile ou fichier verrouillé)" }

& gcc -O2 -o (Join-Path $Build "sniffer_tui.exe") "$Root/gui_tui/sniffer_tui.c" @common $lib -lws2_32
if ($LASTEXITCODE -ne 0) { throw "TUI échouée" }

$guiV = Join-Path $Build "sniffer_gui_v.exe"
Push-Location (Join-Path $Root "gui")
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& v -cc gcc -o $guiV -cflags "-I$Root/core -DSNIFFER_STATIC" -ldflags "$lib -lws2_32" main.v 2>$null | Out-Null
$ErrorActionPreference = $prevEap
if ($LASTEXITCODE -eq 0) {
    Write-Host "GUI V compilée: $guiV" -ForegroundColor Cyan
} else {
    Write-Host "GUI V ignorée (mettre a jour v.exe / vlib avec makev.bat)." -ForegroundColor Yellow
}
Pop-Location

Write-Host ""
Write-Host "Build OK:" -ForegroundColor Green
Write-Host "  $lib"
Write-Host "  $(Join-Path $Build 'sniffer_cli.exe')"
Write-Host "  $(Join-Path $Build 'sniffer_gui.exe')"
Write-Host "  $(Join-Path $Build 'sniffer_tui.exe')"
Write-Host ""
Write-Host "GUI:  .\run_gui.ps1   (ou build\sniffer_gui.exe en admin)"
Write-Host "TUI:  build\sniffer_tui.exe"
