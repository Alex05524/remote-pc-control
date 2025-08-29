$ErrorActionPreference = "Stop"

function Remove-DirForce([string]$path) {
    if (-not (Test-Path $path)) { return }
    try { cmd /c "attrib -r -s -h `"$path\*`" /s /d" | Out-Null } catch {}
    for ($i=0; $i -lt 8; $i++) {
        try {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
            return
        } catch {
            Start-Sleep -Milliseconds 500
            try { cmd /c "rmdir /s /q `"$path`"" | Out-Null } catch {}
            if (-not (Test-Path $path)) { return }
        }
    }
    Write-Warning ("Could not remove: {0}. Close files and retry." -f $path)
}

# В корень проекта
Set-Location "$PSScriptRoot\.."

[Console]::InputEncoding  = [System.Text.UTF8Encoding]::new()
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

# Пути
$root     = Get-Location
$distDir  = Join-Path $root "dist"
$buildDir = Join-Path $root "build"
$target   = Join-Path $root "rpc-agent.exe"

# Предчистка, чтобы cx_Freeze не спотыкался об «cannot be cleaned»
Remove-DirForce $distDir
Remove-DirForce $buildDir
if (Test-Path $target) { Remove-Item -LiteralPath $target -Force }

# 1) Build cx_Freeze в .\dist
python -m pip install --upgrade pip
python -m pip install --upgrade cx_Freeze==7.2.* pystray pillow mss pyautogui psutil websockets pywin32
python .\scripts\setup_agent_cxfreeze.py build_exe --build-exe .\dist

# Проверим результат сборки
$agentExe = Join-Path $distDir "rpc-agent.exe"
if (-not (Test-Path $agentExe)) {
    Write-Error ("Built exe not found: {0}" -f $agentExe)
    exit 1
}

# 2) Найдём 7-Zip
$sevenZipBase = "${env:ProgramFiles}\7-Zip"
if (-not (Test-Path $sevenZipBase)) { $sevenZipBase = "${env:ProgramFiles(x86)}\7-Zip" }
$sevenExe = Join-Path $sevenZipBase "7z.exe"
$sevenSfx = Join-Path $sevenZipBase "7z.sfx"
if (-not (Test-Path $sevenExe) -or -not (Test-Path $sevenSfx)) {
    Write-Error "7-Zip not found. Install: winget install -e --id 7zip.7zip"
    exit 1
}

# 3) Создадим payload.7z из содержимого dist
$payload = Join-Path $distDir "payload.7z"
if (Test-Path $payload) { Remove-Item -LiteralPath $payload -Force }
& $sevenExe a -t7z -mx=9 -mmt=on "$payload" "$distDir\*" | Out-Null

# 4) Соберём один portable EXE: SFX + config + payload
$sfxConfig = Join-Path $root "scripts\sfx_config.txt"
if (-not (Test-Path $sfxConfig)) {
@"
;!@Install@!UTF-8!
Title="RPC Agent"
RunProgram="rpc-agent.exe"
;!@InstallEnd@!
"@ | Set-Content -LiteralPath $sfxConfig -Encoding UTF8
}
if (Test-Path $target) { Remove-Item -LiteralPath $target -Force }

$cmd = 'copy /b "{0}"+"{1}"+"{2}" "{3}"' -f $sevenSfx, $sfxConfig, $payload, $target
cmd /c $cmd | Out-Null

# 5) Очистка
Remove-DirForce $distDir
Remove-DirForce $buildDir

Write-Host ("Done. Final portable exe: {0}" -f $target)