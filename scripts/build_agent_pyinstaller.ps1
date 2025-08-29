$ErrorActionPreference = "Stop"

$root    = Resolve-Path "$PSScriptRoot\.."
$agentPy = Join-Path $root "agent\agent.py"
$distDir = Join-Path $root "dist"
$workDir = Join-Path $root "build\pyinstaller"
$webDir  = Join-Path $root "server\web\agent"

python -m pip install --upgrade pip
python -m pip install --upgrade pyinstaller

# Удаляем конфликтующий бэкпорт pathlib (если установлен)
python -m pip uninstall -y pathlib 2>$null | Out-Null

# Чистка
if (Test-Path $workDir) { Remove-Item -Recurse -Force $workDir }
if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Force -Path $distDir | Out-Null }
if (-not (Test-Path $webDir))  { New-Item -ItemType Directory -Force -Path $webDir  | Out-Null }

# 1) Тихий exe (без консоли)
pyinstaller `
  --noconfirm --clean `
  --onefile --windowed `
  --name rpc-agent `
  --distpath "$distDir" `
  --workpath "$workDir" `
  --hidden-import http `
  --hidden-import websockets `
  --hidden-import websockets.asyncio `
  --hidden-import websockets.client `
  --hidden-import PIL.Image `
  --hidden-import pystray._win32 `
  --hidden-import win32api `
  --hidden-import win32con `
  --hidden-import win32gui `
  "$agentPy"

# 2) Консольный exe для отладки
pyinstaller `
  --noconfirm --clean `
  --onefile --console `
  --name rpc-agent-console `
  --distpath "$distDir" `
  --workpath "$workDir" `
  --hidden-import http `
  --hidden-import websockets `
  --hidden-import websockets.asyncio `
  --hidden-import websockets.client `
  --hidden-import PIL.Image `
  --hidden-import pystray._win32 `
  --hidden-import win32api `
  --hidden-import win32con `
  --hidden-import win32gui `
  "$agentPy"

# Проверка
$exe1 = Join-Path $distDir "rpc-agent.exe"
$exe2 = Join-Path $distDir "rpc-agent-console.exe"
if (-not (Test-Path $exe1) -or -not (Test-Path $exe2)) {
  Write-Error "Build failed: $exe1 / $exe2 not found"
  exit 1
}

# Публикуем в веб
Copy-Item -Force $exe1 $webDir
Copy-Item -Force $exe2 $webDir

Write-Host "Done. Built: $exe1, $exe2 and published to $webDir"