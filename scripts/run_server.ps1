$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\..\server"

$env:ALLOW_PUBLIC_AGENTS = "1"
$env:SHARED_SECRET = "rpcs_dev_secret_change_me"
$env:AUTH_TS_SKEW = "-1"

# TLS, если есть cert.pem/key.pem
if ((Test-Path -LiteralPath ".\cert.pem" -PathType Leaf) -and (Test-Path -LiteralPath ".\key.pem" -PathType Leaf)) {
  $env:SSL_CERTFILE = (Resolve-Path ".\cert.pem")
  $env:SSL_KEYFILE  = (Resolve-Path ".\key.pem")
}

# Фаервол: открыть порт на всех профилях
if (-not (Get-NetFirewallRule -DisplayName "RPC Server 8765" -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName "RPC Server 8765" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8765 -Profile Any | Out-Null
}

# Папка для раздачи агента
$webAgentDir = Join-Path (Get-Location) "web\agent"
if (-not (Test-Path $webAgentDir)) { New-Item -ItemType Directory -Force -Path $webAgentDir | Out-Null }
$repoRoot = Resolve-Path "$PSScriptRoot\.."
$builtExe = Join-Path $repoRoot "dist\rpc-agent.exe"
$pubExe   = Join-Path $webAgentDir "rpc-agent.exe"
if (Test-Path $builtExe) { Copy-Item -Force $builtExe $pubExe }

python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt

# Печать ссылок для клиентов
$port = 8765
$scheme = if ($env:SSL_CERTFILE -and $env:SSL_KEYFILE) { "https" } else { "http" }
try {
  $ips = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceOperationalStatus Up |
    Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } |
    Select-Object -ExpandProperty IPAddress -Unique)
} catch { $ips = @() }

Write-Host "Откройте на клиентском ПК PowerShell и выполните:" -ForegroundColor Yellow
foreach ($ip in $ips) {
  Write-Host ("  iwr ""{0}://{1}:{2}/bootstrap.ps1?host={1}&port={2}"" -UseBasicParsing | iex" -f $scheme, $ip, $port) -ForegroundColor Cyan
}
Write-Host ("Проверка здоровья: {0}://<IP>:{1}/health" -f $scheme, $port) -ForegroundColor Yellow

# ЯВНО слушаем на всех интерфейсах через uvicorn
$uvicornArgs = @("app:app","--host","0.0.0.0","--port","$port")
if ($env:SSL_CERTFILE -and $env:SSL_KEYFILE) {
  $uvicornArgs += @("--ssl-certfile","$env:SSL_CERTFILE","--ssl-keyfile","$env:SSL_KEYFILE")
}
python -m uvicorn @uvicornArgs