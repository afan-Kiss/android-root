# Git 凭据助手：从项目根目录 api_key 文件读取 GitHub PAT
param([string]$Operation = "get")

$apiKeyFile = Join-Path $PSScriptRoot "api_key"
if (-not (Test-Path $apiKeyFile)) { exit 1 }

$content = Get-Content $apiKeyFile -Raw
if ($content -notmatch 'api_key=(.+)') { exit 1 }
$token = $matches[1].Trim()

if ($Operation -eq "get") {
    [Console]::In.ReadToEnd() | Out-Null
    Write-Output "protocol=https"
    Write-Output "host=github.com"
    Write-Output "username=x-access-token"
    Write-Output "password=$token"
}
