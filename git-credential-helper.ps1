# Git 凭据助手：从项目根目录 api_key 文件读取 GitHub PAT
param([string]$Operation = "get")

$inputText = [Console]::In.ReadToEnd()
if ($Operation -ne "get") {
    exit 0
}

$apiKeyFile = Join-Path $PSScriptRoot "api_key"
if (-not (Test-Path $apiKeyFile)) { exit 1 }

$content = Get-Content $apiKeyFile -Raw
if ($content -notmatch 'api_key=(.+)') { exit 1 }
$token = $matches[1].Trim()

$hostName = "github.com"
if ($inputText -match '(?m)^host=(.+)$') {
    $hostName = $matches[1].Trim()
}
if ($hostName -ne "github.com") {
    exit 1
}

Write-Output "protocol=https"
Write-Output "host=$hostName"
Write-Output "username=x-access-token"
Write-Output "password=$token"
