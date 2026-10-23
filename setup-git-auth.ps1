# 一次性配置：让 git pull / push 自动从 api_key 读取 GitHub PAT
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$helper = Join-Path $root "git-credential-helper.ps1"
$apiKeyFile = Join-Path $root "api_key"

if (-not (Test-Path -LiteralPath $apiKeyFile)) {
    Write-Error "缺少 api_key 文件，请先创建：api_key=github_pat_..."
    exit 1
}

if (-not (Test-Path -LiteralPath $helper)) {
    Write-Error "缺少 git-credential-helper.ps1"
    exit 1
}

# Git config 会吞掉反斜杠，中文路径需用正斜杠
$helperPath = ($helper -replace '\\', '/')
$helperCmd = "!powershell -NoProfile -ExecutionPolicy Bypass -File `"$helperPath`""
git -C $root config --local --replace-all credential.helper $helperCmd

Write-Host "已配置本地 credential.helper，可直接使用 git push / git pull"
Write-Host "也可使用 .\push-github.ps1，无需 credential.helper"
