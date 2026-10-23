# 使用项目内 api_key 操作 GitHub（token 不进入 git 历史）
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$GitArgs
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$apiKeyFile = Join-Path $root "api_key"

function Read-GitHubToken {
    if (-not (Test-Path -LiteralPath $apiKeyFile)) {
        Write-Error "缺少 api_key 文件"
        exit 1
    }
    $content = Get-Content -LiteralPath $apiKeyFile -Raw
    if ($content -notmatch 'api_key=(.+)') {
        Write-Error "api_key 格式错误，应为 api_key=..."
        exit 1
    }
    return $matches[1].Trim()
}

function Get-AuthUrl([string]$Url, [string]$Token) {
    if ($Url -match '^https://([^@]+@)?github\.com/(.+)$') {
        return "https://x-access-token:${Token}@github.com/$($matches[2])"
    }
    return $Url
}

function Resolve-RemoteUrl([string]$Name, [string]$Token) {
    if ($Name -eq "origin" -or $Name -match '^https://github\.com/') {
        $url = if ($Name -eq "origin") {
            git -C $root remote get-url origin 2>$null
        } else {
            $Name
        }
        if (-not $url) {
            Write-Error "未配置 origin 远程仓库"
            exit 1
        }
        return Get-AuthUrl $url $Token
    }
    return $Name
}

$token = Read-GitHubToken
$env:GIT_TERMINAL_PROMPT = "0"

if ($GitArgs.Count -eq 0) {
    $remote = git -C $root remote get-url origin 2>$null
    if (-not $remote) {
        Write-Error "未配置 origin 远程仓库"
        exit 1
    }
    & git -C $root push (Get-AuthUrl $remote $token)
    exit $LASTEXITCODE
}

$cmd = $GitArgs[0]

switch ($cmd) {
    "help" {
        Write-Host @"
用法:
  .\push-github.ps1                    推送到 origin
  .\push-github.ps1 push [-u] origin [branch]
  .\push-github.ps1 pull [origin] [branch]
  .\push-github.ps1 fetch [origin]
  .\push-github.ps1 gh <gh 子命令...>  使用 api_key 调用 GitHub CLI
  .\push-github.ps1 <任意 git 命令>    透传给 git -C 项目根

首次使用 git pull/push 可运行: .\setup-git-auth.ps1
"@
        exit 0
    }
    "gh" {
        if ($GitArgs.Count -lt 2) {
            Write-Error "用法: .\push-github.ps1 gh <子命令...>"
            exit 1
        }
        $env:GH_TOKEN = $token
        $ghArgs = $GitArgs[1..($GitArgs.Count - 1)]
        & gh.exe @ghArgs
        exit $LASTEXITCODE
    }
    { $_ -in @("push", "pull", "fetch", "clone") } {
        $newArgs = @($cmd)
        for ($i = 1; $i -lt $GitArgs.Count; $i++) {
            if ($GitArgs[$i] -in @("-u", "--set-upstream")) { continue }
            if ($GitArgs[$i] -eq "origin" -or $GitArgs[$i] -like "https://github.com/*") {
                $newArgs += Resolve-RemoteUrl $GitArgs[$i] $token
            } else {
                $newArgs += $GitArgs[$i]
            }
        }
        if ($cmd -eq "clone") {
            & git @newArgs
        } else {
            & git -C $root @newArgs
        }
        if ($LASTEXITCODE -eq 0 -and $cmd -eq "push") {
            $setUpstream = $GitArgs -contains "-u" -or $GitArgs -contains "--set-upstream"
            if ($setUpstream) {
                $branch = git -C $root rev-parse --abbrev-ref HEAD
                git -C $root config branch.$branch.remote origin
                git -C $root branch --set-upstream-to=origin/$branch $branch 2>$null
            }
        }
        exit $LASTEXITCODE
    }
    default {
        & git -C $root @GitArgs
        exit $LASTEXITCODE
    }
}
