# 使用项目内 api_key 推送到 GitHub（token 不进入 git 历史）
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$GitArgs
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$apiKeyFile = Join-Path $root "api_key"

if (-not (Test-Path -LiteralPath $apiKeyFile)) {
    Write-Error "缺少 api_key 文件"
    exit 1
}

$content = Get-Content -LiteralPath $apiKeyFile -Raw
if ($content -notmatch 'api_key=(.+)') {
    Write-Error "api_key 格式错误，应为 api_key=..."
    exit 1
}
$token = $matches[1].Trim()
$env:GIT_TERMINAL_PROMPT = "0"

function Get-AuthUrl([string]$Url) {
    if ($Url -match '^https://([^@]+@)?github\.com/(.+)$') {
        return "https://x-access-token:${token}@github.com/$($matches[2])"
    }
    return $Url
}

if ($GitArgs.Count -eq 0) {
    $remote = git -C $root remote get-url origin 2>$null
    if (-not $remote) {
        Write-Error "未配置 origin 远程仓库"
        exit 1
    }
    & git -C $root push (Get-AuthUrl $remote)
} elseif ($GitArgs[0] -eq "push") {
    $setUpstream = $GitArgs -contains "-u" -or $GitArgs -contains "--set-upstream"
    $newArgs = @("push")
    for ($i = 1; $i -lt $GitArgs.Count; $i++) {
        if ($GitArgs[$i] -in @("-u", "--set-upstream")) { continue }
        if ($GitArgs[$i] -eq "origin" -or $GitArgs[$i] -like "https://github.com/*") {
            $url = if ($GitArgs[$i] -eq "origin") { git -C $root remote get-url origin } else { $GitArgs[$i] }
            $newArgs += Get-AuthUrl $url
        } else {
            $newArgs += $GitArgs[$i]
        }
    }
    & git -C $root @newArgs
    if ($LASTEXITCODE -eq 0 -and $setUpstream) {
        $branch = git -C $root rev-parse --abbrev-ref HEAD
        git -C $root config branch.$branch.remote origin
        git -C $root branch --set-upstream-to=origin/$branch $branch 2>$null
    }
    exit $LASTEXITCODE
} else {
    & git -C $root @GitArgs
}
