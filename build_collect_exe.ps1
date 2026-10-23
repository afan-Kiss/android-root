$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
python prepare_bundle.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$base = @("--noconfirm","--onefile","--windowed","--clean","--add-data","bundle;bundle","--hidden-import=collect_runtime")
pyinstaller @base --name CollectServer --hidden-import=live_collect_db --hidden-import=live_collect_mysql --hidden-import=live_collect_store --hidden-import=live_collect_server --hidden-import=live_collect_web --hidden-import=pymysql collect_server_app.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$client = @(
    "--noconfirm","--onefile","--windowed","--clean",
    "--add-data","bundle;bundle",
    "--hidden-import=collect_runtime",
    "--collect-submodules=Cryptodome",
    "--collect-submodules=Crypto",
    "--hidden-import=Cryptodome.Cipher.AES",
    "--hidden-import=Cryptodome.Util.Padding",
    "--hidden-import=Crypto.Cipher.AES",
    "--hidden-import=live_collect_client",
    "--hidden-import=device_profile_pool",
    "--hidden-import=device_register",
    "--hidden-import=device_warmup",
    "--hidden-import=live_square",
    "--hidden-import=live_audience",
    "--hidden-import=pure_sign",
    "--hidden-import=profile_tools",
    "--collect-submodules=sign"
)
pyinstaller @client --name CollectClient --paths "bundle/sign_vendor" --paths "bundle/app" collect_client_app.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "OK dist\CollectServer.exe"
Write-Host "OK dist\CollectClient.exe"
