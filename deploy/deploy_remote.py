import os
import sys
import time
from pathlib import Path

import paramiko

HOST = "39.108.179.146"
PORT = 22
PASSWORD = "HUAzai4869"
REMOTE_DIR = r"C:\dy_collect"
LOCAL_DIR = Path(__file__).resolve().parent
FILES = [
    "live_collect_db.py",
    "live_collect_mysql.py",
    "live_collect_store.py",
    "live_collect_server.py",
    "server.env",
    "start_server.ps1",
]
USERS = ["Administrator", "administrator", "admin", "fdqc"]


def try_connect():
    for user in USERS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(HOST, port=PORT, username=user, password=PASSWORD, timeout=15, allow_agent=False, look_for_keys=False)
            print("connected as", user)
            return client, user
        except Exception as e:
            print("fail", user, e)
            client.close()
    return None, None


def run(client, cmd, timeout=120):
    print("$", cmd)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.strip())
    if err.strip():
        print("ERR:", err.strip())
    print("exit", code)
    return code, out, err


def main():
    client, user = try_connect()
    if not client:
        print("SSH failed for all users")
        return 1

    sftp = client.open_sftp()
    try:
        for d in (REMOTE_DIR, REMOTE_DIR + "/logs"):
            try:
                sftp.mkdir(d)
            except OSError:
                pass
    except Exception as e:
        print("mkdir warn", e)

    for name in FILES:
        local = LOCAL_DIR / name
        remote = REMOTE_DIR + "/" + name
        print("upload", name)
        sftp.put(str(local), remote)

    run(client, f'powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path {REMOTE_DIR} | Out-Null"')
    run(client, "python --version")
    run(client, "py -3 --version")
    run(client, "python -m pip install pymysql -q")
    run(client, "py -3 -m pip install pymysql -q")

    fw = (
        'powershell -NoProfile -Command "'
        "if (-not (Get-NetFirewallRule -DisplayName 'DY Collect 9909' -ErrorAction SilentlyContinue)) "
        "{ New-NetFirewallRule -DisplayName 'DY Collect 9909' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9909 }"
        '"'
    )
    run(client, fw)

    stop = (
        'powershell -NoProfile -Command "'
        "Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*python*' } | Stop-Process -Force -ErrorAction SilentlyContinue"
        '"'
    )
    run(client, stop)

    start = f'powershell -NoProfile -ExecutionPolicy Bypass -File "{REMOTE_DIR}\\start_server.ps1"'
    run(client, start)
    time.sleep(3)
    run(client, f'powershell -NoProfile -Command "try {{ (Invoke-WebRequest -UseBasicParsing http://127.0.0.1:9909/api/health -TimeoutSec 8).Content }} catch {{ $_.Exception.Message }}"')

    sftp.close()
    client.close()
    print("deploy done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())