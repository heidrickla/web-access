#!/usr/bin/env bash
# File scanning through a real Windows RDP server (NLA). proxy4.toml runs a stand-in scanner; the
# Windows machine is named in fixtures.env: WIN_HOST, WIN_USER, WIN_PASS, and WIN_KEY, an SSH key
# for WIN_USER. Skipped without WIN_HOST. Steps that need the RDP session (the remote clipboard)
# run there as scheduled tasks; the browser test asks for them through remote/.
set -uo pipefail
cd "$(dirname "$0")"
set -a; . ./fixtures.env; set +a
if [ -z "${WIN_HOST:-}" ]; then echo "SKIP file scanning: no WIN_HOST in fixtures.env"; exit 0; fi
bin=$(cd ../.. && pwd)/target/release/web-access-proxy
B=http://127.0.0.1:8446
O=(-H "Origin: $B" -H "Content-Type: application/json")

win() { ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i "$WIN_KEY" "$WIN_USER@$WIN_HOST" "$@"; }
# A PowerShell script, encoded so no shell on either side rewrites it.
# Progress records go to stderr as CLIXML; they are turned off, and stderr is kept apart.
winps() { win "powershell -NoProfile -NonInteractive -EncodedCommand $(printf '%s' "\$ProgressPreference = 'SilentlyContinue'; $1" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)"; }

read -r -d '' SETUP <<'EOF'
$ErrorActionPreference = 'Stop'
foreach ($d in 'C:\scan', 'C:\scan\in', 'C:\scan\out') { New-Item -ItemType Directory -Force $d | Out-Null }
Get-ChildItem C:\scan\in, C:\scan\out -File | Remove-Item -Force
# The EICAR file below must stay on disk for the remote to copy it.
Add-MpPreference -ExclusionPath 'C:\scan'
[IO.File]::WriteAllText('C:\scan\out\report.txt', 'quarterly report, a harmless file')
$e = '*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X'
[IO.File]::WriteAllText('C:\scan\out\eicar.com', -join $e[($e.Length - 1)..0])
Set-Content C:\scan\set-report.ps1 "Set-Clipboard -Path 'C:\scan\out\report.txt'; 'set-report in session ' + (Get-Process -Id `$PID).SessionId | Add-Content C:\scan\steps.log"
Set-Content C:\scan\set-eicar.ps1 "Set-Clipboard -Path 'C:\scan\out\eicar.com'; 'set-eicar in session ' + (Get-Process -Id `$PID).SessionId | Add-Content C:\scan\steps.log"
# The shell's own Paste, as Explorer does it; the copy runs in this process, so wait for it.
# It records what the session's clipboard offered and what arrived, in C:\scan\steps.log.
Set-Content C:\scan\paste.ps1 @'
param([int]$Seconds = 60)
Add-Type -AssemblyName System.Windows.Forms
$formats = [Windows.Forms.Clipboard]::GetDataObject().GetFormats() -join ','
(New-Object -ComObject Shell.Application).NameSpace('C:\scan\in').Self.InvokeVerb('Paste')
$until = (Get-Date).AddSeconds($Seconds)
# The copy calls back into this thread, so the wait pumps its messages.
function Pump([int]$ms) { $end = (Get-Date).AddMilliseconds($ms); while ((Get-Date) -lt $end) { [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 50 } }
do { Pump 1000; $f = @(Get-ChildItem C:\scan\in -File) } while ($f.Count -eq 0 -and (Get-Date) -lt $until)
Pump 3000
"paste in session $((Get-Process -Id $PID).SessionId): formats [$formats], files $(@(Get-ChildItem C:\scan\in -File).Count)" | Add-Content C:\scan\steps.log
'@
"setup done"
EOF

# Runs C:\scan\<step>.ps1 in WIN_USER's interactive session and waits for it to end.
read -r -d '' IN_SESSION <<'EOF'
$name = 'wa-scan-' + $step
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\scan\$file.ps1 $argv"
$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$env:USERNAME" -LogonType Interactive
Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Force | Out-Null
$before = (Get-ScheduledTaskInfo -TaskName $name).LastRunTime
Start-ScheduledTask -TaskName $name
$until = (Get-Date).AddSeconds(120)
do { Start-Sleep -Milliseconds 500; $t = Get-ScheduledTask -TaskName $name; $i = Get-ScheduledTaskInfo -TaskName $name }
while (($t.State -eq 'Running' -or $i.LastRunTime -eq $before) -and (Get-Date) -lt $until)
Unregister-ScheduledTask -TaskName $name -Confirm:$false
"result $($i.LastTaskResult)"
EOF

read -r -d '' WAIT_SESSION <<'EOF'
$until = (Get-Date).AddSeconds(120)
do {
  $s = @(Get-Process explorer -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -ne 0 -and $_.UserName -like "*\$env:USERNAME" })
  if ($s.Count -gt 0) { Start-Sleep 5; 'ready'; exit }
  Start-Sleep 2
} while ((Get-Date) -lt $until)
'no desktop session'
EOF

step() {
  case "$1" in
    set-report|set-eicar) winps "\$step='$1'; \$file='$1'; \$argv=''; $IN_SESSION" ;;
    paste) winps "\$step='paste'; \$file='paste'; \$argv='-Seconds 60'; $IN_SESSION" ;;
    paste-nothing) winps "\$step='paste'; \$file='paste'; \$argv='-Seconds 15'; $IN_SESSION" ;;
    wait-session) winps "$WAIT_SESSION" ;;
    clear-in) winps 'Get-ChildItem C:\scan\in -File | Remove-Item -Force' >/dev/null; echo ok ;;
    list-in) winps 'Get-ChildItem C:\scan\in -File | ForEach-Object { "$($_.Name) $($_.Length) $((Get-FileHash $_.FullName -Algorithm SHA256).Hash)" }' ;;
    *) echo "unknown step $1" ;;
  esac
}

# Serves the browser test's requests until it writes remote/stop.
agent() {
  while [ ! -f remote/stop ]; do
    for req in remote/req-*; do
      [ -e "$req" ] || continue
      id=${req#remote/req-}
      step "$(cat "$req")" 2> "remote/err-$id" | tr -d '\r' > "remote/tmp-$id"
      mv "remote/tmp-$id" "remote/done-$id"
      rm -f "$req"
    done
    sleep 0.3
  done
}

pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1: expected $2, got $3"; fail=$((fail+1)); fi; }

check "the Windows side is set up" "setup done" "$(winps "$SETUP" | tr -d '\r' | tail -1)"

./proxy.sh stop 4; rm -rf data4 log4
mkdir -p data4
printf '%s\n%s\n' "$LOCAL_PASS" "$LOCAL_PASS" | "$bin" local-account proxy4.toml devscan --admin >/dev/null
./proxy.sh start 4 >/dev/null
# The scanner's first check runs at start.
for i in $(seq 1 20); do grep -q 'file scanner check passed' log4 && break; sleep 0.5; done
check "the stand-in scanner passes its check at start" 1 "$(grep -c 'file scanner check passed' log4)"

curl -s -c scan.jar "${O[@]}" -d "{\"username\":\"devscan\",\"password\":\"$LOCAL_PASS\"}" "$B/api/login" >/dev/null
inst=$(curl -s -D - -o /dev/null -b scan.jar "$B/api/me" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-data-instance"{print $2}')
L=(-b scan.jar "${O[@]}" -H "X-Data-Instance: $inst")
sid=$(curl -s "${L[@]}" -d "{\"name\":\"win-01\",\"host\":\"$WIN_HOST\",\"port\":3389}" "$B/api/admin/servers" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
uid=$(curl -s -b scan.jar "$B/api/admin/users" | python3 -c 'import sys,json;print(json.load(sys.stdin)["users"][0]["id"])')
check "the server is assigned" 200 "$(curl -s -o /dev/null -w '%{http_code}' -X PUT "${L[@]}" -d "{\"server_ids\":[$sid]}" "$B/api/admin/users/$uid/servers")"

rm -rf remote; mkdir -p remote
agent &
agent_pid=$!
./run-e2e.sh e2e4; browser=$?
touch remote/stop; wait "$agent_pid"
./proxy.sh stop 4
echo "remote steps:"; winps 'Get-Content C:\scan\steps.log -ErrorAction SilentlyContinue'
winps 'Remove-MpPreference -ExclusionPath C:\scan; Remove-Item -Recurse -Force C:\scan' >/dev/null
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] && [ "$browser" -eq 0 ]
