# The MSI on a clean Windows Server: 0.2.0 installed and configured, upgraded to this version, a
# rebuild of the same version over a config that no longer loads, uninstall, and a reinstall that
# remembers REMOTE_ADDRESSES. One PASS or FAIL line per property; INFO lines are observations.
#
# Run as an administrator from C:\wa holding web-access-proxy-0.2.0.msi and two builds of this
# version, web-access-proxy-new-a.msi and web-access-proxy-new-b.msi (each build has its own
# ProductCode). Leaves the product installed; the config survives in C:\ProgramData\web-access.
$ErrorActionPreference = 'Continue'
$data = 'C:\ProgramData\web-access'
$cfg = Join-Path $data 'config.toml'
$exe = 'C:\Program Files\web-access\web-access-proxy.exe'
$failed = 0

function Check($name, $ok, $detail = '') {
    $word = if ($ok) { 'PASS' } else { 'FAIL'; $script:failed++ }
    Write-Output "$word $name $detail"
}
function Msi([string]$arguments) {
    (Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru).ExitCode
}
# Always an array: Windows PowerShell 5.1 gives a single PSCustomObject no Count.
function Products {
    , @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' |
        Get-ItemProperty | Where-Object { $_.DisplayName -like 'web-access*' })
}
# This version's rule, or with -Name '0.2' the rule 0.2 and earlier wrote.
function RuleFacts([string]$Name = 'web-access RDP proxy') {
    if ($Name -eq '0.2') { $Name = 'web-access proxy' }
    $r = @(Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue)
    if ($r.Count -eq 0) { return 'no rule' }
    $a = $r[0] | Get-NetFirewallApplicationFilter
    $p = $r[0] | Get-NetFirewallPortFilter
    $ad = $r[0] | Get-NetFirewallAddressFilter
    "count=$($r.Count) program=$($a.Program) localport=$($p.LocalPort) remote=$($ad.RemoteAddress -join ',')"
}
function Running([int]$secs) {
    for ($i = 0; $i -lt $secs; $i++) {
        $s = Get-Service WebAccessProxy -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq 'Running') { return $true }
        Start-Sleep 1
    }
    $false
}
function Answers {
    try { (Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8443/ -TimeoutSec 5).StatusCode -eq 200 } catch { $false }
}
# The installed binary loads and runs: a missing runtime DLL shows here as 0xC0000135.
function Runs {
    if (-not (Test-Path $exe)) { return 'no exe' }
    $v = & $exe --version 2>&1
    "exit=$LASTEXITCODE $v"
}
# The service log's newest line holding `text`, waiting up to `secs` for one.
function Logged([string]$text, [int]$secs) {
    for ($i = 0; $i -lt $secs; $i++) {
        $l = Get-ChildItem $data -Filter 'web-access-proxy-*.log' | Get-Content |
            Select-String -SimpleMatch $text | Select-Object -Last 1
        if ($l) { return "$l" }
        Start-Sleep 1
    }
    ''
}
function Marked { (Test-Path $cfg) -and (Select-String -Path $cfg -SimpleMatch 'upgrade-test-marker' -Quiet) }
$good = @'
# upgrade-test-marker
listen = "0.0.0.0:8443"
allow_local_accounts = true

[tls]
verify = "insecure"
'@

# 1. 0.2.0, configured and running: the state a real upgrade starts from.
$e = Msi '/i C:\wa\web-access-proxy-0.2.0.msi /qn /l*v C:\wa\01-install-0.2.0.log'
Check '0.2.0 installs' ($e -eq 0) "exit $e"
Set-Content -Path $cfg -Value $good -Encoding ascii
Start-Service WebAccessProxy -ErrorAction SilentlyContinue
Check '0.2.0 runs with the test config' (Running 30)
Check '0.2.0 answers on 8443' (Answers)
Write-Output "INFO 0.2.0 rule: $(RuleFacts 0.2)"

# 2. The upgrade.
$e = Msi '/i C:\wa\web-access-proxy-new-a.msi /qn /l*v C:\wa\02-upgrade.log'
Check 'the upgrade succeeds' ($e -eq 0) "exit $e"
$run = Runs
Check 'the upgraded exe is in place and runs' ($run -like 'exit=0 *') $run
Check 'config.toml survives the upgrade from 0.2.0' (Marked)
$old = 'C:\Program Files (x86)\web-access\web-access-proxy.exe'
Check "0.2.0's copy in Program Files (x86) is removed" (-not (Test-Path $old))
$image = (Get-CimInstance Win32_Service -Filter "Name = 'WebAccessProxy'").PathName
Check 'the service runs the new exe' ($image -like "*$exe*") $image
Check 'the upgrade starts the service' (Running 60)
Check 'the new version answers on 8443' (Answers)
$scan = Logged 'file scanner check passed' 60
Check 'files are scanned by the anti-malware product registered with Windows' ($scan -like '*AMSI: *') $scan
$pr = Products
Check 'one product is installed' ($pr.Count -eq 1) (($pr | ForEach-Object { $_.DisplayVersion }) -join ',')
$facts = RuleFacts
Check 'one firewall rule, naming the exe' (($facts -like 'count=1 *') -and ($facts -like "*program=$exe *")) $facts
Check 'the rule has no port and admits any address' (($facts -like '*localport=Any*') -and ($facts -like '*remote=Any*')) $facts
Check "0.2.0's rule is gone" ((RuleFacts 0.2) -eq 'no rule') (RuleFacts 0.2)
Check 'the notices and licence are installed' ((Test-Path 'C:\Program Files\web-access\notices.html') -and (Test-Path 'C:\Program Files\web-access\notices-client.html') -and (Test-Path 'C:\Program Files\web-access\LICENSE.txt'))

# 3. A rebuild of the same version, over a config that no longer loads.
Add-Content -Path $cfg -Value 'broken = [' -Encoding ascii
$e = Msi '/i C:\wa\web-access-proxy-new-b.msi /qn /l*v C:\wa\03-same-version.log'
Check 'a rebuild of the same version upgrades in place' ($e -eq 0) "exit $e"
$pr = Products
Check 'still one product' ($pr.Count -eq 1) (($pr | ForEach-Object { $_.PSChildName }) -join ',')
$facts = RuleFacts
Check 'the rule survives the removal of the version it replaced' (($facts -like 'count=1 *') -and ($facts -like "*program=$exe *")) $facts
Check 'a failed start does not fail the upgrade' (($e -eq 0) -and -not (Running 15))
Set-Content -Path $cfg -Value $good -Encoding ascii
Start-Service WebAccessProxy -ErrorAction SilentlyContinue
Check 'the service starts once the config is fixed' (Running 30)

# 4. Uninstall, then an install that sets REMOTE_ADDRESSES, then one that does not.
$e = Msi '/x C:\wa\web-access-proxy-new-b.msi /qn /l*v C:\wa\04-uninstall.log'
Check 'uninstall succeeds' ($e -eq 0) "exit $e"
Check 'config.toml is kept on uninstall' (Marked)
Check 'the rule goes with the product' ((RuleFacts) -eq 'no rule') (RuleFacts)
$e = Msi '/i C:\wa\web-access-proxy-new-a.msi /qn REMOTE_ADDRESSES=10.20.0.0/16 /l*v C:\wa\05-install-scoped.log'
Check 'an install with REMOTE_ADDRESSES succeeds' ($e -eq 0) "exit $e"
$facts = RuleFacts
Check 'REMOTE_ADDRESSES scopes the rule' ($facts -like '*remote=10.20.0.0/255.255.0.0*') $facts
Check 'a first install leaves the service stopped' (-not (Running 10))
$run = Runs
Check 'a first install puts a runnable exe in place' ($run -like 'exit=0 *') $run
$e = Msi '/x C:\wa\web-access-proxy-new-a.msi /qn /l*v C:\wa\06-uninstall.log'
$e2 = Msi '/i C:\wa\web-access-proxy-new-a.msi /qn /l*v C:\wa\07-reinstall.log'
$facts = RuleFacts
Check 'a reinstall remembers REMOTE_ADDRESSES' (($e -eq 0) -and ($e2 -eq 0) -and ($facts -like '*remote=10.20.0.0/255.255.0.0*')) $facts
Write-Output "failed=$failed"
exit $failed
