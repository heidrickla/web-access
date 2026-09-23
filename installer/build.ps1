<#
Build the MSI. Run from anywhere; paths resolve against this script.

The Windows binary is NOT built here. Produce it first, then drop it in payload/:

    # on a Linux host with rustup and gcc-mingw-w64-x86-64
    rustup target add x86_64-pc-windows-gnu
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
        cargo build --release --target x86_64-pc-windows-gnu

    # or natively on Windows with the MSVC toolchain
    cargo build --release

WiX v5 SPECIFICALLY. v6 and v7 require accepting the Open Source Maintenance Fee EULA, which is a
licensing decision and carries a fee for commercial use; v5 is the last version without that gate and
uses the same v4 schema, so this file needs no changes if that decision is ever made differently.
The extension must be pinned to match the toolset: an unpinned `wix extension add` resolves to the
newest version and fails against v5 with WIX0144.
#>
[CmdletBinding()]
param(
    [string]$Exe = (Join-Path $PSScriptRoot 'payload\web-access-proxy.exe'),
    [string]$Output = (Join-Path $PSScriptRoot 'web-access-proxy.msi')
)

$ErrorActionPreference = 'Stop'
$env:PATH = "$env:PATH;$env:USERPROFILE\.dotnet\tools"

if (-not (Test-Path $Exe)) {
    throw "no binary at $Exe -- build it first, see the header of this script"
}

$version = (Get-Item $Exe).Length
Write-Host "payload: $Exe ($version bytes)"

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "installing WiX v5"
    dotnet tool install --global wix --version 5.0.2
}

$wixVersion = (& wix --version)
if ($wixVersion -notmatch '^5\.') {
    throw "wix $wixVersion is installed; this build wants v5 (see the header). dotnet tool update --global wix --version 5.0.2"
}

& wix extension add -g WixToolset.Firewall.wixext/5.0.2 | Out-Null

# Source paths in the .wxs are relative to the working directory, not to the .wxs itself.
Push-Location $PSScriptRoot
try {
    & wix build web-access-proxy.wxs -ext WixToolset.Firewall.wixext -o $Output
    if ($LASTEXITCODE -ne 0) { throw "wix build failed with $LASTEXITCODE" }
}
finally {
    Pop-Location
}

$msi = Get-Item $Output
Write-Host "built $($msi.FullName) ($([math]::Round($msi.Length/1MB,2)) MB)"
