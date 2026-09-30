<#
Build the MSI. Run from anywhere; paths resolve against this script.

    pwsh installer/build.ps1               build the proxy and the MSI from a clean tree
    pwsh installer/build.ps1 -Dev          the same from a tree with uncommitted changes, for testing
    pwsh installer/build.ps1 -Exe <path>   package a binary built elsewhere (cross-compiled on Linux)

The version comes from Cargo.toml, and the binary reports it with the source revision it was
built from (`web-access-proxy.exe --version`, the log's first line, the Migration tab), so an
installed proxy names exactly what it is. A release is built from its tag, v<version>.

Cross-compiling on Linux, with rustup and gcc-mingw-w64-x86-64:

    rustup target add x86_64-pc-windows-gnu
    export WEB_ACCESS_BUILD="$(git describe --tags --always --dirty)"
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
    cargo build --release --offline --locked --target x86_64-pc-windows-gnu

WiX v5 specifically. v6 and v7 require accepting the Open Source Maintenance Fee EULA, which is a
licensing decision and carries a fee for commercial use; v5 is the last version without that gate
and uses the same v4 schema. The extension must be pinned to match the toolset: an unpinned
`wix extension add` resolves to the newest version and fails against v5 with WIX0144.
#>
[CmdletBinding()]
param(
    [string]$Exe,
    [string]$Output,
    [switch]$Dev
)

$ErrorActionPreference = 'Stop'
$env:PATH = "$env:PATH;$env:USERPROFILE\.dotnet\tools"
$repo = Split-Path $PSScriptRoot -Parent

$cargo = Get-Content (Join-Path $repo 'Cargo.toml') -Raw
if ($cargo -notmatch '(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"') {
    throw "no version in Cargo.toml"
}
$version = $Matches[1]
if (-not $Output) { $Output = Join-Path $PSScriptRoot "web-access-proxy-$version.msi" }

Push-Location $repo
try {
    $dirty = git status --porcelain --untracked-files=no
    $build = git describe --tags --always --dirty
}
finally {
    Pop-Location
}
if ($dirty -and -not $Dev) {
    throw "the tree has uncommitted changes; commit them, or build with -Dev for a test package"
}

$payload = Join-Path $PSScriptRoot 'payload\web-access-proxy.exe'
New-Item -ItemType Directory -Force (Split-Path $payload) | Out-Null
if ($Exe) {
    Copy-Item $Exe $payload -Force
}
else {
    Push-Location $repo
    try {
        $env:WEB_ACCESS_BUILD = $build
        cargo build --release --offline --locked
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with $LASTEXITCODE" }
    }
    finally {
        Remove-Item Env:WEB_ACCESS_BUILD -ErrorAction SilentlyContinue
        Pop-Location
    }
    Copy-Item (Join-Path $repo 'target\release\web-access-proxy.exe') $payload -Force
}

# The binary and the package must name the same version.
$reported = & $payload --version
if ($reported -notmatch "^web-access-proxy $([regex]::Escape($version)) ") {
    throw "the binary reports '$reported', not version $version"
}
Write-Host "payload: $reported"

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "installing WiX v5"
    dotnet tool install --global wix --version 5.0.2
}
$wixVersion = (& wix --version)
if ($wixVersion -notmatch '^5\.') {
    throw "wix $wixVersion is installed; this build wants v5 (see the header). dotnet tool update --global wix --version 5.0.2"
}
& wix extension add -g WixToolset.Firewall.wixext/5.0.2 | Out-Null
& wix extension add -g WixToolset.Util.wixext/5.0.2 | Out-Null

# Source paths in the .wxs are relative to the working directory, not to the .wxs itself.
Push-Location $PSScriptRoot
try {
    & wix build web-access-proxy.wxs -arch x64 -d "ProductVersion=$version" -ext WixToolset.Firewall.wixext -ext WixToolset.Util.wixext -o $Output
    if ($LASTEXITCODE -ne 0) { throw "wix build failed with $LASTEXITCODE" }
}
finally {
    Pop-Location
}

$msi = Get-Item $Output
Write-Host "built $($msi.FullName) ($([math]::Round($msi.Length/1MB,2)) MB), version $version"
