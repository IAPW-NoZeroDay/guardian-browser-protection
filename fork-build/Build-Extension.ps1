<#
.SYNOPSIS
    Builds this fork of Check as a signed CRX3, plus the updates.xml that Edge and Chrome poll.

.DESCRIPTION
    1. Copies the same files upstream ships to the stores (Prepare-StorePackage.ps1): manifest.json, blocked.html,
       config, images, options, popup, rules, scripts and styles. Markdown and other dev files are left out.
    2. Stamps the version: 1.3.0 becomes 1.3.0.<Build> (version_name "1.3.0-fork.<Build>"), so every build is
       newer than the last and newer than the store's 1.3.0.
    3. Zips it and signs it with the fork signing key (crx3.mjs). The key fixes the extension ID.
    4. Writes updates.xml pointing at <UpdateBaseUrl>/browser-protection-<version>.crx.

    The signing key never goes in the repo. Default location: %USERPROFILE%\.browser-protection\signing.pem.
    Keep a copy in the password vault: losing it means a new extension ID and redeploying to every PC.

.EXAMPLE
    .\Build-Extension.ps1 -Build 1 -UpdateBaseUrl 'https://example.com/check'
.EXAMPLE
    .\Build-Extension.ps1 -NewKey      # first time only: creates the signing key, prints the extension ID
#>
[CmdletBinding()]
param(
    [int]$Build = 1,
    [string]$UpdateBaseUrl = 'https://REPLACE-ME/browser-protection',
    [string]$KeyPath = (Join-Path $env:USERPROFILE '.browser-protection\signing.pem'),
    [string]$OutDir = (Join-Path $PSScriptRoot 'out'),
    [switch]$NewKey
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot
$crx3 = Join-Path $PSScriptRoot 'crx3.mjs'
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js is required (node crx3.mjs).' }

if ($NewKey) {
    $dir = Split-Path $KeyPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $id = node $crx3 keygen $KeyPath
    if ($LASTEXITCODE) { throw 'Key generation failed.' }
    # Only this user (and SYSTEM/Administrators) can read the key.
    & icacls.exe $KeyPath /inheritance:r /grant:r "${env:USERNAME}:(R,W)" '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    Write-Host "Signing key created: $KeyPath"
    Write-Host "Extension ID: $id"
    Write-Host 'Store a copy of the key in the password vault now.'
    return
}
if (-not (Test-Path $KeyPath)) { throw "Signing key not found at $KeyPath. Run with -NewKey once, or restore it from the vault." }

# --- 1. Stage ---------------------------------------------------------------------------------------
$stage = Join-Path $OutDir 'stage'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
foreach ($item in 'manifest.json', 'blocked.html', 'config', 'images', 'options', 'popup', 'rules', 'scripts', 'styles') {
    Copy-Item (Join-Path $repo $item) (Join-Path $stage $item) -Recurse -Force
}
Get-ChildItem $stage -Recurse -File -Include '*.md', '*.log', '.DS_Store', 'Thumbs.db', '*.tmp' | Remove-Item -Force

# --- 2. Version ---------------------------------------------------------------------------------------
$manifestPath = Join-Path $stage 'manifest.json'
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$base = ($manifest.version -split '\.')[0..2] -join '.'
$version = "$base.$Build"
$manifest.version = $version
$manifest | Add-Member -NotePropertyName version_name -NotePropertyValue "$base-fork.$Build" -Force
$manifest | ConvertTo-Json -Depth 20 | Set-Content $manifestPath -Encoding utf8NoBOM

# --- 3. Zip and sign ------------------------------------------------------------------------------------
$zip = Join-Path $OutDir "browser-protection-$version.zip"
$crx = Join-Path $OutDir "browser-protection-$version.crx"
Remove-Item $zip, $crx -Force -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
$id = node $crx3 pack $zip $KeyPath $crx
if ($LASTEXITCODE) { throw 'Signing failed.' }

# --- 4. updates.xml ---------------------------------------------------------------------------------------
$codebase = "$($UpdateBaseUrl.TrimEnd('/'))/browser-protection-$version.crx"
@"
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='$id'>
    <updatecheck codebase='$codebase' version='$version' />
  </app>
</gupdate>
"@ | Set-Content (Join-Path $OutDir 'updates.xml') -Encoding utf8NoBOM

[pscustomobject]@{
    ExtensionId = $id
    Version     = $version
    Crx         = $crx
    Sha256      = (Get-FileHash $crx -Algorithm SHA256).Hash
    UpdatesXml  = Join-Path $OutDir 'updates.xml'
    UpdateUrl   = "$($UpdateBaseUrl.TrimEnd('/'))/updates.xml"
}
