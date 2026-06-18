#Requires -Version 5
# hort-cli installer (Windows). Fail-closed: cosign-verified or no install.
#   irm https://hort.rs/install-cli.ps1 | iex
[CmdletBinding()]
param(
  [string]$Version = $env:HORT_VERSION,
  [string]$Dir     = $(if ($env:HORT_INSTALL_DIR) { $env:HORT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\hort\bin' }),
  [switch]$AddToPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$GhRepo        = 'project-hort/hort'
$IdentityRegex = if ($env:HORT_TEST_BAD_IDENTITY -eq '1') { 'https://github.com/definitely-not-project-hort/.*' } else { 'https://github.com/project-hort/.*' }
$OidcIssuer    = 'https://token.actions.githubusercontent.com'
$Api           = if ($env:HORT_API) { $env:HORT_API } else { 'https://api.github.com' }
$DlBase        = if ($env:HORT_DL_BASE) { $env:HORT_DL_BASE } else { "https://github.com/$GhRepo/releases/download" }
$PinUrl        = if ($env:HORT_PIN_URL) { $env:HORT_PIN_URL } else { 'https://hort.rs/cosign.pin' }

function Say($m) { Write-Host "hort install: $m" }
function Die($m) { Write-Error "hort install: ERROR: $m"; exit 1 }

function Invoke-Api($url) {
  $headers = @{}
  if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
  return Invoke-RestMethod -UseBasicParsing -Uri $url -Headers $headers
}

function Resolve-Latest {
  # prerelease-aware: newest release (incl. prereleases) is the first entry of /releases
  $rel = Invoke-Api "$Api/repos/$GhRepo/releases?per_page=1"
  $tag = @($rel)[0].tag_name
  if (-not $tag) { Die 'no release found (rate-limited? set $env:GITHUB_TOKEN, or pass -Version)' }
  return $tag
}

function Get-PinValue($pin, $key) {
  $line = ($pin -split "`n" | Where-Object { $_ -match "^$key=" } | Select-Object -First 1)
  if ($line) { return ($line -replace "^$key=", '').Trim() }
  return $null
}

function Ensure-Cosign($tmp) {
  $existing = Get-Command cosign -ErrorAction SilentlyContinue
  if ($existing) {
    $vline = (& $existing.Source version 2>$null | Select-String 'GitVersion')
    if ($vline -and ($vline.ToString() -match 'v?([3-9]|\d{2,})\.')) { return $existing.Source }
  }
  $pin  = (Invoke-WebRequest -UseBasicParsing -Uri $PinUrl).Content
  $cv   = Get-PinValue $pin 'COSIGN_VERSION'
  $want = Get-PinValue $pin 'COSIGN_SHA256_windows_amd64'
  if (-not $cv -or -not $want) { Die 'cosign pin malformed' }
  $cb = Join-Path $tmp 'cosign.exe'
  Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/sigstore/cosign/releases/download/$cv/cosign-windows-amd64.exe" -OutFile $cb
  $got = (Get-FileHash -Algorithm SHA256 $cb).Hash.ToLower()
  if ($got -ne $want.ToLower()) { Die "bootstrapped cosign hash mismatch (expected $want got $got) — aborting" }
  return $cb
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("hort-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $asset = 'hort-cli-windows-amd64'
  if (-not $Version) { $Version = Resolve-Latest }
  $base = "$DlBase/$Version"
  Say "downloading $asset.exe ($Version)"
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset.exe"        -OutFile "$tmp\$asset.exe"
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset.exe.sha256" -OutFile "$tmp\$asset.exe.sha256"
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset.exe.bundle" -OutFile "$tmp\$asset.exe.bundle"

  Say 'verifying SHA-256'
  $want = ((Get-Content "$tmp\$asset.exe.sha256") -split '\s+')[0].ToLower()
  $got  = (Get-FileHash -Algorithm SHA256 "$tmp\$asset.exe").Hash.ToLower()
  if ($got -ne $want) { Die 'SHA-256 verification failed — aborting, nothing installed' }

  # No verification bypass exists in the shipped script. Tests stub cosign by putting a
  # fake `cosign` on PATH (see install/tests/), so this real path always runs.
  Say 'verifying cosign signature (fail-closed)'
  $cosign = Ensure-Cosign $tmp
  & $cosign verify-blob --certificate-oidc-issuer=$OidcIssuer --certificate-identity-regexp=$IdentityRegex --bundle "$tmp\$asset.exe.bundle" "$tmp\$asset.exe" *> $null
  if ($LASTEXITCODE -ne 0) { Die 'cosign signature verification failed — aborting, nothing installed' }

  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  Move-Item -Force "$tmp\$asset.exe" (Join-Path $Dir 'hort-cli.exe')

  $onPath = ($env:PATH -split ';') -contains $Dir
  if (-not $onPath) {
    if ($AddToPath) {
      $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
      [Environment]::SetEnvironmentVariable('PATH', "$userPath;$Dir", 'User')
      Say "added $Dir to your user PATH — open a new terminal to pick it up"
    } else { Say "NOTE: $Dir is not on PATH. Add it, or re-run with -AddToPath." }
  }
  Say "installed -> $Dir\hort-cli.exe — verified"
}
finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
