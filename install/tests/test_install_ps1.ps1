# Happy-path test for install-cli.ps1. Run on a Windows runner with python on PATH.
# cosign is stubbed by putting a fake `cosign.cmd` on PATH (version reports >= v3, verify-blob
# exits 0) — the shipped install-cli.ps1 has NO verification bypass, so the real cosign path runs.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("hort-test-" + [System.Guid]::NewGuid().ToString())
$rel  = Join-Path $work 'site\releases\download\v9.9.9-beta.1'
New-Item -ItemType Directory -Force -Path $rel | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $work 'site\repos\project-hort\hort') | Out-Null
'fake' | Out-File -Encoding ascii (Join-Path $rel 'hort-cli-windows-amd64.exe')
$h = (Get-FileHash -Algorithm SHA256 (Join-Path $rel 'hort-cli-windows-amd64.exe')).Hash.ToLower()
"$h  hort-cli-windows-amd64.exe" | Out-File -Encoding ascii (Join-Path $rel 'hort-cli-windows-amd64.exe.sha256')
'' | Out-File -Encoding ascii (Join-Path $rel 'hort-cli-windows-amd64.exe.bundle')
'[{"tag_name":"v9.9.9-beta.1","prerelease":true}]' | Out-File -Encoding ascii (Join-Path $work 'site\repos\project-hort\hort\releases')

# cosign stub on PATH (prepended so it wins over any real cosign on the runner).
$stub = Join-Path $work 'stubbin'
New-Item -ItemType Directory -Force -Path $stub | Out-Null
@'
@echo off
if "%~1"=="version" (
  echo GitVersion: v3.1.1
  exit /b 0
)
exit /b 0
'@ | Out-File -Encoding ascii (Join-Path $stub 'cosign.cmd')

$server = Start-Process -PassThru -WindowStyle Hidden python -ArgumentList '-m','http.server','8772' -WorkingDirectory (Join-Path $work 'site')
try {
  Start-Sleep -Seconds 2
  $env:PATH         = "$stub;$env:PATH"
  $env:HORT_DL_BASE = 'http://127.0.0.1:8772/releases/download'
  $env:HORT_API     = 'http://127.0.0.1:8772'
  & "$here\..\install-cli.ps1" -Dir (Join-Path $work 'bin')
  if (-not (Test-Path (Join-Path $work 'bin\hort-cli.exe'))) { throw 'FAIL: hort-cli.exe not installed' }
  Write-Host 'PASS: happy path'
} finally {
  Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
