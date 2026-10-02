param(
  [Parameter(Mandatory = $true)][ValidateSet('kernel', 'package')][string]$Contract,
  [string]$TestBinary,
  [string]$EvidenceDirectory,
  [string]$NodeExecutable,
  [string]$NpmCli,
  [switch]$Worker
)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
function Require-Path([string]$Path, [string]$Kind) {
  if (-not [IO.Path]::IsPathFullyQualified($Path) -or $Path -match '[\x00-\x1f"]' -or
      -not (Test-Path -LiteralPath $Path -PathType $Kind)) {
    throw 'Independent contract paths must be absolute existing inputs'
  }
}
if (-not $Worker) {
  # Task Scheduler supplies an independent owner, not a workaround in native
  # admission. Workers must still prove absence of ambient Jobs. No PID lookup,
  # weakened BREAKAWAY checks, or Job-free fallback is introduced in Sandsurf.
  $EvidenceDirectory = Join-Path $env:RUNNER_TEMP ('sandsurf-contract-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
  $arguments = "-NoProfile -NonInteractive -File `"$PSCommandPath`" -Worker -Contract $Contract -EvidenceDirectory `"$EvidenceDirectory`""
  if ($Contract -eq 'kernel') {
    Require-Path $TestBinary 'Leaf'
    $arguments += " -TestBinary `"$TestBinary`""
  } else {
    $NodeExecutable = (Get-Command node).Source
    $NpmCli = Join-Path (Split-Path $NodeExecutable) 'node_modules/npm/bin/npm-cli.js'
    Require-Path $NodeExecutable 'Leaf'
    Require-Path $NpmCli 'Leaf'
    $arguments += " -NodeExecutable `"$NodeExecutable`" -NpmCli `"$NpmCli`""
  }
  $task = 'SandsurfContract-' + [Guid]::NewGuid().ToString('N')
  $action = New-ScheduledTaskAction -Execute (Get-Command pwsh).Source -Argument $arguments
  $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
  try {
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null
    Start-ScheduledTask -TaskName $task
    $receipt = Join-Path $EvidenceDirectory 'contract.json'
    $deadline = [DateTime]::UtcNow.AddMinutes(4)
    while (-not (Test-Path -LiteralPath $receipt)) {
      if ([DateTime]::UtcNow -ge $deadline) { throw 'Independent contract owner exceeded its deadline' }
      Start-Sleep -Milliseconds 250
    }
    Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'contract.log')
    $result = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    if ($result.formatVersion -ne 1 -or $result.contract -ne $Contract -or
        $result.exitCode -ne 0 -or $result.vmQualification -ne $false) {
      throw 'Independent contract failed'
    }
  } finally {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
  }
  exit 0
}
Require-Path $EvidenceDirectory 'Container'
$log = Join-Path $EvidenceDirectory 'contract.log'
$result = Join-Path $EvidenceDirectory 'contract.json'
Set-Location -LiteralPath $repository
try {
  if ($Contract -eq 'kernel') {
    Require-Path $TestBinary 'Leaf'
    $env:SANDSURF_WINDOWS_RESOURCE_TEST = '1'
    & $TestBinary '--test-threads=1' *> $log
  } else {
    Require-Path $NodeExecutable 'Leaf'
    Require-Path $NpmCli 'Leaf'
    $env:PATH = (Split-Path $NodeExecutable) + ';' + $env:PATH
    $env:NODE_OPTIONS = '--max-old-space-size=512'
    & $NodeExecutable $NpmCli 'run' 'test:package' *> $log
  }
  $code = $LASTEXITCODE
  if ($null -eq $code) { throw 'The contract process has no exit status' }
} catch {
  $_ | Out-String | Add-Content -LiteralPath $log
  $code = 1
}
$receipt = @{ formatVersion = 1; contract = $Contract; exitCode = $code; vmQualification = $false }
# Observers never parse a partially written receipt.
$pending = $result + '.pending'
[IO.File]::WriteAllText($pending, ($receipt | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
[IO.File]::Move($pending, $result)
exit $code
