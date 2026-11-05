$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot "..\McpEgressGuardRecovery.psm1"
Import-Module $modulePath -Force

function New-TestState([string]$StatePath) {
  return @{
    schema = "codex-bridge-b1-egress-recovery/v2"
    phase = "probe-running"
    blockedReason = $null
    statePath = $StatePath
    service = @{
      path = "C:\runner-temp\artifact\codex-bridge-service.exe"
      sha256 = ("a" * 64) -join ""
      backupPath = "C:\runner-temp\probe\codex-bridge-service.exe.original"
      originalMoveAttempted = $true
      originalRestored = $false
    }
    probe = @{
      startAttempted = $true
      pid = 4120
      startedAtUtc = "2026-11-05T01:02:03.0000000Z"
      imagePath = "C:\runner-temp\artifact\codex-bridge-service.exe"
      imageSha256 = ("b" * 64) -join ""
      exitConfirmed = $false
      terminated = $false
    }
    firewall = @{
      ruleNames = @("CodexBridgeB1-test-IPv4", "CodexBridgeB1-test-IPv6")
      removedRuleNames = @()
    }
    audit = @{
      backupPath = "C:\runner-temp\audit.csv"
      backupAttempted = $true
      backupCreated = $true
      changeAttempted = $true
      restored = $false
    }
    cleanup = @{
      serviceStopped = $false
      temporaryFilesStarted = $false
      completed = $false
    }
  }
}

function New-MockBackend($Mock, [string]$StatePath) {
  $getProbeIdentity = {
    param($State)
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
      throw "synthetic_recovery_state_not_persisted"
    }
    $persisted = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -AsHashtable
    if ($persisted.phase -ne "recovering") {
      throw "synthetic_recovery_phase_not_persisted"
    }
    if ($Mock.probeStatus -eq "unknown") { return @{ status = "unknown"; processId = 0 } }
    if ($Mock.probeStatus -eq "running") {
      return @{
        status = "verified-running"
        processId = 4120
        path = $State.probe.imagePath
        startedAtUtc = "2026-11-05T01:02:03.0000000Z"
        sha256 = $State.probe.imageSha256
      }
    }
    return @{ status = "not-found"; processId = 0 }
  }.GetNewClosure()

  $stopProbe = {
    param($State, $Identity)
    $Mock.calls.Add("stop-probe")
    if ([int]$State.probe.pid -ne [int]$Identity.processId -or
        [string]::IsNullOrWhiteSpace([string]$State.probe.startedAtUtc) -or
        [string]$State.probe.startedAtUtc -ne [string]$Identity.startedAtUtc) {
      throw "synthetic_probe_identity_not_persisted_before_stop"
    }
    if ($Mock.stopFails) { throw "synthetic_probe_stop_failure" }
    $Mock.probeStatus = "not-found"
  }.GetNewClosure()

  $restoreService = {
    param($State)
    $Mock.calls.Add("restore-service")
    if ($Mock.restoreServiceFails) { throw "synthetic_service_restore_failure" }
    $Mock.serviceRestored = $true
  }.GetNewClosure()

  $verifyService = {
    param($State)
    return [bool]$Mock.serviceRestored
  }.GetNewClosure()

  $shutdownService = {
    param($State)
    $Mock.calls.Add("shutdown-service")
    if ($Mock.shutdownFails) { throw "synthetic_service_shutdown_failure" }
    return $true
  }.GetNewClosure()

  $testFirewallRule = {
    param($RuleName)
    return -not $Mock.removedRules.Contains($RuleName)
  }.GetNewClosure()

  $removeFirewallRule = {
    param($RuleName)
    $Mock.calls.Add("remove-$RuleName")
    if ($Mock.firewallRemoveFails -and $RuleName -eq $Mock.firewallRemoveFails) {
      throw "synthetic_firewall_remove_failure"
    }
    [void]$Mock.removedRules.Add($RuleName)
  }.GetNewClosure()

  $restoreAudit = {
    param($State)
    $Mock.calls.Add("restore-audit")
    if ($Mock.auditRestoreFails) { throw "synthetic_audit_restore_failure" }
    $Mock.auditRestored = $true
  }.GetNewClosure()

  return @{
    GetProbeIdentity = $getProbeIdentity
    StopProbe = $stopProbe
    RestoreService = $restoreService
    VerifyService = $verifyService
    ShutdownService = $shutdownService
    TestFirewallRule = $testFirewallRule
    RemoveFirewallRule = $removeFirewallRule
    RestoreAudit = $restoreAudit
  }
}

function New-MockState {
  return [pscustomobject]@{
    calls = [Collections.Generic.List[string]]::new()
    probeStatus = "running"
    removedRules = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    serviceRestored = $false
    auditRestored = $false
    stopFails = $false
    restoreServiceFails = $false
    shutdownFails = $false
    firewallRemoveFails = $null
    auditRestoreFails = $false
  }
}

function Invoke-ExpectedFailure([scriptblock]$Action, [string]$ExpectedCategory) {
  try {
    & $Action
  } catch {
    if ($_.Exception.Message -eq $ExpectedCategory) { return }
    throw "Unexpected failure category: $($_.Exception.Message)"
  }
  throw "Expected failure was not raised: $ExpectedCategory"
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("codex-bridge-b1-mock-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop | Out-Null
$passed = 0
try {
  $statePath = Join-Path $testRoot "state-timeout.json"
  $state = New-TestState $statePath
  $mock = New-MockState
  $backend = New-MockBackend $mock $statePath
  Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend | Out-Null
  if (-not $state.probe.exitConfirmed -or -not $state.service.originalRestored -or
      -not $mock.auditRestored -or $mock.removedRules.Count -ne 2 -or
      $state.phase -ne "guard-restored") {
    throw "mock_timeout_recovery_incomplete"
  }
  $restoreIndex = $mock.calls.IndexOf("restore-service")
  $firstRuleIndex = $mock.calls.IndexOf("remove-CodexBridgeB1-test-IPv4")
  if ($mock.calls.IndexOf("stop-probe") -lt 0 -or $restoreIndex -lt 0 -or
      $firstRuleIndex -le $restoreIndex) { throw "mock_recovery_order_invalid" }
  $passed++
  Write-Output "PASS test=mock-probe-timeout-recovery"

  $statePath = Join-Path $testRoot "state-timeout-pid-not-yet-persisted.json"
  $state = New-TestState $statePath
  $state.probe.pid = 0
  $state.probe.startedAtUtc = $null
  $mock = New-MockState
  $backend = New-MockBackend $mock $statePath
  Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend | Out-Null
  if ($state.probe.pid -ne 4120 -or
      $state.probe.startedAtUtc -ne "2026-11-05T01:02:03.0000000Z" -or
      -not $mock.calls.Contains("stop-probe")) {
    throw "mock_discovered_probe_identity_not_persisted"
  }
  $passed++
  Write-Output "PASS test=mock-probe-identity-persisted-before-stop"

  $callCount = $mock.calls.Count
  Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend | Out-Null
  if ($mock.calls.Count -ne ($callCount + 1) -or
      $mock.calls[$mock.calls.Count - 1] -ne "shutdown-service" -or
      $state.phase -ne "guard-restored") {
    throw "mock_recovery_not_idempotent"
  }
  $passed++
  Write-Output "PASS test=mock-recovery-idempotent-repeat"

  $statePath = Join-Path $testRoot "state-identity-unknown.json"
  $state = New-TestState $statePath
  $mock = New-MockState
  $mock.probeStatus = "unknown"
  $backend = New-MockBackend $mock $statePath
  Invoke-ExpectedFailure { Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend } "probe_identity_unverified"
  if ($mock.calls.Count -ne 0 -or $state.phase -ne "blocked") { throw "mock_unknown_probe_was_mutated" }
  $passed++
  Write-Output "PASS test=mock-unknown-probe-fails-closed"

  $statePath = Join-Path $testRoot "state-service-restore-failure.json"
  $state = New-TestState $statePath
  $mock = New-MockState
  $mock.restoreServiceFails = $true
  $backend = New-MockBackend $mock $statePath
  Invoke-ExpectedFailure { Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend } "synthetic_service_restore_failure"
  if ($mock.calls.Contains("remove-CodexBridgeB1-test-IPv4") -or $mock.auditRestored -or
      $state.phase -ne "blocked") { throw "mock_service_restore_failure_not_fail_closed" }
  $mock.restoreServiceFails = $false
  Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend | Out-Null
  if ($state.phase -ne "guard-restored" -or -not $state.service.originalRestored -or
      $mock.removedRules.Count -ne 2 -or -not $mock.auditRestored) {
    throw "mock_service_restore_retry_failed"
  }
  $passed++
  Write-Output "PASS test=mock-service-restore-failure-keeps-guard-and-retries"

  $statePath = Join-Path $testRoot "state-audit-retry.json"
  $state = New-TestState $statePath
  $mock = New-MockState
  $mock.auditRestoreFails = $true
  $backend = New-MockBackend $mock $statePath
  Invoke-ExpectedFailure { Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend } "synthetic_audit_restore_failure"
  if ($state.phase -ne "blocked" -or $mock.removedRules.Count -ne 2 -or $mock.auditRestored) {
    throw "mock_audit_failure_state_invalid"
  }
  $mock.auditRestoreFails = $false
  Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend | Out-Null
  if ($state.phase -ne "guard-restored" -or -not $mock.auditRestored) {
    throw "mock_audit_retry_failed"
  }
  $passed++
  Write-Output "PASS test=mock-audit-restore-retry"

  $statePath = Join-Path $testRoot "state-firewall-retry.json"
  $state = New-TestState $statePath
  $mock = New-MockState
  $mock.firewallRemoveFails = "CodexBridgeB1-test-IPv6"
  $backend = New-MockBackend $mock $statePath
  Invoke-ExpectedFailure { Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend } "synthetic_firewall_remove_failure"
  if ($state.phase -ne "blocked" -or $mock.auditRestored -or
      -not $mock.removedRules.Contains("CodexBridgeB1-test-IPv4")) {
    throw "mock_firewall_failure_state_invalid"
  }
  $mock.firewallRemoveFails = $null
  Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend | Out-Null
  if ($state.phase -ne "guard-restored" -or -not $mock.auditRestored -or
      $mock.removedRules.Count -ne 2) { throw "mock_firewall_retry_failed" }
  $passed++
  Write-Output "PASS test=mock-firewall-cleanup-retry"

  $statePath = Join-Path $testRoot "state-probe-stop-failure.json"
  $state = New-TestState $statePath
  $mock = New-MockState
  $mock.stopFails = $true
  $backend = New-MockBackend $mock $statePath
  Invoke-ExpectedFailure { Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend } "synthetic_probe_stop_failure"
  if ($mock.calls.Count -ne 1 -or $mock.calls[0] -ne "stop-probe" -or
      $state.phase -ne "blocked" -or $mock.removedRules.Count -ne 0) {
    throw "mock_probe_stop_failure_not_fail_closed"
  }
  $passed++
  Write-Output "PASS test=mock-probe-stop-failure-keeps-guard"

  $statePath = Join-Path $testRoot "state-audit-backup-missing.json"
  $state = New-TestState $statePath
  $state.audit.backupCreated = $false
  $mock = New-MockState
  $backend = New-MockBackend $mock $statePath
  Invoke-ExpectedFailure { Invoke-McpEgressGuardRecovery -StatePath $statePath -State $state -Backend $backend } "audit_backup_unavailable"
  if ($mock.calls.Count -ne 0 -or $mock.removedRules.Count -ne 0 -or
      $state.phase -ne "blocked") { throw "mock_missing_audit_backup_not_fail_closed" }
  $passed++
  Write-Output "PASS test=mock-missing-audit-backup-fails-closed"

  if ($passed -ne 9) { throw "mock_test_count_mismatch" }
  Write-Output "PASS test=mock-recovery-summary executed=$passed failures=0"
} finally {
  Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
