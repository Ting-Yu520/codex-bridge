Set-StrictMode -Version Latest

function Save-McpEgressGuardState {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$StatePath,
    [Parameter(Mandatory = $true)]
    [hashtable]$State
  )

  $fullPath = [IO.Path]::GetFullPath($StatePath)
  $parent = [IO.Path]::GetDirectoryName($fullPath)
  if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "guard_state_directory_missing"
  }
  $temporary = "$fullPath.$PID.$([guid]::NewGuid().ToString('N')).tmp"
  $backup = "$temporary.bak"
  $json = ConvertTo-Json -InputObject $State -Depth 12
  try {
    [IO.File]::WriteAllText($temporary, $json, [Text.UTF8Encoding]::new($false))
    if ([IO.File]::Exists($fullPath)) {
      [IO.File]::Replace($temporary, $fullPath, $backup)
      if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) }
    } else {
      [IO.File]::Move($temporary, $fullPath)
    }
  } finally {
    if ([IO.File]::Exists($temporary)) {
      [IO.File]::Delete($temporary)
    }
    if ([IO.File]::Exists($backup)) {
      [IO.File]::Delete($backup)
    }
  }
}

function Invoke-McpEgressGuardRecovery {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$StatePath,
    [Parameter(Mandatory = $true)]
    [hashtable]$State,
    [Parameter(Mandatory = $true)]
    [hashtable]$Backend
  )

  $requiredOperations = @(
    "GetProbeIdentity", "StopProbe", "RestoreService", "VerifyService",
    "ShutdownService", "TestFirewallRule", "RemoveFirewallRule", "RestoreAudit"
  )
  foreach ($operation in $requiredOperations) {
    if (-not $Backend.ContainsKey($operation) -or $Backend[$operation] -isnot [scriptblock]) {
      throw "recovery_backend_invalid"
    }
  }
  if ($State.schema -ne "codex-bridge-b1-egress-recovery/v2") {
    throw "recovery_state_schema_invalid"
  }
  if ($State.cleanup.completed) {
    if ($State.probe.startAttempted -and -not $State.probe.exitConfirmed) {
      throw "completed_state_probe_not_confirmed"
    }
    if (-not $State.service.originalRestored -or -not $State.cleanup.serviceStopped -or
        -not $State.cleanup.temporaryFilesStarted -or
        ($State.audit.changeAttempted -and -not $State.audit.restored)) {
      throw "completed_state_invariants_invalid"
    }
    foreach ($ruleName in @($State.firewall.ruleNames)) {
      if (& $Backend.TestFirewallRule $ruleName) { throw "completed_state_firewall_rule_present" }
    }
    if (-not (& $Backend.ShutdownService $State)) {
      throw "completed_state_candidate_process_present"
    }
    return "already-complete"
  }
  $State.phase = "recovering"
  $State.blockedReason = $null
  Save-McpEgressGuardState -StatePath $StatePath -State $State

  try {
    if ($State.audit.changeAttempted -and
        (-not $State.audit.backupCreated -or
         [string]::IsNullOrWhiteSpace([string]$State.audit.backupPath))) {
      throw "audit_backup_unavailable"
    }
    if (-not $State.service.originalRestored -and
        ([string]::IsNullOrWhiteSpace([string]$State.service.path) -or
         [string]::IsNullOrWhiteSpace([string]$State.service.sha256) -or
         [string]::IsNullOrWhiteSpace([string]$State.service.backupPath))) {
      throw "service_recovery_identity_unavailable"
    }

    if ($State.probe.startAttempted -and -not $State.probe.exitConfirmed) {
      $probeIdentity = & $Backend.GetProbeIdentity $State
      if ($null -eq $probeIdentity -or $probeIdentity.status -eq "unknown") {
        throw "probe_identity_unverified"
      }
      if ($probeIdentity.status -eq "verified-running") {
        if ([int]$probeIdentity.processId -le 0 -or
            [string]::IsNullOrWhiteSpace([string]$probeIdentity.path) -or
            [string]::IsNullOrWhiteSpace([string]$probeIdentity.startedAtUtc) -or
            [string]$probeIdentity.sha256 -ne [string]$State.probe.imageSha256) {
          throw "probe_identity_unverified"
        }
        $State.probe.pid = [int]$probeIdentity.processId
        $State.probe.startedAtUtc = [string]$probeIdentity.startedAtUtc
        $State.probe.imagePath = [string]$probeIdentity.path
        $State.probe.terminationAttempted = $true
        Save-McpEgressGuardState -StatePath $StatePath -State $State
        & $Backend.StopProbe $State $probeIdentity
        $probeIdentity = & $Backend.GetProbeIdentity $State
        if ($null -eq $probeIdentity -or $probeIdentity.status -notin @("not-found", "verified-exited")) {
          throw "probe_exit_unverified"
        }
        $State.probe.terminated = $true
      } elseif ($probeIdentity.status -notin @("not-found", "verified-exited")) {
        throw "probe_identity_unverified"
      }
      $State.probe.exitConfirmed = $true
      Save-McpEgressGuardState -StatePath $StatePath -State $State
    }

    if (-not $State.service.originalRestored) {
      & $Backend.RestoreService $State
      if (-not (& $Backend.VerifyService $State)) {
        throw "service_restore_hash_mismatch"
      }
      $State.service.originalRestored = $true
      Save-McpEgressGuardState -StatePath $StatePath -State $State
    } elseif (-not $State.cleanup.temporaryFilesStarted -and
              -not (& $Backend.VerifyService $State)) {
      throw "service_identity_unverified"
    }

    if (-not (& $Backend.ShutdownService $State)) {
      throw "service_shutdown_unconfirmed"
    }
    if (-not $State.cleanup.serviceStopped) {
      $State.cleanup.serviceStopped = $true
      Save-McpEgressGuardState -StatePath $StatePath -State $State
    }

    foreach ($ruleName in @($State.firewall.ruleNames)) {
      if (& $Backend.TestFirewallRule $ruleName) {
        & $Backend.RemoveFirewallRule $ruleName
      }
      if (& $Backend.TestFirewallRule $ruleName) {
        throw "firewall_rule_remains"
      }
      $removed = @($State.firewall.removedRuleNames)
      if ($removed -notcontains $ruleName) {
        $State.firewall.removedRuleNames = @($removed + $ruleName)
        Save-McpEgressGuardState -StatePath $StatePath -State $State
      }
    }

    if ($State.audit.changeAttempted -and -not $State.audit.restored) {
      & $Backend.RestoreAudit $State
      $State.audit.restored = $true
      Save-McpEgressGuardState -StatePath $StatePath -State $State
    }

    $State.phase = "guard-restored"
    $State.blockedReason = $null
    Save-McpEgressGuardState -StatePath $StatePath -State $State
    return "guard-restored"
  } catch {
    $message = [string]$_.Exception.Message
    if ($message -notmatch '^[a-z0-9_]{1,96}$') { $message = "recovery_action_failed" }
    $State.phase = "blocked"
    $State.blockedReason = $message
    try {
      Save-McpEgressGuardState -StatePath $StatePath -State $State
    } catch {
      throw "recovery_state_write_failed"
    }
    throw $message
  }
}

Export-ModuleMember -Function Save-McpEgressGuardState, Invoke-McpEgressGuardRecovery
