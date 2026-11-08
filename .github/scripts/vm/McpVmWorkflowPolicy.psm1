Set-StrictMode -Version Latest

$script:GateABranch = 'ci/mcp-cache-hints-route-tests-20261104'
$script:GateB1Branch = 'ci/mcp-cache-hints-exe-process-20261105'

function New-CodexBridgeWorkflowDecision([bool]$Valid, [string]$ErrorCategory, [string[]]$Jobs) {
  return [pscustomobject]@{
    valid = $Valid
    errorCategory = $ErrorCategory
    jobs = @($Jobs)
  }
}

function Get-CodexBridgeWorkflowDecision {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$EventName,
    [AllowEmptyString()][string]$Ref = '',
    [AllowEmptyString()][string]$HeadRef = '',
    [AllowEmptyString()][string]$BaseRef = '',
    [AllowEmptyString()][string]$TestMode = '',
    [AllowEmptyString()][string]$Architecture = '',
    [AllowEmptyString()][string]$RequestedSourceCommit = '',
    [AllowEmptyString()][string]$WorkflowSha = ''
  )

  if ($EventName -ceq 'workflow_dispatch') {
    if ([string]::IsNullOrWhiteSpace($TestMode)) {
      return New-CodexBridgeWorkflowDecision $false 'dispatch_test_mode_missing' @()
    }
    if ($TestMode -cnotin @('standard', 'b1-compile-only', 'b1-package-inventory-only', 'b1-dependency-audit-only')) {
      return New-CodexBridgeWorkflowDecision $false 'dispatch_test_mode_invalid' @()
    }
    if ([string]::IsNullOrWhiteSpace($Architecture)) {
      return New-CodexBridgeWorkflowDecision $false 'dispatch_architecture_missing' @()
    }
    if ($Architecture -cnotin @('all', 'x64', 'arm64')) {
      return New-CodexBridgeWorkflowDecision $false 'dispatch_architecture_invalid' @()
    }
    if ($TestMode -ceq 'b1-dependency-audit-only') {
      if ($RequestedSourceCommit -notmatch '^[0-9a-fA-F]{40}$') {
        return New-CodexBridgeWorkflowDecision $false 'dispatch_dependency_audit_source_commit_invalid' @()
      }
      if ($WorkflowSha -notmatch '^[0-9a-fA-F]{40}$') {
        return New-CodexBridgeWorkflowDecision $false 'dispatch_dependency_audit_workflow_sha_invalid' @()
      }
      if (-not [string]::Equals($RequestedSourceCommit, $WorkflowSha, [StringComparison]::OrdinalIgnoreCase)) {
        return New-CodexBridgeWorkflowDecision $false 'dispatch_dependency_audit_source_commit_mismatch' @()
      }
    }

    $branch = $Ref -replace '^refs/heads/', ''
    if ($branch -ceq $script:GateABranch) {
      if ($TestMode -cne 'standard') {
        return New-CodexBridgeWorkflowDecision $false 'dispatch_gate_a_mode_invalid' @()
      }
      if ($Architecture -cne 'x64') {
        return New-CodexBridgeWorkflowDecision $false 'dispatch_gate_a_architecture_invalid' @()
      }
      return New-CodexBridgeWorkflowDecision $true '' @('mcp-route-tests')
    }
    if ($branch -ceq $script:GateB1Branch) {
      if ($Architecture -cne 'x64') {
        return New-CodexBridgeWorkflowDecision $false 'dispatch_gate_b1_architecture_invalid' @()
      }
      if ($TestMode -ceq 'standard') {
        return New-CodexBridgeWorkflowDecision $true '' @('mcp-exe-process-tests')
      }
      if ($TestMode -ceq 'b1-compile-only' -or
          $TestMode -ceq 'b1-package-inventory-only' -or
          $TestMode -ceq 'b1-dependency-audit-only') {
        return New-CodexBridgeWorkflowDecision $true '' @('mcp-exe-compile-only')
      }
      return New-CodexBridgeWorkflowDecision $false 'dispatch_gate_b1_mode_invalid' @()
    }
    if ($branch -ceq 'win' -or $branch -cmatch '^codex/platform-[^/]+$') {
      if ($TestMode -cne 'standard') {
        return New-CodexBridgeWorkflowDecision $false 'dispatch_formal_branch_mode_invalid' @()
      }
      return New-CodexBridgeWorkflowDecision $true '' @('build')
    }
    return New-CodexBridgeWorkflowDecision $false 'dispatch_ref_not_allowlisted' @()
  }

  if ($EventName -ceq 'push') {
    if ($Ref -ceq 'refs/heads/win' -or $Ref -cmatch '^refs/heads/codex/platform-[^/]+$') {
      return New-CodexBridgeWorkflowDecision $true '' @('build')
    }
    return New-CodexBridgeWorkflowDecision $true '' @()
  }

  if ($EventName -ceq 'pull_request') {
    if ($BaseRef -cne 'win') { return New-CodexBridgeWorkflowDecision $true '' @() }
    if ($HeadRef -cne $script:GateABranch -and $HeadRef -cne $script:GateB1Branch) {
      return New-CodexBridgeWorkflowDecision $true '' @('build')
    }
    return New-CodexBridgeWorkflowDecision $true '' @()
  }

  return New-CodexBridgeWorkflowDecision $true '' @()
}

function Get-CodexBridgeCompileStatusLines {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][int]$SwiftExitCode,
    [switch]$CompileAttempted
  )

  $lines = [Collections.Generic.List[string]]::new()
  if ($CompileAttempted) {
    if ($SwiftExitCode -eq 0) {
      [void]$lines.Add('COMPILE_PASS')
      [void]$lines.Add('B1_COMPILE_STATUS=PASS')
    } else {
      [void]$lines.Add('COMPILE_FAIL')
      [void]$lines.Add('B1_COMPILE_STATUS=FAIL')
    }
  } else {
    [void]$lines.Add('B1_COMPILE_STATUS=FAIL')
    [void]$lines.Add('B1_COMPILE_PHASE=NOT_REACHED')
  }
  [void]$lines.Add('B1_XCTEST_STATUS=NOT_RUN')
  [void]$lines.Add('B1_EXE_STATUS=NOT_RUN')
  [void]$lines.Add('B1_SCHEMA_STATUS=NOT_TESTED')
  [void]$lines.Add('B1_VM_STATUS=NOT_TESTED')
  [void]$lines.Add('B1_GATE_STATUS=NOT_PASSED')
  return $lines.ToArray()
}

Export-ModuleMember -Function Get-CodexBridgeWorkflowDecision, Get-CodexBridgeCompileStatusLines
