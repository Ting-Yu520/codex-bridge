[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $true)][guid]$VMId,
  [Parameter(Mandatory = $true)][string]$RunRoot,
  [Parameter(Mandatory = $true)][string]$GuestSummaryPath,
  [Parameter(Mandatory = $true)][string]$GuestSummarySha256,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{32,64}$')][string]$ExpectedNonce,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSourceCommit,
  [Parameter(Mandatory = $true)][string]$OfflineMediaIsoPath,
  [Parameter(Mandatory = $true)][string]$HostEvidenceIsoPath,
  [Parameter(Mandatory = $true)][string]$ExpectedMediaIsoSha256,
  [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
  [Parameter(Mandatory = $true)][string]$ConfirmVMId,
  [switch]$DestroyIsolatedVM
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module (Join-Path $PSScriptRoot 'McpVmValidation.psm1') -Force
$state = $null
$preRemovalReport = $null

function Get-FileSha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Assert-PathUnder([string]$Root, [string]$Path) {
  $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $full = [IO.Path]::GetFullPath($Path)
  if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { throw 'path_outside_run_root' }
  $rootItem = Get-Item -LiteralPath $rootFull.TrimEnd('\', '/') -Force -ErrorAction Stop
  if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse_root_not_allowed' }
  $relative = $full.Substring($rootFull.Length)
  $cursor = $rootFull.TrimEnd('\', '/')
  foreach ($part in ($relative -split '[\\/]')) {
    if (-not $part) { continue }
    $cursor = Join-Path $cursor $part
    $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse_point_not_allowed' }
  }
  return $full
}

function Test-GuestSummarySafeToRemove($Summary) {
  $allowedFields = @('reportSchema', 'vmId', 'nonce', 'sourceCommit', 'buildRunId', 'productionCommit', 'portableSha256', 'serviceExeSha256', 'schemaSha256', 'vmIsolation', 'windows', 'servicePid', 'serviceImage', 'serviceProcessStatus', 'portableIdentityAfterRun', 'serviceEgressObservation', 'routeTests', 'responses', 'swiftTestsExecuted', 'swiftTestFailures', 'schemaValidation', 'serviceExit', 'descendantExit', 'cleanup', 'vmShutdown', 'vmDestruction', 'overall')
  if ($Summary.PSObject.Properties.Name | Where-Object { $_ -notin $allowedFields }) { return $false }
  if ($Summary.reportSchema -cne 'codex-bridge-b1-vm-run-report/v1' -or
      $Summary.vmId -cne $VMId.ToString().ToLowerInvariant() -or
      $Summary.nonce -cne $ExpectedNonce -or
      $Summary.sourceCommit -cne $ExpectedSourceCommit -or
      $Summary.buildRunId -ne 41665722609 -or
      $Summary.productionCommit -cne 'f2235028773e7d9e0da714218a5694c4eb8bfef3' -or
      $Summary.portableSha256 -cne '3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d' -or
      $Summary.serviceExeSha256 -cne '428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521' -or
      $Summary.schemaSha256 -cne 'EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203' -or
      $Summary.vmIsolation.VMN5 -cne 'BLOCKED' -or
      $Summary.serviceImage -cne 'candidate-relative:codex-bridge-service.exe' -or
      $Summary.serviceProcessStatus -notin @('EXITED', 'NOT_STARTED', 'BLOCKED') -or
      $Summary.portableIdentityAfterRun -notin @('PASS', 'FAIL', 'NOT_TESTED') -or
      $Summary.serviceEgressObservation -cne 'NOT_OBSERVED' -or
      $Summary.cleanup -cne 'PASS' -or $Summary.vmShutdown -notin @('REQUESTED', 'NOT_REQUESTED')) { return $false }
  if ($Summary.serviceProcessStatus -eq 'EXITED') {
    if ($Summary.serviceExit -cne 'PASS' -or $Summary.descendantExit -cne 'PASS' -or [int]$Summary.servicePid -le 0) { return $false }
  } elseif ($Summary.serviceProcessStatus -eq 'NOT_STARTED') {
    if ($Summary.serviceExit -notin @('PASS', 'NOT_STARTED') -or
        $Summary.descendantExit -notin @('PASS', 'NOT_TESTED') -or [int]$Summary.servicePid -gt 0) { return $false }
  } else { return $false }
  $allowedRoutes = @('server-discover', 'tools-list', 'resources-list', 'resources-read', 'resources-read-invalid')
  if ($Summary.routeTests) {
    foreach ($property in $Summary.routeTests.PSObject.Properties) {
      if ($property.Name -notin $allowedRoutes -or $property.Value -notin @('PASS', 'FAIL', 'NOT_TESTED')) { return $false }
    }
  }
  if ($Summary.responses) {
    foreach ($property in $Summary.responses.PSObject.Properties) {
      if ($property.Name -notin $allowedRoutes -or $property.Value -notmatch '^[a-f0-9]{64}$') { return $false }
    }
  }
  return $true
}

function Test-GuestSummaryPassed($Summary) {
  if (-not (Test-McpVmN5PassClaim -Claim $Summary.vmIsolation.VMN5)) { return $false }
  if ($Summary.overall -cne 'PENDING_HOST_FINALIZER' -or $Summary.schemaValidation -cne 'PASS' -or
      $Summary.serviceExit -cne 'PASS' -or $Summary.descendantExit -cne 'PASS' -or
      $Summary.cleanup -cne 'PASS' -or $Summary.vmShutdown -cne 'REQUESTED' -or
      $Summary.windows.architecture -cne 'x64' -or $Summary.swiftTestsExecuted -ne 1 -or
      $Summary.swiftTestFailures -ne 0) { return $false }
  if ($Summary.portableIdentityAfterRun -cne 'PASS') { return $false }
  if ($Summary.serviceProcessStatus -cne 'EXITED' -or [int]$Summary.servicePid -le 0) { return $false }
  foreach ($name in @('VMN1', 'VMN2', 'VMN3', 'VMN4', 'VMN5')) {
    if ($Summary.vmIsolation.$name -cne 'PASS') { return $false }
  }
  $expectedRoutes = @('server-discover', 'tools-list', 'resources-list', 'resources-read', 'resources-read-invalid')
  if (-not $Summary.routeTests -or -not $Summary.responses -or
      $Summary.routeTests.PSObject.Properties.Count -ne $expectedRoutes.Count -or
      $Summary.responses.PSObject.Properties.Count -ne $expectedRoutes.Count) { return $false }
  foreach ($name in $expectedRoutes) {
    $route = $Summary.routeTests.PSObject.Properties[$name]
    $response = $Summary.responses.PSObject.Properties[$name]
    if ($null -eq $route -or $route.Value -cne 'PASS' -or $null -eq $response -or
        $response.Value -notmatch '^[a-f0-9]{64}$') { return $false }
  }
  return $true
}

try {
  if (-not $DestroyIsolatedVM -or $ConfirmVMId -cne $VMId.ToString()) { throw 'explicit_vm_destruction_confirmation_required' }
  if ($RunRoot -notmatch '[\\/]codex-bridge-vm-[0-9a-fA-F-]{36}$') { throw 'run_root_not_unique' }
  if ($GuestSummarySha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'guest_summary_hash_missing' }
  if ($ExpectedMediaIsoSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'offline_media_digest_missing' }
  $runRootFull = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\', '/')
  $summaryPath = Assert-PathUnder $runRootFull $GuestSummaryPath
  if ([IO.Path]::GetFileName($summaryPath) -cne 'vm-guest-summary.json') { throw 'guest_summary_name_invalid' }
  $summarySidecarPath = Join-Path (Split-Path -Parent $summaryPath) 'vm-guest-summary.sha256'
  [void](Assert-PathUnder $runRootFull $summarySidecarPath)
  $sidecarLine = (Get-Content -LiteralPath $summarySidecarPath -Raw -Encoding ASCII).Trim()
  if ($sidecarLine -notmatch '^([A-Fa-f0-9]{64})  vm-guest-summary\.json$' -or $Matches[1].ToLowerInvariant() -cne $GuestSummarySha256.ToLowerInvariant()) {
    throw 'guest_summary_sidecar_mismatch'
  }
  $evidenceRoot = [IO.Path]::GetFullPath($EvidenceDirectory)
  if (-not $evidenceRoot.StartsWith($runRootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'evidence_directory_outside_run_root'
  }
  if (-not (Test-Path -LiteralPath $evidenceRoot -PathType Container)) { throw 'evidence_directory_missing' }
  [void](Assert-PathUnder $runRootFull $evidenceRoot)
  if (Test-Path -LiteralPath (Join-Path $evidenceRoot 'vm-host-finalization.json')) { throw 'finalization_evidence_already_exists' }
  if ((Get-FileSha256 $summaryPath) -cne $GuestSummarySha256.ToLowerInvariant()) { throw 'guest_summary_digest_mismatch' }
  $summary = Get-Content -LiteralPath $summaryPath -Raw -Encoding UTF8 | ConvertFrom-Json
  if (-not (Test-GuestSummarySafeToRemove $summary)) { throw 'guest_report_not_safe_for_cleanup' }

  $vmMatches = @(Get-VM -Id $VMId -ErrorAction Stop | Where-Object { $_.Id -eq $VMId })
  if ($vmMatches.Count -ne 1) { throw 'vm_identity_not_unique' }
  $vm = $vmMatches[0]
  if ([string]$vm.State -cne 'Off') { throw 'vm_not_confirmed_off' }
  if (@(Get-VMSnapshot -VM $vm -ErrorAction Stop).Count -ne 0) { throw 'unexpected_checkpoint_present' }
  if (@(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop).Count -ne 0 -or
      @(Get-VMAssignableDevice -VMName $vm.Name -ErrorAction Stop).Count -ne 0) { throw 'vm_network_or_passthrough_device_present' }
  if ((Get-VMHost -ErrorAction Stop).EnableEnhancedSessionMode -ne $false) { throw 'enhanced_session_not_disabled' }
  if (@(Get-VMIntegrationService -VMName $vm.Name -ErrorAction Stop | Where-Object { $_.Enabled }).Count -ne 0) {
    throw 'enabled_integration_service_present'
  }
  if (@(Get-VMComPort -VMName $vm.Name -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Path) }).Count -ne 0 -or
      @(Get-VMFloppyDiskDrive -VMName $vm.Name -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Path) }).Count -ne 0 -or
      @(Get-VMFibreChannelHba -VMName $vm.Name -ErrorAction Stop).Count -ne 0 -or
      @(Get-VMGpuPartitionAdapter -VMName $vm.Name -ErrorAction Stop).Count -ne 0) {
    throw 'unapproved_host_guest_channel_present'
  }
  $mediaIsoFull = [IO.Path]::GetFullPath($OfflineMediaIsoPath)
  $evidenceIsoFull = [IO.Path]::GetFullPath($HostEvidenceIsoPath)
  [void](Assert-PathUnder $runRootFull $evidenceIsoFull)
  if ((Get-FileSha256 $mediaIsoFull) -cne $ExpectedMediaIsoSha256.ToLowerInvariant()) { throw 'offline_media_digest_mismatch' }
  $dvdDrives = @(Get-VMDvdDrive -VMName $vm.Name -ErrorAction Stop)
  if ($dvdDrives.Count -ne 2 -or
      @($dvdDrives | Where-Object { $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $mediaIsoFull }).Count -ne 1 -or
      @($dvdDrives | Where-Object { $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $evidenceIsoFull }).Count -ne 1) {
    throw 'vm_virtual_media_layout_changed'
  }

  $diskDrives = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
  if ($diskDrives.Count -ne 1) { throw 'expected_output_disk_detached_before_finalization' }
  $diskPaths = @($diskDrives | ForEach-Object { [IO.Path]::GetFullPath([string]$_.Path) })
  $osDiskPath = [IO.Path]::GetFullPath((Join-Path $runRootFull 'vm-os.vhdx'))
  $outputDiskPath = [IO.Path]::GetFullPath((Join-Path $runRootFull 'vm-output.vhdx'))
  $expectedDiskPaths = @($osDiskPath, $outputDiskPath)
  $actualDiskSet = @($diskPaths | Sort-Object) -join "`n"
  $expectedDiskSet = $osDiskPath
  if ($actualDiskSet -cne $expectedDiskSet) { throw 'virtual_disk_identity_mismatch' }
  foreach ($path in $diskPaths) {
    [void](Assert-PathUnder $runRootFull $path)
  }
  [void](Assert-PathUnder $runRootFull $outputDiskPath)
  foreach ($otherVm in @(Get-VM -ErrorAction Stop | Where-Object { $_.Id -ne $VMId })) {
    $outputReferences = @(Get-VMHardDiskDrive -VM $otherVm -ErrorAction Stop | Where-Object {
      $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $outputDiskPath
    })
    if ($outputReferences.Count -gt 0) { throw 'output_disk_referenced_by_other_vm' }
  }

  $state = [ordered]@{
    reportSchema = 'codex-bridge-b1-vm-host-finalization/v1'
    vmId = $VMId.ToString().ToLowerInvariant()
    nonce = $ExpectedNonce
    sourceCommit = $ExpectedSourceCommit
    guestSummarySha256 = $GuestSummarySha256.ToLowerInvariant()
    serviceExit = $summary.serviceExit
    serviceProcessStatus = $summary.serviceProcessStatus
    portableIdentityAfterRun = $summary.portableIdentityAfterRun
    serviceEgressObservation = $summary.serviceEgressObservation
    schemaValidation = $summary.schemaValidation
    vmN5Status = 'BLOCKED'
    vmN5Reason = 'vmn5_trust_anchor_unavailable'
    testOutcome = if (Test-GuestSummaryPassed $summary) { 'PASS' } else { 'FAIL_OR_BLOCKED' }
    vmBoundary = 'PASS'
    vmPowerState = 'OFF'
    vmConfigurationRemoval = 'NOT_STARTED'
    scratchDiskRemoval = 'NOT_STARTED'
    removedScratchDiskCount = 0
    scratchDiskSha256 = @()
    overall = 'BLOCKED'
  }
  if (-not (Test-Path -LiteralPath $evidenceRoot)) { New-Item -ItemType Directory -Path $evidenceRoot -ErrorAction Stop | Out-Null }
  $preRemovalReport = Join-Path $evidenceRoot 'vm-host-finalization.json'
  [IO.File]::WriteAllText($preRemovalReport, (($state | ConvertTo-Json -Depth 8) + "`n"), [Text.UTF8Encoding]::new($false))
  if (-not $PSCmdlet.ShouldProcess($VMId.ToString(), 'Remove isolated Hyper-V VM and its two scratch VHDX files')) { throw 'host_finalization_not_confirmed' }

  Remove-VM -VM $vm -Force -ErrorAction Stop
  if (@(Get-VM -Id $VMId -ErrorAction SilentlyContinue).Count -ne 0) { throw 'vm_configuration_removal_unconfirmed' }
  $state.vmConfigurationRemoval = 'PASS'
  foreach ($path in $expectedDiskPaths) {
    foreach ($remainingVm in @(Get-VM -ErrorAction Stop)) {
      $references = @(Get-VMHardDiskDrive -VM $remainingVm -ErrorAction Stop | Where-Object {
        $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $path
      })
      if ($references.Count -gt 0) { throw 'scratch_disk_referenced_by_other_vm' }
    }
    $image = Get-DiskImage -ImagePath $path -ErrorAction Stop
    if ($null -eq $image -or $image.Attached -ne $false) { throw 'scratch_disk_attached_after_vm_removal' }
    $state.scratchDiskSha256 += [pscustomobject]@{
      file = [IO.Path]::GetFileName($path)
      sha256 = Get-FileSha256 $path
    }
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $path) { throw 'scratch_disk_removal_unconfirmed' }
    $state.removedScratchDiskCount++
    $state.scratchDiskRemoval = if ($state.removedScratchDiskCount -eq $expectedDiskPaths.Count) { 'PASS' } else { 'PARTIAL' }
  }
  $state.overall = if ($state.testOutcome -eq 'PASS') { 'PASS' } else { 'FAIL_OR_BLOCKED' }
  [IO.File]::WriteAllText($preRemovalReport, (($state | ConvertTo-Json -Depth 8) + "`n"), [Text.UTF8Encoding]::new($false))
  $digest = Get-FileSha256 $preRemovalReport
  [IO.File]::WriteAllText((Join-Path $evidenceRoot 'vm-host-finalization.sha256'), "$digest  vm-host-finalization.json`n", [Text.UTF8Encoding]::new($false))
  Write-Output "PASS test=vm-finalized VMN5=$($state.vmN5Status) gate=$($state.overall) vm_configuration=removed scratch_disks=removed report_sha256=$digest"
} catch {
  if ($state -and $preRemovalReport) {
    try {
      [IO.File]::WriteAllText($preRemovalReport, (($state | ConvertTo-Json -Depth 8) + "`n"), [Text.UTF8Encoding]::new($false))
      $partialDigest = Get-FileSha256 $preRemovalReport
      [IO.File]::WriteAllText((Join-Path $evidenceRoot 'vm-host-finalization.sha256'), "$partialDigest  vm-host-finalization.json`n", [Text.UTF8Encoding]::new($false))
    } catch { }
  }
  Write-Output 'BLOCKED stage=host-finalization error_category=vm_state_report_or_cleanup_unverified'
  exit 2
}
