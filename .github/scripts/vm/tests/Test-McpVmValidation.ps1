$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot "..\McpVmValidation.psm1"
Import-Module $modulePath -Force
Import-Module (Join-Path $PSScriptRoot "..\McpVmSupervisor.psm1") -Force

function New-HostEvidence {
  return @{
    schema = "codex-bridge-b1-vm-host-evidence/v1"
    vmId = "9d468b50-193d-4531-84d1-0c3a799bb8ba"
    nonce = "synthetic-nonce-001"
    sourceCommit = "5d0e0904221a8185c66ae301ece3ea05e81810b4"
    expectedGuestAccountSid = "S-1-5-21-1000-2000-3000-1101"
    vmConfigurationSha256 = ("a" * 64)
    checks = @{
      VMN1 = @{ status = "PASS"; adapterCount = 0; assignedDeviceCount = 0; externalPathCount = 0 }
      VMN4 = @{
        status = "PASS"; enhancedSessionDisabled = $true; clipboardDisabled = $true
        guestServiceInterfaceDisabled = $true; dataExchangeDisabled = $true
        sharedFolderCount = 0; enabledIntegrationServiceCount = 0
        configuredComPortCount = 0; configuredFloppyDriveCount = 0
        fibreChannelAdapterCount = 0; gpuPartitionAdapterCount = 0
        expectedScratchDiskSet = $true; hardDiskPathsWithinRunRoot = $true
        outputDiskAttachedExactlyOnce = $true; offlineMediaAttachedReadOnly = $true
        unapprovedChannels = @()
      }
      VMN5 = @{
        status = "BLOCKED"; result = "VM_N5_BLOCKED"
        hashFormatStatus = "HASH_FORMAT_VALID"; hashIntegrityStatus = "HASH_INTEGRITY_NOT_CHECKED"
        trustAnchorStatus = "TRUST_ANCHOR_UNAVAILABLE"; reason = "vmn5_trust_anchor_unavailable"
        controllerSha256 = ("a" * 64); mediaManifestSha256 = ("b" * 64)
      }
    }
    build = @{
      runId = 41665722609
      productionCommit = "f2235028773e7d9e0da714218a5694c4eb8bfef3"
      portableZipSha256 = "3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d"
      serviceExeSha256 = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
    }
  }
}

function New-GuestEvidence {
  param([string]$HostEvidenceSha256 = ("e" * 64))
  return @{
    schema = "codex-bridge-b1-vm-guest-evidence/v1"
    vmId = "9d468b50-193d-4531-84d1-0c3a799bb8ba"
    nonce = "synthetic-nonce-001"
    hostEvidenceSha256 = $HostEvidenceSha256
    sourceCommit = "5d0e0904221a8185c66ae301ece3ea05e81810b4"
    checks = @{
      VMN2 = @{
        status = "PASS"; defaultRouteCount = 0; activeNonLoopbackAdapterCount = 0
        proxyPresent = $false; knownCredentialPresent = $false
        userIsAdministrator = $false; isolatedTestAccountMatched = $true
        realCodexConfigurationPresent = $false
      }
      VMN3 = @{ status = "PASS"; ipv4Loopback = $true }
      VMN4 = @{
        status = "PASS"; powerShellDirectServiceDisabled = $true
        powerShellDirectServiceStopped = $true; enhancedSessionDisconnected = $true
      }
    }
  }
}

function New-CleanupState {
  param([string]$Root)
  $candidateRoot = Join-Path $Root ("codex-bridge-vm-candidate-" + [guid]::NewGuid().ToString("N"))
  return @{
    pid = 4120
    launchState = "started"
    imagePath = Join-Path $candidateRoot "codex-bridge-service.exe"
    imageSha256 = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
    startedAtUtc = "2026-11-05T01:02:03.0000000Z"
    dataRoot = Join-Path $Root "codex-bridge-b1-data-synthetic"
    profileRoot = Join-Path $Root "codex-bridge-b1-profile-synthetic"
    captureDirectory = Join-Path $Root "codex-bridge-mcp-process-captures"
    sourceRoot = Join-Path $Root ("codex-bridge-vm-source-" + [guid]::NewGuid().ToString("N"))
    candidateRoot = $candidateRoot
  }
}

function New-CleanupBackend {
  param($State, $Record)
  return @{
    GetProcessById = {
      param($ProcessId)
      if ($State.pidIdentityUnknown) { return @{ processId = $ProcessId; path = "C:\unexpected.exe"; createdAtUtc = "2026-11-05T01:02:03.0000000Z" } }
      if ($State.processRunning) { return @{ processId = $ProcessId; path = $Record.imagePath; createdAtUtc = $Record.startedAtUtc } }
      return $null
    }.GetNewClosure()
    GetProcessesByPath = { param($Path) if ($State.otherCandidateProcesses) { return @(@{ processId = 9001; path = $Path }) }; return @() }.GetNewClosure()
    GetFileHash = { param($Path) return $State.fileHash }.GetNewClosure()
    GetDescendants = { param($ProcessId, $StartedAtUtc) return @($State.descendants) }.GetNewClosure()
    RequestShutdown = { param($Path) $State.shutdownCalls++; if ($State.shutdownFails) { return $false }; $State.processRunning = $false; return $true }.GetNewClosure()
    WaitForExit = { param($ProcessId, $StartedAtUtc, $TimeoutSeconds) return -not $State.processRunning }.GetNewClosure()
    WaitForDescendantsExit = { param($Items, $TimeoutSeconds) return $State.descendants.Count -eq 0 }.GetNewClosure()
    RemoveTemporaryPath = { param($Path) $State.removedPaths.Add($Path); if ($State.deleteFails) { throw "synthetic_temp_cleanup_failure" } }.GetNewClosure()
  }
}

function New-CleanupMock {
  return [pscustomobject]@{
    processRunning = $true
    pidIdentityUnknown = $false
    otherCandidateProcesses = $false
    fileHash = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
    descendants = @()
    shutdownCalls = 0
    shutdownFails = $false
    deleteFails = $false
    removedPaths = [Collections.Generic.List[string]]::new()
  }
}

function New-MediaManifest($Root) {
  $names = @(
    "portable-zip", "test-source-bundle", "swift-6.3.3-toolchain",
    "swiftpm-pinned-source-cache", "visual-studio-cpp-sdk", "windows-adk-oscdimg",
    "vcpkg-x64-windows-sqlite", "python-3.13.11-runtime",
    "python-3.13.11-wheelhouse", "windows-x64-base-image"
  )
  $dependencies = [Collections.Generic.List[object]]::new()
  foreach ($name in $names) {
    $relative = switch ($name) {
      "portable-zip" { "codex-bridge-windows-x64.zip"; break }
      "test-source-bundle" { "codex-bridge-vm-test-source.zip"; break }
      "swiftpm-pinned-source-cache" { "swiftpm-pinned-source-cache.zip"; break }
      default { "$name.synthetic" }
    }
    [IO.File]::WriteAllBytes((Join-Path $Root $relative), [Text.Encoding]::UTF8.GetBytes("synthetic-$name"))
    $digest = (Get-FileHash -LiteralPath (Join-Path $Root $relative) -Algorithm SHA256).Hash.ToLowerInvariant()
    $dependencies.Add(@{ name = $name; source = "synthetic-test"; version = "1"; path = $relative; sha256 = $digest })
  }
  return @{
    schema = "codex-bridge-b1-vm-media/v1"
    testSourceCommit = "5d0e0904221a8185c66ae301ece3ea05e81810b4"
    schemaSha256 = "EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203"
    build = @{
      runId = 41665722609
      productionCommit = "f2235028773e7d9e0da714218a5694c4eb8bfef3"
      portableZipSha256 = "3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d"
      serviceExeSha256 = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
    }
    dependencies = $dependencies.ToArray()
  }
}

function Assert-Equal($Actual, $Expected, [string]$Name) {
  if ($Actual -ne $Expected) { throw "assertion_failed_$Name`_actual=$Actual`_expected=$Expected" }
}

function Assert-Contains($Collection, [string]$Expected, [string]$Name) {
  if (@($Collection) -cnotcontains $Expected) { throw "assertion_failed_$Name`_missing=$Expected" }
}

$passed = 0
$root = Join-Path ([IO.Path]::GetTempPath()) ("mcp-vm-validation-mock-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null
try {
  $hostEvidence = New-HostEvidence
  $hostDigest = "f" * 64
  $hostResult = Test-McpVmHostEvidence -Evidence $hostEvidence -ExpectedVmId $hostEvidence.vmId `
    -ExpectedNonce $hostEvidence.nonce -ExpectedSourceCommit $hostEvidence.sourceCommit `
    -ActualSha256 $hostDigest -ExpectedSha256 $hostDigest
  Assert-Equal $hostResult.status "BLOCKED" "hash_format_does_not_attest_host"
  Assert-Contains $hostResult.reasons "vmn5_trust_anchor_unavailable" "n5_trust_anchor_required"
  $passed++; Write-Output "PASS test=valid-hash-without-trust-anchor-blocked"

  $n5Assessment = Get-McpVmN5Assessment -ConfigurationSha256 ("a" * 64)
  Assert-Equal $n5Assessment.hashFormatStatus "HASH_FORMAT_VALID" "n5_hash_format_stage"
  Assert-Equal $n5Assessment.hashIntegrityStatus "HASH_INTEGRITY_NOT_CHECKED" "n5_integrity_not_assumed"
  Assert-Equal $n5Assessment.trustAnchorStatus "TRUST_ANCHOR_UNAVAILABLE" "n5_anchor_unavailable"
  Assert-Equal $n5Assessment.result "VM_N5_BLOCKED" "n5_result_stays_blocked"
  $passed++; Write-Output "PASS test=n5-stages-separated-without-anchor"

  $n5Assessment = Get-McpVmN5Assessment -ConfigurationSha256 ("a" * 64) `
    -ExpectedConfigurationSha256 ("a" * 64)
  Assert-Equal $n5Assessment.hashIntegrityStatus "HASH_INTEGRITY_CHECKED" "n5_matching_digest_integrity-stage"
  Assert-Equal $n5Assessment.status "BLOCKED" "n5_integrity-check-does-not-attest-source"
  $passed++; Write-Output "PASS test=integrity-check-does-not-create-trust"

  $forgedN5Claim = @{
    status = "PASS"; result = "VM_N5_PASS"; hashFormatStatus = "HASH_FORMAT_VALID"
    hashIntegrityStatus = "HASH_INTEGRITY_CHECKED"; trustAnchorStatus = "TRUST_ANCHOR_VERIFIED"
  }
  Assert-Equal (Test-McpVmN5PassClaim -Claim $forgedN5Claim) $false "summary-cannot-promote-blocked-n5"
  $passed++; Write-Output "PASS test=forged-summary-n5-pass-claim-rejected"

  $hostEvidence = New-HostEvidence
  $replacedDigest = "c" * 64
  $hostEvidence.checks.VMN5.status = "PASS"
  $hostEvidence.checks.VMN5.result = "VM_N5_PASS"
  $hostEvidence.checks.VMN5.trustAnchorStatus = "TRUST_ANCHOR_VERIFIED"
  $hostResult = Test-McpVmHostEvidence -Evidence $hostEvidence -ExpectedVmId $hostEvidence.vmId `
    -ExpectedNonce $hostEvidence.nonce -ExpectedSourceCommit $hostEvidence.sourceCommit `
    -ActualSha256 $replacedDigest -ExpectedSha256 $replacedDigest
  Assert-Equal $hostResult.status "BLOCKED" "matching_replaced_state_and_sidecar_untrusted"
  Assert-Contains $hostResult.reasons "vmn5_trust_anchor_unavailable" "replacement_digest_not_trusted"
  $passed++; Write-Output "PASS test=state-and-sidecar-replaced-together-blocked"

  $hostEvidence = New-HostEvidence
  $guestEvidence = New-GuestEvidence
  $guestResult = Test-McpVmGuestEvidence -Evidence $guestEvidence -HostEvidence $hostEvidence `
    -ExpectedHostEvidenceSha256 $guestEvidence.hostEvidenceSha256 -ExpectedNonce $hostEvidence.nonce `
    -ExpectedSourceCommit $hostEvidence.sourceCommit
  Assert-Equal $guestResult.status "BLOCKED" "guest-cannot-promote-unauthenticated-host"
  Assert-Contains $guestResult.reasons "vmn5_trust_anchor_unavailable" "guest_n5_trust_anchor_required"
  $passed++; Write-Output "PASS test=valid-host-and-guest-evidence-without-anchor-blocked"

  $hostEvidence = New-HostEvidence
  $hostEvidence.checks.VMN5.status = "PASS"
  $hostEvidence.checks.VMN5.hashFormatStatus = "HASH_FORMAT_VALID"
  $hostEvidence.checks.VMN5.hashIntegrityStatus = "HASH_INTEGRITY_CHECKED"
  $hostEvidence.checks.VMN5.trustAnchorStatus = "TRUST_ANCHOR_VERIFIED"
  $hostEvidence.checks.VMN5.result = "VM_N5_PASS"
  $hostResult = Test-McpVmHostEvidence -Evidence $hostEvidence -ExpectedVmId $hostEvidence.vmId `
    -ExpectedNonce $hostEvidence.nonce -ExpectedSourceCommit $hostEvidence.sourceCommit `
    -ActualSha256 $hostDigest -ExpectedSha256 $hostDigest
  Assert-Equal $hostResult.status "BLOCKED" "forged_n5_promotion_rejected"
  Assert-Contains $hostResult.reasons "vmn5_trust_anchor_unavailable" "forged_anchor_fields_ignored"
  $passed++; Write-Output "PASS test=forged-n5-pass-claim-blocked"

  $hostEvidence.checks.VMN1.adapterCount = 1
  $blocked = Test-McpVmHostEvidence -Evidence $hostEvidence -ExpectedVmId $hostEvidence.vmId `
    -ExpectedNonce $hostEvidence.nonce -ExpectedSourceCommit $hostEvidence.sourceCommit `
    -ActualSha256 $hostDigest -ExpectedSha256 $hostDigest
  Assert-Equal $blocked.status "BLOCKED" "host_adapter_present"
  $passed++; Write-Output "PASS test=host-adapter-present-blocked"

  $hostEvidence = New-HostEvidence
  $hostEvidence.checks.VMN4.enhancedSessionDisabled = $false
  $blocked = Test-McpVmHostEvidence -Evidence $hostEvidence -ExpectedVmId $hostEvidence.vmId `
    -ExpectedNonce $hostEvidence.nonce -ExpectedSourceCommit $hostEvidence.sourceCommit `
    -ActualSha256 $hostDigest -ExpectedSha256 $hostDigest
  Assert-Equal $blocked.status "BLOCKED" "enhanced_session_enabled"
  $passed++; Write-Output "PASS test=unapproved-host-channel-blocked"

  $hostEvidence = New-HostEvidence
  $blocked = Test-McpVmHostEvidence -Evidence $hostEvidence -ExpectedVmId $hostEvidence.vmId `
    -ExpectedNonce $hostEvidence.nonce -ExpectedSourceCommit $hostEvidence.sourceCommit `
    -ActualSha256 $hostDigest -ExpectedSha256 ("0" * 64)
  Assert-Equal $blocked.status "BLOCKED" "host_digest_mismatch"
  $passed++; Write-Output "PASS test=host-evidence-digest-required"

  $hostEvidence = New-HostEvidence
  $guestEvidence = New-GuestEvidence
  $guestResult = Test-McpVmGuestEvidence -Evidence $guestEvidence -HostEvidence $hostEvidence `
    -ExpectedHostEvidenceSha256 $guestEvidence.hostEvidenceSha256 -ExpectedNonce $hostEvidence.nonce `
    -ExpectedSourceCommit $hostEvidence.sourceCommit
  Assert-Equal $guestResult.status "BLOCKED" "guest_evidence_cannot_validate_host_n5"
  Assert-Contains $guestResult.reasons "vmn5_trust_anchor_unavailable" "guest_requires_independent_host_anchor"
  $guestEvidence.checks.VMN2.defaultRouteCount = 1
  $blocked = Test-McpVmGuestEvidence -Evidence $guestEvidence -HostEvidence $hostEvidence `
    -ExpectedHostEvidenceSha256 $guestEvidence.hostEvidenceSha256 -ExpectedNonce $hostEvidence.nonce `
    -ExpectedSourceCommit $hostEvidence.sourceCommit
  Assert-Equal $blocked.status "BLOCKED" "guest_default_route_present"
  $passed++; Write-Output "PASS test=guest-network-evidence-fail-closed"

  $hostEvidence = New-HostEvidence
  $guestEvidence = New-GuestEvidence
  $guestEvidence.checks.VMN2.isolatedTestAccountMatched = $false
  $blocked = Test-McpVmGuestEvidence -Evidence $guestEvidence -HostEvidence $hostEvidence `
    -ExpectedHostEvidenceSha256 $guestEvidence.hostEvidenceSha256 -ExpectedNonce $hostEvidence.nonce `
    -ExpectedSourceCommit $hostEvidence.sourceCommit
  Assert-Equal $blocked.status "BLOCKED" "guest_test_account_identity_mismatch"
  $passed++; Write-Output "PASS test=isolated-guest-account-identity-required"

  $mediaManifestRoot = Join-Path $root "media-manifest-valid"
  New-Item -ItemType Directory -Path $mediaManifestRoot | Out-Null
  $mediaManifest = New-MediaManifest $mediaManifestRoot
  $mediaResult = Test-McpVmMediaManifest -Manifest $mediaManifest -MediaRoot $mediaManifestRoot `
    -ExpectedTestSourceCommit $mediaManifest.testSourceCommit `
    -HashFile { param($Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
  Assert-Equal $mediaResult.status "PASS" "complete_media_manifest"
  $passed++; Write-Output "PASS test=complete-offline-media-manifest"

  $missingRoot = Join-Path $root "media-manifest-missing"
  New-Item -ItemType Directory -Path $missingRoot | Out-Null
  $missingManifest = New-MediaManifest $missingRoot
  $missingManifest.dependencies = @($missingManifest.dependencies | Select-Object -Skip 1)
  $mediaResult = Test-McpVmMediaManifest -Manifest $missingManifest -MediaRoot $missingRoot `
    -ExpectedTestSourceCommit $missingManifest.testSourceCommit `
    -HashFile { param($Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
  Assert-Equal $mediaResult.status "BLOCKED" "missing_offline_media_dependency"
  $passed++; Write-Output "PASS test=missing-offline-dependency-blocked"

  $duplicateRoot = Join-Path $root "media-manifest-duplicate"
  New-Item -ItemType Directory -Path $duplicateRoot | Out-Null
  $duplicateManifest = New-MediaManifest $duplicateRoot
  [IO.File]::WriteAllBytes((Join-Path $duplicateRoot "duplicate.synthetic"), [Text.Encoding]::UTF8.GetBytes("duplicate"))
  $duplicateHash = (Get-FileHash -LiteralPath (Join-Path $duplicateRoot "duplicate.synthetic") -Algorithm SHA256).Hash.ToLowerInvariant()
  $duplicateManifest.dependencies += @{ name = "portable-zip"; source = "synthetic-test"; version = "1"; path = "duplicate.synthetic"; sha256 = $duplicateHash }
  $mediaResult = Test-McpVmMediaManifest -Manifest $duplicateManifest -MediaRoot $duplicateRoot `
    -ExpectedTestSourceCommit $duplicateManifest.testSourceCommit `
    -HashFile { param($Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
  Assert-Equal $mediaResult.status "BLOCKED" "duplicate_offline_media_dependency"
  $passed++; Write-Output "PASS test=duplicate-offline-dependency-blocked"

  $cleanup = New-CleanupMock
  $record = New-CleanupState $root
  $record.imagePath = Join-Path $record.candidateRoot "codex-bridge-service.exe"
  $record.dataRoot = Join-Path $root "codex-bridge-b1-data-synthetic"
  $record.profileRoot = Join-Path $root "codex-bridge-b1-profile-synthetic"
  $record.captureDirectory = Join-Path $root "codex-bridge-mcp-process-captures"
  $backend = New-CleanupBackend $cleanup $record
  $result = Invoke-McpVmServiceCleanup -Record $record -CandidatePath $record.imagePath `
    -ExpectedSha256 $record.imageSha256 -RunnerTemp $root -Backend $backend -CandidateDirectory $record.candidateRoot
  Assert-Equal $result.serviceExit "PASS" "service_cleanup_complete"
  Assert-Equal $result.temporaryCleanup "PASS" "temporary_cleanup_complete"
  Assert-Equal $cleanup.shutdownCalls 1 "shutdown_once"
  $passed++; Write-Output "PASS test=verified-service-shutdown-and-cleanup"

  $cleanup = New-CleanupMock
  $cleanup.processRunning = $false
  $record = New-CleanupState $root
  $record.pid = 0
  $record.launchState = "prepared"
  $record.startedAtUtc = ""
  $backend = New-CleanupBackend $cleanup $record
  $result = Invoke-McpVmServiceCleanup -Record $record -CandidatePath $record.imagePath `
    -ExpectedSha256 $record.imageSha256 -RunnerTemp $root -Backend $backend -CandidateDirectory $record.candidateRoot
  Assert-Equal $result.serviceExit "PASS" "prelaunch_no_process"
  Assert-Equal $result.temporaryCleanup "PASS" "prelaunch_safe_cleanup"
  Assert-Equal $cleanup.shutdownCalls 0 "prelaunch_no_shutdown"
  $passed++; Write-Output "PASS test=prepared-no-process-cleanup"

  $cleanup = New-CleanupMock
  $cleanup.otherCandidateProcesses = $true
  $record = New-CleanupState $root
  $record.pid = 0
  $record.launchState = "prepared"
  $record.startedAtUtc = ""
  $backend = New-CleanupBackend $cleanup $record
  $blocked = Invoke-McpVmServiceCleanup -Record $record -CandidatePath $record.imagePath `
    -ExpectedSha256 $record.imageSha256 -RunnerTemp $root -Backend $backend -CandidateDirectory $record.candidateRoot
  Assert-Equal $blocked.serviceExit "BLOCKED" "prepared_unassociated_process"
  Assert-Equal $cleanup.shutdownCalls 0 "prepared_process_no_shutdown"
  Assert-Equal $cleanup.removedPaths.Count 0 "prepared_process_no_delete"
  $passed++; Write-Output "PASS test=prepared-record-with-unknown-process-blocked"

  $cleanup = New-CleanupMock
  $record = New-CleanupState $root
  $record.pid = 0
  $record.launchState = "launching"
  $record.startedAtUtc = ""
  $backend = New-CleanupBackend $cleanup $record
  $blocked = Invoke-McpVmServiceCleanup -Record $record -CandidatePath $record.imagePath `
    -ExpectedSha256 $record.imageSha256 -RunnerTemp $root -Backend $backend -CandidateDirectory $record.candidateRoot
  Assert-Equal $blocked.serviceExit "BLOCKED" "launch-intent-without-pid-blocked"
  Assert-Equal $cleanup.shutdownCalls 0 "launch-intent-no-unverified-shutdown"
  Assert-Equal $cleanup.removedPaths.Count 0 "launch-intent-no-temp-deletion"
  $passed++; Write-Output "PASS test=launching-state-without-pid-blocked"

  $cleanup = New-CleanupMock
  $cleanup.pidIdentityUnknown = $true
  $record = New-CleanupState $root
  $backend = New-CleanupBackend $cleanup $record
  $blocked = Invoke-McpVmServiceCleanup -Record $record -CandidatePath $record.imagePath `
    -ExpectedSha256 $record.imageSha256 -RunnerTemp $root -Backend $backend -CandidateDirectory $record.candidateRoot
  Assert-Equal $blocked.serviceExit "BLOCKED" "unknown_pid_image"
  Assert-Equal $cleanup.shutdownCalls 0 "unknown_pid_no_shutdown"
  Assert-Equal $cleanup.removedPaths.Count 0 "unknown_pid_no_delete"
  $passed++; Write-Output "PASS test=unknown-process-identity-no-kill-or-delete"

  $cleanup = New-CleanupMock
  $cleanup.fileHash = "0" * 64
  $record = New-CleanupState $root
  $backend = New-CleanupBackend $cleanup $record
  $blocked = Invoke-McpVmServiceCleanup -Record $record -CandidatePath $record.imagePath `
    -ExpectedSha256 $record.imageSha256 -RunnerTemp $root -Backend $backend -CandidateDirectory $record.candidateRoot
  Assert-Equal $blocked.serviceExit "BLOCKED" "service_hash_mismatch"
  Assert-Equal $cleanup.shutdownCalls 0 "hash_mismatch_no_shutdown"
  $passed++; Write-Output "PASS test=service-hash-mismatch-blocked"

  $cleanup = New-CleanupMock
  $cleanup.shutdownFails = $true
  $record = New-CleanupState $root
  $backend = New-CleanupBackend $cleanup $record
  $blocked = Invoke-McpVmServiceCleanup -Record $record -CandidatePath $record.imagePath `
    -ExpectedSha256 $record.imageSha256 -RunnerTemp $root -Backend $backend -CandidateDirectory $record.candidateRoot
  Assert-Equal $blocked.serviceExit "BLOCKED" "shutdown_failure"
  Assert-Equal $cleanup.removedPaths.Count 0 "shutdown_failure_no_delete"
  $passed++; Write-Output "PASS test=shutdown-failure-retains-temp-data"

  $cleanup = New-CleanupMock
  $cleanup.descendants = @(@{
    processId = 9002; path = "C:\unexpected\child.exe"; createdAtUtc = "2026-11-05T01:02:04.0000000Z"
  })
  $record = New-CleanupState $root
  $backend = New-CleanupBackend $cleanup $record
  $blocked = Invoke-McpVmServiceCleanup -Record $record -CandidatePath $record.imagePath `
    -ExpectedSha256 $record.imageSha256 -RunnerTemp $root -Backend $backend -CandidateDirectory $record.candidateRoot
  Assert-Equal $blocked.descendants "BLOCKED" "unknown_child_blocked"
  Assert-Equal $cleanup.shutdownCalls 1 "verified_service_shutdown_even_with_unknown_child"
  Assert-Equal $cleanup.removedPaths.Count 0 "unknown_child_no_delete"
  $passed++; Write-Output "PASS test=unknown-child-blocks-cleanup"

  $cleanup = New-CleanupMock
  $cleanup.deleteFails = $true
  $record = New-CleanupState $root
  $backend = New-CleanupBackend $cleanup $record
  $blocked = Invoke-McpVmServiceCleanup -Record $record -CandidatePath $record.imagePath `
    -ExpectedSha256 $record.imageSha256 -RunnerTemp $root -Backend $backend -CandidateDirectory $record.candidateRoot
  Assert-Equal $blocked.serviceExit "PASS" "cleanup_failure_service_exit_remains_pass"
  Assert-Equal $blocked.temporaryCleanup "BLOCKED" "cleanup_failure_blocked"
  $passed++; Write-Output "PASS test=partial-cleanup-failure-blocked"

  $tempFile = Join-Path $root "codex-bridge-vm-protocol-summary-synthetic.json"
  [IO.File]::WriteAllText($tempFile, "synthetic-summary")
  Remove-McpVmSafeTemporaryFile -Path $tempFile -RunnerTemp $root -ExpectedName "codex-bridge-vm-protocol-summary-synthetic.json"
  Assert-Equal (Test-Path -LiteralPath $tempFile) $false "diagnostic_file_removed"
  $passed++; Write-Output "PASS test=verified-temp-evidence-file-cleanup"

  $tempFile = Join-Path $root "unexpected-summary.json"
  [IO.File]::WriteAllText($tempFile, "synthetic-summary")
  $identityBlocked = $false
  try { Remove-McpVmSafeTemporaryFile -Path $tempFile -RunnerTemp $root -ExpectedName "codex-bridge-vm-protocol-summary-synthetic.json" }
  catch { $identityBlocked = $true }
  Assert-Equal $identityBlocked $true "diagnostic_file_name_mismatch_blocked"
  Assert-Equal (Test-Path -LiteralPath $tempFile) $true "mismatched_file_retained"
  $passed++; Write-Output "PASS test=temp-evidence-file-name-mismatch-blocked"

  $nestedRoot = Join-Path $root "nested"
  New-Item -ItemType Directory -Path $nestedRoot | Out-Null
  $tempFile = Join-Path $nestedRoot "codex-bridge-vm-protocol-summary-synthetic.json"
  [IO.File]::WriteAllText($tempFile, "synthetic-summary")
  $pathBlocked = $false
  try { Remove-McpVmSafeTemporaryFile -Path $tempFile -RunnerTemp $root -ExpectedName "codex-bridge-vm-protocol-summary-synthetic.json" }
  catch { $pathBlocked = $true }
  Assert-Equal $pathBlocked $true "diagnostic_file_outside_direct_child_blocked"
  Assert-Equal (Test-Path -LiteralPath $tempFile) $true "outside_file_retained"
  $passed++; Write-Output "PASS test=temp-evidence-file-path-mismatch-blocked"

  $vmRoot = Join-Path $PSScriptRoot ".."
  $hostControllerText = Get-Content -LiteralPath (Join-Path $vmRoot "Invoke-McpVmHostController.ps1") -Raw
  $isoBuilderText = Get-Content -LiteralPath (Join-Path $vmRoot "New-McpVmEvidenceIso.ps1") -Raw
  $guestHarnessText = Get-Content -LiteralPath (Join-Path $vmRoot "Invoke-McpVmGuestHarness.ps1") -Raw
  $importText = Get-Content -LiteralPath (Join-Path $vmRoot "Import-McpVmGuestSummary.ps1") -Raw
  $finalizerText = Get-Content -LiteralPath (Join-Path $vmRoot "Complete-McpVmHostRun.ps1") -Raw
  $pythonValidatorText = Get-Content -LiteralPath (Join-Path $vmRoot "validate-mcp-vm-captures.py") -Raw
  foreach ($assertion in @(
    @{ ok = $hostControllerText.Contains('Get-McpVmN5Assessment'); name = 'host-controller-assessment' },
    @{ ok = $hostControllerText.Contains('hashIntegrityStatus = $n5Assessment.hashIntegrityStatus'); name = 'host-controller-stage-reporting' },
    @{ ok = $isoBuilderText.Contains('Test-McpVmN5TrustAnchorAvailable'); name = 'iso-trust-anchor-gate' },
    @{ ok = $guestHarnessText.Contains('VMN5 = "BLOCKED"'); name = 'guest-summary-hard-blocked' },
    @{ ok = $guestHarnessText.Contains('stage=guest-preflight VMN5=BLOCKED error_category=vmn5_trust_anchor_unavailable'); name = 'guest-service-start-blocked' },
    @{ ok = $importText.Contains('$summary.vmIsolation.VMN5 -cne ''BLOCKED'''); name = 'import-n5-claim-checked' },
    @{ ok = $finalizerText.Contains('Test-McpVmN5PassClaim'); name = 'finalizer-cannot-promote-n5' },
    @{ ok = $pythonValidatorText.Contains('VMN5_TRUST_ANCHOR_CONFIGURED = False'); name = 'python-validator-anchor-absent' },
    @{ ok = $pythonValidatorText.Contains('("BLOCKED" if name == "VMN5" else "NOT_TESTED")'); name = 'python-summary-keeps-n5-blocked' }
  )) {
    Assert-Equal $assertion.ok $true $assertion.name
  }
  $passed++; Write-Output "PASS test=n5-blocked-propagates-across-vm-entrypoints"

  if ($passed -ne 28) { throw "mock_test_count_mismatch_$passed" }
  Write-Output "PASS test=vm-validation-summary executed=$passed failures=0"
} finally {
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
