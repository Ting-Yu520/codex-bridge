Set-StrictMode -Version Latest

$script:ExpectedBuildRunId = 41665722609
$script:ExpectedProductionCommit = "f2235028773e7d9e0da714218a5694c4eb8bfef3"
$script:ExpectedPortableZipSha256 = "3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d"
$script:ExpectedServiceExeSha256 = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
$script:ExpectedSchemaSha256 = "EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203"
$script:RequiredMediaDependencyNames = @(
  "portable-zip",
  "test-source-bundle",
  "swift-6.3.3-toolchain",
  "swiftpm-pinned-source-cache",
  "visual-studio-cpp-sdk",
  "windows-adk-oscdimg",
  "vcpkg-x64-windows-sqlite",
  "python-3.13.11-runtime",
  "python-3.13.11-wheelhouse",
  "windows-x64-base-image"
)
$script:RequiredMediaDependencyPaths = @{
  "portable-zip" = "codex-bridge-windows-x64.zip"
  "test-source-bundle" = "codex-bridge-vm-test-source.zip"
  "swiftpm-pinned-source-cache" = "swiftpm-pinned-source-cache.zip"
}

function Get-McpVmField($Object, [string]$Name) {
  if ($null -eq $Object) { return $null }
  if ($Object -is [Collections.IDictionary]) {
    if ($Object.Contains($Name)) { return $Object[$Name] }
    return $null
  }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -ne $property) { return $property.Value }
  return $null
}

function Test-McpVmSha256([string]$Value) {
  return $Value -cmatch '^[A-Fa-f0-9]{64}$'
}

function Test-McpVmN5TrustAnchorAvailable {
  # No independent, authenticated host-evidence anchor is configured for this VM workflow.
  # This function intentionally has no parameter or environment-variable override.
  return $false
}

function Test-McpVmN5PassClaim {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)]$Claim)

  if (-not (Test-McpVmN5TrustAnchorAvailable)) { return $false }
  return (Get-McpVmField $Claim "status") -ceq "PASS" -and
    (Get-McpVmField $Claim "result") -ceq "VM_N5_PASS" -and
    (Get-McpVmField $Claim "hashFormatStatus") -ceq "HASH_FORMAT_VALID" -and
    (Get-McpVmField $Claim "hashIntegrityStatus") -ceq "HASH_INTEGRITY_CHECKED" -and
    (Get-McpVmField $Claim "trustAnchorStatus") -ceq "TRUST_ANCHOR_VERIFIED"
}

function Get-McpVmN5Assessment {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$ConfigurationSha256,
    [AllowNull()][string]$ExpectedConfigurationSha256
  )

  $formatStatus = if (Test-McpVmSha256 $ConfigurationSha256) { "HASH_FORMAT_VALID" } else { "HASH_FORMAT_INVALID" }
  $integrityStatus = "HASH_INTEGRITY_NOT_CHECKED"
  if (-not [string]::IsNullOrWhiteSpace($ExpectedConfigurationSha256)) {
    $integrityStatus = if ((Test-McpVmSha256 $ConfigurationSha256) -and
      (Test-McpVmSha256 $ExpectedConfigurationSha256) -and
      $ConfigurationSha256 -ieq $ExpectedConfigurationSha256) {
      "HASH_INTEGRITY_CHECKED"
    } else {
      "HASH_INTEGRITY_MISMATCH"
    }
  }

  return [pscustomobject]@{
    status = "BLOCKED"
    result = "VM_N5_BLOCKED"
    hashFormatStatus = $formatStatus
    hashIntegrityStatus = $integrityStatus
    trustAnchorStatus = "TRUST_ANCHOR_UNAVAILABLE"
    reason = "vmn5_trust_anchor_unavailable"
  }
}

function New-McpVmEvidenceResult([string]$Status, [string[]]$Reasons) {
  return [pscustomobject]@{
    status = $Status
    reasons = @($Reasons)
  }
}

function Test-McpVmHostEvidence {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]$Evidence,
    [Parameter(Mandatory = $true)][string]$ExpectedVmId,
    [Parameter(Mandatory = $true)][string]$ExpectedNonce,
    [Parameter(Mandatory = $true)][string]$ExpectedSourceCommit,
    [Parameter(Mandatory = $true)][string]$ActualSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256
  )

  $reasons = [Collections.Generic.List[string]]::new()
  if ((Get-McpVmField $Evidence "schema") -ne "codex-bridge-b1-vm-host-evidence/v1") {
    $reasons.Add("host_schema_invalid")
  }
  if ((Get-McpVmField $Evidence "vmId") -ne $ExpectedVmId) { $reasons.Add("host_vm_identity_mismatch") }
  if ((Get-McpVmField $Evidence "nonce") -ne $ExpectedNonce) { $reasons.Add("host_nonce_mismatch") }
  if ((Get-McpVmField $Evidence "sourceCommit") -ne $ExpectedSourceCommit) {
    $reasons.Add("host_source_commit_mismatch")
  }
  if ([string](Get-McpVmField $Evidence "expectedGuestAccountSid") -notmatch '^S-1-5-21(-[0-9]{1,12}){4}$') {
    $reasons.Add("host_expected_test_account_identity_missing")
  }
  if (-not (Test-McpVmSha256 $ActualSha256) -or
      -not (Test-McpVmSha256 $ExpectedSha256) -or
      $ActualSha256 -cne $ExpectedSha256) {
    $reasons.Add("host_evidence_digest_mismatch")
  }

  $checks = Get-McpVmField $Evidence "checks"
  $n1 = Get-McpVmField $checks "VMN1"
  $n4 = Get-McpVmField $checks "VMN4"
  $n5 = Get-McpVmField $checks "VMN5"
  if ((Get-McpVmField $n1 "status") -ne "PASS" -or
      [int](Get-McpVmField $n1 "adapterCount") -ne 0 -or
      [int](Get-McpVmField $n1 "assignedDeviceCount") -ne 0 -or
      [int](Get-McpVmField $n1 "externalPathCount") -ne 0) {
    $reasons.Add("vmn1_host_network_boundary_unverified")
  }
  if ((Get-McpVmField $n4 "status") -ne "PASS" -or
      (Get-McpVmField $n4 "enhancedSessionDisabled") -ne $true -or
      (Get-McpVmField $n4 "clipboardDisabled") -ne $true -or
      (Get-McpVmField $n4 "guestServiceInterfaceDisabled") -ne $true -or
      (Get-McpVmField $n4 "dataExchangeDisabled") -ne $true -or
      [int](Get-McpVmField $n4 "sharedFolderCount") -ne 0 -or
      [int](Get-McpVmField $n4 "enabledIntegrationServiceCount") -ne 0 -or
      [int](Get-McpVmField $n4 "configuredComPortCount") -ne 0 -or
      [int](Get-McpVmField $n4 "configuredFloppyDriveCount") -ne 0 -or
      [int](Get-McpVmField $n4 "fibreChannelAdapterCount") -ne 0 -or
      [int](Get-McpVmField $n4 "gpuPartitionAdapterCount") -ne 0 -or
      (Get-McpVmField $n4 "expectedScratchDiskSet") -ne $true -or
      (Get-McpVmField $n4 "hardDiskPathsWithinRunRoot") -ne $true -or
      (Get-McpVmField $n4 "outputDiskAttachedExactlyOnce") -ne $true -or
      (Get-McpVmField $n4 "offlineMediaAttachedReadOnly") -ne $true -or
      @((Get-McpVmField $n4 "unapprovedChannels")).Count -ne 0) {
    $reasons.Add("vmn4_host_channel_boundary_unverified")
  }
  $configurationSha256 = [string](Get-McpVmField $Evidence "vmConfigurationSha256")
  $n5Assessment = Get-McpVmN5Assessment -ConfigurationSha256 $configurationSha256
  if ((Get-McpVmField $n5 "status") -cne $n5Assessment.status -or
      (Get-McpVmField $n5 "result") -cne $n5Assessment.result -or
      (Get-McpVmField $n5 "hashFormatStatus") -cne $n5Assessment.hashFormatStatus -or
      (Get-McpVmField $n5 "hashIntegrityStatus") -cne $n5Assessment.hashIntegrityStatus -or
      (Get-McpVmField $n5 "trustAnchorStatus") -cne $n5Assessment.trustAnchorStatus -or
      (Get-McpVmField $n5 "reason") -cne $n5Assessment.reason -or
      -not (Test-McpVmSha256 ([string](Get-McpVmField $n5 "controllerSha256"))) -or
      -not (Test-McpVmSha256 ([string](Get-McpVmField $n5 "mediaManifestSha256")))) {
    $reasons.Add("vmn5_status_claim_untrusted")
  }
  if (-not (Test-McpVmN5TrustAnchorAvailable)) { $reasons.Add("vmn5_trust_anchor_unavailable") }

  $build = Get-McpVmField $Evidence "build"
  if ([long](Get-McpVmField $build "runId") -ne $script:ExpectedBuildRunId -or
      (Get-McpVmField $build "productionCommit") -ne $script:ExpectedProductionCommit -or
      (Get-McpVmField $build "portableZipSha256") -cne $script:ExpectedPortableZipSha256 -or
      (Get-McpVmField $build "serviceExeSha256") -cne $script:ExpectedServiceExeSha256) {
    $reasons.Add("host_candidate_build_identity_mismatch")
  }

  $status = if ($reasons.Count -eq 0) { "PASS" } else { "BLOCKED" }
  return New-McpVmEvidenceResult $status $reasons.ToArray()
}

function Test-McpVmGuestEvidence {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]$Evidence,
    [Parameter(Mandatory = $true)]$HostEvidence,
    [Parameter(Mandatory = $true)][string]$ExpectedHostEvidenceSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedNonce,
    [Parameter(Mandatory = $true)][string]$ExpectedSourceCommit
  )

  $reasons = [Collections.Generic.List[string]]::new()
  if ((Get-McpVmField $Evidence "schema") -ne "codex-bridge-b1-vm-guest-evidence/v1") {
    $reasons.Add("guest_schema_invalid")
  }
  if ((Get-McpVmField $Evidence "nonce") -ne $ExpectedNonce -or
      (Get-McpVmField $HostEvidence "nonce") -ne $ExpectedNonce) {
    $reasons.Add("guest_host_nonce_mismatch")
  }
  if ((Get-McpVmField $Evidence "vmId") -ne (Get-McpVmField $HostEvidence "vmId")) {
    $reasons.Add("guest_host_vm_identity_mismatch")
  }
  if ((Get-McpVmField $Evidence "sourceCommit") -ne $ExpectedSourceCommit -or
      (Get-McpVmField $HostEvidence "sourceCommit") -ne $ExpectedSourceCommit) {
    $reasons.Add("guest_source_commit_mismatch")
  }
  if ([string](Get-McpVmField $HostEvidence "expectedGuestAccountSid") -notmatch '^S-1-5-21(-[0-9]{1,12}){4}$') {
    $reasons.Add("guest_expected_test_account_identity_missing")
  }
  if (-not (Test-McpVmSha256 $ExpectedHostEvidenceSha256) -or
      (Get-McpVmField $Evidence "hostEvidenceSha256") -cne $ExpectedHostEvidenceSha256) {
    $reasons.Add("guest_host_evidence_digest_mismatch")
  }

  $hostChecks = Get-McpVmField $HostEvidence "checks"
  foreach ($name in @("VMN1", "VMN4")) {
    if ((Get-McpVmField (Get-McpVmField $hostChecks $name) "status") -ne "PASS") {
      $reasons.Add("host_$($name.ToLowerInvariant())_not_pass")
    }
  }
  $hostN5 = Get-McpVmField $hostChecks "VMN5"
  if ((Get-McpVmField $hostN5 "status") -cne "BLOCKED" -or
      (Get-McpVmField $hostN5 "result") -cne "VM_N5_BLOCKED" -or
      (Get-McpVmField $hostN5 "trustAnchorStatus") -cne "TRUST_ANCHOR_UNAVAILABLE") {
    $reasons.Add("host_vmn5_status_claim_untrusted")
  }
  if (-not (Test-McpVmN5TrustAnchorAvailable)) { $reasons.Add("vmn5_trust_anchor_unavailable") }
  $guestChecks = Get-McpVmField $Evidence "checks"
  $n2 = Get-McpVmField $guestChecks "VMN2"
  $n3 = Get-McpVmField $guestChecks "VMN3"
  $n4 = Get-McpVmField $guestChecks "VMN4"
  if ((Get-McpVmField $n2 "status") -ne "PASS" -or
      [int](Get-McpVmField $n2 "defaultRouteCount") -ne 0 -or
      [int](Get-McpVmField $n2 "activeNonLoopbackAdapterCount") -ne 0 -or
      (Get-McpVmField $n2 "isolatedTestAccountMatched") -ne $true -or
      (Get-McpVmField $n2 "proxyPresent") -ne $false -or
      (Get-McpVmField $n2 "knownCredentialPresent") -ne $false -or
      (Get-McpVmField $n2 "userIsAdministrator") -ne $false -or
      (Get-McpVmField $n2 "realCodexConfigurationPresent") -ne $false) {
    $reasons.Add("vmn2_guest_network_state_unverified")
  }
  if ((Get-McpVmField $n3 "status") -ne "PASS" -or
      (Get-McpVmField $n3 "ipv4Loopback") -ne $true) {
    $reasons.Add("vmn3_guest_loopback_unverified")
  }
  if ((Get-McpVmField $n4 "status") -ne "PASS" -or
      (Get-McpVmField $n4 "powerShellDirectServiceDisabled") -ne $true -or
      (Get-McpVmField $n4 "powerShellDirectServiceStopped") -ne $true -or
      (Get-McpVmField $n4 "enhancedSessionDisconnected") -ne $true) {
    $reasons.Add("vmn4_guest_management_channel_unverified")
  }

  $status = if ($reasons.Count -eq 0) { "PASS" } else { "BLOCKED" }
  return New-McpVmEvidenceResult $status $reasons.ToArray()
}

function Test-McpVmMediaManifest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]$Manifest,
    [Parameter(Mandatory = $true)][string]$MediaRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedTestSourceCommit,
    [Parameter(Mandatory = $true)][scriptblock]$HashFile
  )

  $reasons = [Collections.Generic.List[string]]::new()
  if ((Get-McpVmField $Manifest "schema") -ne "codex-bridge-b1-vm-media/v1") {
    $reasons.Add("media_manifest_schema_invalid")
  }
  if ((Get-McpVmField $Manifest "testSourceCommit") -ne $ExpectedTestSourceCommit) {
    $reasons.Add("media_test_source_commit_mismatch")
  }
  if ((Get-McpVmField $Manifest "schemaSha256") -cne $script:ExpectedSchemaSha256) {
    $reasons.Add("media_schema_digest_mismatch")
  }
  $build = Get-McpVmField $Manifest "build"
  if ([long](Get-McpVmField $build "runId") -ne $script:ExpectedBuildRunId -or
      (Get-McpVmField $build "productionCommit") -ne $script:ExpectedProductionCommit -or
      (Get-McpVmField $build "portableZipSha256") -cne $script:ExpectedPortableZipSha256 -or
      (Get-McpVmField $build "serviceExeSha256") -cne $script:ExpectedServiceExeSha256) {
    $reasons.Add("media_candidate_build_identity_mismatch")
  }

  $dependencies = @(Get-McpVmField $Manifest "dependencies")
  if ($dependencies.Count -eq 0) { $reasons.Add("media_dependency_manifest_empty") }
  $dependencyNames = [Collections.Generic.List[string]]::new()
  $root = [IO.Path]::GetFullPath($MediaRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  foreach ($dependency in $dependencies) {
    $name = [string](Get-McpVmField $dependency "name")
    $source = [string](Get-McpVmField $dependency "source")
    $version = [string](Get-McpVmField $dependency "version")
    $relativePath = [string](Get-McpVmField $dependency "path")
    $expectedHash = [string](Get-McpVmField $dependency "sha256")
    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($source) -or
        [string]::IsNullOrWhiteSpace($version) -or -not (Test-McpVmSha256 $expectedHash) -or
        [string]::IsNullOrWhiteSpace($relativePath) -or [IO.Path]::IsPathRooted($relativePath) -or
        ($relativePath -split '[\\/]') -contains '..') {
      $reasons.Add("media_dependency_metadata_incomplete")
      continue
    }
    if ($dependencyNames.Contains($name)) { $reasons.Add("media_dependency_name_duplicate") }
    $dependencyNames.Add($name)
    if ($script:RequiredMediaDependencyPaths.ContainsKey($name) -and
        $relativePath.Replace('\', '/') -cne $script:RequiredMediaDependencyPaths[$name]) {
      $reasons.Add("media_dependency_path_mismatch")
    }
    $fullPath = [IO.Path]::GetFullPath((Join-Path $root $relativePath))
    if (-not $fullPath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
      $reasons.Add("media_dependency_file_missing_or_outside")
      continue
    }
    $actualHash = [string](& $HashFile $fullPath)
    if (-not (Test-McpVmSha256 $actualHash) -or $actualHash.ToLowerInvariant() -cne $expectedHash.ToLowerInvariant()) {
      $reasons.Add("media_dependency_digest_mismatch")
    }
  }
  $actualNames = (@($dependencyNames | Sort-Object -Unique) -join "`n")
  $requiredNames = (@($script:RequiredMediaDependencyNames | Sort-Object -Unique) -join "`n")
  if ($actualNames -cne $requiredNames) { $reasons.Add("media_required_dependency_set_mismatch") }

  $status = if ($reasons.Count -eq 0) { "PASS" } else { "BLOCKED" }
  return New-McpVmEvidenceResult $status $reasons.ToArray()
}

function Test-McpVmCleanupPath([string]$Root, [string]$Path, [string]$ExpectedLeaf) {
  if ([string]::IsNullOrWhiteSpace($Root) -or [string]::IsNullOrWhiteSpace($Path)) { return $false }
  $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
  $fullPath = [IO.Path]::GetFullPath($Path)
  return [IO.Path]::GetDirectoryName($fullPath).TrimEnd('\', '/') -ieq $rootPath -and
    [IO.Path]::GetFileName($fullPath).StartsWith($ExpectedLeaf, [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-McpVmServiceCleanup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]$Record,
    [Parameter(Mandatory = $true)][string]$CandidatePath,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256,
    [Parameter(Mandatory = $true)][string]$RunnerTemp,
    [Parameter(Mandatory = $true)][hashtable]$Backend,
    [Parameter(Mandatory = $true)][string]$CandidateDirectory,
    [switch]$SkipTemporaryCleanup
  )

  $result = [ordered]@{
    serviceExit = "BLOCKED"
    descendants = "NOT_TESTED"
    temporaryCleanup = "BLOCKED"
    errorCategory = $null
  }
  $operations = @(
    "GetProcessById", "GetProcessesByPath", "GetFileHash", "GetDescendants",
    "RequestShutdown", "WaitForExit", "WaitForDescendantsExit", "RemoveTemporaryPath"
  )
  foreach ($operation in $operations) {
    if (-not $Backend.ContainsKey($operation) -or $Backend[$operation] -isnot [scriptblock]) {
      $result.errorCategory = "supervisor_backend_invalid"
      return [pscustomobject]$result
    }
  }

  $servicePid = [int](Get-McpVmField $Record "pid")
  $recordedPath = [string](Get-McpVmField $Record "imagePath")
  $recordedHash = [string](Get-McpVmField $Record "imageSha256")
  $startedAtUtc = [string](Get-McpVmField $Record "startedAtUtc")
  $launchState = [string](Get-McpVmField $Record "launchState")
  $preparedWithoutPid = $servicePid -eq 0 -and $launchState -ceq "prepared"
  if (($servicePid -le 0 -and -not $preparedWithoutPid) -or
      (-not $preparedWithoutPid -and [string]::IsNullOrWhiteSpace($startedAtUtc)) -or
      -not (Test-McpVmSha256 $ExpectedSha256) -or -not (Test-McpVmSha256 $recordedHash) -or
      $recordedHash.ToLowerInvariant() -cne $ExpectedSha256.ToLowerInvariant()) {
    $result.errorCategory = "service_record_identity_incomplete"
    return [pscustomobject]$result
  }
  try {
    $candidateFull = [IO.Path]::GetFullPath($CandidatePath)
    $recordedFull = [IO.Path]::GetFullPath($recordedPath)
    if ($candidateFull -ine $recordedFull) {
      $result.errorCategory = "service_record_path_mismatch"
      return [pscustomobject]$result
    }
    foreach ($entry in @(
      @{ name = "dataRoot"; prefix = "codex-bridge-b1-data-" },
      @{ name = "profileRoot"; prefix = "codex-bridge-b1-profile-" },
      @{ name = "captureDirectory"; prefix = "codex-bridge-mcp-process-captures" },
      @{ name = "sourceRoot"; prefix = "codex-bridge-vm-source-" },
      @{ name = "candidateRoot"; prefix = "codex-bridge-vm-candidate-" }
    )) {
      if (-not (Test-McpVmCleanupPath -Root $RunnerTemp -Path ([string](Get-McpVmField $Record $entry.name)) -ExpectedLeaf $entry.prefix)) {
        $result.errorCategory = "temporary_cleanup_path_unverified"
        return [pscustomobject]$result
      }
    }
    $actualHash = [string](& $Backend.GetFileHash $candidateFull)
    if ($actualHash.ToLowerInvariant() -cne $ExpectedSha256.ToLowerInvariant()) {
      $result.errorCategory = "service_exe_hash_mismatch"
      return [pscustomobject]$result
    }
    if (-not $preparedWithoutPid) { $expectedStart = [DateTime]::Parse($startedAtUtc).ToUniversalTime() }
  } catch {
    $result.errorCategory = "service_identity_unverified"
    return [pscustomobject]$result
  }

  if ($preparedWithoutPid) {
    try {
      $unassociated = @(& $Backend.GetProcessesByPath $candidateFull)
      if ($unassociated.Count -gt 0) {
        $result.errorCategory = "candidate_process_present_without_pid_record"
        return [pscustomobject]$result
      }
      $result.serviceExit = "PASS"
      $result.descendants = "PASS"
    } catch {
      $result.errorCategory = "service_cleanup_process_inventory_failed"
      return [pscustomobject]$result
    }
  } else {
    try {
      $process = & $Backend.GetProcessById $servicePid
      if ($null -eq $process) {
        $samePath = @(& $Backend.GetProcessesByPath $candidateFull)
        if ($samePath.Count -gt 0) {
          $result.errorCategory = "unassociated_candidate_process_present"
          return [pscustomobject]$result
        }
        $leftoverDescendants = @(& $Backend.GetDescendants $servicePid $startedAtUtc)
        if ($leftoverDescendants.Count -gt 0) {
          $result.descendants = "BLOCKED"
          $result.errorCategory = "service_descendant_remains_after_parent_exit"
          return [pscustomobject]$result
        }
        $result.serviceExit = "PASS"
        $result.descendants = "PASS"
      } else {
        $processPath = [IO.Path]::GetFullPath([string](Get-McpVmField $process "path"))
        $processStart = [DateTime]::Parse([string](Get-McpVmField $process "createdAtUtc")).ToUniversalTime()
        if ([int](Get-McpVmField $process "processId") -ne $servicePid -or $processPath -ine $candidateFull -or
            [Math]::Abs(($processStart - $expectedStart).TotalSeconds) -gt 4) {
          $result.errorCategory = "service_pid_image_identity_mismatch"
          return [pscustomobject]$result
        }
        $descendants = @(& $Backend.GetDescendants $servicePid $startedAtUtc)
        $unknownDescendant = $false
        $candidateDirectoryFull = [IO.Path]::GetFullPath($CandidateDirectory).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        foreach ($child in $descendants) {
          $childPathValue = [string](Get-McpVmField $child "path")
          if ([int](Get-McpVmField $child "processId") -le 0 -or
              [string]::IsNullOrWhiteSpace($childPathValue) -or
              [string]::IsNullOrWhiteSpace([string](Get-McpVmField $child "createdAtUtc"))) {
            $unknownDescendant = $true
            continue
          }
          $childPath = [IO.Path]::GetFullPath($childPathValue)
          if (-not $childPath.StartsWith($candidateDirectoryFull, [StringComparison]::OrdinalIgnoreCase)) {
            $unknownDescendant = $true
          }
        }
        if (-not (& $Backend.RequestShutdown $candidateFull)) {
          $result.errorCategory = "service_shutdown_request_failed"
          return [pscustomobject]$result
        }
        if (-not (& $Backend.WaitForExit $servicePid $startedAtUtc 60)) {
          $result.errorCategory = "service_exit_unconfirmed"
          return [pscustomobject]$result
        }
        $result.serviceExit = "PASS"
        $remainingDescendants = @(& $Backend.GetDescendants $servicePid $startedAtUtc)
        if ($unknownDescendant) {
          $result.descendants = "BLOCKED"
          $result.errorCategory = "service_descendant_identity_unverified"
          return [pscustomobject]$result
        }
        if ($remainingDescendants.Count -eq 0 -and (& $Backend.WaitForDescendantsExit -Items $descendants -TimeoutSeconds 30)) {
          $result.descendants = "PASS"
        } else {
          $result.descendants = "BLOCKED"
          $result.errorCategory = "service_descendant_remains"
          return [pscustomobject]$result
        }
        $remaining = @(& $Backend.GetProcessesByPath $candidateFull)
        if ($remaining.Count -gt 0) {
          $result.serviceExit = "BLOCKED"
          $result.errorCategory = "candidate_process_remains"
          return [pscustomobject]$result
        }
      }
    } catch {
      $result.serviceExit = "BLOCKED"
      $result.errorCategory = "service_cleanup_backend_failed"
      return [pscustomobject]$result
    }
  }

  if ($result.serviceExit -ne "PASS" -or $result.descendants -ne "PASS") { return [pscustomobject]$result }
  if ($SkipTemporaryCleanup) {
    $result.temporaryCleanup = "NOT_TESTED"
    return [pscustomobject]$result
  }
  try {
    foreach ($name in @("captureDirectory", "sourceRoot", "candidateRoot", "profileRoot", "dataRoot")) {
      & $Backend.RemoveTemporaryPath ([string](Get-McpVmField $Record $name))
    }
    $result.temporaryCleanup = "PASS"
  } catch {
    $result.temporaryCleanup = "BLOCKED"
    $result.errorCategory = "temporary_cleanup_failed"
  }
  return [pscustomobject]$result
}

Export-ModuleMember -Function Test-McpVmN5TrustAnchorAvailable, Test-McpVmN5PassClaim, Get-McpVmN5Assessment, Test-McpVmHostEvidence, Test-McpVmGuestEvidence, Test-McpVmMediaManifest, Invoke-McpVmServiceCleanup
