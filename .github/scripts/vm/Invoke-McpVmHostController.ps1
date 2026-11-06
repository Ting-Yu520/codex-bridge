[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][ValidateSet("Collect", "Recheck")][string]$Mode,
  [Parameter(Mandatory = $true)][guid]$VMId,
  [Parameter(Mandatory = $true)][string]$RunRoot,
  [Parameter(Mandatory = $true)][string]$MediaRoot,
  [Parameter(Mandatory = $true)][string]$MediaManifestPath,
  [Parameter(Mandatory = $true)][string]$OfflineMediaIsoPath,
  [Parameter(Mandatory = $true)][string]$HostEvidenceIsoPath,
  [Parameter(Mandatory = $true)][string]$ExpectedMediaIsoSha256,
  [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{40}$")][string]$TestSourceCommit,
  [Parameter(Mandatory = $true)][ValidatePattern("^[0-9a-f]{32,64}$")][string]$Nonce,
  [Parameter(Mandatory = $true)][ValidatePattern('^S-1-5-21(-[0-9]{1,12}){4}$')][string]$ExpectedGuestAccountSid,
  [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
  [string]$ExistingHostEvidencePath
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$modulePath = Join-Path $PSScriptRoot "McpVmValidation.psm1"
Import-Module $modulePath -Force

function Get-PathSha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Get-BytesSha256([byte[]]$Bytes) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Assert-NoReparsePath([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "path_reparse_point"
  }
}

function Get-HostVmSnapshot($VM) {
  $adapters = @(Get-VMNetworkAdapter -VMName $VM.Name -ErrorAction Stop)
  $assignedDevices = @(Get-VMAssignableDevice -VMName $VM.Name -ErrorAction Stop)
  $hostSettings = Get-VMHost -ErrorAction Stop
  $integrationServices = @(Get-VMIntegrationService -VMName $VM.Name -ErrorAction Stop)
  $enabledIntegrationServices = @($integrationServices | Where-Object { $_.Enabled } | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
  $serviceStates = @{}
  foreach ($serviceName in @("Guest Service Interface", "Shutdown", "VSS")) {
    $matches = @($integrationServices | Where-Object { $_.Name -eq $serviceName })
    if ($matches.Count -ne 1) { throw "integration_service_inventory_incomplete" }
    $serviceStates[$serviceName] = [bool]$matches[0].Enabled
  }
  $exchangeMatches = @($integrationServices | Where-Object { $_.Name -in @("Data Exchange", "Key-Value Pair Exchange") })
  if ($exchangeMatches.Count -ne 1) { throw "data_exchange_service_inventory_incomplete" }
  $serviceStates["Data Exchange"] = [bool]$exchangeMatches[0].Enabled
  $hardDisks = @(Get-VMHardDiskDrive -VMName $VM.Name -ErrorAction Stop)
  $dvdDrives = @(Get-VMDvdDrive -VMName $VM.Name -ErrorAction Stop)
  $configuredComPorts = @(Get-VMComPort -VMName $VM.Name -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Path) })
  $configuredFloppyDrives = @(Get-VMFloppyDiskDrive -VMName $VM.Name -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Path) })
  $fibreChannelAdapters = @(Get-VMFibreChannelHba -VMName $VM.Name -ErrorAction Stop)
  $gpuPartitionAdapters = @(Get-VMGpuPartitionAdapter -VMName $VM.Name -ErrorAction Stop)
  $outputDiskFull = [IO.Path]::GetFullPath($script:OutputDiskPath)
  $attachedOutput = @($hardDisks | Where-Object {
    $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $outputDiskFull
  })
  $expectedDiskNames = @("vm-os.vhdx", "vm-output.vhdx")
  $actualDiskNames = @($hardDisks | ForEach-Object { [IO.Path]::GetFileName([string]$_.Path) } | Sort-Object -Unique)
  $expectedDiskSet = $hardDisks.Count -eq 2 -and ((@($actualDiskNames | Sort-Object) -join "`n") -ceq (@($expectedDiskNames | Sort-Object) -join "`n"))
  $runRootFull = [IO.Path]::GetFullPath($script:RunRootFull).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $diskPathsWithinRunRoot = $hardDisks.Count -gt 0
  $diskPathHashes = [Collections.Generic.List[string]]::new()
  foreach ($drive in $hardDisks) {
    if ([string]::IsNullOrWhiteSpace($drive.Path)) { $diskPathsWithinRunRoot = $false; continue }
    $full = [IO.Path]::GetFullPath($drive.Path)
    if (-not $full.StartsWith($runRootFull, [StringComparison]::OrdinalIgnoreCase)) {
      $diskPathsWithinRunRoot = $false
    }
    $diskPathsWithinRunRoot = $diskPathsWithinRunRoot -and (Test-Path -LiteralPath $full -PathType Leaf)
    $diskPathsWithinRunRoot = $diskPathsWithinRunRoot -and ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
    $diskPathsWithinRunRoot = $diskPathsWithinRunRoot -and $attachedOutput.Count -eq 1 -and $expectedDiskSet
    $diskPathHashes.Add((Get-StringSetSha256 @($full)))
  }
  $mediaIsoFull = [IO.Path]::GetFullPath($script:OfflineMediaIsoFull)
  $evidenceIsoFull = [IO.Path]::GetFullPath($script:HostEvidenceIsoFull)
  $evidenceIsoPrefix = [IO.Path]::GetFullPath($script:RunRootFull).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $evidenceIsoPathSafe = $evidenceIsoFull.StartsWith($evidenceIsoPrefix, [StringComparison]::OrdinalIgnoreCase) -and
    [IO.Path]::GetFileName($evidenceIsoFull) -eq "vm-evidence.iso" -and
    (Test-Path -LiteralPath $evidenceIsoFull -PathType Leaf)
  $attachedMedia = @($dvdDrives | Where-Object {
    $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $mediaIsoFull
  })
  $attachedEvidence = @($dvdDrives | Where-Object {
    $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $evidenceIsoFull
  })
  $noOtherDVD = $dvdDrives.Count -eq 2 -and $attachedMedia.Count -eq 1 -and
    $attachedEvidence.Count -eq 1 -and $evidenceIsoPathSafe
  $enhancedSessionDisabled = $hostSettings.EnableEnhancedSessionMode -eq $false
  $gsiDisabled = $serviceStates["Guest Service Interface"] -eq $false
  $dataExchangeDisabled = $serviceStates["Data Exchange"] -eq $false
  $unapprovedChannels = [Collections.Generic.List[string]]::new()
  if (-not $enhancedSessionDisabled) { $unapprovedChannels.Add("enhanced-session") }
  if (-not $gsiDisabled) { $unapprovedChannels.Add("guest-service-interface") }
  if (-not $dataExchangeDisabled) { $unapprovedChannels.Add("key-value-exchange") }
  if ($serviceStates["Shutdown"]) { $unapprovedChannels.Add("host-shutdown-integration") }
  if ($serviceStates["VSS"]) { $unapprovedChannels.Add("guest-vss-integration") }
  if ($enabledIntegrationServices.Count -gt 0) { $unapprovedChannels.Add("enabled-integration-service") }
  if ($configuredComPorts.Count -gt 0) { $unapprovedChannels.Add("configured-com-port") }
  if ($configuredFloppyDrives.Count -gt 0) { $unapprovedChannels.Add("configured-floppy-drive") }
  if ($fibreChannelAdapters.Count -gt 0) { $unapprovedChannels.Add("fibre-channel-adapter") }
  if ($gpuPartitionAdapters.Count -gt 0) { $unapprovedChannels.Add("gpu-partition-adapter") }
  if (-not $diskPathsWithinRunRoot -or -not $noOtherDVD) { $unapprovedChannels.Add("unverified-virtual-media-layout") }

  $observations = [ordered]@{
    provider = "Hyper-V"
    networkAdapterCount = $adapters.Count
    assignedDeviceCount = $assignedDevices.Count
    externalPathCount = $adapters.Count + $assignedDevices.Count
    configuredComPortCount = $configuredComPorts.Count
    configuredFloppyDriveCount = $configuredFloppyDrives.Count
    fibreChannelAdapterCount = $fibreChannelAdapters.Count
    gpuPartitionAdapterCount = $gpuPartitionAdapters.Count
    enhancedSessionEnabled = -not $enhancedSessionDisabled
    clipboardDisabled = $enhancedSessionDisabled
    guestServiceInterfaceEnabled = -not $gsiDisabled
    dataExchangeEnabled = -not $dataExchangeDisabled
    sharedFolderCount = if ($gsiDisabled) { 0 } else { -1 }
    unapprovedChannels = @($unapprovedChannels)
    attachedHardDiskCount = $hardDisks.Count
    expectedScratchDiskSet = $expectedDiskSet
    hardDiskPathsWithinRunRoot = $diskPathsWithinRunRoot
    outputDiskAttachedExactlyOnce = $attachedOutput.Count -eq 1
    offlineMediaAttachedReadOnly = $noOtherDVD
    offlineMediaSha256 = Get-PathSha256 $mediaIsoFull
    hostEvidenceIsoPathSha256 = (Get-StringSetSha256 @($evidenceIsoFull))
    hardDiskPathSetSha256 = (Get-StringSetSha256 $diskPathHashes.ToArray())
    integrationServiceStates = $serviceStates
    enabledIntegrationServiceCount = $enabledIntegrationServices.Count
    enabledIntegrationServices = $enabledIntegrationServices
  }
  $snapshotBytes = [Text.Encoding]::UTF8.GetBytes(($observations | ConvertTo-Json -Depth 8 -Compress))
  $configDigest = Get-BytesSha256 $snapshotBytes
  return [pscustomobject]@{ observations = $observations; configSha256 = $configDigest }
}

function Get-StringSetSha256([string[]]$Values) {
  $normalized = @($Values | Sort-Object)
  $bytes = [Text.Encoding]::UTF8.GetBytes(($normalized -join "`n"))
  return Get-BytesSha256 $bytes
}

try {
  if ($Nonce -notmatch '^[0-9a-f]{32,64}$') { throw "nonce_invalid" }
  $script:RunRootFull = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\', '/')
  if ([IO.Path]::GetFileName($script:RunRootFull) -notmatch '^codex-bridge-vm-[0-9a-fA-F-]{36}$') {
    throw "run_root_name_not_isolated"
  }
  $script:MediaRootFull = [IO.Path]::GetFullPath($MediaRoot)
  $script:MediaManifestFull = [IO.Path]::GetFullPath($MediaManifestPath)
  $script:OfflineMediaIsoFull = [IO.Path]::GetFullPath($OfflineMediaIsoPath)
  $script:HostEvidenceIsoFull = [IO.Path]::GetFullPath($HostEvidenceIsoPath)
  $script:OutputDiskPath = Join-Path $script:RunRootFull "vm-output.vhdx"
  foreach ($path in @($script:MediaRootFull, $script:MediaManifestFull, $script:OfflineMediaIsoFull, $script:HostEvidenceIsoFull)) {
    Assert-NoReparsePath $path
  }
  $mediaDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($script:MediaRootFull))
  if ($mediaDrive.DriveType -ne [IO.DriveType]::CDRom) { throw "asset_media_not_readonly_iso" }
  if (-not (Test-McpVmSha256 $ExpectedMediaIsoSha256) -or
      (Get-PathSha256 $script:OfflineMediaIsoFull) -cne $ExpectedMediaIsoSha256.ToLowerInvariant()) {
    throw "offline_media_digest_mismatch"
  }
  $manifestBytes = [IO.File]::ReadAllBytes($script:MediaManifestFull)
  $manifestHash = Get-BytesSha256 $manifestBytes
  $manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
  $manifestCheck = Test-McpVmMediaManifest -Manifest $manifest -MediaRoot $script:MediaRootFull `
    -ExpectedTestSourceCommit $TestSourceCommit -HashFile { param($Path) Get-PathSha256 $Path }
  if ($manifestCheck.status -ne "PASS") { throw "offline_media_manifest_invalid" }

  $matches = @(Get-VM -Id $VMId -ErrorAction Stop | Where-Object { $_.Id -eq $VMId })
  if ($matches.Count -ne 1) { throw "vm_identity_not_unique" }
  $vm = $matches[0]
  if ([string]$vm.State -ne "Off") { throw "vm_must_be_off_for_host_evidence" }
  $snapshot = Get-HostVmSnapshot $vm
  $o = $snapshot.observations
  $o.mediaManifestSha256 = $manifestHash
  $o.controllerSha256 = Get-PathSha256 $PSCommandPath
  $n5Assessment = Get-McpVmN5Assessment -ConfigurationSha256 ([string]$snapshot.configSha256)
  $checks = [ordered]@{
    VMN1 = @{ status = if ($o.networkAdapterCount -eq 0 -and $o.assignedDeviceCount -eq 0) { "PASS" } else { "BLOCKED" }; adapterCount = $o.networkAdapterCount; assignedDeviceCount = $o.assignedDeviceCount; externalPathCount = $o.externalPathCount }
    VMN4 = @{ status = if ($o.enhancedSessionEnabled -eq $false -and $o.clipboardDisabled -eq $true -and $o.guestServiceInterfaceEnabled -eq $false -and $o.dataExchangeEnabled -eq $false -and $o.sharedFolderCount -eq 0 -and $o.enabledIntegrationServiceCount -eq 0 -and $o.configuredComPortCount -eq 0 -and $o.configuredFloppyDriveCount -eq 0 -and $o.fibreChannelAdapterCount -eq 0 -and $o.gpuPartitionAdapterCount -eq 0 -and $o.expectedScratchDiskSet -eq $true -and $o.hardDiskPathsWithinRunRoot -eq $true -and $o.outputDiskAttachedExactlyOnce -eq $true -and $o.offlineMediaAttachedReadOnly -eq $true -and @($o.unapprovedChannels).Count -eq 0) { "PASS" } else { "BLOCKED" }; enhancedSessionDisabled = ($o.enhancedSessionEnabled -eq $false); clipboardDisabled = $o.clipboardDisabled; guestServiceInterfaceDisabled = ($o.guestServiceInterfaceEnabled -eq $false); dataExchangeDisabled = ($o.dataExchangeEnabled -eq $false); sharedFolderCount = $o.sharedFolderCount; enabledIntegrationServiceCount = $o.enabledIntegrationServiceCount; configuredComPortCount = $o.configuredComPortCount; configuredFloppyDriveCount = $o.configuredFloppyDriveCount; fibreChannelAdapterCount = $o.fibreChannelAdapterCount; gpuPartitionAdapterCount = $o.gpuPartitionAdapterCount; expectedScratchDiskSet = $o.expectedScratchDiskSet; hardDiskPathsWithinRunRoot = $o.hardDiskPathsWithinRunRoot; outputDiskAttachedExactlyOnce = $o.outputDiskAttachedExactlyOnce; offlineMediaAttachedReadOnly = $o.offlineMediaAttachedReadOnly; unapprovedChannels = @($o.unapprovedChannels) }
    VMN5 = @{
      status = $n5Assessment.status
      result = $n5Assessment.result
      hashFormatStatus = $n5Assessment.hashFormatStatus
      hashIntegrityStatus = $n5Assessment.hashIntegrityStatus
      trustAnchorStatus = $n5Assessment.trustAnchorStatus
      reason = $n5Assessment.reason
      controllerSha256 = Get-PathSha256 $PSCommandPath
      mediaManifestSha256 = $manifestHash
    }
  }
  if ($Mode -eq "Collect") {
    if (Test-Path -LiteralPath $EvidenceDirectory) { throw "evidence_directory_already_exists" }
    New-Item -ItemType Directory -Path $EvidenceDirectory -ErrorAction Stop | Out-Null
    $evidencePath = Join-Path $EvidenceDirectory "vm-host-evidence.json"
    $hashPath = Join-Path $EvidenceDirectory "vm-host-evidence.sha256"
    $contextPath = Join-Path $EvidenceDirectory "vm-run-context.json"
    $contextHashPath = Join-Path $EvidenceDirectory "vm-run-context.sha256"
    $evidence = [ordered]@{
      schema = "codex-bridge-b1-vm-host-evidence/v1"
      vmId = $VMId.ToString().ToLowerInvariant()
      nonce = $Nonce.ToLowerInvariant()
      sourceCommit = $TestSourceCommit
      expectedGuestAccountSid = $ExpectedGuestAccountSid
      generatedUtc = [DateTime]::UtcNow.ToString("o")
      build = @{
        runId = 41665722609
        productionCommit = "f2235028773e7d9e0da714218a5694c4eb8bfef3"
        portableZipSha256 = "3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d"
        serviceExeSha256 = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
      }
      observations = $o
      vmConfigurationSha256 = $snapshot.configSha256
      checks = $checks
    }
    $encoding = [Text.UTF8Encoding]::new($false)
    $evidenceBytes = $encoding.GetBytes(($evidence | ConvertTo-Json -Depth 12) + "`n")
    [IO.File]::WriteAllBytes($evidencePath, $evidenceBytes)
    $evidenceHash = Get-BytesSha256 $evidenceBytes
    [IO.File]::WriteAllText($hashPath, "$evidenceHash  vm-host-evidence.json`n", $encoding)
    $context = [ordered]@{
      schema = "codex-bridge-b1-vm-run-context/v1"
      vmId = $VMId.ToString().ToLowerInvariant()
      nonce = $Nonce.ToLowerInvariant()
      testSourceCommit = $TestSourceCommit
      expectedGuestAccountSid = $ExpectedGuestAccountSid
      hostEvidenceSha256 = $evidenceHash
      mediaManifestSha256 = $manifestHash
      mediaIsoSha256 = Get-PathSha256 $script:OfflineMediaIsoFull
    }
    $contextBytes = $encoding.GetBytes(($context | ConvertTo-Json -Depth 6) + "`n")
    [IO.File]::WriteAllBytes($contextPath, $contextBytes)
    $contextHash = Get-BytesSha256 $contextBytes
    [IO.File]::WriteAllText($contextHashPath, "$contextHash  vm-run-context.json`n", $encoding)
    Write-Output "VM_HOST_EVIDENCE status=created VMN1=$($checks.VMN1.status) VMN4=$($checks.VMN4.status) VMN5=$($checks.VMN5.status) hash_format=$($checks.VMN5.hashFormatStatus) hash_integrity=$($checks.VMN5.hashIntegrityStatus) trust_anchor=$($checks.VMN5.trustAnchorStatus) reason=$($checks.VMN5.reason) host_sha256=$evidenceHash context_sha256=$contextHash"
    if (@($checks.Values | Where-Object { $_.status -ne "PASS" }).Count -gt 0) { exit 2 }
  } else {
    if ([string]::IsNullOrWhiteSpace($ExistingHostEvidencePath) -or -not (Test-Path -LiteralPath $ExistingHostEvidencePath -PathType Leaf)) {
      throw "existing_host_evidence_required"
    }
    $existing = Get-Content -LiteralPath $ExistingHostEvidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($existing.vmId -ne $VMId.ToString().ToLowerInvariant() -or
        $existing.nonce -ne $Nonce.ToLowerInvariant() -or
        $existing.sourceCommit -ne $TestSourceCommit -or
        $existing.vmConfigurationSha256 -ne $snapshot.configSha256 -or
        $existing.observations.controllerSha256 -cne (Get-PathSha256 $PSCommandPath) -or
        $existing.observations.mediaManifestSha256 -cne $manifestHash -or
        $existing.observations.offlineMediaSha256 -cne (Get-PathSha256 $script:OfflineMediaIsoFull)) {
      throw "vm_host_configuration_changed"
    }
    $verifyN5 = Get-McpVmN5Assessment -ConfigurationSha256 ([string]$snapshot.configSha256) `
      -ExpectedConfigurationSha256 ([string]$existing.vmConfigurationSha256)
    Write-Output "VMN5_RECHECK status=$($verifyN5.status) hash_format=$($verifyN5.hashFormatStatus) hash_integrity=$($verifyN5.hashIntegrityStatus) trust_anchor=$($verifyN5.trustAnchorStatus) reason=$($verifyN5.reason)"
    if (-not (Test-McpVmN5TrustAnchorAvailable)) { throw "vmn5_trust_anchor_unavailable" }
    if (@($existing.checks.PSObject.Properties.Value | Where-Object { $_.status -ne "PASS" }).Count -gt 0 -or
        @($checks.Values | Where-Object { $_.status -ne "PASS" }).Count -gt 0) {
      throw "vm_host_boundary_not_pass"
    }
    Write-Output "PASS test=vm-host-recheck VMN1=PASS VMN4=PASS VMN5=$($verifyN5.status) config_sha256=$($snapshot.configSha256)"
  }
} catch {
  if (-not (Test-McpVmN5TrustAnchorAvailable)) {
    Write-Output "BLOCKED stage=host-controller VMN5=BLOCKED error_category=vmn5_trust_anchor_unavailable"
  } else {
    Write-Output "BLOCKED stage=host-controller error_category=host_evidence_or_boundary_unverified"
  }
  exit 1
}
