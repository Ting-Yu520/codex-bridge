[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $true)][ValidateSet('Seed', 'PackHostEvidence')][string]$Mode,
  [Parameter(Mandatory = $true)][string]$RunRoot,
  [Parameter(Mandatory = $true)][string]$MediaRoot,
  [Parameter(Mandatory = $true)][string]$MediaManifestPath,
  [Parameter(Mandatory = $true)][string]$OsCdImgPath,
  [Parameter(Mandatory = $true)][string]$OfflineMediaIsoPath,
  [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedMediaIsoSha256,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$TestSourceCommit,
  [guid]$VMId,
  [string]$HostEvidenceDirectory,
  [string]$ExpectedNonce,
  [string]$ReplaceSeedIsoSha256
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$modulePath = Join-Path $PSScriptRoot 'McpVmValidation.psm1'
Import-Module $modulePath -Force

function Get-FileSha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Get-BytesSha256([byte[]]$Bytes) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Assert-NoReparsePath([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse_point_not_allowed' }
}

function Assert-PathUnder([string]$Root, [string]$Path) {
  $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $full = [IO.Path]::GetFullPath($Path)
  if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { throw 'path_outside_approved_root' }
  Assert-NoReparsePath $full
  return $full
}

function ConvertTo-WindowsArgument([string]$Value) {
  $builder = [Text.StringBuilder]::new()
  [void]$builder.Append('"')
  $slashes = 0
  foreach ($character in $Value.ToCharArray()) {
    if ($character -eq '\') { $slashes++; continue }
    if ($character -eq '"') {
      [void]$builder.Append(('\' * (($slashes * 2) + 1)))
      [void]$builder.Append('"')
      $slashes = 0
      continue
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
    [void]$builder.Append($character)
  }
  if ($slashes -gt 0) { [void]$builder.Append(('\' * ($slashes * 2))) }
  [void]$builder.Append('"')
  return $builder.ToString()
}

function Get-ManifestDependency($Manifest, [string]$Name) {
  $matches = @($Manifest.dependencies | Where-Object { $_.name -ceq $Name })
  if ($matches.Count -ne 1) { throw 'oscdimg_manifest_entry_invalid' }
  return $matches[0]
}

function Assert-HostEvidenceBundle(
  [string]$Directory,
  [string]$VMIdText,
  [string]$Nonce,
  [string]$ExpectedManifestSha256,
  [string]$ExpectedMediaIsoSha256
) {
  if (-not (Test-McpVmN5TrustAnchorAvailable)) { throw 'vmn5_trust_anchor_unavailable' }
  $expectedNames = @(
    'vm-host-evidence.json', 'vm-host-evidence.sha256',
    'vm-run-context.json', 'vm-run-context.sha256'
  )
  $items = @(Get-ChildItem -LiteralPath $Directory -Force -ErrorAction Stop)
  if ($items.Count -ne $expectedNames.Count -or
      @($items | Where-Object { $_.PSIsContainer -or $_.Name -notin $expectedNames }).Count -ne 0) {
    throw 'host_evidence_bundle_file_set_invalid'
  }
  foreach ($item in $items) { Assert-NoReparsePath $item.FullName }

  $hostPath = Join-Path $Directory 'vm-host-evidence.json'
  $hostHashPath = Join-Path $Directory 'vm-host-evidence.sha256'
  $contextPath = Join-Path $Directory 'vm-run-context.json'
  $contextHashPath = Join-Path $Directory 'vm-run-context.sha256'
  $hostHash = Get-FileSha256 $hostPath
  $contextHash = Get-FileSha256 $contextPath
  $hostSidecar = (Get-Content -LiteralPath $hostHashPath -Raw -Encoding ASCII).Trim()
  $contextSidecar = (Get-Content -LiteralPath $contextHashPath -Raw -Encoding ASCII).Trim()
  if ($hostSidecar -cne "$hostHash  vm-host-evidence.json" -or
      $contextSidecar -cne "$contextHash  vm-run-context.json") { throw 'host_evidence_sidecar_mismatch' }

  $host = Get-Content -LiteralPath $hostPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $context = Get-Content -LiteralPath $contextPath -Raw -Encoding UTF8 | ConvertFrom-Json
  if ($host.schema -cne 'codex-bridge-b1-vm-host-evidence/v1' -or
      $context.schema -cne 'codex-bridge-b1-vm-run-context/v1' -or
      $host.vmId -cne $VMIdText -or $context.vmId -cne $VMIdText -or
      $host.nonce -cne $Nonce -or $context.nonce -cne $Nonce -or
      $host.sourceCommit -cne $TestSourceCommit -or $context.testSourceCommit -cne $TestSourceCommit -or
      $host.expectedGuestAccountSid -cne $context.expectedGuestAccountSid -or
      [string]$context.expectedGuestAccountSid -notmatch '^S-1-5-21(-[0-9]{1,12}){4}$' -or
      $context.hostEvidenceSha256 -cne $hostHash -or
      $context.mediaManifestSha256 -cne $ExpectedManifestSha256 -or
      $context.mediaIsoSha256 -cne $ExpectedMediaIsoSha256) { throw 'host_evidence_context_identity_invalid' }
  if ($host.observations.mediaManifestSha256 -cne $ExpectedManifestSha256 -or
      $host.observations.offlineMediaSha256 -cne $ExpectedMediaIsoSha256) {
    throw 'host_evidence_media_identity_invalid'
  }
  foreach ($name in @('VMN1', 'VMN4', 'VMN5')) {
    if ($host.checks.$name.status -cne 'PASS') { throw 'host_evidence_boundary_not_pass' }
  }
  if ($host.build.runId -ne 41665722609 -or
      $host.build.productionCommit -cne 'f2235028773e7d9e0da714218a5694c4eb8bfef3' -or
      $host.build.portableZipSha256 -cne '3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d' -or
      $host.build.serviceExeSha256 -cne '428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521') {
    throw 'host_candidate_identity_invalid'
  }
  return [pscustomobject]@{ hostSha256 = $hostHash; contextSha256 = $contextHash }
}

$stageRoot = $null
$stagedIso = $null
$process = $null
$processIdentity = $null
$processStarted = $false
$processExited = $true
$destination = $null
$backupPath = $null
$cleanupFailed = $false
$isoHash = $null
try {
  $runRootFull = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\', '/')
  if ([IO.Path]::GetFileName($runRootFull) -notmatch '^codex-bridge-vm-[0-9a-fA-F-]{36}$') { throw 'run_root_name_not_isolated' }
  Assert-NoReparsePath $runRootFull
  $mediaRootFull = [IO.Path]::GetFullPath($MediaRoot).TrimEnd('\', '/')
  Assert-NoReparsePath $mediaRootFull
  $manifestFull = Assert-PathUnder $mediaRootFull $MediaManifestPath
  $offlineIsoFull = Assert-PathUnder $mediaRootFull $OfflineMediaIsoPath
  $osCdImgFull = Assert-PathUnder $mediaRootFull $OsCdImgPath
  $mediaDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($mediaRootFull))
  if ($mediaDrive.DriveType -ne [IO.DriveType]::CDRom) { throw 'asset_media_not_readonly_iso' }
  if ((Get-FileSha256 $offlineIsoFull) -cne $ExpectedMediaIsoSha256.ToLowerInvariant()) { throw 'offline_media_digest_mismatch' }

  $manifestBytes = [IO.File]::ReadAllBytes($manifestFull)
  $manifestHash = Get-BytesSha256 $manifestBytes
  $manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
  $mediaCheck = Test-McpVmMediaManifest -Manifest $manifest -MediaRoot $mediaRootFull `
    -ExpectedTestSourceCommit $TestSourceCommit -HashFile { param($Path) Get-FileSha256 $Path }
  if ($mediaCheck.status -ne 'PASS') { throw 'offline_media_manifest_invalid' }
  $oscdimgDependency = Get-ManifestDependency $manifest 'windows-adk-oscdimg'
  $expectedOsCdImg = [IO.Path]::GetFullPath((Join-Path $mediaRootFull ([string]$oscdimgDependency.path)))
  if ($expectedOsCdImg -cne $osCdImgFull -or
      (Get-FileSha256 $osCdImgFull) -cne ([string]$oscdimgDependency.sha256).ToLowerInvariant()) {
    throw 'oscdimg_identity_mismatch'
  }

  $destination = Join-Path $runRootFull 'vm-evidence.iso'
  $stageRoot = Join-Path $runRootFull ('.vm-evidence-stage-' + [guid]::NewGuid().ToString('N'))
  $stagedIso = Join-Path $runRootFull ('.vm-evidence-' + [guid]::NewGuid().ToString('N') + '.iso')
  New-Item -ItemType Directory -Path $stageRoot -ErrorAction Stop | Out-Null

  if ($Mode -eq 'Seed') {
    if ((Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath ($destination + '.sha256'))) {
      throw 'seed_destination_already_exists'
    }
    $seedText = "Synthetic offline VM evidence seed. No credentials or user data.`n"
    [IO.File]::WriteAllText((Join-Path $stageRoot 'SEED.txt'), $seedText, [Text.UTF8Encoding]::new($false))
  } else {
    if (-not $VMId -or $VMId -eq [guid]::Empty -or
        $ExpectedNonce -notmatch '^[0-9a-f]{32,64}$' -or
        $TestSourceCommit -notmatch '^[0-9a-f]{40}$' -or
        -not (Test-McpVmSha256 $ReplaceSeedIsoSha256)) { throw 'host_evidence_identity_parameters_missing' }
    $vmMatches = @(Get-VM -Id $VMId -ErrorAction Stop | Where-Object { $_.Id -eq $VMId })
    if ($vmMatches.Count -ne 1 -or [string]$vmMatches[0].State -cne 'Off') { throw 'vm_must_be_unique_and_off' }
    $vm = $vmMatches[0]
    $dvdDrives = @(Get-VMDvdDrive -VMName $vm.Name -ErrorAction Stop)
    if (@($dvdDrives | Where-Object { $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $destination }).Count -ne 1 -or
        @($dvdDrives | Where-Object { $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $offlineIsoFull }).Count -ne 1) {
      throw 'vm_readonly_media_layout_mismatch'
    }
    if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
        (Get-FileSha256 $destination) -cne $ReplaceSeedIsoSha256.ToLowerInvariant()) {
      throw 'seed_iso_identity_mismatch'
    }
    Assert-NoReparsePath $destination
    if (-not (Test-Path -LiteralPath $HostEvidenceDirectory -PathType Container)) { throw 'host_evidence_directory_missing' }
    $hostEvidenceRoot = Assert-PathUnder $runRootFull $HostEvidenceDirectory
    $bundle = Assert-HostEvidenceBundle $hostEvidenceRoot `
      $VMId.ToString().ToLowerInvariant() $ExpectedNonce.ToLowerInvariant() $manifestHash `
      $ExpectedMediaIsoSha256.ToLowerInvariant()
    foreach ($name in @('vm-host-evidence.json', 'vm-host-evidence.sha256', 'vm-run-context.json', 'vm-run-context.sha256')) {
      [IO.File]::WriteAllBytes((Join-Path $stageRoot $name), [IO.File]::ReadAllBytes((Join-Path $HostEvidenceDirectory $name)))
    }
  }

  if (-not $PSCmdlet.ShouldProcess($destination, "Build offline $Mode evidence ISO")) { throw 'iso_build_not_confirmed' }
  $arguments = @('-m', '-o', '-u2', '-udfver102', $stageRoot, $stagedIso) |
    ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $osCdImgFull
  $startInfo.Arguments = $arguments -join ' '
  $startInfo.WorkingDirectory = $runRootFull
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $toolEnvironment = $startInfo.EnvironmentVariables
  $toolEnvironment.Clear()
  foreach ($name in @('SystemRoot', 'WINDIR')) {
    $value = [Environment]::GetEnvironmentVariable($name, 'Machine')
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'oscdimg_system_environment_missing' }
    $toolEnvironment[$name] = $value
  }
  $toolEnvironment['TEMP'] = $stageRoot
  $toolEnvironment['TMP'] = $stageRoot
  $toolEnvironment['PATH'] = (Split-Path -Parent $osCdImgFull) + ';' + "$($toolEnvironment['SystemRoot'])\System32"
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  if (-not $process.Start()) { throw 'oscdimg_start_failed' }
  $processStarted = $true
  $processExited = $false
  $processIdentity = [pscustomobject]@{ id = $process.Id; path = $osCdImgFull; startTimeUtc = $process.StartTime.ToUniversalTime() }
  $stdoutTask = $process.StandardOutput.ReadToEndAsync()
  $stderrTask = $process.StandardError.ReadToEndAsync()
  if (-not $process.WaitForExit(180000)) {
    $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$($processIdentity.id)" -ErrorAction Stop
    if ($null -eq $processInfo -or [IO.Path]::GetFullPath([string]$processInfo.ExecutablePath) -ine $processIdentity.path) {
      throw 'oscdimg_timeout_identity_unverified'
    }
    $sameProcess = Get-Process -Id $processIdentity.id -ErrorAction Stop
    if ($sameProcess.StartTime.ToUniversalTime() -ne $processIdentity.startTimeUtc) { throw 'oscdimg_timeout_identity_changed' }
    $sameProcess.Kill()
    if (-not $process.WaitForExit(10000)) { throw 'oscdimg_timeout_cleanup_blocked' }
    $processExited = $true
    throw 'oscdimg_timeout'
  }
  $processExited = $true
  $null = $stdoutTask.GetAwaiter().GetResult()
  $null = $stderrTask.GetAwaiter().GetResult()
  if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $stagedIso -PathType Leaf) -or
      (Get-Item -LiteralPath $stagedIso).Length -lt 2048) { throw 'oscdimg_build_failed' }
  $isoHash = Get-FileSha256 $stagedIso
  if ($Mode -eq 'Seed') {
    [IO.File]::Move($stagedIso, $destination)
  } else {
    $backupPath = Join-Path $runRootFull ('vm-evidence-seed-' + $ReplaceSeedIsoSha256.Substring(0, 12).ToLowerInvariant() + '.iso')
    if (Test-Path -LiteralPath $backupPath) { throw 'seed_backup_already_exists' }
    [IO.File]::Move($destination, $backupPath)
    try { [IO.File]::Move($stagedIso, $destination) }
    catch {
      if (-not (Test-Path -LiteralPath $destination) -and (Test-Path -LiteralPath $backupPath)) {
        [IO.File]::Move($backupPath, $destination)
      }
      throw
    }
  }
  $finalHash = Get-FileSha256 $destination
  if ($finalHash -cne $isoHash) { throw 'evidence_iso_install_digest_mismatch' }
  $sidecar = "$finalHash  vm-evidence.iso`n"
  [IO.File]::WriteAllText(($destination + '.sha256'), $sidecar, [Text.UTF8Encoding]::new($false))
  $isoHash = $finalHash
} catch {
  if (-not (Test-McpVmN5TrustAnchorAvailable)) {
    Write-Output 'BLOCKED stage=evidence-iso VMN5=BLOCKED error_category=vmn5_trust_anchor_unavailable'
  } else {
    Write-Output 'BLOCKED stage=evidence-iso error_category=media_or_evidence_identity_unverified'
  }
  exit 2
} finally {
  if ($process) { $process.Dispose() }
  if ($processExited) {
    if ($stageRoot -and (Test-Path -LiteralPath $stageRoot -PathType Container)) {
      try { Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction Stop } catch { $cleanupFailed = $true }
    }
    if ($stagedIso -and (Test-Path -LiteralPath $stagedIso -PathType Leaf)) {
      try { Remove-Item -LiteralPath $stagedIso -Force -ErrorAction Stop } catch { $cleanupFailed = $true }
    }
  } elseif ($processStarted) {
    $cleanupFailed = $true
  }
}

if ($cleanupFailed) {
  Write-Output 'BLOCKED stage=evidence-iso-cleanup error_category=staging_or_process_cleanup_failed'
  exit 2
}
if ($isoHash) { Write-Output "PASS test=vm-evidence-iso mode=$Mode sha256=$isoHash" }
