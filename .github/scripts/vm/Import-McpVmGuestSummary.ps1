[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $true)][guid]$VMId,
  [Parameter(Mandatory = $true)][string]$RunRoot,
  [Parameter(Mandatory = $true)][string]$OutputVolumeLabel,
  [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
  [Parameter(Mandatory = $true)][string]$ConfirmVMId
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$mounted = $false
$accessPathAdded = $false
$outputDrive = $null
$disk = $null
$partition = $null
$mountRoot = $null
$runRootFull = $null
$summaryCopied = $false
$cleanupFailed = $false
$summaryHash = $null
$vmN5ClaimRejected = $false

function Get-FileSha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Assert-NoReparsePath([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse_point_not_allowed' }
}

function Assert-PathUnder([string]$Root, [string]$Path) {
  $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $full = [IO.Path]::GetFullPath($Path)
  if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { throw 'path_outside_run_root' }
  Assert-NoReparsePath $full
  return $full
}

try {
  if ($ConfirmVMId -cne $VMId.ToString()) { throw 'explicit_vm_identity_confirmation_required' }
  $runRootFull = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\', '/')
  if ([IO.Path]::GetFileName($runRootFull) -notmatch '^codex-bridge-vm-[0-9a-fA-F-]{36}$') { throw 'run_root_name_not_isolated' }
  Assert-NoReparsePath $runRootFull
  $outputDiskPath = Join-Path $runRootFull 'vm-output.vhdx'
  $osDiskPath = Join-Path $runRootFull 'vm-os.vhdx'
  Assert-NoReparsePath $outputDiskPath
  Assert-NoReparsePath $osDiskPath

  $evidenceRoot = Assert-PathUnder $runRootFull $EvidenceDirectory
  $existingEvidence = @(Get-ChildItem -LiteralPath $evidenceRoot -Force -ErrorAction Stop)
  $expectedExisting = @('vm-host-evidence.json', 'vm-host-evidence.sha256', 'vm-run-context.json', 'vm-run-context.sha256')
  if ($existingEvidence.Count -ne $expectedExisting.Count -or
      @($existingEvidence | Where-Object { $_.PSIsContainer -or $_.Name -notin $expectedExisting }).Count -ne 0) {
    throw 'host_evidence_directory_contents_invalid'
  }
  foreach ($item in $existingEvidence) { Assert-NoReparsePath $item.FullName }

  $vmMatches = @(Get-VM -Id $VMId -ErrorAction Stop | Where-Object { $_.Id -eq $VMId })
  if ($vmMatches.Count -ne 1 -or [string]$vmMatches[0].State -cne 'Off') { throw 'vm_must_be_unique_and_off' }
  $vm = $vmMatches[0]
  if (@(Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction Stop).Count -ne 0 -or
      @(Get-VMAssignableDevice -VMName $vm.Name -ErrorAction Stop).Count -ne 0) {
    throw 'vm_network_or_assigned_device_present'
  }
  $hardDisks = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
  if ($hardDisks.Count -ne 2) { throw 'vm_scratch_disk_set_invalid' }
  $outputMatches = @($hardDisks | Where-Object { $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $outputDiskPath })
  $osMatches = @($hardDisks | Where-Object { $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $osDiskPath })
  if ($outputMatches.Count -ne 1 -or $osMatches.Count -ne 1) { throw 'vm_scratch_disk_identity_mismatch' }
  $outputDrive = $outputMatches[0]

  if (-not $PSCmdlet.ShouldProcess($VMId.ToString(), 'Detach the exact output VHDX and mount it read-only to import sanitized report files')) {
    throw 'guest_summary_import_not_confirmed'
  }
  Remove-VMHardDiskDrive -VMHardDiskDrive $outputDrive -Confirm:$false -ErrorAction Stop
  $remainingDrives = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
  if ($remainingDrives.Count -ne 1 -or
      [IO.Path]::GetFullPath([string]$remainingDrives[0].Path) -ine $osDiskPath) {
    throw 'output_disk_detach_unconfirmed'
  }

  $preMountImage = Get-DiskImage -ImagePath $outputDiskPath -ErrorAction Stop
  if ($null -eq $preMountImage -or $preMountImage.Attached -ne $false) { throw 'output_disk_already_mounted' }
  $mounted = $true
  $mountedDisk = Mount-VHD -Path $outputDiskPath -ReadOnly -NoDriveLetter -PassThru -ErrorAction Stop
  $diskMatches = @($mountedDisk | Get-Disk -ErrorAction Stop)
  if ($diskMatches.Count -ne 1 -or $diskMatches[0].IsBoot -or $diskMatches[0].IsSystem -or
      -not $diskMatches[0].IsReadOnly) { throw 'output_disk_mount_identity_invalid' }
  $disk = $diskMatches[0]
  $partitions = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop | Where-Object { $_.Type -notin @('Reserved', 'System') })
  if ($partitions.Count -ne 1) { throw 'output_disk_partition_layout_invalid' }
  $partition = $partitions[0]
  $volumes = @($partition | Get-Volume -ErrorAction Stop)
  if ($volumes.Count -ne 1 -or $volumes[0].FileSystemLabel -cne $OutputVolumeLabel -or
      $volumes[0].FileSystem -cne 'NTFS') { throw 'output_volume_identity_invalid' }

  $mountRoot = Join-Path $runRootFull ('.guest-output-mount-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $mountRoot -ErrorAction Stop | Out-Null
  $accessPathAdded = $true
  Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber `
    -AccessPath $mountRoot -ErrorAction Stop

  $sourceFiles = @(Get-ChildItem -LiteralPath $mountRoot -Force -ErrorAction Stop)
  $expectedNames = @('vm-guest-summary.json', 'vm-guest-summary.sha256')
  if ($sourceFiles.Count -ne 2 -or
      @($sourceFiles | Where-Object { $_.PSIsContainer -or $_.Name -notin $expectedNames }).Count -ne 0) {
    throw 'guest_output_file_set_invalid'
  }
  foreach ($item in $sourceFiles) { Assert-NoReparsePath $item.FullName }
  $sourceSummary = Join-Path $mountRoot 'vm-guest-summary.json'
  $sourceSidecar = Join-Path $mountRoot 'vm-guest-summary.sha256'
  $summaryHash = Get-FileSha256 $sourceSummary
  $sidecarLine = (Get-Content -LiteralPath $sourceSidecar -Raw -Encoding ASCII).Trim()
  if ($sidecarLine -cne "$summaryHash  vm-guest-summary.json") { throw 'guest_summary_sidecar_mismatch' }
  $summary = Get-Content -LiteralPath $sourceSummary -Raw -Encoding UTF8 | ConvertFrom-Json
  if ($summary.reportSchema -cne 'codex-bridge-b1-vm-run-report/v1' -or
      $summary.vmId -cne $VMId.ToString().ToLowerInvariant() -or
      $summary.vmShutdown -notin @('REQUESTED', 'NOT_REQUESTED')) { throw 'guest_summary_identity_invalid' }
  if ($summary.vmIsolation.VMN5 -cne 'BLOCKED') {
    $vmN5ClaimRejected = $true
    throw 'vmn5_status_claim_untrusted'
  }

  $destSummary = Join-Path $evidenceRoot 'vm-guest-summary.json'
  $destSidecar = Join-Path $evidenceRoot 'vm-guest-summary.sha256'
  if ((Test-Path -LiteralPath $destSummary) -or (Test-Path -LiteralPath $destSidecar)) { throw 'guest_summary_destination_exists' }
  [IO.File]::Copy($sourceSummary, $destSummary, $false)
  [IO.File]::Copy($sourceSidecar, $destSidecar, $false)
  if ((Get-FileSha256 $destSummary) -cne $summaryHash) { throw 'guest_summary_copy_digest_mismatch' }
  $summaryCopied = $true
} catch {
  if ($vmN5ClaimRejected) {
    Write-Output 'BLOCKED stage=guest-summary-import VMN5=BLOCKED error_category=vmn5_status_claim_untrusted'
  } elseif ($summaryCopied) {
    Write-Output 'BLOCKED stage=guest-summary-import error_category=summary_copy_or_mount_cleanup_unverified'
  } else {
    Write-Output 'BLOCKED stage=guest-summary-import error_category=guest_report_or_output_volume_unverified'
  }
  exit 2
} finally {
  if ($accessPathAdded -and $disk -and $partition -and $mountRoot) {
    try { Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber `
      -AccessPath $mountRoot -ErrorAction Stop; $accessPathAdded = $false }
    catch { $cleanupFailed = $true }
  }
  if ($mounted) {
    try { Dismount-VHD -Path $outputDiskPath -ErrorAction Stop; $mounted = $false }
    catch { $cleanupFailed = $true }
  }
  if ($mountRoot -and (Test-Path -LiteralPath $mountRoot -PathType Container) -and -not $accessPathAdded) {
    try { Remove-Item -LiteralPath $mountRoot -Force -ErrorAction Stop }
    catch { $cleanupFailed = $true }
  }
}

if ($cleanupFailed) {
  Write-Output 'BLOCKED stage=guest-summary-import-cleanup error_category=read_only_mount_cleanup_failed'
  exit 2
}
if ($summaryCopied) {
  Write-Output "PASS test=guest-summary-import VMN5=BLOCKED vm_id=$($VMId.ToString().ToLowerInvariant()) summary_sha256=$summaryHash output_disk=read-only-detached"
}
