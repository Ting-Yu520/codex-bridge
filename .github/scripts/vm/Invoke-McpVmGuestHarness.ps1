[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$MediaRoot,
  [Parameter(Mandatory = $true)][string]$RunContextRoot,
  [Parameter(Mandatory = $true)][string]$ExpectedContextSha256,
  [Parameter(Mandatory = $true)][string]$OfflineMediaIsoRoot,
  [Parameter(Mandatory = $true)][string]$OutputDirectory,
  [Parameter(Mandatory = $true)][string]$SwiftExe,
  [Parameter(Mandatory = $true)][string]$PythonExe,
  [Parameter(Mandatory = $true)][string]$VcpkgRoot,
  [Parameter(Mandatory = $true)][string]$OutputVolumeLabel,
  [Parameter(Mandatory = $true)][switch]$RunOfflineTest
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$scriptRoot = $PSScriptRoot
Import-Module (Join-Path $scriptRoot "McpVmValidation.psm1") -Force
Import-Module (Join-Path $scriptRoot "McpVmSupervisor.psm1") -Force

$expectedRunId = 41665722609
$expectedProductionCommit = "f2235028773e7d9e0da714218a5694c4eb8bfef3"
$expectedPortableZipSha256 = "3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d"
$expectedServiceSha256 = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
$expectedSchemaSha256 = "EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203"
$routeTestStatus = "NOT_TESTED"
$schemaStatus = "NOT_TESTED"
$cleanup = [pscustomobject]@{ serviceExit = "NOT_STARTED"; descendants = "NOT_TESTED"; temporaryCleanup = "NOT_STARTED"; errorCategory = $null }
$runnerStatus = "NOT_STARTED"
$harnessExitCode = 1
$testLog = $null
$servicePid = $null
$responseDigests = @{}
$routeResults = @{}
$guestEvidenceStatus = "BLOCKED"
$portableIdentityAfterRun = "NOT_TESTED"
$createdSourceRoot = $null
$createdCandidateRoot = $null
$runnerTemp = [IO.Path]::GetTempPath().TrimEnd('\', '/')
$testRunnerProcess = $null
$logWriter = $null
$testRunnerExited = $true
$runStarted = $false
$cleanupAttempted = $false
$swiftTestsExecuted = 0
$swiftTestFailures = -1
$protocolSummaryPath = $null
$guestEvidencePath = $null
$swiftLog = $null
$guestEvidence = $null
$hostEvidence = $null
$context = $null
$captureDirectory = $null
$pidRecordPath = $null
$dataRoot = $null
$profileRoot = $null
$hostEvidencePath = $null
$testSourceCommit = "unknown"

function Get-FileSha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function ConvertTo-WindowsArgument([string]$Value) {
  if ($Value.Length -eq 0) { return '""' }
  if ($Value -notmatch '[\s"]') { return $Value }
  $builder = [Text.StringBuilder]::new()
  [void]$builder.Append([char]34)
  $backslashes = 0
  foreach ($character in $Value.ToCharArray()) {
    if ([int]$character -eq 92) { $backslashes++; continue }
    if ([int]$character -eq 34) {
      if ($backslashes -gt 0) { [void]$builder.Append([char]92, 2 * $backslashes) }
      [void]$builder.Append([char]92)
      [void]$builder.Append([char]34)
      $backslashes = 0
      continue
    }
    if ($backslashes -gt 0) { [void]$builder.Append([char]92, $backslashes) }
    [void]$builder.Append($character)
    $backslashes = 0
  }
  if ($backslashes -gt 0) { [void]$builder.Append([char]92, 2 * $backslashes) }
  [void]$builder.Append([char]34)
  return $builder.ToString()
}

function Get-BytesSha256([byte[]]$Bytes) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Write-JsonFile([string]$Path, $Value) {
  $encoding = [Text.UTF8Encoding]::new($false)
  $bytes = $encoding.GetBytes(($Value | ConvertTo-Json -Depth 14) + "`n")
  [IO.File]::WriteAllBytes($Path, $bytes)
  return Get-BytesSha256 $bytes
}

function Assert-PathNoReparse([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "path_reparse_point" }
}

function Remove-McpVmGuestTempFile([string]$Path, [string]$RunnerTemp, [string]$Nonce) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  $full = [IO.Path]::GetFullPath($Path)
  $allowed = @(
    "codex-bridge-vm-service-$Nonce.pid.json",
    "codex-bridge-vm-guest-evidence-$Nonce.json",
    "codex-bridge-vm-protocol-summary-$Nonce.json",
    "codex-bridge-vm-swift-test-$Nonce.log"
  )
  $leaf = [IO.Path]::GetFileName($full)
  if ($leaf -cnotin $allowed) { throw 'temp_file_name_not_allowed' }
  Remove-McpVmSafeTemporaryFile -Path $full -RunnerTemp $RunnerTemp -ExpectedName $leaf
}

function Expand-McpVmZipSafely([string]$ZipPath, [string]$Destination) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zipFull = [IO.Path]::GetFullPath($ZipPath)
  $destFull = [IO.Path]::GetFullPath($Destination)
  New-Item -ItemType Directory -Path $destFull -ErrorAction Stop | Out-Null
  $archive = [IO.Compression.ZipFile]::OpenRead($zipFull)
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  try {
    [long]$totalBytes = 0
    foreach ($entry in $archive.Entries) {
      $entryName = $entry.FullName.Replace('\', '/')
      if ([string]::IsNullOrWhiteSpace($entryName) -or $entryName.StartsWith('/') -or
          $entryName.Contains(':') -or ($entryName -split '/') -contains '..' -or
          ($entryName -split '/') -contains '.') { throw "archive_entry_invalid" }
      $unixType = ([int]($entry.ExternalAttributes -shr 16)) -band 0xF000
      if ($unixType -eq 0xA000) { throw "archive_symlink_not_allowed" }
      $target = [IO.Path]::GetFullPath((Join-Path $destFull $entryName.Replace('/', [IO.Path]::DirectorySeparatorChar)))
      $prefix = $destFull.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
      if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not $seen.Add($target)) {
        throw "archive_path_escape_or_duplicate"
      }
      $isDirectory = $entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')
      if ($isDirectory) {
        New-Item -ItemType Directory -Path $target -Force -ErrorAction Stop | Out-Null
        continue
      }
      $totalBytes += $entry.Length
      if ($totalBytes -gt 4GB) { throw "archive_expansion_limit" }
      $parent = Split-Path -Parent $target
      if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
      if (((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "archive_parent_reparse_point"
      }
      $input = $entry.Open()
      $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
    }
  } finally { $archive.Dispose() }
}

function Assert-PortablePayload([string]$PayloadRoot) {
  $manifestPath = Join-Path $PayloadRoot "SHA256SUMS.txt"
  $manifest = @{}
  foreach ($line in [IO.File]::ReadAllLines($manifestPath, [Text.UTF8Encoding]::new($false, $true))) {
    if ($line -notmatch '^([A-Fa-f0-9]{64})  (.+)$') { throw "portable_manifest_format_invalid" }
    $relative = $Matches[2].Replace('\', '/')
    if ($relative.StartsWith('/') -or $relative.Contains(':') -or ($relative -split '/') -contains '..') {
      throw "portable_manifest_path_invalid"
    }
    if ($manifest.ContainsKey($relative)) { throw "portable_manifest_duplicate_path" }
    $manifest[$relative] = $Matches[1].ToLowerInvariant()
  }
  $files = @(Get-ChildItem -LiteralPath $PayloadRoot -File -Recurse -Force | Where-Object { $_.FullName -ine $manifestPath })
  if ($files.Count -ne $manifest.Count) { throw "portable_manifest_file_set_mismatch" }
  foreach ($file in $files) {
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "portable_reparse_point" }
    $relative = $file.FullName.Substring($PayloadRoot.Length).TrimStart('\', '/').Replace('\', '/')
    if (-not $manifest.ContainsKey($relative) -or (Get-FileSha256 $file.FullName) -cne $manifest[$relative]) {
      throw "portable_file_digest_mismatch"
    }
  }
  $info = Get-Content -LiteralPath (Join-Path $PayloadRoot "BUILD-INFO.json") -Raw -Encoding UTF8 | ConvertFrom-Json
  if ($info.schema -ne "codex-bridge-windows-portable/v1" -or $info.appVersion -ne "2.2.3" -or
      $info.architecture -ne "x64" -or $info.targetTriple -ne "x86_64-unknown-windows-msvc" -or
      $info.gitCommit -ne $expectedProductionCommit -or $info.swiftVersion -notmatch '^Swift version 6\.3\.3') {
    throw "portable_build_info_mismatch"
  }
  $service = Join-Path $PayloadRoot "codex-bridge-service.exe"
  if ((Get-FileSha256 $service) -cne $expectedServiceSha256) { throw "service_exe_digest_mismatch" }
  . (Join-Path $PayloadRoot "Scripts\windows-portable-support.ps1")
  if ((Get-PEMachine $service) -ne [UInt16]0x8664) { throw "service_exe_architecture_mismatch" }
  foreach ($pe in @(Get-ChildItem -LiteralPath $PayloadRoot -File -Recurse | Where-Object { $_.Extension -in @('.exe', '.dll') })) {
    if ((Get-PEMachine $pe.FullName) -ne [UInt16]0x8664) { throw "portable_pe_architecture_mismatch" }
  }
  return $service
}

function Get-GuestNetworkAndAccountFacts([string]$ExpectedGuestAccountSid) {
  $routeCount = 0
  try {
    $routeCount = @(
      Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop
      Get-NetRoute -DestinationPrefix "::/0" -ErrorAction Stop
    ).Count
  } catch { $routeCount = -1 }
  $proxyNames = @(
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
    "OPENAI_API_KEY", "CODEX_BRIDGE_RUNTIME_KEY", "CODEX_BRIDGE_TUNNEL_TOKEN",
    "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"
  )
  $environmentNames = @([Environment]::GetEnvironmentVariables().Keys | ForEach-Object { [string]$_ })
  $knownCredentialPresent = @($environmentNames | Where-Object { $_ -cin $proxyNames }).Count -gt 0
  $proxyPresent = $knownCredentialPresent
  try {
    $proxyEnable = (Get-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
      -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
    if ($null -ne $proxyEnable -and [int]$proxyEnable -ne 0) { $proxyPresent = $true }
  } catch { $proxyPresent = $true }
  $winHttpOutput = @(& "$env:SystemRoot\System32\netsh.exe" winhttp show proxy 2>$null) -join "`n"
  $direct = $winHttpOutput -match '(?i)Direct access \(no proxy server\)|直接访问.{0,8}无代理服务器'
  if (-not $direct) { $proxyPresent = $true }

  $administrator = $true
  $isolatedTestAccountMatched = $false
  try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $actualSid = if ($identity.User) { $identity.User.Value } else { "" }
    $isolatedTestAccountMatched = $actualSid -ceq $ExpectedGuestAccountSid
  } catch { $administrator = $true }
  $profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
  $configCandidates = @(
    (Join-Path $profile ".codex"),
    (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)) "Codex"),
    (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) "Codex")
  )
  $realCodexConfigurationPresent = @($configCandidates | Where-Object { Test-Path -LiteralPath $_ }).Count -gt 0
  $credentialStoreCandidates = @(
    (Join-Path $profile "AppData\Local\Microsoft\Credentials"),
    (Join-Path $profile "AppData\Roaming\Microsoft\Credentials"),
    (Join-Path $profile "AppData\Local\Microsoft\Vault")
  )
  if (@($credentialStoreCandidates | Where-Object { Test-Path -LiteralPath $_ }).Count -gt 0) {
    $knownCredentialPresent = $true
  }
  $upAdapters = @()
  try {
    $upAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
      $_.Status -eq "Up" -and $_.InterfaceDescription -notmatch '(?i)software loopback'
    })
  } catch { $upAdapters = @(@{ unknown = $true }) }
  return [pscustomobject]@{
    defaultRouteCount = $routeCount
    activeNonLoopbackAdapterCount = $upAdapters.Count
    proxyPresent = [bool]$proxyPresent
    knownCredentialPresent = [bool]$knownCredentialPresent
    userIsAdministrator = [bool]$administrator
    isolatedTestAccountMatched = [bool]$isolatedTestAccountMatched
    realCodexConfigurationPresent = [bool]$realCodexConfigurationPresent
  }
}

function Test-GuestLoopback {
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  $client = $null
  $accepted = $null
  try {
    $listener.Start()
    $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect([Net.IPAddress]::Loopback, $port)
    $accepted = $listener.AcceptTcpClient()
    return $client.Connected -and $accepted.Connected
  } catch { return $false }
  finally {
    if ($accepted) { $accepted.Dispose() }
    if ($client) { $client.Dispose() }
    $listener.Stop()
  }
}

function Get-GuestEvidence($Context, [string]$HostEvidenceSha256) {
  $network = Get-GuestNetworkAndAccountFacts ([string]$Context.expectedGuestAccountSid)
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  $architecture = if ([Environment]::Is64BitOperatingSystem -and
      [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -eq "X64") { "x64" } else { "unknown" }
  $vmic = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='vmicvmsession'" -ErrorAction Stop)
  $pDirectDisabled = $vmic.Count -eq 1 -and $vmic[0].StartMode -eq "Disabled"
  $pDirectStopped = $vmic.Count -eq 1 -and $vmic[0].State -eq "Stopped"
  $hostEvidence = Get-Content -LiteralPath (Join-Path $RunContextRoot "vm-host-evidence.json") -Raw -Encoding UTF8 | ConvertFrom-Json
  $enhancedDisconnected = $hostEvidence.checks.VMN4.status -eq "PASS" -and
    $hostEvidence.observations.enhancedSessionEnabled -eq $false
  $n2Pass = $architecture -eq "x64" -and $network.defaultRouteCount -eq 0 -and
    $network.activeNonLoopbackAdapterCount -eq 0 -and -not $network.proxyPresent -and
    -not $network.knownCredentialPresent -and -not $network.userIsAdministrator -and
    $network.isolatedTestAccountMatched -and
    -not $network.realCodexConfigurationPresent
  $n4Pass = $pDirectDisabled -and $pDirectStopped -and $enhancedDisconnected
  $loopback = Test-GuestLoopback
  return [pscustomobject]@{
    schema = "codex-bridge-b1-vm-guest-evidence/v1"
    vmId = $Context.vmId
    nonce = $Context.nonce
    sourceCommit = $Context.testSourceCommit
    hostEvidenceSha256 = $HostEvidenceSha256
    platform = @{ architecture = $architecture; windowsVersion = [string]$os.Caption + " " + [string]$os.Version }
    checks = @{
      VMN2 = @{
        status = if ($n2Pass) { "PASS" } else { "BLOCKED" }
        defaultRouteCount = $network.defaultRouteCount
        activeNonLoopbackAdapterCount = $network.activeNonLoopbackAdapterCount
        proxyPresent = $network.proxyPresent
        knownCredentialPresent = $network.knownCredentialPresent
        userIsAdministrator = $network.userIsAdministrator
        isolatedTestAccountMatched = $network.isolatedTestAccountMatched
        realCodexConfigurationPresent = $network.realCodexConfigurationPresent
      }
      VMN3 = @{ status = if ($loopback) { "PASS" } else { "BLOCKED" }; ipv4Loopback = $loopback }
      VMN4 = @{
        status = if ($n4Pass) { "PASS" } else { "BLOCKED" }
        powerShellDirectServiceDisabled = $pDirectDisabled
        powerShellDirectServiceStopped = $pDirectStopped
        enhancedSessionDisconnected = $enhancedDisconnected
      }
    }
  }
}

function Get-GuestSummary([string]$TestSourceCommit, $HostChecks, $GuestChecks, [string]$CaptureDir) {
  $summary = [ordered]@{
    reportSchema = "codex-bridge-b1-vm-run-report/v1"
    vmId = if ($hostEvidence) { $hostEvidence.vmId } else { "unknown" }
    nonce = if ($hostEvidence) { $hostEvidence.nonce } else { "unknown" }
    sourceCommit = $TestSourceCommit
    buildRunId = $expectedRunId
    productionCommit = $expectedProductionCommit
    portableSha256 = $expectedPortableZipSha256
    serviceExeSha256 = $expectedServiceSha256
    schemaSha256 = $expectedSchemaSha256
    vmIsolation = @{
      VMN1 = $HostChecks.VMN1.status
      VMN2 = $GuestChecks.VMN2.status
      VMN3 = $GuestChecks.VMN3.status
      VMN4 = if ($HostChecks.VMN4.status -eq "PASS" -and $GuestChecks.VMN4.status -eq "PASS") { "PASS" } else { "BLOCKED" }
      VMN5 = "BLOCKED"
    }
    windows = if ($guestEvidence) { $guestEvidence.platform } else { @{ architecture = "unknown"; windowsVersion = "NOT_TESTED" } }
    servicePid = $servicePid
    serviceImage = "candidate-relative:codex-bridge-service.exe"
    serviceProcessStatus = if ($cleanup.serviceExit -eq "BLOCKED") { "BLOCKED" } elseif ([int]$servicePid -gt 0) { "EXITED" } else { "NOT_STARTED" }
    portableIdentityAfterRun = $portableIdentityAfterRun
    serviceEgressObservation = "NOT_OBSERVED"
    routeTests = $routeResults
    responses = $responseDigests
    swiftTestsExecuted = $swiftTestsExecuted
    swiftTestFailures = $swiftTestFailures
    schemaValidation = $schemaStatus
    serviceExit = $cleanup.serviceExit
    descendantExit = $cleanup.descendants
    cleanup = $cleanup.temporaryCleanup
    vmShutdown = "NOT_REQUESTED"
    vmDestruction = "PENDING_HOST_FINALIZER"
    overall = "BLOCKED"
  }
  return $summary
}

function Invoke-McpVmGuestVerifiedCleanup($Record, [string]$CandidateService, [string]$CandidateRoot, [string]$TempRoot) {
  $backend = New-McpVmProcessBackend -CandidatePath $CandidateService `
    -CandidateDirectory $CandidateRoot -RunnerTemp $TempRoot -ExpectedSha256 $expectedServiceSha256
  $first = Invoke-McpVmServiceCleanup -Record $Record -CandidatePath $CandidateService `
    -ExpectedSha256 $expectedServiceSha256 -RunnerTemp $TempRoot -Backend $backend `
    -CandidateDirectory $CandidateRoot -SkipTemporaryCleanup
  if ($first.serviceExit -ne "PASS" -or $first.descendants -ne "PASS") {
    return [pscustomobject]@{
      cleanup = $first
      portableIdentityAfterRun = "NOT_TESTED"
    }
  }

  try {
    [void](Assert-PortablePayload $CandidateRoot)
  } catch {
    return [pscustomobject]@{
      cleanup = [pscustomobject]@{
        serviceExit = $first.serviceExit; descendants = $first.descendants
        temporaryCleanup = "BLOCKED"; errorCategory = "portable_postrun_identity_mismatch"
      }
      portableIdentityAfterRun = "FAIL"
    }
  }

  $preparedRecord = @{
    pid = 0; launchState = "prepared"; startedAtUtc = ""
    imagePath = $Record.imagePath; imageSha256 = $Record.imageSha256
    dataRoot = $Record.dataRoot; profileRoot = $Record.profileRoot
    captureDirectory = $Record.captureDirectory; sourceRoot = $Record.sourceRoot
    candidateRoot = $Record.candidateRoot
  }
  $final = Invoke-McpVmServiceCleanup -Record $preparedRecord -CandidatePath $CandidateService `
    -ExpectedSha256 $expectedServiceSha256 -RunnerTemp $TempRoot -Backend $backend `
    -CandidateDirectory $CandidateRoot
  if ($final.serviceExit -ne "PASS" -or $final.descendants -ne "PASS" -or $final.temporaryCleanup -ne "PASS") {
    $cleanupError = [string]$final.errorCategory
    if ([string]::IsNullOrWhiteSpace($cleanupError)) { $cleanupError = "temporary_cleanup_not_confirmed" }
    return [pscustomobject]@{
      cleanup = [pscustomobject]@{
        serviceExit = $first.serviceExit; descendants = $first.descendants
        temporaryCleanup = "BLOCKED"; errorCategory = $cleanupError
      }
      portableIdentityAfterRun = "PASS"
    }
  }
  return [pscustomobject]@{
    cleanup = [pscustomobject]@{
      serviceExit = $first.serviceExit; descendants = $first.descendants
      temporaryCleanup = "PASS"; errorCategory = $null
    }
    portableIdentityAfterRun = "PASS"
  }
}

try {
  if (-not $RunOfflineTest) { throw "explicit_offline_test_switch_required" }
  if (-not (Test-McpVmSha256 $ExpectedContextSha256)) { throw "context_digest_missing" }
  foreach ($path in @($MediaRoot, $RunContextRoot, $OfflineMediaIsoRoot, $OutputDirectory, $SwiftExe, $PythonExe, $VcpkgRoot)) {
    Assert-PathNoReparse $path
  }
  $mediaRootFull = [IO.Path]::GetFullPath($MediaRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $isoRootFull = [IO.Path]::GetFullPath($OfflineMediaIsoRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  if (-not $mediaRootFull.StartsWith($isoRootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "media_root_not_on_approved_iso"
  }
  if ($runnerTemp -match '\s') { throw "temp_path_spaces_not_supported" }
  $outputFull = [IO.Path]::GetFullPath($OutputDirectory)
  $outputDriveRoot = [IO.Path]::GetPathRoot($outputFull)
  $outputDriveLetter = $outputDriveRoot.TrimEnd('\', ':')
  $outputVolume = Get-Volume -DriveLetter $outputDriveLetter -ErrorAction Stop
  $outputPartition = Get-Partition -DriveLetter $outputDriveLetter -ErrorAction Stop
  $outputDisk = Get-Disk -Number $outputPartition.DiskNumber -ErrorAction Stop
  if ($outputVolume.FileSystemLabel -cne $OutputVolumeLabel -or $outputDisk.IsBoot -or $outputDisk.IsSystem -or
      $outputDriveRoot -ieq [IO.Path]::GetPathRoot($runnerTemp)) {
    throw "output_volume_not_isolated"
  }
  $contextDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($RunContextRoot)))
  $mediaDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($OfflineMediaIsoRoot)))
  if ($contextDrive.DriveType -ne [IO.DriveType]::CDRom -or $mediaDrive.DriveType -ne [IO.DriveType]::CDRom) {
    throw "run_context_or_asset_media_not_readonly_iso"
  }
  $contextPath = Join-Path $RunContextRoot "vm-run-context.json"
  $hostEvidencePath = Join-Path $RunContextRoot "vm-host-evidence.json"
  $hostHashPath = Join-Path $RunContextRoot "vm-host-evidence.sha256"
  $contextBytes = [IO.File]::ReadAllBytes($contextPath)
  if ((Get-BytesSha256 $contextBytes) -cne $ExpectedContextSha256.ToLowerInvariant()) { throw "context_digest_mismatch" }
  $context = [Text.Encoding]::UTF8.GetString($contextBytes) | ConvertFrom-Json
  $testSourceCommit = [string]$context.testSourceCommit
  if ($context.schema -ne "codex-bridge-b1-vm-run-context/v1" -or
      $context.testSourceCommit -notmatch '^[0-9a-f]{40}$' -or
      $context.mediaManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw "run_context_invalid" }
  $hostBytes = [IO.File]::ReadAllBytes($hostEvidencePath)
  $hostDigest = Get-BytesSha256 $hostBytes
  $sidecar = (Get-Content -LiteralPath $hostHashPath -Raw -Encoding ASCII).Trim() -split '\s+'
  if ($sidecar.Count -lt 1 -or $sidecar[0] -cne $hostDigest -or
      $hostDigest -cne $context.hostEvidenceSha256.ToLowerInvariant()) { throw "host_evidence_digest_mismatch" }
  $hostEvidence = [Text.Encoding]::UTF8.GetString($hostBytes) | ConvertFrom-Json
  $mediaManifestPath = Join-Path $MediaRoot "media-manifest.json"
  $mediaManifestBytes = [IO.File]::ReadAllBytes($mediaManifestPath)
  if ((Get-BytesSha256 $mediaManifestBytes) -cne $context.mediaManifestSha256.ToLowerInvariant()) {
    throw "media_manifest_digest_mismatch"
  }
  $mediaManifest = [Text.Encoding]::UTF8.GetString($mediaManifestBytes) | ConvertFrom-Json
  $manifestCheck = Test-McpVmMediaManifest -Manifest $mediaManifest -MediaRoot $MediaRoot `
    -ExpectedTestSourceCommit $context.testSourceCommit -HashFile { param($Path) Get-FileSha256 $Path }
  if ($manifestCheck.status -ne "PASS") { throw "media_manifest_or_artifact_invalid" }
  if (-not (Test-McpVmN5TrustAnchorAvailable)) {
    Write-Output "BLOCKED stage=guest-preflight VMN5=BLOCKED error_category=vmn5_trust_anchor_unavailable"
    throw "vmn5_trust_anchor_unavailable"
  }
  $hostCheck = Test-McpVmHostEvidence -Evidence $hostEvidence -ExpectedVmId $context.vmId `
    -ExpectedNonce $context.nonce -ExpectedSourceCommit $context.testSourceCommit `
    -ActualSha256 $hostDigest -ExpectedSha256 $context.hostEvidenceSha256
  if ($hostCheck.status -ne "PASS") { throw "host_isolation_evidence_not_pass" }

  $guestEvidence = Get-GuestEvidence $context $hostDigest
  $guestCheck = Test-McpVmGuestEvidence -Evidence $guestEvidence -HostEvidence $hostEvidence `
    -ExpectedHostEvidenceSha256 $hostDigest -ExpectedNonce $context.nonce `
    -ExpectedSourceCommit $context.testSourceCommit
  $guestEvidenceStatus = $guestCheck.status
  $sourceCommitPath = Join-Path $MediaRoot "SOURCE-COMMIT.txt"
  if ((Get-Content -LiteralPath $sourceCommitPath -Raw -Encoding ASCII).Trim() -cne $context.testSourceCommit) {
    throw "source_bundle_commit_mismatch"
  }
  if ($guestEvidenceStatus -ne "PASS") { throw "guest_isolation_evidence_not_pass" }

  $runnerTemp = [IO.Path]::GetTempPath().TrimEnd('\', '/')
  if ($runnerTemp -match '\s') { throw "temp_path_spaces_not_supported" }
  $nonce = $context.nonce.Substring(0, 32)
  $createdSourceRoot = Join-Path $runnerTemp "codex-bridge-vm-source-$nonce"
  $createdCandidateRoot = Join-Path $runnerTemp "codex-bridge-vm-candidate-$nonce"
  $candidateZip = Join-Path $MediaRoot "codex-bridge-windows-x64.zip"
  $sourceZip = Join-Path $MediaRoot "codex-bridge-vm-test-source.zip"
  $swiftPackageCacheZip = Join-Path $MediaRoot "swiftpm-pinned-source-cache.zip"
  if ((Get-FileSha256 $candidateZip) -cne $expectedPortableZipSha256) { throw "portable_zip_digest_mismatch" }
  Expand-McpVmZipSafely $sourceZip $createdSourceRoot
  Expand-McpVmZipSafely $candidateZip $createdCandidateRoot
  $candidateService = Assert-PortablePayload $createdCandidateRoot
  $packageRoot = Join-Path $createdSourceRoot "Packages\BridgeCore"
  if (-not (Test-Path -LiteralPath $packageRoot -PathType Container) -or
      -not (Test-Path -LiteralPath $swiftPackageCacheZip -PathType Leaf)) { throw "offline_swiftpm_source_cache_missing" }
  Expand-McpVmZipSafely $swiftPackageCacheZip $packageRoot
  if (-not (Test-Path -LiteralPath (Join-Path $packageRoot ".build\checkouts") -PathType Container) -or
      -not (Test-Path -LiteralPath (Join-Path $packageRoot ".build\repositories") -PathType Container)) {
    throw "offline_swiftpm_cache_incomplete"
  }
  $packageLockPath = Join-Path $packageRoot "Package.resolved"
  $schemaPath = Join-Path $createdSourceRoot ".github\schemas\mcp-2026-07-28.json"
  $validatorPath = Join-Path $createdSourceRoot ".github\scripts\vm\validate-mcp-vm-captures.py"
  $requirementsLockPath = Join-Path $createdSourceRoot ".github\scripts\vm\requirements-vm.txt"
  if (-not (Test-Path -LiteralPath (Join-Path $packageRoot "Package.swift") -PathType Leaf) -or
      -not (Test-Path -LiteralPath $packageLockPath -PathType Leaf) -or
      -not (Test-Path -LiteralPath $schemaPath -PathType Leaf) -or
      -not (Test-Path -LiteralPath $validatorPath -PathType Leaf) -or
      -not (Test-Path -LiteralPath $requirementsLockPath -PathType Leaf)) { throw "offline_test_source_incomplete" }
  if ((Get-FileSha256 $schemaPath).ToUpperInvariant() -cne $expectedSchemaSha256) { throw "fixed_schema_digest_mismatch" }

  $pythonVersion = @(& $PythonExe -I --version 2>&1) -join " "
  if ($LASTEXITCODE -ne 0 -or $pythonVersion -notmatch '^Python 3\.13\.11$') { throw "python_runtime_version_mismatch" }
  $swiftVersion = @(& $SwiftExe --version 2>&1) -join "`n"
  if ($LASTEXITCODE -ne 0 -or $swiftVersion -notmatch '(?m)^Swift version 6\.3\.3\b') { throw "swift_toolchain_version_mismatch" }
  if (-not (Test-Path -LiteralPath (Join-Path $VcpkgRoot "installed\x64-windows\include\sqlite3.h") -PathType Leaf) -or
      -not (Test-Path -LiteralPath (Join-Path $VcpkgRoot "installed\x64-windows\lib\sqlite3.lib") -PathType Leaf) -or
      -not (Test-Path -LiteralPath (Join-Path $VcpkgRoot "installed\x64-windows\bin\sqlite3.dll") -PathType Leaf)) {
    throw "sqlite_x64_development_dependency_missing"
  }

  $guestEvidence = Get-GuestEvidence $context $hostDigest
  $guestEvidencePath = Join-Path $runnerTemp "codex-bridge-vm-guest-evidence-$nonce.json"
  [void](Write-JsonFile $guestEvidencePath $guestEvidence)
  $captureDirectory = Join-Path $runnerTemp "codex-bridge-mcp-process-captures-$nonce"
  $pidRecordPath = Join-Path $runnerTemp "codex-bridge-vm-service-$nonce.pid.json"
  if ((Test-Path -LiteralPath $captureDirectory) -or (Test-Path -LiteralPath $pidRecordPath)) {
    throw "guest_temp_collision"
  }
  $dataRoot = Join-Path $runnerTemp "codex-bridge-b1-data-$nonce"
  $profileRoot = Join-Path $runnerTemp "codex-bridge-b1-profile-$nonce"
  $appData = Join-Path $profileRoot "AppData\Roaming"
  $localAppData = Join-Path $profileRoot "AppData\Local"
  $codexHome = Join-Path $profileRoot "CodexHome"
  $protocolSummaryPath = Join-Path $runnerTemp "codex-bridge-vm-protocol-summary-$nonce.json"

  $commonPythonArgs = @(
    $validatorPath, "--context", $contextPath, "--expected-context-sha256", $ExpectedContextSha256,
    "--host-evidence", $hostEvidencePath, "--host-evidence-sha256", $hostHashPath,
    "--guest-evidence", $guestEvidencePath, "--media-manifest", $mediaManifestPath,
    "--media-root", $MediaRoot, "--package-resolved", $packageLockPath,
    "--requirements-lock", $requirementsLockPath,
    "--schema", $schemaPath
  )
  $preflightOutput = @(& $PythonExe -I @commonPythonArgs --capture-dir $captureDirectory `
    --output $protocolSummaryPath --preflight-only 2>$null)
  if ($LASTEXITCODE -ne 0) { throw "vm_python_schema_preflight_failed" }

  if (-not $RunOfflineTest) { throw "explicit_offline_test_switch_required" }
  $buildEnvironmentScript = Join-Path $createdSourceRoot "Scripts\windows-build-environment.ps1"
  $swiftArgumentsScript = Join-Path $createdSourceRoot "Scripts\windows-swift-arguments.ps1"
  if (-not (Test-Path -LiteralPath $buildEnvironmentScript -PathType Leaf) -or
      -not (Test-Path -LiteralPath $swiftArgumentsScript -PathType Leaf)) { throw "windows_swift_build_scripts_missing" }
  . $buildEnvironmentScript
  $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
  if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw "vswhere_missing" }
  $vsRoot = @(& $vswhere -latest -property installationPath | Select-Object -First 1)
  if ($LASTEXITCODE -ne 0 -or -not $vsRoot) { throw "visual_studio_build_tools_missing" }
  $buildEnvironment = Get-WindowsBuildEnvironment -Architecture "x64"
  $vcpkgInstalledRoot = Join-Path $VcpkgRoot "installed\x64-windows"
  $includePaths = @((Join-Path $vcpkgInstalledRoot "include")) + $buildEnvironment.IncludePaths
  $libraryPaths = @((Join-Path $vcpkgInstalledRoot "lib")) + $buildEnvironment.LibraryPaths
  . $swiftArgumentsScript
  $swiftArgs = @(Get-WindowsSwiftArguments -VcpkgInstalledRoot $vcpkgInstalledRoot `
    -TargetTriple "x86_64-unknown-windows-msvc" -LibraryPaths $buildEnvironment.LibraryPaths)

  $captureDirectory = Join-Path $runnerTemp "codex-bridge-mcp-process-captures-$nonce"
  $pidRecordPath = Join-Path $runnerTemp "codex-bridge-vm-service-$nonce.pid.json"
  $swiftLog = Join-Path $runnerTemp "codex-bridge-vm-swift-test-$nonce.log"
  $argumentValues = @("test") + $swiftArgs + @("-c", "debug", "--skip-update", "--filter", "MCPWindowsExecutableProcessTests")
  $arguments = (@($argumentValues | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) })) -join " "
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = [IO.Path]::GetFullPath($SwiftExe)
  $startInfo.Arguments = $arguments
  $startInfo.WorkingDirectory = $packageRoot
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $envBlock = $startInfo.EnvironmentVariables
  $envBlock.Clear()
  foreach ($name in @("SystemRoot", "WINDIR")) { $envBlock[$name] = [Environment]::GetEnvironmentVariable($name) }
  $envBlock["USERPROFILE"] = $profileRoot
  $envBlock["APPDATA"] = $appData
  $envBlock["LOCALAPPDATA"] = $localAppData
  $envBlock["HOME"] = $profileRoot
  $envBlock["HOMEDRIVE"] = [IO.Path]::GetPathRoot($profileRoot).TrimEnd('\')
  $envBlock["HOMEPATH"] = $profileRoot.Substring(([IO.Path]::GetPathRoot($profileRoot)).Length - 1)
  $envBlock["TEMP"] = $runnerTemp
  $envBlock["TMP"] = $runnerTemp
  $envBlock["RUNNER_TEMP"] = $runnerTemp
  $envBlock["CODEX_BRIDGE_VM_SOURCE_ROOT"] = $createdSourceRoot
  $envBlock["CODEX_BRIDGE_VM_CANDIDATE_ROOT"] = $createdCandidateRoot
  $envBlock["CODEX_BRIDGE_VM_DATA_ROOT"] = $dataRoot
  $envBlock["CODEX_BRIDGE_VM_PROFILE_ROOT"] = $profileRoot
  $envBlock["CODEX_BRIDGE_CANDIDATE_DIR"] = $createdCandidateRoot
  $envBlock["CODEX_BRIDGE_CANDIDATE_SHA256"] = $expectedServiceSha256
  $envBlock["CODEX_BRIDGE_ARTIFACT_VERIFICATION"] = "PASS"
  $envBlock["CODEX_BRIDGE_MCP_PROCESS_CAPTURE_DIR"] = $captureDirectory
  $envBlock["CODEX_BRIDGE_MCP_PROCESS_PID_FILE"] = $pidRecordPath
  $swiftVersionDirectory = (Get-Item -LiteralPath (Split-Path -Parent $SwiftExe)).Parent.Parent
  if (-not $swiftVersionDirectory -or $swiftVersionDirectory.Name -notmatch '^6\.3\.3') {
    throw "swift_toolchain_directory_version_mismatch"
  }
  $swiftRoot = $swiftVersionDirectory.Parent.Parent.FullName
  $swiftRuntimeBin = Join-Path $swiftRoot "Runtimes\6.3.3\usr\bin"
  $sdkRoot = Join-Path $swiftRoot "Platforms\6.3.3\Windows.platform\Developer\SDKs\Windows.sdk"
  $msvcRoot = Split-Path -Parent $buildEnvironment.IncludePaths[1]
  $msvcBin = Join-Path $msvcRoot "bin\Hostx64\x64"
  $sdkVersion = Split-Path -Leaf (Split-Path -Parent $buildEnvironment.IncludePaths[2])
  $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
  $sdkBin = Join-Path $kitsRoot "bin\$sdkVersion\x64"
  if (-not (Test-Path -LiteralPath (Join-Path $swiftRuntimeBin "swiftCore.dll") -PathType Leaf) -or
      -not (Test-Path -LiteralPath $sdkRoot -PathType Container) -or
      -not (Test-Path -LiteralPath (Join-Path $msvcBin "cl.exe") -PathType Leaf) -or
      -not (Test-Path -LiteralPath (Join-Path $sdkBin "rc.exe") -PathType Leaf)) {
    throw "offline_windows_build_toolchain_incomplete"
  }
  $envBlock["PATH"] = @(
    (Split-Path -Parent $SwiftExe), $swiftRuntimeBin,
    (Join-Path $VcpkgRoot "installed\x64-windows\bin"),
    $msvcBin, $sdkBin, "$env:SystemRoot\System32", "$env:SystemRoot"
  ) -join ";"
  $envBlock["SDKROOT"] = $sdkRoot
  $envBlock["INCLUDE"] = $includePaths -join ";"
  $envBlock["LIB"] = $libraryPaths -join ";"
  $envBlock["LIBPATH"] = @($buildEnvironment.LibraryPaths) -join ";"
  $envBlock["TARGET_LIBRARY_PATHS"] = $libraryPaths -join ";"
  $envBlock["TARGET_TRIPLE"] = "x86_64-unknown-windows-msvc"
  $logWriter = [IO.File]::Create($swiftLog)
  $testRunnerProcess = [Diagnostics.Process]::new()
  $testRunnerProcess.StartInfo = $startInfo
  $testRunnerProcess.EnableRaisingEvents = $false
  if (-not $testRunnerProcess.Start()) { throw "swift_test_process_start_failed" }
  $runStarted = $true
  $stdoutTask = $testRunnerProcess.StandardOutput.ReadToEndAsync()
  $stderrTask = $testRunnerProcess.StandardError.ReadToEndAsync()
  $testRunnerExited = $testRunnerProcess.WaitForExit(1200000)
  if ($testRunnerExited -and ($routeTestStatus -eq "PASS" -or $routeTestStatus -eq "FAIL")) {
    $schemaOutput = @(& $PythonExe -I $validatorPath @commonPythonArgs `
      --capture-dir $captureDirectory --output $protocolSummaryPath 2>$null)
    if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $protocolSummaryPath -PathType Leaf)) {
      $schemaStatus = "PASS"
      $protocolSummary = Get-Content -LiteralPath $protocolSummaryPath -Raw -Encoding UTF8 | ConvertFrom-Json
      $responseDigests = @{}
      foreach ($property in $protocolSummary.protocol.responses.PSObject.Properties) {
        $responseDigests[$property.Name] = $property.Value.sha256
      }
    } else {
      $schemaStatus = "FAIL"
      Write-Output "FAIL test=mcp-schema error_category=vm_schema_validator_failed"
    }
  }

  if ($testRunnerExited) {
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $logWriter.Write([Text.Encoding]::UTF8.GetBytes($stdout))
    $logWriter.Write([Text.Encoding]::UTF8.GetBytes($stderr))
    $logWriter.Flush()
    $logWriter.Dispose()
    $runnerStatus = if ($testRunnerProcess.ExitCode -eq 0) { "PASS" } else { "FAIL" }
    $testLog = $stdout + "`n" + $stderr
    $routeMatches = [regex]::Matches($testLog, 'B1_MCP_ROUTE name=([a-z-]+) status=(PASS|FAIL)')
    foreach ($match in $routeMatches) { $routeResults[$match.Groups[1].Value] = $match.Groups[2].Value }
    $summaryMatch = [regex]::Match($testLog, 'Executed\s+(\d+)\s+tests?,(?:\s+with)?\s+(\d+)\s+failures?')
    if ($summaryMatch.Success) {
      $swiftTestsExecuted = [int]$summaryMatch.Groups[1].Value
      $swiftTestFailures = [int]$summaryMatch.Groups[2].Value
    }
    if ($summaryMatch.Success -and $summaryMatch.Groups[1].Value -eq "1" -and
        $summaryMatch.Groups[2].Value -eq "0" -and $testRunnerProcess.ExitCode -eq 0 -and
        $routeResults.Count -eq 5 -and @($routeResults.Values | Where-Object { $_ -ne "PASS" }).Count -eq 0) {
      $routeTestStatus = "PASS"
    } else { $routeTestStatus = "FAIL" }
    Write-Output "XCTEST status=$runnerStatus executed=$($summaryMatch.Groups[1].Value) failures=$($summaryMatch.Groups[2].Value) routes=$($routeResults.Count)"
  } else {
    $runnerStatus = "BLOCKED"
    $routeTestStatus = "BLOCKED"
    Write-Output "BLOCKED stage=xctest error_category=swift_test_timeout_runner_identity_retained"
  }

  if ($testRunnerExited) {
    $runRecord = [ordered]@{
      pid = 0; launchState = "prepared"; imagePath = $candidateService; imageSha256 = $expectedServiceSha256
      startedAtUtc = ""; dataRoot = $dataRoot; profileRoot = $profileRoot
      captureDirectory = $captureDirectory; sourceRoot = $createdSourceRoot; candidateRoot = $createdCandidateRoot
    }
    if (Test-Path -LiteralPath $pidRecordPath -PathType Leaf) {
      $runRecord = Get-Content -LiteralPath $pidRecordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    if ($runStarted -and ($testLog -match 'B1_PROCESS_LAUNCH_INTENT' -or [string]::IsNullOrWhiteSpace($testLog)) -and
        [int]$runRecord.pid -le 0) {
      $runRecord.launchState = "launching"
    }
    $servicePid = $runRecord.pid
    $cleanupAttempted = $true
    $supervisorResult = Invoke-McpVmGuestVerifiedCleanup $runRecord $candidateService $createdCandidateRoot $runnerTemp
    $cleanup = $supervisorResult.cleanup
    $portableIdentityAfterRun = $supervisorResult.portableIdentityAfterRun
  }

} catch {
  $routeTestStatus = if ($runStarted) { "FAIL" } else { "NOT_TESTED" }
  Write-Output "BLOCKED stage=guest-harness error_category=guest_preflight_or_execution_failed"
} finally {
  if ($logWriter) {
    try { $logWriter.Dispose() } catch { $cleanup.temporaryCleanup = "BLOCKED"; $cleanup.errorCategory = "swift_log_handle_cleanup_failed" }
  }
  if ($testRunnerProcess -and $testRunnerExited) {
    try { $testRunnerProcess.Dispose() } catch { $cleanup.temporaryCleanup = "BLOCKED"; $cleanup.errorCategory = "swift_runner_handle_cleanup_failed" }
  }
  if ($runStarted -and -not $testRunnerExited) {
    $cleanup = [pscustomobject]@{ serviceExit = "BLOCKED"; descendants = "NOT_TESTED"; temporaryCleanup = "BLOCKED"; errorCategory = "swift_test_runner_still_active" }
  }
  if ($runStarted -and $testRunnerExited -and -not $cleanupAttempted) {
    try {
      $candidateService = Join-Path $createdCandidateRoot "codex-bridge-service.exe"
      $runRecord = [ordered]@{
        pid = 0; launchState = "prepared"; imagePath = $candidateService; imageSha256 = $expectedServiceSha256
        startedAtUtc = ""; dataRoot = $dataRoot; profileRoot = $profileRoot
        captureDirectory = $captureDirectory; sourceRoot = $createdSourceRoot; candidateRoot = $createdCandidateRoot
      }
      if (Test-Path -LiteralPath $pidRecordPath -PathType Leaf) {
        $runRecord = Get-Content -LiteralPath $pidRecordPath -Raw -Encoding UTF8 | ConvertFrom-Json
      }
      if ($runStarted -and ($testLog -match 'B1_PROCESS_LAUNCH_INTENT' -or [string]::IsNullOrWhiteSpace($testLog)) -and
          [int]$runRecord.pid -le 0) {
        $runRecord.launchState = "launching"
      }
      $cleanupAttempted = $true
      $supervisorResult = Invoke-McpVmGuestVerifiedCleanup $runRecord $candidateService $createdCandidateRoot $runnerTemp
      $cleanup = $supervisorResult.cleanup
      $portableIdentityAfterRun = $supervisorResult.portableIdentityAfterRun
    } catch {
      $cleanup = [pscustomobject]@{ serviceExit = "BLOCKED"; descendants = "BLOCKED"; temporaryCleanup = "BLOCKED"; errorCategory = "cleanup_after_guest_failure_unverified" }
    }
  }
  if (-not $runStarted -and $runnerTemp) {
    $prelaunchCleanupFailed = $false
    foreach ($path in @($captureDirectory, $createdSourceRoot, $createdCandidateRoot, $profileRoot, $dataRoot)) {
      if ($path -and (Test-Path -LiteralPath $path)) {
        try { Remove-McpVmSafeTemporaryPath $path $runnerTemp } catch { $prelaunchCleanupFailed = $true }
      }
    }
    $cleanup.temporaryCleanup = if ($prelaunchCleanupFailed) { "BLOCKED" } else { "PASS" }
  }

  $serviceAndDirectoriesClean = $cleanup.temporaryCleanup -eq "PASS" -and
    ((-not $runStarted) -or ($cleanup.serviceExit -eq "PASS" -and $cleanup.descendants -eq "PASS"))
  if ($serviceAndDirectoriesClean -and $nonce) {
    foreach ($path in @($pidRecordPath, $guestEvidencePath, $protocolSummaryPath, $swiftLog)) {
      if ($path) {
        try { Remove-McpVmGuestTempFile $path $runnerTemp $nonce }
        catch {
          $cleanup.temporaryCleanup = "BLOCKED"
          $cleanup.errorCategory = "guest_temp_file_cleanup_failed"
          break
        }
      }
    }
  }

  try {
    $outputRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($OutputDirectory))
    $tempRoot = if ($runnerTemp) { [IO.Path]::GetPathRoot($runnerTemp) } else { $null }
    if (-not $outputRoot -or -not $tempRoot -or $outputRoot -ieq $tempRoot) { throw "separate_output_volume_unavailable" }
      $driveLetter = $outputRoot.TrimEnd('\', ':')
      $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
      $partition = Get-Partition -DriveLetter $driveLetter -ErrorAction Stop
      $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
      if ($volume.FileSystemLabel -cne $OutputVolumeLabel -or $disk.IsBoot -or $disk.IsSystem) {
        throw "output_volume_identity_changed"
      }
      if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null }
      if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force -ErrorAction Stop).Count -ne 0) {
        throw "output_directory_not_empty"
      }
      $hostCheck = if ($hostEvidence) { $hostEvidence.checks } else { @{ VMN1 = @{ status = "BLOCKED" }; VMN4 = @{ status = "BLOCKED" }; VMN5 = @{ status = "BLOCKED" } } }
      $guestCheck = if ($guestEvidence) { $guestEvidence.checks } else { @{ VMN2 = @{ status = "BLOCKED" }; VMN3 = @{ status = "BLOCKED" }; VMN4 = @{ status = "BLOCKED" } } }
      $summary = Get-GuestSummary $testSourceCommit $hostCheck $guestCheck $captureDirectory
      $summary.routeTests = $routeResults
      $summary.responses = $responseDigests
      $summary.schemaValidation = $schemaStatus
      $summary.swiftTestsExecuted = $swiftTestsExecuted
      $summary.swiftTestFailures = $swiftTestFailures
      $summary.serviceExit = $cleanup.serviceExit
      $summary.descendantExit = $cleanup.descendants
      $summary.cleanup = $cleanup.temporaryCleanup
      $summary.servicePid = $servicePid
      $summary.vmShutdown = if ($runStarted -and $cleanup.serviceExit -eq "PASS" -and $cleanup.temporaryCleanup -eq "PASS") { "REQUESTED" } else { "NOT_REQUESTED" }
      $testConditions = @($summary.vmIsolation.Values | Where-Object { $_ -ne "PASS" }).Count -eq 0 -and
        $routeTestStatus -eq "PASS" -and $schemaStatus -eq "PASS" -and
        (Test-McpVmN5TrustAnchorAvailable) -and
        $cleanup.serviceExit -eq "PASS" -and $cleanup.descendants -eq "PASS" -and $cleanup.temporaryCleanup -eq "PASS"
      $summary.overall = if ($testConditions) { "PENDING_HOST_FINALIZER" } else { "FAIL_OR_BLOCKED" }
      $summaryPath = Join-Path $OutputDirectory "vm-guest-summary.json"
      [void](Write-JsonFile $summaryPath $summary)
      $summaryHash = Get-FileSha256 $summaryPath
      [IO.File]::WriteAllText((Join-Path $OutputDirectory "vm-guest-summary.sha256"), "$summaryHash  vm-guest-summary.json`n", [Text.UTF8Encoding]::new($false))
      Write-Output "VM_GUEST_RESULT overall=$($summary.overall) VMN5=$($summary.vmIsolation.VMN5) routeTests=$routeTestStatus schema=$schemaStatus serviceExit=$($cleanup.serviceExit) cleanup=$($cleanup.temporaryCleanup) summary_sha256=$summaryHash"
      if ($summary.vmShutdown -eq "REQUESTED") {
        $shutdown = Start-Process -FilePath "$env:SystemRoot\System32\shutdown.exe" -ArgumentList "/s /t 0 /d p:4:1" -PassThru -Wait -WindowStyle Hidden
        if ($shutdown.ExitCode -ne 0) { Write-Output "BLOCKED stage=guest-shutdown error_category=shutdown_request_failed" }
        elseif ($summary.overall -eq "PENDING_HOST_FINALIZER") {
          $harnessExitCode = 0
          Write-Output "PASS stage=guest-shutdown status=requested"
        }
      }
  } catch {
    Write-Output "BLOCKED stage=guest-summary error_category=sanitized_report_write_failed"
  }
}

exit $harnessExitCode
