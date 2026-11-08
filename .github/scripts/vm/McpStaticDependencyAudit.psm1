Set-StrictMode -Version Latest

if (-not ('CodexBridgeStaticAuditFileIdentity' -as [type])) {
  $source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class CodexBridgeStaticAuditFileIdentity {
  [StructLayout(LayoutKind.Sequential)]
  private struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  private struct ByHandleFileInformation {
    public uint Attributes;
    public FileTime CreationTime;
    public FileTime LastAccessTime;
    public FileTime LastWriteTime;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
  }
  [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern SafeFileHandle CreateFile(string path, uint desiredAccess, uint shareMode,
    IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);
  public static string Read(string path) {
    const uint ShareReadWriteDelete = 0x00000007;
    const uint OpenExisting = 3;
    const uint BackupSemantics = 0x02000000;
    const uint OpenReparsePoint = 0x00200000;
    using (SafeFileHandle handle = CreateFile(path, 0, ShareReadWriteDelete, IntPtr.Zero,
      OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero)) {
      if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
      ByHandleFileInformation information;
      if (!GetFileInformationByHandle(handle, out information))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      return String.Format("{0:X8}:{1:X8}{2:X8}", information.VolumeSerialNumber,
        information.FileIndexHigh, information.FileIndexLow);
    }
  }
}
'@
  Add-Type -TypeDefinition $source -ErrorAction Stop
}

$script:CodexBridgeAuditSchemaSha256 = 'ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203'
$script:CodexBridgeAuditAllowedCategories = @(
  'harness-build-output',
  'swift-toolchain-6.3.3',
  'vcpkg-x64-dependencies',
  'approved-portable-service',
  'windows-system-components'
)

function Get-CodexBridgeAuditRootIdentity {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Identity,
    [Parameter(Mandatory = $true)][ValidateSet('harness-build-output', 'swift-toolchain-6.3.3', 'vcpkg-x64-dependencies', 'approved-portable-service', 'windows-system-components')][string]$SourceCategory
  )

  switch ($SourceCategory) {
    'harness-build-output' {
      return 'commit={0};run={1};target={2};configuration={3};compile={4};corelock={5};sdklok={6}' -f `
        $Identity.sourceCommit, $Identity.sourceWorkflowRun, $Identity.targetTriple, $Identity.buildConfiguration,
        $Identity.compileArgumentsSha256, $Identity.bridgeCoreLockSha256, $Identity.mcpSdkLockSha256
    }
    'swift-toolchain-6.3.3' {
      return 'version={0};variant={1};installer={2};pathid={3}' -f $Identity.swiftVersion, $Identity.swiftToolchainVariant, $Identity.swiftInstallerSha256, $Identity.swiftToolchainPathIdSha256
    }
    'vcpkg-x64-dependencies' {
      return 'revision={0};sqlite={1}' -f $Identity.vcpkgRevision, $Identity.sqlitePackage
    }
    'approved-portable-service' {
      return 'run={0};artifact={1};portable={2};commit={3};service={4}' -f `
        $Identity.portableRunId, $Identity.portableArtifactSha256, $Identity.portableZipSha256,
        $Identity.portableSourceCommit, $Identity.portableServiceSha256
    }
    'windows-system-components' {
      return 'image={0};msvc={1};sdk={2}' -f $Identity.windowsRunnerImage, $Identity.msvcVersion, $Identity.windowsSdkVersion
    }
  }
}

function Get-CodexBridgeAuditFullPath([string]$Path, [bool]$Directory, [string]$FailureCategory) {
  if ([string]::IsNullOrWhiteSpace($Path)) { throw "audit_$FailureCategory" }
  try {
    $full = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($Directory -and -not $item.PSIsContainer) { throw "audit_$FailureCategory" }
    if (-not $Directory -and $item.PSIsContainer) { throw "audit_$FailureCategory" }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'audit_reparse_point_not_allowed' }
    $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $full -ErrorAction Stop).Path)
    if (-not [string]::Equals($resolved, $full, [StringComparison]::OrdinalIgnoreCase)) { throw 'audit_path_alias_not_allowed' }
    return $full
  } catch {
    if ($_.Exception.Message -match '^audit_[a-z0-9_]+$') { throw }
    throw "audit_$FailureCategory"
  }
}

function Assert-CodexBridgeAuditNoReparseAncestors([string]$Path) {
  $current = [IO.Path]::GetFullPath($Path)
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'audit_reparse_point_not_allowed' }
    $parent = Split-Path -Parent $current
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ieq $current) { return }
    $current = $parent
  }
  throw 'audit_path_ancestor_unverified'
}

function Test-CodexBridgeAuditPathWithin([string]$Path, [string]$Root) {
  $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $pathFull = [IO.Path]::GetFullPath($Path)
  return $pathFull.StartsWith(($rootFull + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)
}

function Get-CodexBridgeAuditFileIdentity([string]$Path) {
  try { return [CodexBridgeStaticAuditFileIdentity]::Read($Path) }
  catch { throw 'audit_file_identity_unavailable' }
}

function Get-CodexBridgeAuditSha256([string]$Path, [string]$ExpectedFileIdentity = '') {
  $before = Get-CodexBridgeAuditFileIdentity $Path
  if ($ExpectedFileIdentity -and $before -cne $ExpectedFileIdentity) { throw 'audit_file_identity_changed' }
  $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  $after = Get-CodexBridgeAuditFileIdentity $Path
  if ($before -cne $after) { throw 'audit_file_identity_changed' }
  return [pscustomobject]@{ sha256 = $hash; identity = $before }
}

function Get-CodexBridgeAuditPEMachine([string]$Path) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $reader = [IO.BinaryReader]::new($stream)
  try {
    if ($stream.Length -lt 70 -or $reader.ReadByte() -ne 0x4d -or $reader.ReadByte() -ne 0x5a) { throw 'audit_pe_header_invalid' }
    $stream.Position = 0x3c
    $peOffset = $reader.ReadInt32()
    if ($peOffset -lt 64 -or ($peOffset + 6) -gt $stream.Length) { throw 'audit_pe_header_invalid' }
    $stream.Position = $peOffset
    if ([BitConverter]::ToString($reader.ReadBytes(4)) -cne '50-45-00-00') { throw 'audit_pe_header_invalid' }
    switch ($reader.ReadUInt16()) {
      0x8664 { return 'AMD64' }
      0x014c { return 'I386' }
      0xaa64 { return 'ARM64' }
      default { throw 'audit_pe_machine_unrecognized' }
    }
  } catch {
    if ($_.Exception.Message -match '^audit_[a-z0-9_]+$') { throw }
    throw 'audit_pe_header_invalid'
  } finally {
    $reader.Dispose()
  }
}

function Parse-CodexBridgeDumpbinImports {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines,
    [ValidateRange(1024, 4194304)][int]$MaximumCharacters = 1048576,
    [ValidateRange(1, 65536)][int]$MaximumImports = 4096
  )

  $totalCharacters = 0
  foreach ($line in $Lines) {
    $totalCharacters += $line.Length
    if ($totalCharacters -gt $MaximumCharacters) { throw 'audit_dumpbin_output_limit_exceeded' }
  }
  $imports = [Collections.Generic.List[object]]::new()
  $section = ''
  $sawImportSection = $false
  foreach ($line in $Lines) {
    if ($line -match '^\s*Section contains the following imports:\s*$') {
      $section = 'ordinary'
      $sawImportSection = $true
      continue
    }
    if ($line -match '^\s*Section contains the following delay load imports:\s*$') {
      $section = 'delay'
      $sawImportSection = $true
      continue
    }
    if (-not $section) { continue }
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -match '^ {4}([A-Za-z0-9_.+-]{1,128}\.dll)\s*$') {
      $name = $Matches[1].ToLowerInvariant()
      $imports.Add([pscustomobject]@{ name = $name; kind = $section })
      if ($imports.Count -gt $MaximumImports) { throw 'audit_dumpbin_import_limit_exceeded' }
      continue
    }
    if ($line -match '^\s{8,}\S') { continue }
    if ($line -match '^\s*Summary\s*$' -or $line -match '^\s*Dump of file\s+') { $section = ''; continue }
    if ($line -match '^\S') { $section = ''; continue }
    throw 'audit_dumpbin_format_unrecognized'
  }
  if (-not $sawImportSection) { throw 'audit_dumpbin_output_unrecognized' }
  return @($imports | Sort-Object name, kind -Unique)
}

function Get-CodexBridgeAuditImportResult {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$DumpbinPath,
    [Parameter(Mandatory = $true)][string]$RunnerTemp,
    [scriptblock]$PeImportProvider,
    [int]$TimeoutSeconds = 60,
    [int]$CleanupSeconds = 5,
    [int]$MaximumCharacters = 1048576,
    [int]$MaximumImports = 4096
  )
  if ($PeImportProvider) {
    $providedResults = @(& $PeImportProvider $Path)
    if ($providedResults.Count -ne 1) { throw 'audit_dumpbin_provider_output_invalid' }
    $provided = $providedResults[0]
    if ($null -eq $provided -or
        -not ($provided.PSObject.Properties.Name -contains 'ExitCode') -or
        -not ($provided.PSObject.Properties.Name -contains 'Output')) {
      throw 'audit_dumpbin_provider_output_invalid'
    }
    if ($provided.ExitCode -ne 0) { throw 'audit_dumpbin_failed' }
    $lines = @($provided.Output | ForEach-Object { [string]$_ })
  } else {
    $runnerTempFull = Get-CodexBridgeAuditFullPath $RunnerTemp $true 'runner_temp_invalid'
    Assert-CodexBridgeAuditNoReparseAncestors $runnerTempFull
    $outputPath = Join-Path $runnerTempFull ('mcp-audit-' + [Guid]::NewGuid().ToString('N'))
    $stdoutPath = $outputPath + '.stdout.txt'
    $stderrPath = $outputPath + '.stderr.txt'
    $process = $null
    $cleanupAttempted = $false
    $startInfo = $null
    try {
      if (Test-Path -LiteralPath $stdoutPath -or Test-Path -LiteralPath $stderrPath) { throw 'audit_dumpbin_temp_collision' }
      $arguments = '/nologo /imports "{0}"' -f $Path
      $process = Start-Process -FilePath $DumpbinPath -ArgumentList $arguments `
        -WorkingDirectory (Split-Path -Parent $DumpbinPath) -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath -WindowStyle Hidden -PassThru -ErrorAction Stop
      $processId = $process.Id
      $startTimeTicks = $process.StartTime.ToUniversalTime().Ticks
      $stopwatch = [Diagnostics.Stopwatch]::StartNew()
      while (-not $process.WaitForExit(100)) {
        $outputBytes = 0L
        foreach ($outputFile in @($stdoutPath, $stderrPath)) {
          if (Test-Path -LiteralPath $outputFile -PathType Leaf) {
            $outputBytes += (Get-Item -LiteralPath $outputFile -Force -ErrorAction Stop).Length
          }
        }
        if ($outputBytes -gt $MaximumCharacters) {
          $cleanupAttempted = $true
          Stop-CodexBridgeAuditOwnedProcess -Process $process -ExpectedPath $DumpbinPath `
            -ExpectedId $processId -ExpectedStartTimeTicks $startTimeTicks -CleanupSeconds $CleanupSeconds
          throw 'audit_dumpbin_output_limit_exceeded'
        }
        if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
          $cleanupAttempted = $true
          Stop-CodexBridgeAuditOwnedProcess -Process $process -ExpectedPath $DumpbinPath `
            -ExpectedId $processId -ExpectedStartTimeTicks $startTimeTicks -CleanupSeconds $CleanupSeconds
          throw 'audit_dumpbin_timeout'
        }
      }
      [void]$process.WaitForExit()
      if ($process.ExitCode -ne 0) { throw 'audit_dumpbin_failed' }
      $outputBytes = 0L
      foreach ($outputFile in @($stdoutPath, $stderrPath)) {
        if (Test-Path -LiteralPath $outputFile -PathType Leaf) {
          $outputBytes += (Get-Item -LiteralPath $outputFile -Force -ErrorAction Stop).Length
        }
      }
      if ($outputBytes -gt $MaximumCharacters) { throw 'audit_dumpbin_output_limit_exceeded' }
      $outputText = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
        [IO.File]::ReadAllText($stdoutPath, [Text.Encoding]::UTF8)
      } else { '' }
      $lines = @($outputText -split '\r?\n')
    } catch {
      if ($_.Exception.Message -match '^audit_[a-z0-9_]+$') { throw }
      throw 'audit_dumpbin_execution_failed'
    } finally {
      if ($process) {
        try {
          $process.Refresh()
          if (-not $process.HasExited -and -not $cleanupAttempted) {
            $cleanupAttempted = $true
            Stop-CodexBridgeAuditOwnedProcess -Process $process -ExpectedPath $DumpbinPath `
              -ExpectedId $process.Id -ExpectedStartTimeTicks $process.StartTime.ToUniversalTime().Ticks `
              -CleanupSeconds $CleanupSeconds
          }
        } finally { $process.Dispose() }
      }
      foreach ($outputFile in @($stdoutPath, $stderrPath)) {
        if (Test-Path -LiteralPath $outputFile -PathType Leaf) {
          $item = Get-Item -LiteralPath $outputFile -Force -ErrorAction SilentlyContinue
          if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
            Remove-Item -LiteralPath $outputFile -Force -ErrorAction SilentlyContinue
          }
        }
      }
    }
  }
  return @(Parse-CodexBridgeDumpbinImports -Lines $lines -MaximumCharacters $MaximumCharacters -MaximumImports $MaximumImports)
}

function Stop-CodexBridgeAuditOwnedProcess {
  param(
    [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
    [Parameter(Mandatory = $true)][string]$ExpectedPath,
    [Parameter(Mandatory = $true)][int]$ExpectedId,
    [Parameter(Mandatory = $true)][long]$ExpectedStartTimeTicks,
    [ValidateRange(1, 30)][int]$CleanupSeconds
  )
  try {
    $Process.Refresh()
    if ($Process.HasExited) { return }
    $actualPath = [IO.Path]::GetFullPath($Process.MainModule.FileName)
    $actualStartTicks = $Process.StartTime.ToUniversalTime().Ticks
    $expectedFullPath = [IO.Path]::GetFullPath($ExpectedPath)
  } catch { throw 'audit_dumpbin_process_identity_unverified' }
  if ($Process.Id -ne $ExpectedId -or $actualStartTicks -ne $ExpectedStartTimeTicks -or
      -not [string]::Equals($actualPath, $expectedFullPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'audit_dumpbin_process_identity_unverified'
  }
  try { $Process.Kill() } catch { throw 'audit_dumpbin_process_cleanup_failed' }
  if (-not $Process.WaitForExit($CleanupSeconds * 1000) -or -not $Process.HasExited) {
    throw 'audit_dumpbin_process_cleanup_failed'
  }
}

function Get-CodexBridgeAuditRelativePath([string]$Root, [string]$Path, [string]$Prefix) {
  $relative = [IO.Path]::GetRelativePath($Root, $Path).Replace('\', '/')
  if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|/)\.\.?(/|$)' -or
      $relative -notmatch '^[A-Za-z0-9._+/-]{1,512}$') { throw 'audit_relative_path_unrepresentable' }
  $combined = (($Prefix.Trim('/') + '/' + $relative).Trim('/'))
  if ($combined -notmatch '^[A-Za-z0-9._+/-]{1,768}$' -or $combined -match '(^|/)\.\.?(/|$)') {
    throw 'audit_relative_path_unrepresentable'
  }
  return $combined
}

function Get-CodexBridgeAuditRootFiles {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [ValidateRange(1, 100000)][int]$MaximumFiles = 50000,
    [ValidateRange(1, 128)][int]$MaximumDepth = 48,
    [ValidateRange(1, 500000)][int]$MaximumEntries = 100000,
    [ValidateRange(1, 1073741824)][long]$MaximumFileBytes = 1073741824,
    [ValidateRange(1, 8589934592)][long]$MaximumTotalBytes = 4294967296,
    [ValidateRange(1, 3600)][int]$MaximumSeconds = 600
  )
  $files = [Collections.Generic.List[string]]::new()
  $pending = [Collections.Generic.Stack[object]]::new()
  $entryCount = 0
  $totalBytes = 0L
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $pending.Push([pscustomobject]@{ path = $Root; depth = 0 })
  while ($pending.Count -gt 0) {
    $current = $pending.Pop()
    if ($current.depth -gt $MaximumDepth) { throw 'audit_source_depth_limit_exceeded' }
    foreach ($entryPath in [IO.Directory]::EnumerateFileSystemEntries($current.path)) {
      $entryCount++
      if ($entryCount -gt $MaximumEntries) { throw 'audit_source_entry_limit_exceeded' }
      if ($timer.Elapsed.TotalSeconds -gt $MaximumSeconds) { throw 'audit_source_traversal_timeout' }
      $item = Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'audit_reparse_point_not_allowed' }
      $full = [IO.Path]::GetFullPath($item.FullName)
      if (-not (Test-CodexBridgeAuditPathWithin $full $Root)) { throw 'audit_source_path_escape' }
      if ($item.PSIsContainer) {
        $pending.Push([pscustomobject]@{ path = $full; depth = ($current.depth + 1) })
      } elseif ($item.Extension -ieq '.dll') {
        if ($item.Length -gt $MaximumFileBytes) { throw 'audit_source_file_size_limit_exceeded' }
        $totalBytes += [long]$item.Length
        if ($totalBytes -gt $MaximumTotalBytes) { throw 'audit_source_total_size_limit_exceeded' }
        $files.Add($full)
        if ($files.Count -gt $MaximumFiles) { throw 'audit_source_file_limit_exceeded' }
      }
    }
  }
  return $files.ToArray()
}

function Get-CodexBridgeAuditSystemDll {
  param([string]$Name, [string]$SystemRoot)
  if ($Name -match '^(?:api|ext)-ms-win-[a-z0-9-]+-l[0-9]+-[0-9]+-[0-9]+\.dll$') {
    return [pscustomobject]@{ status = 'UNRESOLVED'; reason = 'api_set_contract_unverified' }
  }
  $systemDirectory = Join-Path $SystemRoot 'System32'
  $candidate = Join-Path $systemDirectory $Name
  if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
  $full = Get-CodexBridgeAuditFullPath $candidate $false 'system_dll_path_invalid'
  Assert-CodexBridgeAuditNoReparseAncestors $full
  $identity = Get-CodexBridgeAuditFileIdentity $full
  $sha = Get-CodexBridgeAuditSha256 $full $identity
  $machine = Get-CodexBridgeAuditPEMachine $full
  if ($machine -cne 'AMD64') { throw 'audit_system_dll_architecture_mismatch' }
  return [pscustomobject]@{
    status = 'SYSTEM_PROVIDED'
    sourceCategory = 'windows-system-components'
    relativePath = "System32/$Name"
    sha256 = $sha.sha256
    peMachine = $machine
    evidence = 'file present in verified x64 System32 root'
  }
}

function New-CodexBridgeAuditReport {
  param([System.Collections.IDictionary]$Identity)
  return [pscustomobject][ordered]@{
    schemaVersion = 1
    sourceCommit = [string]$Identity.sourceCommit
    sourceWorkflowRun = [string]$Identity.sourceWorkflowRun
    toolchainIdentity = [pscustomobject][ordered]@{
      swiftVersion = [string]$Identity.swiftVersion
      toolchainVariant = [string]$Identity.swiftToolchainVariant
      installerSha256 = [string]$Identity.swiftInstallerSha256
      pathIdentitySha256 = [string]$Identity.swiftToolchainPathIdSha256
    }
    targetTriple = [string]$Identity.targetTriple
    buildConfiguration = [string]$Identity.buildConfiguration
    auditScope = 'HARNESS_AND_PORTABLE_SERVICE_STATIC_PE_IMPORTS'
    candidateIdentity = [pscustomobject][ordered]@{
      candidates = @()
      runnerBuildAssociation = 'NOT_VERIFIED'
      runnerTestDiscovery = 'NOT_VERIFIED'
      directRunnerExecution = 'NOT_VERIFIED'
    }
    graphStatus = [pscustomobject][ordered]@{
      harness = 'NOT_RUN'
      portableService = 'NOT_RUN'
    }
    dependencyNodes = @()
    dependencyEdges = @()
    unresolvedDependencies = @()
    dependencyNodeCount = 0
    importEdgeCount = 0
    delayImportEdgeCount = 0
    unresolvedCount = 0
    sourceCollisionCount = 0
    dynamicDependencyStatus = 'NOT_VERIFIED'
    resourceLayoutStatus = 'NOT_VERIFIED'
    inputHashes = [pscustomobject][ordered]@{}
    failureCategory = $null
    auditStatus = 'INCOMPLETE'
    packageExecutable = 'UNRESOLVED'
  }
}

function Invoke-CodexBridgeStaticImportAudit {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Identity,
    [Parameter(Mandatory = $true)][string]$WorkspaceRoot,
    [Parameter(Mandatory = $true)][string]$RunnerTemp,
    [Parameter(Mandatory = $true)][object[]]$SourceRoots,
    [Parameter(Mandatory = $true)][object[]]$Candidates,
    [Parameter(Mandatory = $true)][string]$SystemRoot,
    [Parameter(Mandatory = $true)][string]$DumpbinPath,
    [Parameter(Mandatory = $true)][string]$FixedSchemaPath,
    [Parameter(Mandatory = $true)][string]$ExpectedSchemaSha256,
    [scriptblock]$PeImportProvider,
    [ValidateRange(3, 256)][int]$MaximumNodes = 256,
    [ValidateRange(1, 256)][int]$MaximumDepth = 64,
    [ValidateRange(8, 4096)][int]$MaximumEdges = 2048,
    [ValidateRange(1, 4194304)][int]$MaximumOutputCharacters = 1048576
  )

  $report = New-CodexBridgeAuditReport $Identity
  $auditStopwatch = [Diagnostics.Stopwatch]::StartNew()
  $nodeList = [Collections.Generic.List[object]]::new()
  $edgeList = [Collections.Generic.List[object]]::new()
  $unresolvedList = [Collections.Generic.List[object]]::new()
  $activeGraph = $null
  try {
    if ($Identity.sourceCommit -notmatch '^[0-9a-fA-F]{40}$' -or
        $Identity.requestedSourceCommit -notmatch '^[0-9a-fA-F]{40}$' -or
        -not [string]::Equals($Identity.sourceCommit, $Identity.requestedSourceCommit, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'audit_source_commit_mismatch'
    }
    if ($Identity.sourceWorkflowRun -notmatch '^[0-9]{1,20}$') { throw 'audit_workflow_run_identity_invalid' }
    if ($Identity.targetTriple -cne 'x86_64-unknown-windows-msvc' -or $Identity.buildConfiguration -cne 'debug') { throw 'audit_build_identity_mismatch' }
    if ($Identity.swiftVersion -cne '6.3.3') { throw 'audit_swift_identity_mismatch' }
    if ($Identity.swiftToolchainVariant -cnotin @('6.3.3', '6.3.3+Asserts')) { throw 'audit_swift_variant_mismatch' }
    foreach ($hashField in @('swiftInstallerSha256', 'swiftToolchainPathIdSha256', 'compileArgumentsSha256', 'bridgeCoreLockSha256', 'mcpSdkLockSha256', 'portableArtifactSha256', 'portableZipSha256', 'portableServiceSha256', 'schemaSha256')) {
      if ([string]$Identity[$hashField] -notmatch '^[0-9a-fA-F]{64}$') { throw 'audit_input_hash_invalid' }
    }
    if ($Identity.vcpkgRevision -notmatch '^[0-9a-fA-F]{40}$' -or
        $Identity.sqlitePackage -notmatch '^sqlite3:x64-windows\s+\S+$' -or
        $Identity.portableRunId -cne '41665722609' -or
        $Identity.portableSourceCommit -cne 'f2235028773e7d9e0da714218a5694c4eb8bfef3') {
      throw 'audit_source_identity_mismatch'
    }
    if ($ExpectedSchemaSha256 -cne $script:CodexBridgeAuditSchemaSha256 -or
        $Identity.schemaSha256.ToLowerInvariant() -cne $script:CodexBridgeAuditSchemaSha256) {
      throw 'audit_fixed_schema_identity_mismatch'
    }
    if ($Identity.msvcVersion -notmatch '^[0-9.]{1,32}$' -or
        $Identity.windowsSdkVersion -notmatch '^[0-9.]{1,32}$' -or
        $Identity.windowsRunnerImage -notmatch '^[A-Za-z0-9._-]{1,100}$') {
      throw 'audit_windows_build_identity_invalid'
    }

    $workspace = Get-CodexBridgeAuditFullPath $WorkspaceRoot $true 'workspace_invalid'
    $schemaPath = Get-CodexBridgeAuditFullPath $FixedSchemaPath $false 'fixed_schema_missing'
    Assert-CodexBridgeAuditNoReparseAncestors $workspace
    Assert-CodexBridgeAuditNoReparseAncestors $schemaPath
    $schemaHash = (Get-CodexBridgeAuditSha256 $schemaPath).sha256
    if ($schemaHash -cne $script:CodexBridgeAuditSchemaSha256) { throw 'audit_fixed_schema_sha256_mismatch' }

    $rootMap = [Collections.Generic.List[object]]::new()
    $rootPathKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($sourceRoot in $SourceRoots) {
      if ($sourceRoot.category -cnotin $script:CodexBridgeAuditAllowedCategories) { throw 'audit_source_category_invalid' }
      $allowedKinds = switch ([string]$sourceRoot.category) {
        'harness-build-output' { @('swiftpm-debug-bin') }
        'swift-toolchain-6.3.3' { @('swift-toolchain-bin', 'swift-runtime-bin') }
        'vcpkg-x64-dependencies' { @('vcpkg-runtime-bin') }
        'approved-portable-service' { @('portable-root') }
        'windows-system-components' { @('system32', 'msvc-tools') }
      }
      if ([string]$sourceRoot.sourceKind -cnotin $allowedKinds) { throw 'audit_source_kind_invalid' }
      if ($sourceRoot.sourceIdentity -cne (Get-CodexBridgeAuditRootIdentity -Identity $Identity -SourceCategory $sourceRoot.category)) {
        throw 'audit_source_root_identity_mismatch'
      }
      $rootPath = Get-CodexBridgeAuditFullPath ([string]$sourceRoot.path) $true 'source_root_invalid'
      Assert-CodexBridgeAuditNoReparseAncestors $rootPath
      if (-not $rootPathKeys.Add($rootPath)) { throw 'audit_duplicate_source_root' }
      $prefix = [string]$sourceRoot.relativePrefix
      if ($prefix -notmatch '^[A-Za-z0-9._/-]{1,256}$' -or $prefix -match '(^|/)\.\.?(/|$)') { throw 'audit_source_prefix_invalid' }
      $rootMap.Add([pscustomobject]@{
        category = [string]$sourceRoot.category
        sourceKind = [string]$sourceRoot.sourceKind
        path = $rootPath
        prefix = $prefix
        sourceIdentity = [string]$sourceRoot.sourceIdentity
      })
    }
    foreach ($requiredCategory in $script:CodexBridgeAuditAllowedCategories) {
      if (@($rootMap | Where-Object { $_.category -ceq $requiredCategory }).Count -eq 0) { throw 'audit_source_category_missing' }
    }
    $expectedSystem32 = Get-CodexBridgeAuditFullPath (Join-Path $SystemRoot 'System32') $true 'system32_root_invalid'
    $system32Roots = @($rootMap | Where-Object { $_.category -ceq 'windows-system-components' -and $_.sourceKind -ceq 'system32' })
    if ($system32Roots.Count -ne 1 -or
        -not [string]::Equals($system32Roots[0].path, $expectedSystem32, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'audit_system32_root_mismatch'
    }
    $buildRoot = [IO.Path]::GetFullPath((Join-Path $workspace 'Packages\BridgeCore\.build'))
    $harnessRoots = @($rootMap | Where-Object { $_.category -ceq 'harness-build-output' })
    if (@($harnessRoots | Where-Object { -not (Test-CodexBridgeAuditPathWithin $_.path $buildRoot) }).Count -gt 0) {
      throw 'audit_harness_root_outside_swiftpm_build_tree'
    }

    $candidateByRole = @{}
    $expectedCandidateSpecs = @{
      'candidate-xctest-runner' = @{ name = 'BridgeMCPTests-test-runner.exe'; graph = 'harness'; category = 'harness-build-output' }
      'xctest-test-module' = @{ name = 'BridgeMCPTests.dll'; graph = 'harness'; category = 'harness-build-output' }
      'portable-service' = @{ name = 'codex-bridge-service.exe'; graph = 'portable-service'; category = 'approved-portable-service' }
    }
    foreach ($candidate in $Candidates) {
      if (-not $expectedCandidateSpecs.ContainsKey([string]$candidate.role) -or $candidateByRole.ContainsKey([string]$candidate.role)) {
        throw 'audit_candidate_role_invalid'
      }
      $expected = $expectedCandidateSpecs[[string]$candidate.role]
      if ($candidate.name -cne $expected.name -or $candidate.graph -cne $expected.graph -or $candidate.category -cne $expected.category) {
        throw 'audit_candidate_identity_invalid'
      }
      if ($candidate.expectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'audit_candidate_sha256_invalid' }
      $candidateRoot = @($rootMap | Where-Object { $_.category -ceq $candidate.category })
      if ($candidateRoot.Count -eq 0) { throw 'audit_candidate_root_missing' }
      $path = Get-CodexBridgeAuditFullPath ([string]$candidate.path) $false 'candidate_path_invalid'
      if (-not (@($candidateRoot | Where-Object { Test-CodexBridgeAuditPathWithin $path $_.path }).Count -eq 1)) {
        throw 'audit_candidate_path_outside_source_root'
      }
      Assert-CodexBridgeAuditNoReparseAncestors $path
      $fileIdentity = Get-CodexBridgeAuditFileIdentity $path
      $fileHash = Get-CodexBridgeAuditSha256 $path $fileIdentity
      if ($fileHash.sha256 -cne $candidate.expectedSha256.ToLowerInvariant()) { throw 'audit_candidate_sha256_mismatch' }
      $machine = Get-CodexBridgeAuditPEMachine $path
      if ($machine -cne 'AMD64') { throw 'audit_candidate_architecture_mismatch' }
      $candidateByRole[[string]$candidate.role] = [pscustomobject]@{
        role = [string]$candidate.role
        name = [string]$candidate.name
        graph = [string]$candidate.graph
        category = [string]$candidate.category
        path = $path
        root = $candidateRoot[0]
        sha256 = $fileHash.sha256
        identity = $fileIdentity
        machine = $machine
      }
    }
    foreach ($role in $expectedCandidateSpecs.Keys) {
      if (-not $candidateByRole.ContainsKey($role)) { throw 'audit_candidate_missing' }
    }

    $packageManifest = Get-CodexBridgeAuditFullPath (Join-Path $workspace 'Packages\BridgeCore\Package.swift') $false 'package_manifest_missing'
    $packageText = [IO.File]::ReadAllText($packageManifest)
    if ($packageText -notmatch '(?s)\.testTarget\s*\(\s*name\s*:\s*"BridgeMCPTests"') { throw 'audit_test_target_declaration_missing' }

    $dumpbinFull = Get-CodexBridgeAuditFullPath $DumpbinPath $false 'dumpbin_unavailable'
    Assert-CodexBridgeAuditNoReparseAncestors $dumpbinFull
    if (@($rootMap | Where-Object { $_.category -ceq 'windows-system-components' -and $_.sourceKind -ceq 'msvc-tools' -and (Test-CodexBridgeAuditPathWithin $dumpbinFull $_.path) }).Count -ne 1) {
      throw 'audit_dumpbin_source_unverified'
    }
    $dumpbinHash = (Get-CodexBridgeAuditSha256 $dumpbinFull).sha256

    $rootIndexes = @{}
    foreach ($root in $rootMap) {
      if ($root.category -ceq 'windows-system-components') { continue }
      $files = @(Get-CodexBridgeAuditRootFiles -Root $root.path)
      $index = @{}
      foreach ($file in $files) {
        $baseName = [IO.Path]::GetFileName($file).ToLowerInvariant()
        if (-not $index.ContainsKey($baseName)) { $index[$baseName] = [Collections.Generic.List[string]]::new() }
        $index[$baseName].Add($file)
      }
      $rootIndexes[$root.path] = $index
    }

    $report.inputHashes = [pscustomobject][ordered]@{
      fixedSchemaSha256 = $schemaHash
      bridgeCoreLockSha256 = $Identity.bridgeCoreLockSha256.ToLowerInvariant()
      mcpSdkLockSha256 = $Identity.mcpSdkLockSha256.ToLowerInvariant()
      swiftInstallerSha256 = $Identity.swiftInstallerSha256.ToLowerInvariant()
      swiftToolchainPathIdSha256 = $Identity.swiftToolchainPathIdSha256.ToLowerInvariant()
      compileArgumentsSha256 = $Identity.compileArgumentsSha256.ToLowerInvariant()
      dumpbinSha256 = $dumpbinHash
      portableArtifactSha256 = $Identity.portableArtifactSha256.ToLowerInvariant()
      portableZipSha256 = $Identity.portableZipSha256.ToLowerInvariant()
      portableServiceSha256 = $Identity.portableServiceSha256.ToLowerInvariant()
      candidateSha256 = @($candidateByRole.Values | Sort-Object role | ForEach-Object { [pscustomobject]@{ role = $_.role; sha256 = $_.sha256 } })
    }

    $nodeByIdentity = @{}
    $activeIdentity = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $walk = $null
    $resolveImport = $null

    $resolveImport = {
      param([string]$Name, [string]$Graph)
      $graphCategories = if ($Graph -ceq 'harness') {
        @('harness-build-output', 'swift-toolchain-6.3.3', 'vcpkg-x64-dependencies', 'windows-system-components')
      } else {
        @('approved-portable-service', 'windows-system-components')
      }
      $matches = [Collections.Generic.List[object]]::new()
      $systemUnresolvedReason = $null
      foreach ($root in @($rootMap | Where-Object { $_.category -cin $graphCategories })) {
        if ($root.category -ceq 'windows-system-components' -and $root.sourceKind -ceq 'system32') {
          $systemResult = Get-CodexBridgeAuditSystemDll -Name $Name -SystemRoot $SystemRoot
          if ($systemResult) {
            if ($systemResult.status -ceq 'UNRESOLVED') {
              $systemUnresolvedReason = $systemResult.reason
            } elseif ($systemResult.relativePath.StartsWith('System32/', [StringComparison]::Ordinal)) {
              $systemPath = Join-Path (Join-Path $SystemRoot 'System32') $Name
              $systemIdentity = Get-CodexBridgeAuditFileIdentity $systemPath
              $matches.Add([pscustomobject]@{
                status = 'SYSTEM_PROVIDED'; category = $root.category; root = $root
                path = $systemPath; identity = $systemIdentity; sha256 = $systemResult.sha256
                machine = $systemResult.peMachine; relativePath = $systemResult.relativePath
              })
            }
          }
          continue
        }
        if ($root.category -ceq 'windows-system-components') { continue }
        $index = $rootIndexes[$root.path]
        $key = $Name.ToLowerInvariant()
        if ($index.ContainsKey($key)) {
          foreach ($path in $index[$key]) {
            $full = Get-CodexBridgeAuditFullPath $path $false 'dependency_path_invalid'
            if (-not (Test-CodexBridgeAuditPathWithin $full $root.path)) { throw 'audit_dependency_path_escape' }
            Assert-CodexBridgeAuditNoReparseAncestors $full
            $identityValue = Get-CodexBridgeAuditFileIdentity $full
            $hashValue = Get-CodexBridgeAuditSha256 $full $identityValue
            $machineValue = Get-CodexBridgeAuditPEMachine $full
            if ($machineValue -cne 'AMD64') { throw 'audit_dependency_architecture_mismatch' }
            $matches.Add([pscustomobject]@{
              status = 'RESOLVED'; category = $root.category; root = $root
              path = $full; identity = $identityValue; sha256 = $hashValue.sha256
              machine = $machineValue
              relativePath = Get-CodexBridgeAuditRelativePath $root.path $full $root.prefix
            })
          }
        }
      }
      if ($systemUnresolvedReason) {
        return [pscustomobject]@{ status = 'UNRESOLVED'; reason = $systemUnresolvedReason; match = $null }
      }
      if ($matches.Count -eq 0) {
        $reason = 'no_approved_source'
        return [pscustomobject]@{ status = 'UNRESOLVED'; reason = $reason; match = $null }
      }
      $unique = @($matches | Group-Object identity)
      if ($unique.Count -gt 1) {
        return [pscustomobject]@{
          status = 'UNRESOLVED'; reason = 'COLLISION_UNRESOLVED'; match = $null
          candidateSourceCategories = @($matches.category | Sort-Object -Unique)
        }
      }
      $match = $matches[0]
      if ($matches.Count -gt 1 -and @($matches.category | Sort-Object -Unique).Count -gt 1) {
        return [pscustomobject]@{
          status = 'UNRESOLVED'; reason = 'COLLISION_UNRESOLVED'; match = $null
          candidateSourceCategories = @($matches.category | Sort-Object -Unique)
        }
      }
      return [pscustomobject]@{ status = $match.status; reason = ''; match = $match }
    }

    $walk = {
      param([pscustomobject]$NodeSource, [string]$Graph, [string]$DependencyName, [int]$Depth)
      if ($auditStopwatch.Elapsed.TotalSeconds -gt 2700) { throw 'audit_total_timeout' }
      if ($Depth -gt $MaximumDepth) { throw 'audit_dependency_depth_limit_exceeded' }
      $identityKey = $NodeSource.identity
      if ($activeIdentity.Contains($identityKey)) { throw 'audit_dependency_cycle' }
      if ($nodeByIdentity.ContainsKey($identityKey)) {
        $existingNode = $nodeByIdentity[$identityKey]
        if ($existingNode.graphs -notcontains $Graph) { $existingNode.graphs += $Graph }
        return $existingNode
      }
      if ($nodeList.Count -ge $MaximumNodes) { throw 'audit_node_limit_exceeded' }
      $nodeId = 'n{0:D4}' -f ($nodeList.Count + 1)
      $beforeImportHash = Get-CodexBridgeAuditSha256 $NodeSource.path $identityKey
      if ($beforeImportHash.sha256 -cne $NodeSource.sha256) { throw 'audit_file_content_changed' }
      $imports = @(Get-CodexBridgeAuditImportResult -Path $NodeSource.path -DumpbinPath $dumpbinFull `
        -RunnerTemp $RunnerTemp -PeImportProvider $PeImportProvider -MaximumCharacters $MaximumOutputCharacters)
      $afterImportHash = Get-CodexBridgeAuditSha256 $NodeSource.path $identityKey
      if ($afterImportHash.sha256 -cne $beforeImportHash.sha256) { throw 'audit_file_content_changed' }
      $node = [pscustomobject][ordered]@{
        nodeId = $nodeId
        graph = $Graph
        graphs = @($Graph)
        dependencyName = $DependencyName
        status = $NodeSource.status
        sourceCategory = $NodeSource.category
        sourceKind = $NodeSource.root.sourceKind
        sourceIdentity = $NodeSource.root.sourceIdentity
        relativePath = $NodeSource.relativePath
        sha256 = $NodeSource.sha256
        peMachine = $NodeSource.machine
        importCount = $imports.Count
      }
      $nodeByIdentity[$identityKey] = $node
      $nodeList.Add($node)
      [void]$activeIdentity.Add($identityKey)
      try {
        foreach ($import in $imports) {
          if ($edgeList.Count -ge $MaximumEdges) { throw 'audit_edge_limit_exceeded' }
          if ($import.name -notmatch '^[A-Za-z0-9_.+-]{1,128}\.dll$') {
            $unresolvedList.Add([pscustomobject]@{ graph = $Graph; dependencyName = $null; reason = 'noncanonical_import_name' })
            $edgeList.Add([pscustomobject]@{ fromNodeId = $nodeId; dependencyName = $null; importKind = $import.kind; toNodeId = $null; status = 'UNRESOLVED' })
            continue
          }
          $resolution = & $resolveImport $import.name $Graph
          if ($resolution.status -eq 'UNRESOLVED') {
            $candidateSourceCategories = @()
            if ($resolution.PSObject.Properties.Name -contains 'candidateSourceCategories') {
              $candidateSourceCategories = @($resolution.candidateSourceCategories)
            }
            $unresolvedRecord = [pscustomobject]@{
              graph = $Graph
              dependencyName = $import.name
              reason = $resolution.reason
              candidateSourceCategories = $candidateSourceCategories
            }
            $unresolvedList.Add($unresolvedRecord)
            $edgeList.Add([pscustomobject]@{ fromNodeId = $nodeId; dependencyName = $import.name; importKind = $import.kind; toNodeId = $null; status = 'UNRESOLVED' })
            continue
          }
          $match = $resolution.match
          if ($match.status -ceq 'SYSTEM_PROVIDED' -and $null -eq $match.path) {
            $systemNodeId = 's-' + $import.name.ToLowerInvariant()
            if (-not $nodeByIdentity.ContainsKey($match.identity)) {
              $systemNode = [pscustomobject][ordered]@{
                nodeId = $systemNodeId; graph = $Graph; graphs = @($Graph); dependencyName = $import.name
                status = 'SYSTEM_PROVIDED'; sourceCategory = $match.category; sourceKind = $match.root.sourceKind
                sourceIdentity = $match.root.sourceIdentity; relativePath = $match.relativePath
                sha256 = $null; peMachine = 'NOT_APPLICABLE'; importCount = $null
              }
              $nodeByIdentity[$match.identity] = $systemNode
              $nodeList.Add($systemNode)
            } else {
              $systemNode = $nodeByIdentity[$match.identity]
              if ($systemNode.graphs -notcontains $Graph) { $systemNode.graphs += $Graph }
              $systemNodeId = $systemNode.nodeId
            }
            $edgeList.Add([pscustomobject]@{ fromNodeId = $nodeId; dependencyName = $import.name; importKind = $import.kind; toNodeId = $systemNodeId; status = 'SYSTEM_PROVIDED' })
            continue
          }
          $child = & $walk $match $Graph $import.name ($Depth + 1)
          $edgeList.Add([pscustomobject]@{ fromNodeId = $nodeId; dependencyName = $import.name; importKind = $import.kind; toNodeId = $child.nodeId; status = $match.status })
        }
      } finally {
        [void]$activeIdentity.Remove($identityKey)
      }
      return $node
    }

    foreach ($role in @('candidate-xctest-runner', 'xctest-test-module', 'portable-service')) {
      $candidate = $candidateByRole[$role]
      if ($activeGraph -and $activeGraph -cne $candidate.graph) {
        $previousGraphUnresolved = @($unresolvedList | Where-Object { $_.graph -ceq $activeGraph }).Count
        $previousGraphStatus = if ($previousGraphUnresolved -gt 0) { 'INCOMPLETE' } else { 'PASS' }
        if ($activeGraph -ceq 'harness') { $report.graphStatus.harness = $previousGraphStatus }
        elseif ($activeGraph -ceq 'portable-service') { $report.graphStatus.portableService = $previousGraphStatus }
        $activeGraph = $null
      }
      if (-not $activeGraph) {
        $activeGraph = $candidate.graph
        if ($activeGraph -ceq 'harness') { $report.graphStatus.harness = 'IN_PROGRESS' }
        elseif ($activeGraph -ceq 'portable-service') { $report.graphStatus.portableService = 'IN_PROGRESS' }
      }
      $nodeSource = [pscustomobject]@{
        status = 'RESOLVED'; category = $candidate.category; root = $candidate.root
        path = $candidate.path; identity = $candidate.identity; sha256 = $candidate.sha256
        machine = $candidate.machine; relativePath = Get-CodexBridgeAuditRelativePath $candidate.root.path $candidate.path $candidate.root.prefix
      }
      $node = & $walk $nodeSource $candidate.graph $candidate.name 0
      $report.candidateIdentity.candidates += [pscustomobject]@{
        role = $candidate.role; name = $candidate.name; graph = $candidate.graph
        sourceCategory = $candidate.category; relativePath = $node.relativePath
        sha256 = $candidate.sha256; peMachine = $candidate.machine; nodeId = $node.nodeId
      }
    }
    if ($activeGraph) {
      $activeGraphUnresolved = @($unresolvedList | Where-Object { $_.graph -ceq $activeGraph }).Count
      $activeGraphStatus = if ($activeGraphUnresolved -gt 0) { 'INCOMPLETE' } else { 'PASS' }
      if ($activeGraph -ceq 'harness') { $report.graphStatus.harness = $activeGraphStatus }
      elseif ($activeGraph -ceq 'portable-service') { $report.graphStatus.portableService = $activeGraphStatus }
      $activeGraph = $null
    }

    $runnerNode = @($report.candidateIdentity.candidates | Where-Object { $_.role -ceq 'candidate-xctest-runner' })[0]
    $testModuleNode = @($report.candidateIdentity.candidates | Where-Object { $_.role -ceq 'xctest-test-module' })[0]
    $runnerEdges = @($edgeList | Where-Object { $_.fromNodeId -ceq $runnerNode.nodeId -and $_.dependencyName -ieq 'BridgeMCPTests.dll' -and $_.status -eq 'RESOLVED' })
    $sameBuildRoot = [string]::Equals($candidateByRole['candidate-xctest-runner'].root.path, $candidateByRole['xctest-test-module'].root.path, [StringComparison]::OrdinalIgnoreCase)
    if ($runnerEdges.Count -eq 1 -and $sameBuildRoot -and $testModuleNode.peMachine -ceq 'AMD64') {
      $report.candidateIdentity.runnerBuildAssociation = 'PASS'
    } else {
      $report.candidateIdentity.runnerBuildAssociation = 'FAIL'
      $unresolvedList.Add([pscustomobject]@{ graph = 'harness'; dependencyName = 'BridgeMCPTests.dll'; reason = 'runner_build_association_unverified'; candidateSourceCategories = @('harness-build-output') })
      $report.graphStatus.harness = 'INCOMPLETE'
    }

    $portableRoot = @($rootMap | Where-Object { $_.category -ceq 'approved-portable-service' })[0]
    $resourceRelativePaths = @(
      'BridgeCore_BridgeMCP.bundle/FileTransfer/index.html',
      'BridgeCore_BridgeMCP.bundle/FileTransfer/transfer-core.js',
      'BridgeCore_BridgeMCP.bundle/FileTransfer/transfer-view.js',
      'BridgeCore_BridgeMCP.bundle/FileTransfer/transfer.css'
    )
    $resourceHashes = [Collections.Generic.List[object]]::new()
    foreach ($relative in $resourceRelativePaths) {
      $resource = Join-Path $portableRoot.path ($relative.Replace('/', '\'))
      if (-not (Test-Path -LiteralPath $resource -PathType Leaf)) { throw 'audit_portable_resource_missing' }
      $resourcePath = Get-CodexBridgeAuditFullPath $resource $false 'portable_resource_invalid'
      if (-not (Test-CodexBridgeAuditPathWithin $resourcePath $portableRoot.path)) { throw 'audit_portable_resource_path_escape' }
      Assert-CodexBridgeAuditNoReparseAncestors $resourcePath
      $resourceHashes.Add([pscustomobject]@{ relativePath = Get-CodexBridgeAuditRelativePath $portableRoot.path $resourcePath $portableRoot.prefix; sha256 = (Get-CodexBridgeAuditSha256 $resourcePath).sha256 })
    }
    $report.resourceLayoutStatus = 'PORTABLE_VERIFIED_DEBUG_NOT_VERIFIED'
    $report.inputHashes | Add-Member -NotePropertyName portableResourceHashes -NotePropertyValue $resourceHashes.ToArray()

    $report.dependencyNodes = $nodeList.ToArray()
    $report.dependencyEdges = $edgeList.ToArray()
    $report.unresolvedDependencies = @($unresolvedList | Sort-Object graph, dependencyName, reason -Unique)
    if ($report.candidateIdentity.runnerBuildAssociation -eq 'FAIL') {
      $report.auditStatus = 'INCOMPLETE'
    } elseif ($report.unresolvedDependencies.Count -gt 0) {
      $report.auditStatus = 'INCOMPLETE'
    } else {
      $report.auditStatus = 'PASS'
    }
  } catch {
    $message = [string]$_.Exception.Message
    if ($message -match '^audit_([a-z0-9_]+)$') { $report.failureCategory = $Matches[1] }
    else { $report.failureCategory = 'internal_audit_failure' }
    $report.auditStatus = 'FAIL'
    if ($activeGraph -ceq 'harness') { $report.graphStatus.harness = 'FAIL' }
    elseif ($activeGraph -ceq 'portable-service') { $report.graphStatus.portableService = 'FAIL' }
  }
  if ($nodeList.Count -gt 0) { $report.dependencyNodes = $nodeList.ToArray() }
  if ($edgeList.Count -gt 0) { $report.dependencyEdges = $edgeList.ToArray() }
  if ($unresolvedList.Count -gt 0) {
    $report.unresolvedDependencies = @($unresolvedList | Sort-Object graph, dependencyName, reason -Unique)
  }
  $report.dependencyNodeCount = @($report.dependencyNodes).Count
  $report.importEdgeCount = @($report.dependencyEdges).Count
  $report.delayImportEdgeCount = @($report.dependencyEdges | Where-Object { $_.importKind -ceq 'delay' }).Count
  $report.unresolvedCount = @($report.unresolvedDependencies).Count
  $report.sourceCollisionCount = @($report.unresolvedDependencies | Where-Object { $_.reason -ceq 'COLLISION_UNRESOLVED' }).Count
  $serializedReport = ConvertTo-Json -InputObject $report -Depth 18 -Compress
  if ($serializedReport.Length -gt $MaximumOutputCharacters) {
    $report = New-CodexBridgeAuditReport $Identity
    $report.failureCategory = 'audit_report_limit_exceeded'
    $report.auditStatus = 'FAIL'
  }
  return $report
}

Export-ModuleMember -Function Get-CodexBridgeAuditRootIdentity, Parse-CodexBridgeDumpbinImports, Get-CodexBridgeAuditPEMachine, Invoke-CodexBridgeStaticImportAudit
