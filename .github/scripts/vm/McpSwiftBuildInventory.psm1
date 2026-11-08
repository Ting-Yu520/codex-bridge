Set-StrictMode -Version Latest

if (-not ('CodexBridgePathIdentity' -as [type])) {
  $identitySource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class CodexBridgePathIdentity {
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
  Add-Type -TypeDefinition $identitySource -ErrorAction Stop
}

function Get-CodexBridgeFullPath([string]$Path, [string]$ErrorCategory) {
  if ([string]::IsNullOrWhiteSpace($Path)) { throw $ErrorCategory }
  try {
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath)) { throw $ErrorCategory }
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'inventory_reparse_point_not_allowed' }
    $resolvedPath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $fullPath -ErrorAction Stop).Path)
    if (-not [string]::Equals($resolvedPath, $fullPath, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'inventory_path_alias_not_allowed'
    }
    return $fullPath
  } catch {
    if ($_.Exception.Message -in @('inventory_reparse_point_not_allowed', 'inventory_path_alias_not_allowed')) { throw }
    throw $ErrorCategory
  }
}

function Test-CodexBridgePathWithin([string]$Path, [string]$Root) {
  $normalizedRoot = $Root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $prefix = $normalizedRoot + [IO.Path]::DirectorySeparatorChar
  return $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-CodexBridgeNoReparseAncestors([string]$Path, [string]$StopAt) {
  $current = $Path
  $stop = $StopAt.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  while ($current.StartsWith($stop, [StringComparison]::OrdinalIgnoreCase)) {
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw 'inventory_reparse_point_not_allowed'
    }
    if ($current -ieq $stop) { return }
    $parent = Split-Path -Parent $current
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ieq $current) { break }
    $current = $parent
  }
  throw 'inventory_path_ancestor_unverified'
}

function Get-CodexBridgeFileIdentity([string]$Path) {
  try {
    return [CodexBridgePathIdentity]::Read($Path)
  } catch {
    throw 'inventory_file_identity_unavailable'
  }
}

function Assert-CodexBridgeIdentityUnchanged([string]$Path, [string]$ExpectedIdentity, [string]$ErrorCategory) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'inventory_reparse_point_not_allowed' }
  $actualIdentity = Get-CodexBridgeFileIdentity $Path
  if ($actualIdentity -cne $ExpectedIdentity) { throw $ErrorCategory }
}

function Test-CodexBridgeMZHeader([string]$Path) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    if ($stream.Length -lt 2) { return $false }
    return ($stream.ReadByte() -eq 0x4d -and $stream.ReadByte() -eq 0x5a)
  } finally {
    $stream.Dispose()
  }
}

function Get-CodexBridgeDeclaredTestTargetNames([string]$PackageManifestPath) {
  $manifestText = Get-Content -LiteralPath $PackageManifestPath -Raw -ErrorAction Stop
  $matches = [regex]::Matches($manifestText, '(?s)\.testTarget\s*\(\s*name\s*:\s*"([A-Za-z0-9_-]+)"')
  $names = @($matches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
  if ($names.Count -eq 0) { throw 'inventory_swift_test_targets_unavailable' }
  return $names
}

function Get-CodexBridgeDeclaredTestResourceBundles([string]$PackageManifestPath) {
  $manifestText = Get-Content -LiteralPath $PackageManifestPath -Raw -ErrorAction Stop
  $packageMatch = [regex]::Match($manifestText, '(?s)\blet\s+package\s*=\s*Package\s*\(\s*name\s*:\s*"(?<name>[A-Za-z0-9_-]+)"')
  if (-not $packageMatch.Success) { throw 'inventory_swift_package_identity_unavailable' }
  $packageName = $packageMatch.Groups['name'].Value

  $declarationPattern = '(?ms)^(?<indent>[ \t]*)\.(?<kind>testTarget|target)\s*\(\s*name\s*:\s*"(?<name>[A-Za-z0-9_-]+)"(?<body>.*?)^\k<indent>\)(?:,)?\s*$'
  $declarations = @(
    foreach ($match in [regex]::Matches($manifestText, $declarationPattern)) {
      [pscustomobject]@{
        Kind = $match.Groups['kind'].Value
        Name = $match.Groups['name'].Value
        Body = $match.Groups['body'].Value
      }
    }
  )
  $testDeclarations = @($declarations | Where-Object { $_.Kind -ceq 'testTarget' })
  if ($testDeclarations.Count -eq 0) { throw 'inventory_swift_test_target_declarations_unavailable' }

  $reachableTargetNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($testTarget in $testDeclarations) {
    [void]$reachableTargetNames.Add($testTarget.Name)
    $dependencyMatch = [regex]::Match($testTarget.Body, '(?s)\bdependencies\s*:\s*\[(?<entries>.*?)\]')
    if (-not $dependencyMatch.Success) { continue }
    $dependencyEntries = [regex]::Replace($dependencyMatch.Groups['entries'].Value, '(?s)\.product\s*\([^)]*\)', '')
    foreach ($nameMatch in [regex]::Matches($dependencyEntries, '"(?<name>[A-Za-z0-9_-]+)"')) {
      [void]$reachableTargetNames.Add($nameMatch.Groups['name'].Value)
    }
  }

  $resourceBundleEvidence = [Collections.Generic.List[object]]::new()
  foreach ($target in @($declarations | Where-Object { $reachableTargetNames.Contains($_.Name) })) {
    $resourceMatch = [regex]::Match($target.Body, '(?s)\bresources\s*:\s*\[(?<entries>.*?)\]')
    if (-not $resourceMatch.Success) { continue }
    $entries = $resourceMatch.Groups['entries'].Value
    $supportedRules = [regex]::Matches($entries, '\.copy\s*\(\s*"(?<path>[^"\r\n]+)"\s*\)')
    $remainder = [regex]::Replace($entries, '\.copy\s*\(\s*"[^"\r\n]+"\s*\)', '')
    $remainder = [regex]::Replace($remainder, '[,\s]', '')
    if ($supportedRules.Count -eq 0 -or $remainder.Length -ne 0) {
      throw 'inventory_swift_resource_declaration_unrecognized'
    }
    foreach ($rule in $supportedRules) {
      $resourcePath = $rule.Groups['path'].Value.Replace('/', '\')
      $resourceEntryName = [IO.Path]::GetFileName($resourcePath)
      if ([string]::IsNullOrWhiteSpace($resourceEntryName) -or $resourceEntryName -in @('.', '..') -or $resourceEntryName.Contains(':')) {
        throw 'inventory_swift_resource_declaration_unrecognized'
      }
      $resourceBundleEvidence.Add([pscustomobject]@{
        bundleName = "$packageName`_$($target.Name).resources"
        resourceEntry = $resourceEntryName
        targetName = $target.Name
      })
    }
  }
  return @($resourceBundleEvidence | Sort-Object bundleName, resourceEntry -Unique)
}

function Get-CodexBridgePEMachine([string]$Path) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $reader = [IO.BinaryReader]::new($stream)
  try {
    if ($stream.Length -lt 70 -or $reader.ReadByte() -ne 0x4d -or $reader.ReadByte() -ne 0x5a) {
      throw 'inventory_pe_header_invalid'
    }
    $stream.Position = 0x3c
    $peOffset = $reader.ReadInt32()
    if ($peOffset -lt 64 -or ($peOffset + 6) -gt $stream.Length) { throw 'inventory_pe_header_invalid' }
    $stream.Position = $peOffset
    $signature = $reader.ReadBytes(4)
    if ([BitConverter]::ToString($signature) -cne '50-45-00-00') { throw 'inventory_pe_header_invalid' }
    $machine = $reader.ReadUInt16()
    switch ($machine) {
      0x014c { return 'I386' }
      0x8664 { return 'AMD64' }
      0xaa64 { return 'ARM64' }
      default { return ('UNKNOWN_0x{0:X4}' -f $machine) }
    }
  } finally {
    $reader.Dispose()
  }
}

function Get-CodexBridgePEImports {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$DumpbinPath = '',
    [scriptblock]$PeImportsProvider
  )

  if ($PeImportsProvider) {
    return @(& $PeImportsProvider $Path | Sort-Object -Unique)
  }
  if ([string]::IsNullOrWhiteSpace($DumpbinPath) -or
      -not (Test-Path -LiteralPath $DumpbinPath -PathType Leaf)) {
    throw 'inventory_dumpbin_unavailable'
  }
  $output = @(& $DumpbinPath /nologo /dependents $Path 2>&1)
  $exitCode = $LASTEXITCODE
  if ($exitCode -ne 0) { throw 'inventory_dumpbin_failed' }
  $outputText = $output -join "`n"
  if ($outputText -notmatch 'Image has the following dependencies:') {
    throw 'inventory_dumpbin_output_unrecognized'
  }
  $imports = @(
    foreach ($line in $output) {
      if ([string]$line -match '^\s+([A-Za-z0-9_.+-]+\.dll)\s*$') {
        $Matches[1].ToLowerInvariant()
      }
    }
  )
  return @($imports | Sort-Object -Unique)
}

function New-CodexBridgeBuildInventory {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$WorkspaceRoot,
    [Parameter(Mandatory = $true)][string]$BinPath,
    [string]$DumpbinPath = '',
    [scriptblock]$PeImportsProvider,
    [Parameter(Mandatory = $true)][string]$RunnerTemp,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$SourceCommit,
    [Parameter(Mandatory = $true)][string]$WorkflowRunId,
    [Parameter(Mandatory = $true)][string]$SwiftVersion,
    [Parameter(Mandatory = $true)][string]$SwiftToolchainPathId,
    [Parameter(Mandatory = $true)][string]$SwiftInstallerSha256,
    [Parameter(Mandatory = $true)][string]$VcpkgRevision,
    [Parameter(Mandatory = $true)][string]$VcpkgSqlitePackage,
    [Parameter(Mandatory = $true)][string]$MsvcVersion,
    [Parameter(Mandatory = $true)][string]$WindowsSdkVersion,
    [Parameter(Mandatory = $true)][string]$WindowsRunnerImage,
    [Parameter(Mandatory = $true)][string]$BridgeCoreLockSha256,
    [Parameter(Mandatory = $true)][string]$McpSdkLockSha256,
    [Parameter(Mandatory = $true)][string]$TargetTriple,
    [Parameter(Mandatory = $true)][string]$BuildConfiguration,
    [Parameter(Mandatory = $true)][bool]$BuildTests,
    [Parameter(Mandatory = $true)][string]$ReleaseBinPath,
    [Parameter(Mandatory = $true)][string]$BaseBuildArgumentsSha256,
    [Parameter(Mandatory = $true)][string]$CompileArgumentsSha256,
    [Parameter(Mandatory = $true)][string]$DebugBinPathQueryArgumentsSha256,
    [Parameter(Mandatory = $true)][string]$ReleaseBinPathQueryArgumentsSha256,
    [string]$SchemaExpectedSha256 = 'EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203'
  )

  if ($SourceCommit -notmatch '^[0-9a-fA-F]{40}$') { throw 'inventory_source_commit_invalid' }
  if ($WorkflowRunId -notmatch '^[0-9]{1,20}$') { throw 'inventory_run_id_invalid' }
  if ($SwiftVersion -cne '6.3.3') { throw 'inventory_swift_version_invalid' }
  if ($TargetTriple -cne 'x86_64-unknown-windows-msvc') { throw 'inventory_target_triple_invalid' }
  if ($BuildConfiguration -cne 'debug') { throw 'inventory_build_configuration_invalid' }
  if (-not $BuildTests) { throw 'inventory_test_build_not_enabled' }
  if ($SchemaExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'inventory_schema_sha256_invalid' }
  foreach ($hash in @(
      $SwiftToolchainPathId, $SwiftInstallerSha256, $BridgeCoreLockSha256, $McpSdkLockSha256,
      $BaseBuildArgumentsSha256, $CompileArgumentsSha256,
      $DebugBinPathQueryArgumentsSha256, $ReleaseBinPathQueryArgumentsSha256)) {
    if ($hash -notmatch '^[0-9a-fA-F]{64}$') { throw 'inventory_sha256_identity_invalid' }
  }
  if ($VcpkgRevision -notmatch '^[0-9a-fA-F]{40}$') { throw 'inventory_vcpkg_revision_invalid' }
  if ($VcpkgSqlitePackage -notmatch '^sqlite3:x64-windows\s+\S+$') { throw 'inventory_sqlite_package_identity_invalid' }
  if ($MsvcVersion -notmatch '^[0-9.]{1,32}$') { throw 'inventory_msvc_version_invalid' }
  if ($WindowsSdkVersion -notmatch '^[0-9.]{1,32}$') { throw 'inventory_windows_sdk_version_invalid' }
  if ($WindowsRunnerImage -notmatch '^[A-Za-z0-9._-]{1,100}$') { throw 'inventory_runner_image_invalid' }

  $workspaceFull = Get-CodexBridgeFullPath $WorkspaceRoot 'inventory_workspace_missing'
  $runnerTempFull = Get-CodexBridgeFullPath $RunnerTemp 'inventory_runner_temp_missing'
  $binFull = Get-CodexBridgeFullPath $BinPath 'inventory_bin_path_missing'
  $releaseBinFull = [IO.Path]::GetFullPath($ReleaseBinPath)
  $schemaInputPath = Join-Path $workspaceFull '.github\schemas\mcp-2026-07-28.json'
  if (-not (Test-Path -LiteralPath $schemaInputPath -PathType Leaf)) { throw 'inventory_fixed_schema_missing' }
  $schemaHash = (Get-FileHash -LiteralPath $schemaInputPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($schemaHash -cne $SchemaExpectedSha256.ToLowerInvariant()) { throw 'inventory_fixed_schema_sha256_mismatch' }
  $packageRoot = [IO.Path]::GetFullPath((Join-Path $workspaceFull 'Packages\BridgeCore'))
  $buildRoot = [IO.Path]::GetFullPath((Join-Path $packageRoot '.build'))
  $buildRootItem = Get-Item -LiteralPath $buildRoot -Force -ErrorAction Stop
  if (-not $buildRootItem.PSIsContainer) { throw 'inventory_build_root_invalid' }
  $buildRootFull = [IO.Path]::GetFullPath($buildRootItem.FullName)
  if (-not (Test-CodexBridgePathWithin $binFull $buildRootFull)) {
    throw 'inventory_bin_path_outside_package_build'
  }
  if (-not (Test-CodexBridgePathWithin $releaseBinFull $buildRootFull)) {
    throw 'inventory_release_bin_path_outside_package_build'
  }
  if ([string]::Equals($binFull, $releaseBinFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'inventory_debug_release_binpath_ambiguous'
  }
  if (-not [string]::Equals($BuildConfiguration, 'debug', [StringComparison]::Ordinal)) {
    throw 'inventory_build_configuration_invalid'
  }
  if (-not (Test-CodexBridgePathWithin ([IO.Path]::GetFullPath($OutputPath)) $runnerTempFull)) {
    throw 'inventory_output_outside_runner_temp'
  }
  if ([IO.Path]::GetFullPath($OutputPath).StartsWith($buildRootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'inventory_output_inside_build_tree'
  }
  Assert-CodexBridgeNoReparseAncestors $buildRootFull $workspaceFull
  Assert-CodexBridgeNoReparseAncestors $binFull $buildRootFull

  $releaseCursor = $releaseBinFull
  while (-not (Test-Path -LiteralPath $releaseCursor)) {
    $releaseParent = Split-Path -Parent $releaseCursor
    if ([string]::IsNullOrWhiteSpace($releaseParent) -or $releaseParent -ieq $releaseCursor) {
      throw 'inventory_release_bin_path_unverified'
    }
    $releaseCursor = $releaseParent
  }
  Assert-CodexBridgeNoReparseAncestors ([IO.Path]::GetFullPath($releaseCursor)) $buildRootFull
  $buildRootIdentity = Get-CodexBridgeFileIdentity $buildRootFull
  $binIdentity = Get-CodexBridgeFileIdentity $binFull
  $packageManifestPath = Join-Path $packageRoot 'Package.swift'
  if (-not (Test-Path -LiteralPath $packageManifestPath -PathType Leaf)) {
    throw 'inventory_package_manifest_missing'
  }
  $testTargetNames = @(Get-CodexBridgeDeclaredTestTargetNames $packageManifestPath)
  $testResourceBundles = @(Get-CodexBridgeDeclaredTestResourceBundles $packageManifestPath)

  $sensitivePathPattern = '(?i)(^|[/\\._-])(api[-._/]?key|runtime[-._/]?key|token|cookie|secret|credential)([/\\._-]|$)'
  $pendingDirectories = [Collections.Generic.Stack[string]]::new()
  $pendingDirectories.Push($binFull)
  $files = [Collections.Generic.List[object]]::new()
  $directoryIdentities = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  $fileIdentities = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  $directoryIdentities.Add($binFull, $binIdentity)
  [long]$scannedFileCount = 0
  [long]$outOfScopeFileCount = 0
  [long]$candidateSizeBytes = 0
  [long]$scannedSizeBytes = 0

  while ($pendingDirectories.Count -gt 0) {
    $directory = $pendingDirectories.Pop()
    Assert-CodexBridgeNoReparseAncestors $directory $buildRootFull
    $directoryIdentity = Get-CodexBridgeFileIdentity $directory
    if (-not $directoryIdentities.ContainsKey($directory) -or
        $directoryIdentities[$directory] -cne $directoryIdentity) { throw 'inventory_directory_replaced' }
    foreach ($entryPath in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
      $entry = Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop
      if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'inventory_reparse_point_not_allowed'
      }
      $entryFullPath = [IO.Path]::GetFullPath($entry.FullName)
      if (-not (Test-CodexBridgePathWithin $entryFullPath $binFull)) {
        throw 'inventory_entry_path_escaped_binpath'
      }
      $relativePath = [IO.Path]::GetRelativePath($binFull, $entryFullPath).Replace('\', '/')
      if ($entry.PSIsContainer) {
        $entryDirectoryIdentity = Get-CodexBridgeFileIdentity $entryFullPath
        if ($directoryIdentities.ContainsKey($entryFullPath)) {
          if ($directoryIdentities[$entryFullPath] -cne $entryDirectoryIdentity) { throw 'inventory_directory_replaced' }
        } else {
          $directoryIdentities.Add($entryFullPath, $entryDirectoryIdentity)
        }
        $pendingDirectories.Push($entry.FullName)
        continue
      }

      $scannedFileCount++
      if ($scannedFileCount -gt 50000) { throw 'inventory_file_count_limit_exceeded' }
      $scannedSizeBytes += [long]$entry.Length
      if ($scannedSizeBytes -gt 20GB) { throw 'inventory_size_limit_exceeded' }

      $entryIdentity = Get-CodexBridgeFileIdentity $entryFullPath
      $fileIdentities.Add($entryFullPath, $entryIdentity)
      $extension = [IO.Path]::GetExtension($entry.Name).ToLowerInvariant()
      $fileType = $null
      $classificationEvidence = $null
      $peMachine = $null
      $imports = @()
      $hasMZHeader = Test-CodexBridgeMZHeader $entryFullPath
      if ($extension -in @('.exe', '.dll') -and -not $hasMZHeader) {
        throw 'inventory_expected_pe_header_missing'
      }
      if ($hasMZHeader) {
        $peMachine = Get-CodexBridgePEMachine $entryFullPath
        if ($peMachine -cne 'AMD64') { throw 'inventory_pe_architecture_mismatch' }
        if ($extension -notin @('.exe', '.dll')) {
          $fileType = 'unclassified'
          throw 'inventory_pe_file_type_unclassified'
        }
        $imports = @(Get-CodexBridgePEImports -Path $entryFullPath -DumpbinPath $DumpbinPath -PeImportsProvider $PeImportsProvider)
      }
      if ($extension -ceq '.dll') {
        $fileType = 'dll'
        $classificationEvidence = 'DLL extension plus valid AMD64 PE header'
      } elseif ($extension -ceq '.exe') {
        $baseName = [IO.Path]::GetFileNameWithoutExtension($entry.Name)
        $isAtBinRoot = -not $relativePath.Contains('/')
        if ($isAtBinRoot -and $testTargetNames -ccontains $baseName) {
          $fileType = 'candidate-xctest-runner'
          $classificationEvidence = 'AMD64 PE at SwiftPM bin-path root; filename exactly matches a declared Swift test target; execution not verified'
        } else {
          $fileType = 'ordinary-exe'
          $classificationEvidence = 'EXE extension plus valid AMD64 PE header; no exact declared test-target match'
        }
      } elseif (-not $hasMZHeader) {
        $pathComponents = @($relativePath -split '/')
        $insideDeclaredTestResourceBundle = $false
        if ($pathComponents.Count -gt 1) {
          $insideDeclaredTestResourceBundle = @(
            $testResourceBundles | Where-Object {
              $_.bundleName -ieq $pathComponents[0] -and $_.resourceEntry -ieq $pathComponents[1]
            }
          ).Count -gt 0
        }
        if ($insideDeclaredTestResourceBundle) {
          $fileType = 'resource'
          $classificationEvidence = 'non-PE file inside a SwiftPM resource bundle derived from Package.swift for a declared test target or direct target dependency'
        }
      }

      if ($null -eq $fileType) {
        $outOfScopeFileCount++
        continue
      }

      $sensitiveMatch = [regex]::Match($relativePath, $sensitivePathPattern)
      if ($sensitiveMatch.Success) {
        $matchedKeyword = $sensitiveMatch.Value.Trim([char[]]@('/', [char]92, '.', '_', '-'))
        $sensitiveClassification = switch -Regex ($matchedKeyword) {
          '^api[-._/]?key$' { 'api_key_keyword'; break }
          '^runtime[-._/]?key$' { 'runtime_key_keyword'; break }
          '^token$' { 'token_keyword'; break }
          '^cookie$' { 'cookie_keyword'; break }
          '^secret$' { 'secret_keyword'; break }
          '^credential$' { 'credential_keyword'; break }
          default { 'unclassified_keyword' }
        }
        throw "inventory_sensitive_filename_blocked classification=$sensitiveClassification entry_type=file"
      }

      $hash = (Get-FileHash -LiteralPath $entryFullPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
      Assert-CodexBridgeIdentityUnchanged $entryFullPath $entryIdentity 'inventory_file_replaced_during_hash'
      $candidateSizeBytes += [long]$entry.Length
      $files.Add([pscustomobject]@{
        path = $relativePath
        extension = $extension
        fileType = $fileType
        classificationEvidence = $classificationEvidence
        peMachine = $peMachine
        imports = $imports
        sizeBytes = [long]$entry.Length
        sha256 = $hash
      })
    }
    Assert-CodexBridgeIdentityUnchanged $directory $directoryIdentity 'inventory_directory_replaced'
  }

  if ($scannedFileCount -eq 0) { throw 'inventory_bin_path_empty' }
  foreach ($directoryPath in $directoryIdentities.Keys) {
    Assert-CodexBridgeIdentityUnchanged $directoryPath $directoryIdentities[$directoryPath] 'inventory_directory_replaced'
  }
  foreach ($filePath in $fileIdentities.Keys) {
    Assert-CodexBridgeIdentityUnchanged $filePath $fileIdentities[$filePath] 'inventory_file_replaced_during_hash'
  }
  Assert-CodexBridgeIdentityUnchanged $buildRootFull $buildRootIdentity 'inventory_build_root_replaced'
  Assert-CodexBridgeIdentityUnchanged $binFull $binIdentity 'inventory_debug_bin_path_replaced'
  $orderedFiles = @($files | Sort-Object -Property path)
  $manifest = [ordered]@{
    schemaVersion = 1
    purpose = 'build-output-inventory-only; no runtime package created'
    sourceCommit = $SourceCommit.ToLowerInvariant()
    workflowRunId = $WorkflowRunId
    toolchain = [ordered]@{
      swiftVersion = $SwiftVersion
      executablePathIdSha256 = $SwiftToolchainPathId.ToLowerInvariant()
      installerSha256 = $SwiftInstallerSha256.ToLowerInvariant()
    }
    targetTriple = $TargetTriple
    windowsBuildEnvironment = [ordered]@{
      runnerImage = $WindowsRunnerImage
      msvcVersion = $MsvcVersion
      windowsSdkVersion = $WindowsSdkVersion
      vcpkgRevision = $VcpkgRevision.ToLowerInvariant()
      sqlitePackage = $VcpkgSqlitePackage
    }
    swiftpmLocks = [ordered]@{
      bridgeCorePackageResolvedSha256 = $BridgeCoreLockSha256.ToLowerInvariant()
      vendoredMcpSdkPackageResolvedSha256 = $McpSdkLockSha256.ToLowerInvariant()
    }
    buildPath = [ordered]@{
      packagePath = 'Packages/BridgeCore'
      configuration = $BuildConfiguration
      buildTests = $BuildTests
      targetTriple = $TargetTriple
      debugBinPathRelativeToWorkspace = [IO.Path]::GetRelativePath($workspaceFull, $binFull).Replace('\', '/')
      releaseBinPathRelativeToWorkspace = [IO.Path]::GetRelativePath($workspaceFull, $releaseBinFull).Replace('\', '/')
      baseBuildArgumentsSha256 = $BaseBuildArgumentsSha256.ToLowerInvariant()
      compileArgumentsSha256 = $CompileArgumentsSha256.ToLowerInvariant()
      debugBinPathQueryArgumentsSha256 = $DebugBinPathQueryArgumentsSha256.ToLowerInvariant()
      releaseBinPathQueryArgumentsSha256 = $ReleaseBinPathQueryArgumentsSha256.ToLowerInvariant()
    }
    protocolSchema = [ordered]@{
      protocolVersion = '2026-07-28'
      fileName = 'mcp-2026-07-28.json'
      sha256 = $schemaHash
    }
    inventoryScope = 'SCOPED_RUNTIME_CANDIDATES'
    coverageStatus = 'COVERAGE_UNRESOLVED'
    runtimeDependencyClosure = 'NOT_VERIFIED'
    binPathRelativeToWorkspace = [IO.Path]::GetRelativePath($workspaceFull, $binFull).Replace('\', '/')
    declaredSwiftTestTargets = $testTargetNames
    declaredTestResourceBundles = $testResourceBundles
    outOfScopeFileCount = $outOfScopeFileCount
    candidateFileCount = $orderedFiles.Count
    totalSizeBytes = $candidateSizeBytes
    packageEligible = $false
    testPackageStatus = 'NOT_CREATED'
    executableClassification = 'UNRESOLVED'
    gateB1Status = 'NOT_PASSED'
    candidateFiles = $orderedFiles
  }

  $outputFull = [IO.Path]::GetFullPath($OutputPath)
  $outputDirectory = Split-Path -Parent $outputFull
  if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
  }
  $outputDirectoryFull = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $outputDirectory -ErrorAction Stop).Path)
  Assert-CodexBridgeNoReparseAncestors $outputDirectoryFull $runnerTempFull
  $outputDirectoryIdentity = Get-CodexBridgeFileIdentity $outputDirectoryFull
  $schemaOutputPath = Join-Path $outputDirectoryFull 'mcp-2026-07-28.json'
  $sumsPath = Join-Path $outputDirectoryFull 'SHA256SUMS.txt'
  $sumsShaPath = "$sumsPath.sha256"
  if ((Test-Path -LiteralPath $outputFull) -or
      (Test-Path -LiteralPath $schemaOutputPath) -or
      (Test-Path -LiteralPath $sumsPath) -or
      (Test-Path -LiteralPath $sumsShaPath)) {
    throw 'inventory_output_already_exists'
  }
  $json = $manifest | ConvertTo-Json -Depth 8
  [IO.File]::WriteAllText($outputFull, $json, [Text.UTF8Encoding]::new($false))
  $manifestHash = (Get-FileHash -LiteralPath $outputFull -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  Copy-Item -LiteralPath $schemaInputPath -Destination $schemaOutputPath -ErrorAction Stop
  $schemaOutputHash = (Get-FileHash -LiteralPath $schemaOutputPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  if ($schemaOutputHash -cne $schemaHash) { throw 'inventory_schema_copy_hash_mismatch' }
  $sumsContent = "$manifestHash  inventory.json`n$schemaOutputHash  mcp-2026-07-28.json`n"
  [IO.File]::WriteAllText($sumsPath, $sumsContent, [Text.UTF8Encoding]::new($false))
  $sumsHash = (Get-FileHash -LiteralPath $sumsPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  [IO.File]::WriteAllText($sumsShaPath, "$sumsHash  SHA256SUMS.txt`n", [Text.UTF8Encoding]::new($false))
  $sumsShaHash = (Get-FileHash -LiteralPath $sumsShaPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  $expectedNames = @('inventory.json', 'mcp-2026-07-28.json', 'SHA256SUMS.txt', 'SHA256SUMS.txt.sha256')
  $outputEntries = @(Get-ChildItem -LiteralPath $outputDirectoryFull -Force)
  if ($outputEntries.Count -ne $expectedNames.Count -or
      @($outputEntries | Where-Object { $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -ne 0 -or
      @($outputEntries.Name | Where-Object { $_ -cnotin $expectedNames }).Count -ne 0 -or
      @($expectedNames | Where-Object { $_ -cnotin @($outputEntries.Name) }).Count -ne 0) {
    throw 'inventory_output_manifest_incomplete'
  }
  $verifiedSchemaHash = (Get-FileHash -LiteralPath $schemaOutputPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  $verifiedManifestHash = (Get-FileHash -LiteralPath $outputFull -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  $verifiedSumsHash = (Get-FileHash -LiteralPath $sumsPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  $verifiedSumsSidecar = (Get-Content -LiteralPath $sumsShaPath -Raw -ErrorAction Stop).Trim()
  if ($verifiedSchemaHash -cne $schemaHash -or
      $verifiedManifestHash -cne $manifestHash -or
      $verifiedSumsHash -cne $sumsHash -or
      $verifiedSumsSidecar -cne "$sumsHash  SHA256SUMS.txt") {
    throw 'inventory_output_hash_verification_failed'
  }
  Assert-CodexBridgeIdentityUnchanged $outputDirectoryFull $outputDirectoryIdentity 'inventory_output_directory_replaced'
  return [pscustomobject]@{
    created = $true
    manifestComplete = $true
    candidateFileCount = $orderedFiles.Count
    totalSizeBytes = $candidateSizeBytes
    manifestSha256 = $manifestHash
    schemaSha256 = $schemaOutputHash
    sumsSha256 = $sumsHash
    sumsChecksumFileSha256 = $sumsShaHash
  }
}

Export-ModuleMember -Function New-CodexBridgeBuildInventory
