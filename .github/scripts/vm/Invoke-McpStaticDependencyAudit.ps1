$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:VerifiedSourceCommit = 'UNVERIFIED'
$script:AuditStatus = 'NOT_RUN'
$script:AuditReport = $null
$script:AuditReportSha256 = ''
$script:AuditFailureCategory = ''

function Write-SanitizedAuditOutputs {
  $status = $script:AuditStatus
  $harnessStatus = 'NOT_RUN'
  $portableStatus = 'NOT_RUN'
  $associationStatus = 'NOT_VERIFIED'
  $nodeCount = 0
  $edgeCount = 0
  $delayEdgeCount = 0
  $unresolvedCount = 0
  $collisionCount = 0
  if ($script:AuditReport) {
    if ($status -cnotin @('PASS', 'INCOMPLETE', 'FAIL')) { $status = 'FAIL' }
    $harnessStatus = [string]$script:AuditReport.graphStatus.harness
    $portableStatus = [string]$script:AuditReport.graphStatus.portableService
    $associationStatus = [string]$script:AuditReport.candidateIdentity.runnerBuildAssociation
    $nodeCount = [int]$script:AuditReport.dependencyNodeCount
    $edgeCount = [int]$script:AuditReport.importEdgeCount
    $delayEdgeCount = [int]$script:AuditReport.delayImportEdgeCount
    $unresolvedCount = [int]$script:AuditReport.unresolvedCount
    $collisionCount = [int]$script:AuditReport.sourceCollisionCount
  }
  if ($harnessStatus -cnotin @('PASS', 'INCOMPLETE', 'FAIL', 'NOT_RUN')) { $harnessStatus = 'NOT_RUN' }
  if ($portableStatus -cnotin @('PASS', 'INCOMPLETE', 'FAIL', 'NOT_RUN')) { $portableStatus = 'NOT_RUN' }
  if ($associationStatus -cnotin @('PASS', 'FAIL', 'NOT_VERIFIED')) { $associationStatus = 'NOT_VERIFIED' }
  $sourceCommit = if ($script:VerifiedSourceCommit -match '^[0-9a-f]{40}$') { $script:VerifiedSourceCommit } else { 'UNVERIFIED' }
  $reportSha = if ($script:AuditReportSha256 -match '^[0-9a-f]{64}$') { $script:AuditReportSha256 } else { 'NOT_CREATED' }
  $summaryFields = [ordered]@{
    audit_status = $status
    source_commit = $sourceCommit
    harness_graph_status = $harnessStatus
    portable_graph_status = $portableStatus
    runner_build_association = $associationStatus
    dependency_node_count = $nodeCount
    import_edge_count = $edgeCount
    delay_import_edge_count = $delayEdgeCount
    unresolved_count = $unresolvedCount
    source_collision_count = $collisionCount
    report_sha256 = $reportSha
  }
  if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT)) {
    foreach ($key in $summaryFields.Keys) {
      Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "$key=$($summaryFields[$key])"
    }
  }
  Write-Output "STATIC_IMPORT_AUDIT=$status"
  Write-Output "SOURCE_COMMIT=$sourceCommit"
  Write-Output "HARNESS_GRAPH_STATUS=$harnessStatus"
  Write-Output "PORTABLE_GRAPH_STATUS=$portableStatus"
  Write-Output "RUNNER_BUILD_ASSOCIATION=$associationStatus"
  Write-Output "DEPENDENCY_NODE_COUNT=$nodeCount"
  Write-Output "IMPORT_EDGE_COUNT=$edgeCount"
  Write-Output "DELAY_IMPORT_EDGE_COUNT=$delayEdgeCount"
  Write-Output "UNRESOLVED_COUNT=$unresolvedCount"
  Write-Output "SOURCE_COLLISION_COUNT=$collisionCount"
  Write-Output "AUDIT_REPORT_SHA256=$reportSha"
  if ($script:AuditFailureCategory -match '^audit_[a-z0-9_]+$') {
    Write-Output "AUDIT_FAILURE_CATEGORY=$script:AuditFailureCategory"
  }
  Write-Output 'RUNNER_TEST_DISCOVERY=NOT_VERIFIED'
  Write-Output 'DIRECT_RUNNER_EXECUTION=NOT_VERIFIED'
  Write-Output 'DYNAMIC_DEPENDENCIES=NOT_VERIFIED'
  Write-Output 'PACKAGE_EXECUTABLE=UNRESOLVED'
  Write-Output 'TEST_PACKAGE=NOT_CREATED'
  Write-Output 'XCTEST=NOT_RUN'
  Write-Output 'SERVICE_EXE=NOT_RUN'
  Write-Output 'VM_N5=BLOCKED'
  Write-Output 'GATE_B1=NOT_PASSED'
}

function Get-ArgumentListSha256([string[]]$Arguments) {
  $json = ConvertTo-Json -InputObject ([object[]]$Arguments) -Compress -Depth 3
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    return [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
  } finally { $sha.Dispose() }
}

function Get-VerifiedBinPath([string]$Configuration, [string[]]$BaseArguments, [string]$SwiftExecutable, [string]$WorkspaceRoot) {
  $queryArguments = @($BaseArguments) + @('-c', $Configuration, '--build-tests', '--show-bin-path')
  $queryOutput = @(& $SwiftExecutable build @queryArguments 2>&1)
  $queryExitCode = $LASTEXITCODE
  if ($queryExitCode -ne 0) { throw "audit_show_bin_path_failed_$Configuration" }
  $pathLines = @($queryOutput | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^(?:[A-Za-z]:[\\/]|\\\\)' })
  if ($pathLines.Count -ne 1) { throw "audit_show_bin_path_unrecognized_$Configuration" }
  $path = [IO.Path]::GetFullPath($pathLines[0])
  $buildRoot = [IO.Path]::GetFullPath((Join-Path $WorkspaceRoot 'Packages\BridgeCore\.build'))
  if (-not $path.StartsWith(($buildRoot.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'audit_show_bin_path_outside_build_root'
  }
  if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "audit_show_bin_path_missing_$Configuration" }
  $resolvedPath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $path -ErrorAction Stop).Path)
  if (-not [string]::Equals($resolvedPath, $path, [StringComparison]::OrdinalIgnoreCase)) { throw 'audit_show_bin_path_alias_not_allowed' }
  $current = $path
  while ($current) {
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'audit_build_path_reparse_point' }
    $parent = Split-Path -Parent $current
    if (-not $parent -or $parent -ieq $current) { break }
    $current = $parent
  }
  return [pscustomobject]@{
    path = $path
    argumentsSha256 = Get-ArgumentListSha256 (@('build') + $queryArguments)
  }
}

function Get-FileSha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Add-SourceRoot([Collections.Generic.List[object]]$Roots, [string]$Category, [string]$Kind, [string]$Path, [string]$Prefix, [System.Collections.IDictionary]$Identity) {
  $fullPath = [IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $fullPath -PathType Container)) { throw 'audit_source_root_missing' }
  $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'audit_source_root_reparse_point' }
  $Roots.Add([pscustomobject]@{
    category = $Category
    sourceKind = $Kind
    path = $fullPath
    relativePrefix = $Prefix
    sourceIdentity = Get-CodexBridgeAuditRootIdentity -Identity $Identity -SourceCategory $Category
  })
}

try {
  if ($env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
      $env:GITHUB_REF -cne 'refs/heads/ci/mcp-cache-hints-exe-process-20261105' -or
      $env:TARGET_ARCHITECTURE -cne 'x64' -or
      $env:TEST_MODE -cne 'b1-dependency-audit-only') { throw 'audit_dispatch_boundary_mismatch' }
  if ($env:COMPILE_STATUS -cne 'PASS' -or $env:SWIFT_VERSION -cne '6.3.3' -or
      $env:SWIFT_TOOLCHAIN_VERIFIED_VERSION -cne '6.3.3' -or
      $env:TARGET_TRIPLE -cne 'x86_64-unknown-windows-msvc') { throw 'audit_compile_or_toolchain_prerequisite_failed' }
  if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -cne 'X64' -or
      -not [Environment]::Is64BitProcess) { throw 'audit_runner_not_windows_x64' }

  $sourceCommit = $env:REQUESTED_SOURCE_COMMIT
  $head = (& git -C $env:GITHUB_WORKSPACE rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-fA-F]{40}$' -or
      -not [string]::Equals($sourceCommit, $env:GITHUB_SHA, [StringComparison]::OrdinalIgnoreCase) -or
      -not [string]::Equals($head, $sourceCommit, [StringComparison]::OrdinalIgnoreCase)) { throw 'audit_source_commit_mismatch' }
  $script:VerifiedSourceCommit = $head.ToLowerInvariant()

  Import-Module "$env:GITHUB_WORKSPACE\.github\scripts\SwiftToolchainIdentity.psm1" -Force
  Import-Module "$env:GITHUB_WORKSPACE\.github\scripts\vm\McpStaticDependencyAudit.psm1" -Force
  $swiftExe = $env:SWIFT_EXE_PATH
  if ([string]::IsNullOrWhiteSpace($swiftExe) -or -not (Test-Path -LiteralPath $swiftExe -PathType Leaf)) { throw 'audit_swift_executable_missing' }
  $swiftExe = (Get-Item -LiteralPath $swiftExe -ErrorAction Stop).FullName
  $swiftPathId = Get-SwiftToolchainPathId -Path $swiftExe
  if ($swiftPathId -cne $env:SWIFT_TOOLCHAIN_VERIFIED_PATH_ID) { throw 'audit_swift_path_identity_changed' }
  $installerPath = Join-Path $env:RUNNER_TEMP 'swift-downloads\swift-6.3.3-windows10.exe'
  if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) { throw 'audit_swift_installer_missing' }
  $installerSha = Get-FileSha256 $installerPath
  if ($env:SWIFT_INSTALLER_SHA256 -cne $installerSha) { throw 'audit_swift_installer_identity_changed' }

  $lockFiles = @(
    @{ path = 'Packages/BridgeCore/Package.resolved'; expected = $env:SWIFTPM_CORE_LOCK_SHA256 },
    @{ path = 'Vendor/swift-sdk/Package.resolved'; expected = $env:SWIFTPM_SDK_LOCK_SHA256 }
  )
  foreach ($lock in $lockFiles) {
    $lockPath = Join-Path $env:GITHUB_WORKSPACE ($lock.path.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf) -or (Get-FileSha256 $lockPath) -cne $lock.expected) {
      throw 'audit_swiftpm_lock_identity_changed'
    }
  }

  $vcpkgRoot = Join-Path $env:VCPKG_INSTALLATION_ROOT 'installed\x64-windows'
  $vcpkgRevision = (& git -C $env:VCPKG_INSTALLATION_ROOT rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0 -or $vcpkgRevision -cne $env:VCPKG_REVISION -or
      $env:VCPKG_SQLITE_PACKAGE -notmatch '^sqlite3:x64-windows\s+[0-9]+\.[0-9]+\.[0-9]+(?:#[0-9]+)?$') {
    throw 'audit_vcpkg_identity_changed'
  }
  $sqliteListOutput = @(& (Join-Path $env:VCPKG_INSTALLATION_ROOT 'vcpkg.exe') list 'sqlite3:x64-windows' 2>$null)
  $sqliteListExitCode = $LASTEXITCODE
  if ($sqliteListExitCode -ne 0 -or $sqliteListOutput.Count -ne 1 -or
      $sqliteListOutput[0] -notmatch '^sqlite3:x64-windows[ \t]+(?<version>[0-9]+\.[0-9]+\.[0-9]+(?:#[0-9]+)?)(?:[ \t]+[^\r\n]+)?$') {
    throw 'audit_vcpkg_sqlite_identity_unverified'
  }
  $actualSqliteIdentity = 'sqlite3:x64-windows ' + $Matches.version
  if ($actualSqliteIdentity -cne $env:VCPKG_SQLITE_PACKAGE) { throw 'audit_vcpkg_sqlite_identity_changed' }
  $sqliteDll = Join-Path $vcpkgRoot 'bin\sqlite3.dll'
  if (-not (Test-Path -LiteralPath $sqliteDll -PathType Leaf)) { throw 'audit_vcpkg_sqlite_missing' }
  if ((Get-CodexBridgeAuditPEMachine $sqliteDll) -cne 'AMD64') { throw 'audit_vcpkg_sqlite_architecture_mismatch' }

  $schemaPath = Join-Path $env:GITHUB_WORKSPACE '.github\schemas\mcp-2026-07-28.json'
  $expectedSchemaSha = 'ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203'
  $schemaSha = Get-FileSha256 $schemaPath
  if ($schemaSha -cne $expectedSchemaSha) { throw 'audit_fixed_schema_sha256_mismatch' }

  $portableRunId = '41665722609'
  $portableArtifactSha = 'a7f64d71df9826402748139329d6ab024b8c9bac0f4711a3ce3aaca84bf8ace8'
  $portableZipSha = '3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d'
  $portableSourceCommit = 'f2235028773e7d9e0da714218a5694c4eb8bfef3'
  $portableServiceSha = '428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521'
  if ($env:CODEX_BRIDGE_ARTIFACT_VERIFICATION -cne 'PASS' -or
      $env:CODEX_BRIDGE_CANDIDATE_SHA256 -cne $portableServiceSha -or
      -not (Test-Path -LiteralPath $env:CODEX_BRIDGE_CANDIDATE_DIR -PathType Container)) {
    throw 'audit_approved_portable_identity_unverified'
  }
  $portableRoot = [IO.Path]::GetFullPath($env:CODEX_BRIDGE_CANDIDATE_DIR)
  $servicePath = Join-Path $portableRoot 'codex-bridge-service.exe'
  if ((Get-FileSha256 $servicePath) -cne $portableServiceSha) { throw 'audit_portable_service_sha256_mismatch' }

  . "$env:GITHUB_WORKSPACE\Scripts\windows-swift-arguments.ps1"
  $baseArguments = @(Get-WindowsSwiftArguments `
    -VcpkgInstalledRoot $vcpkgRoot `
    -TargetTriple $env:TARGET_TRIPLE `
    -LibraryPaths ($env:TARGET_LIBRARY_PATHS -split ';'))
  $compileArguments = @($baseArguments) + @('-c', 'debug', '--build-tests')
  $compileArgsSha = Get-ArgumentListSha256 (@('build') + $compileArguments)
  if ($compileArgsSha -cne $env:SWIFT_BUILD_ARGUMENTS_SHA256) { throw 'audit_compile_arguments_identity_changed' }
  Push-Location (Join-Path $env:GITHUB_WORKSPACE 'Packages\BridgeCore')
  try {
    $debugBin = Get-VerifiedBinPath -Configuration 'debug' -BaseArguments $baseArguments -SwiftExecutable $swiftExe -WorkspaceRoot $env:GITHUB_WORKSPACE
    $releaseBin = Get-VerifiedBinPath -Configuration 'release' -BaseArguments $baseArguments -SwiftExecutable $swiftExe -WorkspaceRoot $env:GITHUB_WORKSPACE
  } finally { Pop-Location }
  if ([string]::Equals($debugBin.path, $releaseBin.path, [StringComparison]::OrdinalIgnoreCase)) { throw 'audit_debug_release_binpath_ambiguous' }
  if ($env:MSVC_DUMPBIN_PATH -notmatch '\\bin\\Hostx64\\x64\\dumpbin\.exe$' -or
      -not (Test-Path -LiteralPath $env:MSVC_DUMPBIN_PATH -PathType Leaf)) { throw 'audit_dumpbin_source_unverified' }
  if (-not (Test-Path -LiteralPath $env:WINDOWS_MSVC_ROOT -PathType Container)) { throw 'audit_msvc_root_missing' }
  $expectedDumpbin = Join-Path $env:WINDOWS_MSVC_ROOT 'bin\Hostx64\x64\dumpbin.exe'
  if (-not [string]::Equals([IO.Path]::GetFullPath($expectedDumpbin), [IO.Path]::GetFullPath($env:MSVC_DUMPBIN_PATH), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'audit_dumpbin_source_unverified'
  }
  if ((Get-CodexBridgeAuditPEMachine $env:MSVC_DUMPBIN_PATH) -cne 'AMD64') { throw 'audit_dumpbin_architecture_mismatch' }

  $toolchainBin = Split-Path -Parent $swiftExe
  $toolchainVersionDirectory = (Get-Item -LiteralPath $toolchainBin).Parent.Parent
  if (-not $toolchainVersionDirectory -or $toolchainVersionDirectory.Name -cnotin @('6.3.3', '6.3.3+Asserts') -or
      $toolchainVersionDirectory.Name -cne $env:SWIFT_TOOLCHAIN_VARIANT) { throw 'audit_swift_toolchain_layout_invalid' }
  $swiftRoot = $toolchainVersionDirectory.Parent.Parent.FullName
  $swiftRuntimeBin = Join-Path $swiftRoot 'Runtimes\6.3.3\usr\bin'
  $msvcVersion = $env:WINDOWS_MSVC_VERSION
  $windowsSdkVersion = $env:WINDOWS_SDK_VERSION
  $runnerImage = $env:WINDOWS_RUNNER_IMAGE
  $identity = [ordered]@{
    sourceCommit = $head
    requestedSourceCommit = $sourceCommit
    sourceWorkflowRun = $env:GITHUB_RUN_ID
    targetTriple = $env:TARGET_TRIPLE
    buildConfiguration = 'debug'
    swiftVersion = '6.3.3'
    swiftToolchainVariant = $env:SWIFT_TOOLCHAIN_VARIANT
    swiftInstallerSha256 = $installerSha
    swiftToolchainPathIdSha256 = $swiftPathId
    compileArgumentsSha256 = $compileArgsSha
    bridgeCoreLockSha256 = $env:SWIFTPM_CORE_LOCK_SHA256
    mcpSdkLockSha256 = $env:SWIFTPM_SDK_LOCK_SHA256
    vcpkgRevision = $vcpkgRevision
    sqlitePackage = $env:VCPKG_SQLITE_PACKAGE
    msvcVersion = $msvcVersion
    windowsSdkVersion = $windowsSdkVersion
    windowsRunnerImage = $runnerImage
    portableRunId = $portableRunId
    portableArtifactSha256 = $portableArtifactSha
    portableZipSha256 = $portableZipSha
    portableSourceCommit = $portableSourceCommit
    portableServiceSha256 = $portableServiceSha
    schemaSha256 = $schemaSha
  }

  $roots = [Collections.Generic.List[object]]::new()
  Add-SourceRoot $roots 'harness-build-output' 'swiftpm-debug-bin' $debugBin.path 'Packages/BridgeCore/.build/debug' $identity
  Add-SourceRoot $roots 'swift-toolchain-6.3.3' 'swift-toolchain-bin' $toolchainBin 'Swift/Toolchains/6.3.3/usr/bin' $identity
  Add-SourceRoot $roots 'swift-toolchain-6.3.3' 'swift-runtime-bin' $swiftRuntimeBin 'Swift/Runtimes/6.3.3/usr/bin' $identity
  Add-SourceRoot $roots 'vcpkg-x64-dependencies' 'vcpkg-runtime-bin' (Join-Path $vcpkgRoot 'bin') 'vcpkg/installed/x64-windows/bin' $identity
  Add-SourceRoot $roots 'approved-portable-service' 'portable-root' $portableRoot 'ApprovedPortable' $identity
  Add-SourceRoot $roots 'windows-system-components' 'system32' (Join-Path $env:SystemRoot 'System32') 'Windows/System32' $identity
  Add-SourceRoot $roots 'windows-system-components' 'msvc-tools' $env:WINDOWS_MSVC_ROOT "MSVC/$msvcVersion" $identity

  $candidateSpecs = @(
    [pscustomobject]@{ name = 'BridgeMCPTests-test-runner.exe'; role = 'candidate-xctest-runner'; graph = 'harness'; category = 'harness-build-output'; path = (Join-Path $debugBin.path 'BridgeMCPTests-test-runner.exe'); expectedSha256 = (Get-FileSha256 (Join-Path $debugBin.path 'BridgeMCPTests-test-runner.exe')) }
    [pscustomobject]@{ name = 'BridgeMCPTests.dll'; role = 'xctest-test-module'; graph = 'harness'; category = 'harness-build-output'; path = (Join-Path $debugBin.path 'BridgeMCPTests.dll'); expectedSha256 = (Get-FileSha256 (Join-Path $debugBin.path 'BridgeMCPTests.dll')) }
    [pscustomobject]@{ name = 'codex-bridge-service.exe'; role = 'portable-service'; graph = 'portable-service'; category = 'approved-portable-service'; path = $servicePath; expectedSha256 = $portableServiceSha }
  )

  $reportDirectory = Join-Path $env:RUNNER_TEMP 'b1-static-dependency-audit'
  if (Test-Path -LiteralPath $reportDirectory) { throw 'audit_report_directory_collision' }
  New-Item -ItemType Directory -Path $reportDirectory -ErrorAction Stop | Out-Null
  $reportPath = Join-Path $reportDirectory 'dependency-audit.json'
  $report = Invoke-CodexBridgeStaticImportAudit `
    -Identity $identity -WorkspaceRoot $env:GITHUB_WORKSPACE -RunnerTemp $env:RUNNER_TEMP `
    -SourceRoots $roots.ToArray() -Candidates $candidateSpecs -SystemRoot $env:SystemRoot `
    -DumpbinPath $env:MSVC_DUMPBIN_PATH -FixedSchemaPath $schemaPath -ExpectedSchemaSha256 $expectedSchemaSha `
    -MaximumNodes 256 -MaximumEdges 2048 -MaximumOutputCharacters 1048576
  $script:AuditReport = $report
  $script:AuditStatus = $report.auditStatus.ToUpperInvariant()
  $json = ConvertTo-Json -InputObject $report -Depth 18
  [IO.File]::WriteAllText($reportPath, $json, [Text.UTF8Encoding]::new($false))
  $reportSha = Get-FileSha256 $reportPath
  $script:AuditReportSha256 = $reportSha
  if ($report.auditStatus -ne 'PASS') {
    $failure = if ($report.failureCategory) { $report.failureCategory } else { 'unresolved_dependencies' }
    $script:AuditFailureCategory = if ($failure -match '^audit_[a-z0-9_]+$') { $failure } else { 'audit_unresolved_dependencies' }
  }
} catch {
  $category = if ($_.Exception.Message -match '^audit_[a-z0-9_]+$') { $_.Exception.Message } else { 'audit_prerequisite_or_internal_failure' }
  $script:AuditFailureCategory = $category
  if ($script:AuditReport) {
    if ($script:AuditReport.auditStatus -ceq 'INCOMPLETE' -and $script:AuditReportSha256 -match '^[0-9a-f]{64}$') {
      $script:AuditStatus = 'INCOMPLETE'
    } else {
      $script:AuditStatus = 'FAIL'
    }
  } else {
    $script:AuditStatus = 'NOT_RUN'
  }
} finally {
  Write-SanitizedAuditOutputs
}
if ($script:AuditStatus -cne 'PASS') { exit 1 }
