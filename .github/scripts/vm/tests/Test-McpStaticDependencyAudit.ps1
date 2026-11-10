$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot '..\McpStaticDependencyAudit.psm1'
Import-Module $modulePath -Force
$fixedSchemaPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\schemas\mcp-2026-07-28.json'))
$fixedSchemaSha256 = 'EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203'.ToLowerInvariant()
$entrypointPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Invoke-McpStaticDependencyAudit.ps1'))
$entrypointTokens = $null
$entrypointParseErrors = $null
$entrypointAst = [System.Management.Automation.Language.Parser]::ParseFile($entrypointPath, [ref]$entrypointTokens, [ref]$entrypointParseErrors)
if ($entrypointParseErrors.Count -gt 0) { throw 'assertion_failed_audit_entrypoint_ast_parse' }
$productionFunctionNames = @('Get-ArgumentListSha256', 'Get-VerifiedBinPath', 'ConvertTo-SanitizedAuditFailureCategory', 'Get-SanitizedAuditResultClassification')
$productionFunctionAsts = @($entrypointAst.FindAll({
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $productionFunctionNames -contains $node.Name
}, $true))
if (@($productionFunctionAsts.Name | Select-Object -Unique).Count -ne $productionFunctionNames.Count) {
  throw 'assertion_failed_production_audit_functions_missing'
}
foreach ($productionFunctionAst in $productionFunctionAsts) {
  . ([scriptblock]::Create($productionFunctionAst.Extent.Text))
}
$binPathPairGuardAst = @($entrypointAst.FindAll({
  param($node)
  $node -is [System.Management.Automation.Language.IfStatementAst] -and
    $node.Extent.Text -match 'audit_debug_release_binpath_ambiguous'
}, $true) | Select-Object -First 1)
if ($binPathPairGuardAst.Count -ne 1) { throw 'assertion_failed_production_binpath_pair_guard_missing' }
$script:ProductionBinPathPairGuard = [scriptblock]::Create($binPathPairGuardAst[0].Extent.Text)

function Assert-True([bool]$Value, [string]$Name) {
  if (-not $Value) { throw "assertion_failed_$Name" }
}

function Assert-Equal([string]$Actual, [string]$Expected, [string]$Name) {
  if ($Actual -cne $Expected) { throw "assertion_failed_$Name" }
}

$script:passed = 0
$script:notTested = 0
function Complete-Test([string]$Name) {
  $script:passed++
  Write-Output "PASS test=$Name"
}

function Mark-NotTested([string]$Name, [string]$Reason) {
  $script:notTested++
  Write-Output "NOT_TESTED test=$Name reason=$Reason"
}

function Invoke-SyntheticSwiftBinPathQuery {
  $swiftArguments = @($args | ForEach-Object { [string]$_ })
  $configurationIndex = [Array]::IndexOf([string[]]$swiftArguments, '-c')
  if ($configurationIndex -lt 0 -or $configurationIndex + 1 -ge $swiftArguments.Count) {
    $global:LASTEXITCODE = 89
    Write-Output 'synthetic_swift_configuration_missing'
    return
  }
  $configuration = $swiftArguments[$configurationIndex + 1]
  $script:MockSwiftArguments[$configuration] = $swiftArguments
  $global:LASTEXITCODE = [int]$script:MockSwiftExitCodes[$configuration]
  if ($global:LASTEXITCODE -ne 0) {
    Write-Output 'synthetic_swift_query_failure'
    return
  }
  foreach ($line in @($script:MockSwiftOutputs[$configuration])) { Write-Output ([string]$line) }
}

function New-BinPathFixture {
  $root = Join-Path $env:TEMP ('codex-bridge-binpath-' + [Guid]::NewGuid().ToString('N'))
  $workspace = Join-Path $root 'workspace'
  $buildRoot = Join-Path $workspace 'Packages\BridgeCore\.build'
  $targetRoot = Join-Path $buildRoot 'synthetic-target'
  $debugPath = Join-Path $targetRoot 'debug'
  $releasePath = Join-Path $targetRoot 'release'
  $outsidePath = Join-Path $root 'outside\release'
  New-Item -ItemType Directory -Path $debugPath -Force | Out-Null
  New-Item -ItemType Directory -Path $outsidePath -Force | Out-Null
  return [pscustomobject]@{
    Root = $root
    WorkspaceRoot = $workspace
    BuildRoot = $buildRoot
    TargetRoot = $targetRoot
    DebugPath = $debugPath
    ReleasePath = $releasePath
    OutsidePath = $outsidePath
  }
}

function Remove-BinPathFixture($Fixture) {
  $tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
  $fixtureRoot = [IO.Path]::GetFullPath([string]$Fixture.Root)
  if (-not $fixtureRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
      [IO.Path]::GetFileName($fixtureRoot) -notmatch '^codex-bridge-binpath-[0-9a-f]{32}$') {
    throw 'assertion_failed_binpath_fixture_cleanup_boundary'
  }
  if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}

function Set-SyntheticBinPathResponses($Fixture) {
  $script:MockSwiftOutputs = @{
    debug = @([string]$Fixture.DebugPath)
    release = @([string]$Fixture.ReleasePath)
  }
  $script:MockSwiftExitCodes = @{ debug = 0; release = 0 }
  $script:MockSwiftArguments = @{}
}

function Invoke-SyntheticBinPathQuery($Fixture, [string]$Configuration, [switch]$AllowMissingFinalDirectoryForComparison) {
  $parameters = @{
    Configuration = $Configuration
    BaseArguments = @('-target', 'x86_64-unknown-windows-msvc')
    SwiftExecutable = 'Invoke-SyntheticSwiftBinPathQuery'
    WorkspaceRoot = [string]$Fixture.WorkspaceRoot
  }
  if ($AllowMissingFinalDirectoryForComparison) {
    $parameters.AllowMissingFinalDirectoryForComparison = $true
  }
  return Get-VerifiedBinPath @parameters
}

function Invoke-SyntheticBinPathPair($Fixture) {
  Set-SyntheticBinPathResponses $Fixture
  $debug = Invoke-SyntheticBinPathQuery $Fixture 'debug'
  $release = Invoke-SyntheticBinPathQuery $Fixture 'release' -AllowMissingFinalDirectoryForComparison
  $debugBin = $debug
  $releaseBin = $release
  . $script:ProductionBinPathPairGuard
  return [pscustomobject]@{ Debug = $debug; Release = $release }
}

function Assert-BinPathFailure([scriptblock]$Action, [string]$ExpectedCategory, [string]$Name) {
  $actualCategory = $null
  try { & $Action | Out-Null } catch { $actualCategory = [string]$_.Exception.Message }
  $allowedCategories = @($ExpectedCategory -split '\|')
  if ($actualCategory -cnotin $allowedCategories) { throw "assertion_failed_${Name}_failure_category" }
  Complete-Test $Name
}

function New-SyntheticPE([string]$Path, [UInt16]$Machine = 0x8664, [string]$Payload = 'synthetic-pe') {
  $parent = Split-Path -Parent $Path
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  $bytes = [byte[]]::new(512)
  $bytes[0] = 0x4d
  $bytes[1] = 0x5a
  [BitConverter]::GetBytes([int]0x80).CopyTo($bytes, 0x3c)
  [byte[]]$signature = 0x50, 0x45, 0x00, 0x00
  $signature.CopyTo($bytes, 0x80)
  [BitConverter]::GetBytes($Machine).CopyTo($bytes, 0x84)
  $payloadBytes = [Text.Encoding]::UTF8.GetBytes($Payload)
  $payloadBytes.CopyTo($bytes, 0x100)
  [IO.File]::WriteAllBytes($Path, $bytes)
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-DumpbinFixture([string[]]$Imports = @(), [string[]]$DelayImports = @()) {
  $lines = [Collections.Generic.List[string]]::new()
  $lines.Add('Dump of file synthetic-image.exe')
  $lines.Add('File Type: EXECUTABLE IMAGE')
  $lines.Add('')
  $lines.Add('  Section contains the following imports:')
  $lines.Add('')
  foreach ($name in $Imports) {
    $lines.Add("    $name")
    $lines.Add('             00000000 Import Address Table')
    $lines.Add('                         SyntheticImportedSymbol')
  }
  $lines.Add('')
  $lines.Add('  Section contains the following delay load imports:')
  $lines.Add('')
  foreach ($name in $DelayImports) {
    $lines.Add("    $name")
    $lines.Add('             00000000 Import Address Table')
    $lines.Add('                         SyntheticDelaySymbol')
  }
  return $lines.ToArray()
}

function New-AuditFixture([string]$Scenario = 'pass') {
  $root = Join-Path $env:TEMP ("codex-bridge-static-audit-" + [Guid]::NewGuid().ToString('N'))
  $workspace = Join-Path $root 'workspace'
  $bin = Join-Path $workspace 'Packages\BridgeCore\.build\windows\x64\debug'
  $swift = Join-Path $root 'swift'
  $swiftToolchainBin = Join-Path $swift 'Toolchains\6.3.3\usr\bin'
  $swiftRuntimeBin = Join-Path $swift 'Runtimes\6.3.3\usr\bin'
  $vcpkg = Join-Path $root 'vcpkg\installed\x64-windows\bin'
  $portable = Join-Path $root 'portable-payload'
  $systemRoot = Join-Path $root 'windows'
  $system32 = Join-Path $systemRoot 'System32'
  $vc = Join-Path $root 'msvc\14.51.36231'
  $temp = Join-Path $root 'runner-temp'
  $dumpbin = Join-Path $vc 'bin\Hostx64\x64\dumpbin.exe'
  foreach ($directory in @($bin, $swiftToolchainBin, $swiftRuntimeBin, $vcpkg, $portable, $system32, $vc, $temp, (Split-Path -Parent $dumpbin))) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
  }
  $packageManifest = Join-Path $workspace 'Packages\BridgeCore\Package.swift'
  New-Item -ItemType Directory -Path (Split-Path -Parent $packageManifest) -Force | Out-Null
  [IO.File]::WriteAllText($packageManifest, 'let package = Package(name: "BridgeCore", targets: [.testTarget(name: "BridgeMCPTests")])')
  [IO.File]::WriteAllText($dumpbin, 'mocked trusted dumpbin placeholder')

  $runnerPath = Join-Path $bin 'BridgeMCPTests-test-runner.exe'
  $testModulePath = Join-Path $bin 'BridgeMCPTests.dll'
  $servicePath = Join-Path $portable 'codex-bridge-service.exe'
  $runnerHash = New-SyntheticPE $runnerPath -Payload 'runner'
  $testModuleHash = New-SyntheticPE $testModulePath -Payload 'test-module'
  $serviceHash = New-SyntheticPE $servicePath -Payload 'portable-service'
  $sqliteHarnessPath = Join-Path $vcpkg 'sqlite3.dll'
  $sqliteServicePath = Join-Path $portable 'sqlite3.dll'
  [void](New-SyntheticPE $sqliteHarnessPath -Payload 'harness-sqlite-3.54.1')
  [void](New-SyntheticPE $sqliteServicePath -Payload 'portable-sqlite-distinct')
  $xctestPath = Join-Path $swiftRuntimeBin 'XCTest.dll'
  $testingPath = Join-Path $swiftRuntimeBin 'Testing.dll'
  $foundationPath = Join-Path $swiftRuntimeBin 'FoundationNetworking.dll'
  [void](New-SyntheticPE $xctestPath -Payload 'xctest')
  [void](New-SyntheticPE $testingPath -Payload 'swift-testing')
  [void](New-SyntheticPE $foundationPath -Payload 'foundation-networking')
  $kernelPath = Join-Path $system32 'kernel32.dll'
  [void](New-SyntheticPE $kernelPath -Payload 'system-kernel')
  $resourceRoot = Join-Path $portable 'BridgeCore_BridgeMCP.bundle\FileTransfer'
  New-Item -ItemType Directory -Path $resourceRoot -Force | Out-Null
  foreach ($resourceName in @('index.html', 'transfer-core.js', 'transfer-view.js', 'transfer.css')) {
    [IO.File]::WriteAllText((Join-Path $resourceRoot $resourceName), "synthetic resource $resourceName")
  }

  $identity = [ordered]@{
    sourceCommit = '6c4d86c0cec892f69c27749f81690ed4b70d89d3'
    requestedSourceCommit = '6c4d86c0cec892f69c27749f81690ed4b70d89d3'
    sourceWorkflowRun = '42463264399'
    targetTriple = 'x86_64-unknown-windows-msvc'
    buildConfiguration = 'debug'
    swiftVersion = '6.3.3'
    swiftToolchainVariant = '6.3.3'
    swiftInstallerSha256 = 'a' * 64
    swiftToolchainPathIdSha256 = 'b' * 64
    compileArgumentsSha256 = 'c' * 64
    bridgeCoreLockSha256 = 'd' * 64
    mcpSdkLockSha256 = 'e' * 64
    vcpkgRevision = 'f' * 40
    sqlitePackage = 'sqlite3:x64-windows 3.54.1'
    msvcVersion = '14.51.36231'
    windowsSdkVersion = '10.0.26100.0'
    windowsRunnerImage = 'windows2026'
    portableRunId = '41665722609'
    portableArtifactSha256 = '1' * 64
    portableZipSha256 = '2' * 64
    portableSourceCommit = 'f2235028773e7d9e0da714218a5694c4eb8bfef3'
    portableServiceSha256 = $serviceHash
    schemaSha256 = $fixedSchemaSha256
  }
  $rootSpecs = @(
    [pscustomobject]@{ category = 'harness-build-output'; sourceKind = 'swiftpm-debug-bin'; path = $bin; relativePrefix = 'Packages/BridgeCore/.build'; sourceIdentity = (Get-CodexBridgeAuditRootIdentity -Identity $identity -SourceCategory 'harness-build-output') }
    [pscustomobject]@{ category = 'swift-toolchain-6.3.3'; sourceKind = 'swift-toolchain-bin'; path = $swiftToolchainBin; relativePrefix = 'Swift/Toolchains/6.3.3/usr/bin'; sourceIdentity = (Get-CodexBridgeAuditRootIdentity -Identity $identity -SourceCategory 'swift-toolchain-6.3.3') }
    [pscustomobject]@{ category = 'swift-toolchain-6.3.3'; sourceKind = 'swift-runtime-bin'; path = $swiftRuntimeBin; relativePrefix = 'Swift/Runtimes/6.3.3/usr/bin'; sourceIdentity = (Get-CodexBridgeAuditRootIdentity -Identity $identity -SourceCategory 'swift-toolchain-6.3.3') }
    [pscustomobject]@{ category = 'vcpkg-x64-dependencies'; sourceKind = 'vcpkg-runtime-bin'; path = $vcpkg; relativePrefix = 'vcpkg/installed/x64-windows/bin'; sourceIdentity = (Get-CodexBridgeAuditRootIdentity -Identity $identity -SourceCategory 'vcpkg-x64-dependencies') }
    [pscustomobject]@{ category = 'approved-portable-service'; sourceKind = 'portable-root'; path = $portable; relativePrefix = 'Portable'; sourceIdentity = (Get-CodexBridgeAuditRootIdentity -Identity $identity -SourceCategory 'approved-portable-service') }
    [pscustomobject]@{ category = 'windows-system-components'; sourceKind = 'system32'; path = $system32; relativePrefix = 'Windows/System32'; sourceIdentity = (Get-CodexBridgeAuditRootIdentity -Identity $identity -SourceCategory 'windows-system-components') }
    [pscustomobject]@{ category = 'windows-system-components'; sourceKind = 'msvc-tools'; path = $vc; relativePrefix = 'MSVC/14.51.36231'; sourceIdentity = (Get-CodexBridgeAuditRootIdentity -Identity $identity -SourceCategory 'windows-system-components') }
  )
  $candidateSpecs = @(
    [pscustomobject]@{ name = 'BridgeMCPTests-test-runner.exe'; role = 'candidate-xctest-runner'; graph = 'harness'; category = 'harness-build-output'; path = $runnerPath; expectedSha256 = $runnerHash }
    [pscustomobject]@{ name = 'BridgeMCPTests.dll'; role = 'xctest-test-module'; graph = 'harness'; category = 'harness-build-output'; path = $testModulePath; expectedSha256 = $testModuleHash }
    [pscustomobject]@{ name = 'codex-bridge-service.exe'; role = 'portable-service'; graph = 'portable-service'; category = 'approved-portable-service'; path = $servicePath; expectedSha256 = $serviceHash }
  )
  $imports = @{
    'BridgeMCPTests-test-runner.exe' = New-DumpbinFixture @('BridgeMCPTests.dll', 'XCTest.dll')
    'BridgeMCPTests.dll' = New-DumpbinFixture @('Testing.dll', 'FoundationNetworking.dll', 'sqlite3.dll')
    'codex-bridge-service.exe' = New-DumpbinFixture @('sqlite3.dll')
    'XCTest.dll' = New-DumpbinFixture @('kernel32.dll')
    'Testing.dll' = New-DumpbinFixture @('kernel32.dll')
    'FoundationNetworking.dll' = New-DumpbinFixture @('kernel32.dll')
    'sqlite3.dll' = New-DumpbinFixture @('kernel32.dll')
    'kernel32.dll' = New-DumpbinFixture @()
  }
  switch ($Scenario) {
    'multi-level' {
      [void](New-SyntheticPE (Join-Path $swiftRuntimeBin 'AuditA.dll') -Payload 'audit-a')
      [void](New-SyntheticPE (Join-Path $swiftRuntimeBin 'AuditB.dll') -Payload 'audit-b')
      $imports['BridgeMCPTests.dll'] = New-DumpbinFixture @('AuditA.dll')
      $imports['AuditA.dll'] = New-DumpbinFixture @('AuditB.dll')
      $imports['AuditB.dll'] = New-DumpbinFixture @('kernel32.dll')
    }
    'cycle' {
      [void](New-SyntheticPE (Join-Path $swiftRuntimeBin 'CycleA.dll') -Payload 'cycle-a')
      [void](New-SyntheticPE (Join-Path $swiftRuntimeBin 'CycleB.dll') -Payload 'cycle-b')
      $imports['BridgeMCPTests.dll'] = New-DumpbinFixture @('CycleA.dll')
      $imports['CycleA.dll'] = New-DumpbinFixture @('CycleB.dll')
      $imports['CycleB.dll'] = New-DumpbinFixture @('CycleA.dll')
    }
    'unknown' {
      [void](New-SyntheticPE (Join-Path $system32 'api-ms-win-core-synthetic-l1-1-0.dll') -Payload 'unverified-api-set-contract')
      $imports['BridgeMCPTests.dll'] = New-DumpbinFixture @('UnknownSynthetic.dll', 'api-ms-win-core-synthetic-l1-1-0.dll')
    }
    'collision' {
      [void](New-SyntheticPE (Join-Path $swiftRuntimeBin 'Collision.dll') -Payload 'source-one')
      [void](New-SyntheticPE (Join-Path $vcpkg 'Collision.dll') -Payload 'source-two')
      $imports['BridgeMCPTests.dll'] = New-DumpbinFixture @('Collision.dll')
      $imports['Collision.dll'] = New-DumpbinFixture @('kernel32.dll')
    }
    'wrong-architecture' {
      [void](New-SyntheticPE $xctestPath -Machine 0x014c -Payload 'x86-xctest')
      $imports['BridgeMCPTests-test-runner.exe'] = New-DumpbinFixture @('BridgeMCPTests.dll', 'XCTest.dll')
    }
    'malformed' { $imports['BridgeMCPTests.dll'] = @('synthetic malformed output') }
    'delay-import' {
      [void](New-SyntheticPE (Join-Path $swiftRuntimeBin 'DelayFixture.dll') -Payload 'delay')
      $imports['BridgeMCPTests.dll'] = New-DumpbinFixture @('Testing.dll') @('DelayFixture.dll')
      $imports['DelayFixture.dll'] = New-DumpbinFixture @('kernel32.dll')
    }
  }
  $provider = {
    param([string]$Path)
    $name = [IO.Path]::GetFileName($Path)
    $value = if ($imports.ContainsKey($name)) { @($imports[$name]) } else { @(New-DumpbinFixture @()) }
    return [pscustomobject]@{ ExitCode = 0; Output = [string[]]@($value | ForEach-Object { [string]$_ }) }
  }.GetNewClosure()
  return [pscustomobject]@{
    Root = $root
    WorkspaceRoot = $workspace
    BinPath = $bin
    SwiftRoot = $swift
    VcpkgRoot = (Split-Path -Parent (Split-Path -Parent $vcpkg))
    PortableRoot = $portable
    SystemRoot = $systemRoot
    RunnerTemp = $temp
    SchemaPath = $fixedSchemaPath
    DumpbinPath = $dumpbin
    Identity = $identity
    Roots = $rootSpecs
    Candidates = $candidateSpecs
    Provider = $provider
    Imports = $imports
  }
}

function Invoke-FixtureAudit($Fixture, [switch]$MissingDumpbin, [int]$MaximumDepth = 64) {
  $dumpbinPath = if ($MissingDumpbin) { Join-Path $Fixture.Root 'missing-dumpbin.exe' } else { $Fixture.DumpbinPath }
  $parameters = @{
    Identity = $Fixture.Identity
    WorkspaceRoot = $Fixture.WorkspaceRoot
    RunnerTemp = $Fixture.RunnerTemp
    SourceRoots = $Fixture.Roots
    Candidates = $Fixture.Candidates
    SystemRoot = $Fixture.SystemRoot
    DumpbinPath = $dumpbinPath
    FixedSchemaPath = $Fixture.SchemaPath
    ExpectedSchemaSha256 = $fixedSchemaSha256
    MaximumDepth = $MaximumDepth
  }
  if (-not $MissingDumpbin) { $parameters.PeImportProvider = $Fixture.Provider }
  return Invoke-CodexBridgeStaticImportAudit @parameters
}

$parserLines = New-DumpbinFixture @('OrdinaryFixture.dll') @('DelayFixture.dll')
$parsed = @(Parse-CodexBridgeDumpbinImports -Lines $parserLines)
Assert-Equal ($parsed.Count.ToString()) '2' 'ordinary-and-delay-import-count'
Assert-Equal (($parsed | Where-Object { $_.name -ieq 'OrdinaryFixture.dll' }).kind) 'ordinary' 'ordinary-import-kind'
Assert-Equal (($parsed | Where-Object { $_.name -ieq 'DelayFixture.dll' }).kind) 'delay' 'delay-import-kind'
Complete-Test 'ordinary-and-delay-import-parser'

$multiLevelFixture = New-AuditFixture 'multi-level'
try {
  $report = Invoke-FixtureAudit $multiLevelFixture
  if ($report.auditStatus -ne 'PASS') { Write-Output "DIAGNOSTIC category=$($report.failureCategory) unresolved=$($report.unresolvedDependencies.Count)" }
  Assert-Equal $report.auditStatus 'PASS' 'multi-level-audit-pass'
  Assert-True (@($report.dependencyNodes | Where-Object { $_.dependencyName -ieq 'AuditB.dll' }).Count -eq 1) 'multi-level-recursion-found-grandchild'
  Assert-Equal $report.candidateIdentity.runnerBuildAssociation 'PASS' 'runner-associated-by-built-dll-import'
  Assert-Equal $report.candidateIdentity.runnerTestDiscovery 'NOT_VERIFIED' 'test-discovery-not-claimed'
  Assert-Equal $report.candidateIdentity.directRunnerExecution 'NOT_VERIFIED' 'direct-run-not-claimed'
  Assert-Equal $report.graphStatus.harness 'PASS' 'harness-graph-status-is-independent'
  Assert-Equal $report.graphStatus.portableService 'PASS' 'portable-graph-status-is-independent'
  Assert-Equal $report.dependencyNodeCount ([string]@($report.dependencyNodes).Count) 'dependency-node-count-is-derived'
  Assert-Equal $report.importEdgeCount ([string]@($report.dependencyEdges).Count) 'import-edge-count-is-derived'
  Assert-Equal $report.dynamicDependencyStatus 'NOT_VERIFIED' 'dynamic-dependencies-not-claimed'
  Assert-Equal $report.packageExecutable 'UNRESOLVED' 'static-pass-not-package-pass'
  $depthFixture = New-AuditFixture 'multi-level'
  try {
    $boundedReport = Invoke-FixtureAudit $depthFixture -MaximumDepth 2
    Assert-Equal $boundedReport.auditStatus 'FAIL' 'dependency-depth-limit-fails-closed'
    Assert-Equal $boundedReport.failureCategory 'dependency_depth_limit_exceeded' 'dependency-depth-limit-category'
  } finally {
    Remove-Item -LiteralPath $depthFixture.Root -Recurse -Force
  }
  Complete-Test 'recursive-static-import-audit-and-runner-association'
} finally {
  Remove-Item -LiteralPath $multiLevelFixture.Root -Recurse -Force
}

$baseFixture = New-AuditFixture 'pass'
try {
  $report = Invoke-FixtureAudit $baseFixture
  Assert-Equal $report.auditStatus 'PASS' 'baseline-audit-pass'
  $harnessSqlite = @($report.dependencyNodes | Where-Object { $_.dependencyName -ceq 'sqlite3.dll' -and $_.graph -ceq 'harness' })
  $serviceSqlite = @($report.dependencyNodes | Where-Object { $_.dependencyName -ceq 'sqlite3.dll' -and $_.graph -ceq 'portable-service' })
  Assert-Equal ($harnessSqlite.Count.ToString()) '1' 'harness-sqlite-one-node'
  Assert-Equal ($serviceSqlite.Count.ToString()) '1' 'portable-sqlite-one-node'
  Assert-True ($harnessSqlite[0].sha256 -cne $serviceSqlite[0].sha256) 'sqlite-sources-remain-distinct'
  $sharedSystemNode = @($report.dependencyNodes | Where-Object { $_.dependencyName -ceq 'kernel32.dll' })
  Assert-Equal ($sharedSystemNode.Count.ToString()) '1' 'same-system-file-identity-deduplicated'
  Assert-True ($sharedSystemNode[0].graphs -contains 'harness' -and $sharedSystemNode[0].graphs -contains 'portable-service') 'shared-system-node-records-both-graphs'
  Assert-True (-not ($report.PSObject.Properties.Name -contains 'absoluteHostPath')) 'no-host-path-field'
  Assert-True ((ConvertTo-Json -InputObject $report -Depth 12 -Compress) -notmatch [regex]::Escape($baseFixture.Root)) 'no-absolute-path-in-report'
  Complete-Test 'harness-and-portable-service-graphs-are-independent'
} finally {
  Remove-Item -LiteralPath $baseFixture.Root -Recurse -Force
}

$failureCases = @(
  [pscustomobject]@{ name = 'cycle'; scenario = 'cycle'; expected = 'FAIL'; reason = 'dependency_cycle' }
  [pscustomobject]@{ name = 'unknown-dll'; scenario = 'unknown'; expected = 'INCOMPLETE'; reason = 'no_approved_source' }
  [pscustomobject]@{ name = 'conflicting-same-name'; scenario = 'collision'; expected = 'INCOMPLETE'; reason = 'COLLISION_UNRESOLVED' }
  [pscustomobject]@{ name = 'wrong-architecture'; scenario = 'wrong-architecture'; expected = 'FAIL'; reason = 'architecture' }
  [pscustomobject]@{ name = 'malformed-dumpbin'; scenario = 'malformed'; expected = 'FAIL'; reason = 'dumpbin' }
)
foreach ($case in $failureCases) {
  $fixture = New-AuditFixture $case.scenario
  try {
    $report = Invoke-FixtureAudit $fixture
    Assert-Equal $report.auditStatus $case.expected "audit-$($case.name)-status"
    Assert-True (@($report.unresolvedDependencies | Where-Object { $_.reason -match $case.reason }).Count -gt 0 -or $report.failureCategory -match $case.reason) "audit-$($case.name)-reason"
    if ($case.name -ceq 'unknown-dll') {
      Assert-True (@($report.unresolvedDependencies | Where-Object { $_.dependencyName -ceq 'api-ms-win-core-synthetic-l1-1-0.dll' -and $_.reason -ceq 'api_set_contract_unverified' }).Count -eq 1) 'unknown-api-set-is-not-assumed-system-provided'
      Assert-Equal $report.graphStatus.harness 'INCOMPLETE' 'unknown-harness-import-makes-graph-incomplete'
      Assert-Equal $report.graphStatus.portableService 'PASS' 'unrelated-portable-graph-status-remains-independent'
    }
    if ($case.name -ceq 'conflicting-same-name') {
      Assert-Equal $report.sourceCollisionCount '1' 'source-collision-count-is-derived'
    }
    Complete-Test "audit-$($case.name)-fails-closed"
  } finally {
    Remove-Item -LiteralPath $fixture.Root -Recurse -Force
  }
}

$delayFixture = New-AuditFixture 'delay-import'
try {
  $report = Invoke-FixtureAudit $delayFixture
  Assert-Equal $report.auditStatus 'PASS' 'delay-import-audit-pass'
  Assert-Equal ((@($report.dependencyEdges | Where-Object { $_.dependencyName -ieq 'DelayFixture.dll' }))[0].importKind) 'delay' 'delay-import-edge-preserved'
  Assert-Equal $report.delayImportEdgeCount '1' 'delay-import-count-is-derived'
  Complete-Test 'delay-import-edge-preserved'
} finally {
  Remove-Item -LiteralPath $delayFixture.Root -Recurse -Force
}

$identityFixture = New-AuditFixture 'pass'
try {
  $identityFixture.Identity.requestedSourceCommit = '0000000000000000000000000000000000000000'
  $report = Invoke-FixtureAudit $identityFixture
  Assert-Equal $report.auditStatus 'FAIL' 'incorrect-source-commit-fails'
  Assert-Equal $report.failureCategory 'source_commit_mismatch' 'incorrect-source-commit-category'
  Complete-Test 'incorrect-source-commit-fails-closed'
} finally {
  Remove-Item -LiteralPath $identityFixture.Root -Recurse -Force
}

$missingDumpbinFixture = New-AuditFixture 'pass'
try {
  $report = Invoke-FixtureAudit $missingDumpbinFixture -MissingDumpbin
  Assert-Equal $report.auditStatus 'FAIL' 'missing-dumpbin-fails'
  Assert-Equal $report.failureCategory 'dumpbin_unavailable' 'missing-dumpbin-category'
  Complete-Test 'missing-dumpbin-fails-closed'
} finally {
  Remove-Item -LiteralPath $missingDumpbinFixture.Root -Recurse -Force
}

$hashFixture = New-AuditFixture 'pass'
try {
  $hashFixture.Candidates[0].expectedSha256 = '0' * 64
  $report = Invoke-FixtureAudit $hashFixture
  Assert-Equal $report.auditStatus 'FAIL' 'candidate-source-hash-mismatch-fails'
  Assert-Equal $report.failureCategory 'candidate_sha256_mismatch' 'candidate-source-hash-mismatch-category'
  Complete-Test 'candidate-source-hash-mismatch-fails-closed'
} finally {
  Remove-Item -LiteralPath $hashFixture.Root -Recurse -Force
}

$schemaFixture = New-AuditFixture 'pass'
try {
  $report = Invoke-CodexBridgeStaticImportAudit `
    -Identity $schemaFixture.Identity -WorkspaceRoot $schemaFixture.WorkspaceRoot `
    -RunnerTemp $schemaFixture.RunnerTemp `
    -SourceRoots $schemaFixture.Roots -Candidates $schemaFixture.Candidates `
    -SystemRoot $schemaFixture.SystemRoot -DumpbinPath $schemaFixture.DumpbinPath `
    -FixedSchemaPath $schemaFixture.SchemaPath -ExpectedSchemaSha256 ('0' * 64) `
    -PeImportProvider $schemaFixture.Provider
  Assert-Equal $report.auditStatus 'FAIL' 'schema-sha-mismatch-fails'
  Assert-Equal $report.failureCategory 'fixed_schema_identity_mismatch' 'schema-sha-mismatch-category'
  Complete-Test 'fixed-schema-mismatch-fails-closed'
} finally {
  Remove-Item -LiteralPath $schemaFixture.Root -Recurse -Force
}

$pathFixture = New-AuditFixture 'pass'
try {
  $pathFixture.Candidates[0].path = $pathFixture.Candidates[2].path
  $report = Invoke-FixtureAudit $pathFixture
  Assert-Equal $report.auditStatus 'FAIL' 'candidate-path-escape-fails'
  Assert-Equal $report.failureCategory 'candidate_path_outside_source_root' 'candidate-path-escape-category'
  Complete-Test 'candidate-path-escape-fails-closed'
} finally {
  Remove-Item -LiteralPath $pathFixture.Root -Recurse -Force
}

$reparseFixture = New-AuditFixture 'pass'
$reparsePath = Join-Path $reparseFixture.BinPath 'runner-link'
$reparseTarget = Join-Path $reparseFixture.Root 'runner-link-target'
try {
  $linkCreated = $false
  try {
    New-Item -ItemType Directory -Path $reparseTarget -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath $reparseFixture.Candidates[0].path -Destination (Join-Path $reparseTarget 'BridgeMCPTests-test-runner.exe') -ErrorAction Stop
    New-Item -ItemType Junction -Path $reparsePath -Target $reparseTarget -ErrorAction Stop | Out-Null
    $linkCreated = $true
  } catch {
    Write-Output 'NOT_TESTED test=reparse-point-rejection reason=junction_creation_unavailable'
  }
  if ($linkCreated) {
    $reparseFixture.Candidates[0].path = Join-Path $reparsePath 'BridgeMCPTests-test-runner.exe'
    $report = Invoke-FixtureAudit $reparseFixture
    Assert-Equal $report.auditStatus 'FAIL' 'candidate-reparse-point-fails'
    Assert-True ($report.failureCategory -cin @('reparse_point_not_allowed', 'path_alias_not_allowed')) 'candidate-reparse-point-category'
    Complete-Test 'candidate-reparse-point-fails-closed'
  }
} finally {
  if (Test-Path -LiteralPath $reparsePath) { Remove-Item -LiteralPath $reparsePath -Force -ErrorAction SilentlyContinue }
  Remove-Item -LiteralPath $reparseFixture.Root -Recurse -Force
}

try {
  $longLine = 'x' * 2048
  [void](Parse-CodexBridgeDumpbinImports -Lines @($longLine) -MaximumCharacters 1024)
  throw 'assertion_failed_dumpbin_output_limit_not_enforced'
} catch {
  if ($_.Exception.Message -cne 'audit_dumpbin_output_limit_exceeded') { throw }
  Complete-Test 'dumpbin-parser-output-bound'
}

$defaultReleaseRequirementFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $defaultReleaseRequirementFixture
  [void](Invoke-SyntheticBinPathQuery $defaultReleaseRequirementFixture 'debug')
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $defaultReleaseRequirementFixture 'release' } `
    'audit_show_bin_path_missing_release' 'binpath-missing-directory-requires-explicit-opt-in'
} finally { Remove-BinPathFixture $defaultReleaseRequirementFixture }

$entrypointText = [IO.File]::ReadAllText($entrypointPath)
Assert-True ($entrypointText -match 'Get-VerifiedBinPath -Configuration ''debug''.*WorkspaceRoot \$env:GITHUB_WORKSPACE') 'debug-binpath-query-remains-required'
Assert-True ($entrypointText -match 'Get-VerifiedBinPath -Configuration ''release''.*AllowMissingFinalDirectoryForComparison') 'release-missing-leaf-is-explicitly-scoped'
Complete-Test 'production-debug-release-binpath-call-contract'

$debugReleaseMissingFixture = New-BinPathFixture
try {
  $pair = Invoke-SyntheticBinPathPair $debugReleaseMissingFixture
  Assert-True (Test-Path -LiteralPath $pair.Debug.path -PathType Container) 'debug-existing-path-accepted'
  Assert-True (-not (Test-Path -LiteralPath $pair.Release.path)) 'release-final-directory-remains-missing'
  Assert-Equal $pair.Debug.path $debugReleaseMissingFixture.DebugPath 'debug-returned-path-is-exact'
  Assert-Equal $pair.Release.path $debugReleaseMissingFixture.ReleasePath 'release-returned-path-is-exact'
  Complete-Test 'binpath-debug-exists-release-missing'
} finally { Remove-BinPathFixture $debugReleaseMissingFixture }

$bothBinPathsFixture = New-BinPathFixture
try {
  New-Item -ItemType Directory -Path $bothBinPathsFixture.ReleasePath -Force | Out-Null
  $pair = Invoke-SyntheticBinPathPair $bothBinPathsFixture
  Assert-True (Test-Path -LiteralPath $pair.Debug.path -PathType Container) 'debug-existing-path-validated'
  Assert-True (Test-Path -LiteralPath $pair.Release.path -PathType Container) 'release-existing-path-validated'
  Complete-Test 'binpath-debug-and-release-both-exist'
} finally { Remove-BinPathFixture $bothBinPathsFixture }

$distinctBinPathsFixture = New-BinPathFixture
try {
  $pair = Invoke-SyntheticBinPathPair $distinctBinPathsFixture
  $buildPrefix = [IO.Path]::GetFullPath($distinctBinPathsFixture.BuildRoot).TrimEnd('\') + '\'
  Assert-True ($pair.Debug.path.StartsWith($buildPrefix, [StringComparison]::OrdinalIgnoreCase)) 'debug-contained-by-build-root'
  Assert-True ($pair.Release.path.StartsWith($buildPrefix, [StringComparison]::OrdinalIgnoreCase)) 'release-contained-by-build-root'
  Assert-True (-not [string]::Equals($pair.Debug.path, $pair.Release.path, [StringComparison]::OrdinalIgnoreCase)) 'debug-release-are-distinct'
  Complete-Test 'binpath-debug-release-distinct-under-build-root'
  foreach ($configuration in @('debug', 'release')) {
    $query = @($script:MockSwiftArguments[$configuration])
    $configurationIndex = [Array]::IndexOf([string[]]$query, '-c')
    Assert-True ($configurationIndex -ge 0 -and $query[$configurationIndex + 1] -ceq $configuration) "show-binpath-query-configuration-$configuration"
    Assert-True ($query -contains '--build-tests' -and $query -contains '--show-bin-path' -and
      $query -contains '-target' -and $query -contains 'x86_64-unknown-windows-msvc') "show-binpath-query-build-arguments-$configuration"
  }
  Complete-Test 'binpath-show-bin-path-query-retains-target-and-configuration-arguments'
} finally { Remove-BinPathFixture $distinctBinPathsFixture }

$debugMissingOptInFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $debugMissingOptInFixture
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $debugMissingOptInFixture 'debug' -AllowMissingFinalDirectoryForComparison } `
    'audit_missing_binpath_opt_in_invalid' 'binpath-missing-leaf-opt-in-rejected-for-debug'
} finally { Remove-BinPathFixture $debugMissingOptInFixture }

$missingDebugBinPathFixture = New-BinPathFixture
try {
  Remove-Item -LiteralPath $missingDebugBinPathFixture.DebugPath -Force
  Set-SyntheticBinPathResponses $missingDebugBinPathFixture
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $missingDebugBinPathFixture 'debug' } `
    'audit_show_bin_path_missing_debug' 'binpath-debug-missing-fails'
} finally { Remove-BinPathFixture $missingDebugBinPathFixture }

$outsideDebugBinPathFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $outsideDebugBinPathFixture
  $script:MockSwiftOutputs.debug = @($outsideDebugBinPathFixture.OutsidePath)
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $outsideDebugBinPathFixture 'debug' } `
    'audit_show_bin_path_outside_build_root' 'binpath-debug-outside-build-root-fails'
} finally { Remove-BinPathFixture $outsideDebugBinPathFixture }

$outsideReleaseBinPathFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $outsideReleaseBinPathFixture
  $script:MockSwiftOutputs.release = @($outsideReleaseBinPathFixture.OutsidePath)
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $outsideReleaseBinPathFixture 'release' -AllowMissingFinalDirectoryForComparison } `
    'audit_show_bin_path_outside_build_root' 'binpath-release-outside-build-root-fails'
} finally { Remove-BinPathFixture $outsideReleaseBinPathFixture }

$equalBinPathsFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $equalBinPathsFixture
  $script:MockSwiftOutputs.release = @($equalBinPathsFixture.DebugPath)
  $debugBin = Invoke-SyntheticBinPathQuery $equalBinPathsFixture 'debug'
  $releaseBin = Invoke-SyntheticBinPathQuery $equalBinPathsFixture 'release' -AllowMissingFinalDirectoryForComparison
  Assert-BinPathFailure { . $script:ProductionBinPathPairGuard } `
    'audit_debug_release_binpath_ambiguous' 'binpath-release-equals-debug-fails'
} finally { Remove-BinPathFixture $equalBinPathsFixture }

function New-SyntheticJunction([string]$Path, [string]$Target) {
  try {
    New-Item -ItemType Junction -Path $Path -Target $Target -ErrorAction Stop | Out-Null
    return $true
  } catch { return $false }
}

$aliasReleaseFixture = New-BinPathFixture
try {
  if (New-SyntheticJunction $aliasReleaseFixture.ReleasePath $aliasReleaseFixture.DebugPath) {
    Set-SyntheticBinPathResponses $aliasReleaseFixture
    Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $aliasReleaseFixture 'release' -AllowMissingFinalDirectoryForComparison } `
      'audit_build_path_reparse_point' 'binpath-release-aliases-debug-fails'
  } else { Mark-NotTested 'binpath-release-aliases-debug-fails' 'junction_creation_unavailable' }
} finally {
  if (Test-Path -LiteralPath $aliasReleaseFixture.ReleasePath) { Remove-Item -LiteralPath $aliasReleaseFixture.ReleasePath -Force -ErrorAction SilentlyContinue }
  Remove-BinPathFixture $aliasReleaseFixture
}

$reparseReleaseFixture = New-BinPathFixture
try {
  if (New-SyntheticJunction $reparseReleaseFixture.ReleasePath $reparseReleaseFixture.OutsidePath) {
    Set-SyntheticBinPathResponses $reparseReleaseFixture
    Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $reparseReleaseFixture 'release' -AllowMissingFinalDirectoryForComparison } `
      'audit_build_path_reparse_point' 'binpath-existing-release-reparse-point-fails'
  } else { Mark-NotTested 'binpath-existing-release-reparse-point-fails' 'junction_creation_unavailable' }
} finally {
  if (Test-Path -LiteralPath $reparseReleaseFixture.ReleasePath) { Remove-Item -LiteralPath $reparseReleaseFixture.ReleasePath -Force -ErrorAction SilentlyContinue }
  Remove-BinPathFixture $reparseReleaseFixture
}

$reparseAncestorFixture = New-BinPathFixture
$ancestorJunction = Join-Path $reparseAncestorFixture.BuildRoot 'aliased-target'
try {
  if (New-SyntheticJunction $ancestorJunction $reparseAncestorFixture.OutsidePath) {
    $script:MockSwiftOutputs = @{
      debug = @([string]$reparseAncestorFixture.DebugPath)
      release = @((Join-Path $ancestorJunction 'release'))
    }
    $script:MockSwiftExitCodes = @{ debug = 0; release = 0 }
    $script:MockSwiftArguments = @{}
    Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $reparseAncestorFixture 'release' -AllowMissingFinalDirectoryForComparison } `
      'audit_path_alias_not_allowed|audit_build_path_reparse_point' 'binpath-unsafe-existing-ancestor-fails'
  } else { Mark-NotTested 'binpath-unsafe-existing-ancestor-fails' 'junction_creation_unavailable' }
} finally {
  if (Test-Path -LiteralPath $ancestorJunction) { Remove-Item -LiteralPath $ancestorJunction -Force -ErrorAction SilentlyContinue }
  Remove-BinPathFixture $reparseAncestorFixture
}

$malformedBinPathFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $malformedBinPathFixture
  $script:MockSwiftOutputs.release = @('synthetic swift output without an absolute path')
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $malformedBinPathFixture 'release' -AllowMissingFinalDirectoryForComparison } `
    'audit_show_bin_path_unrecognized_release' 'binpath-malformed-swift-output-fails'
} finally { Remove-BinPathFixture $malformedBinPathFixture }

$multipleBinPathsFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $multipleBinPathsFixture
  $script:MockSwiftOutputs.release = @($multipleBinPathsFixture.DebugPath, $multipleBinPathsFixture.ReleasePath)
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $multipleBinPathsFixture 'release' -AllowMissingFinalDirectoryForComparison } `
    'audit_show_bin_path_unrecognized_release' 'binpath-multiple-swift-paths-fail'
} finally { Remove-BinPathFixture $multipleBinPathsFixture }

$traversalBinPathFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $traversalBinPathFixture
  $script:MockSwiftOutputs.release = @("$($traversalBinPathFixture.BuildRoot)\synthetic-target\..\traversal-release")
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $traversalBinPathFixture 'release' -AllowMissingFinalDirectoryForComparison } `
    'audit_show_bin_path_traversal' 'binpath-release-dot-dot-segment-fails'
} finally { Remove-BinPathFixture $traversalBinPathFixture }

$missingReleaseParentFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $missingReleaseParentFixture
  $script:MockSwiftOutputs.release = @((Join-Path $missingReleaseParentFixture.BuildRoot 'unmaterialized-parent\release'))
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $missingReleaseParentFixture 'release' -AllowMissingFinalDirectoryForComparison } `
    'audit_show_bin_path_parent_missing_release' 'binpath-missing-release-parent-fails'
} finally { Remove-BinPathFixture $missingReleaseParentFixture }

$failedSwiftQueryFixture = New-BinPathFixture
try {
  Set-SyntheticBinPathResponses $failedSwiftQueryFixture
  $script:MockSwiftExitCodes.release = 23
  Assert-BinPathFailure { Invoke-SyntheticBinPathQuery $failedSwiftQueryFixture 'release' -AllowMissingFinalDirectoryForComparison } `
    'audit_show_bin_path_failed_release' 'binpath-swift-query-nonzero-fails'
} finally { Remove-BinPathFixture $failedSwiftQueryFixture }

$candidateRunnerMissingFixture = New-AuditFixture 'pass'
try {
  Remove-Item -LiteralPath $candidateRunnerMissingFixture.Candidates[0].path -Force
  $report = Invoke-FixtureAudit $candidateRunnerMissingFixture
  Assert-Equal $report.auditStatus 'FAIL' 'missing-runner-fails'
  Assert-Equal $report.failureCategory 'candidate_path_invalid' 'missing-runner-category'
  Complete-Test 'candidate-runner-missing-fails-closed'
} finally { Remove-Item -LiteralPath $candidateRunnerMissingFixture.Root -Recurse -Force }

$candidateModuleMissingFixture = New-AuditFixture 'pass'
try {
  Remove-Item -LiteralPath $candidateModuleMissingFixture.Candidates[1].path -Force
  $report = Invoke-FixtureAudit $candidateModuleMissingFixture
  Assert-Equal $report.auditStatus 'FAIL' 'missing-module-fails'
  Assert-Equal $report.failureCategory 'candidate_path_invalid' 'missing-module-category'
  Complete-Test 'candidate-test-module-missing-fails-closed'
} finally { Remove-Item -LiteralPath $candidateModuleMissingFixture.Root -Recurse -Force }

$candidateArchitectureFixture = New-AuditFixture 'pass'
try {
  $candidate = $candidateArchitectureFixture.Candidates[0]
  $candidate.expectedSha256 = New-SyntheticPE $candidate.path -Machine 0x014c -Payload 'synthetic-x86-runner'
  $report = Invoke-FixtureAudit $candidateArchitectureFixture
  Assert-Equal $report.auditStatus 'FAIL' 'candidate-architecture-fails'
  Assert-Equal $report.failureCategory 'candidate_architecture_mismatch' 'candidate-architecture-category'
  Complete-Test 'candidate-pe-architecture-mismatch-fails-closed'
} finally { Remove-Item -LiteralPath $candidateArchitectureFixture.Root -Recurse -Force }

$invalidSourceCommitFixture = New-AuditFixture 'pass'
try {
  $invalidSourceCommitFixture.Identity.sourceCommit = 'not-a-source-commit'
  $invalidSourceCommitFixture.Identity.requestedSourceCommit = 'not-a-source-commit'
  $report = Invoke-FixtureAudit $invalidSourceCommitFixture
  Assert-Equal $report.auditStatus 'FAIL' 'invalid-source-commit-fails'
  Assert-Equal $report.failureCategory 'source_commit_mismatch' 'invalid-source-commit-category'
  Complete-Test 'invalid-source-commit-fails-closed'
} finally { Remove-Item -LiteralPath $invalidSourceCommitFixture.Root -Recurse -Force }

$workflowPath = Join-Path $PSScriptRoot '..\..\..\workflows\windows.yml'
$workflow = Get-Content -LiteralPath $workflowPath -Raw
Assert-True ($workflow -match 'b1-dependency-audit-only') 'workflow-declares-audit-only-mode'
Assert-True ($workflow -match '(?s)if:\s*inputs\.test_mode == ''b1-dependency-audit-only''.*?Invoke-McpStaticDependencyAudit\.ps1') 'workflow-audit-step-gated-to-audit-mode'
$compileJobIndex = $workflow.IndexOf('  mcp-exe-compile-only:')
Assert-True ($compileJobIndex -ge 0) 'compile-only-job-exists'
$compileJobWorkflow = $workflow.Substring($compileJobIndex)
$compileJobSteps = @([regex]::Matches($compileJobWorkflow, '(?ms)^      - (?:name|uses):.*?(?=^      - (?:name|uses):|\z)'))
$auditModeSteps = @($compileJobSteps | Where-Object { $_.Value -match "inputs\.test_mode == 'b1-dependency-audit-only'" })
$auditModeUploads = @($auditModeSteps | Where-Object { $_.Value -match 'uses:\s*actions/upload-artifact' })
Assert-True ($auditModeUploads.Count -eq 0) 'workflow-audit-mode-does-not-upload-artifact'
$boundaryIndex = $compileJobWorkflow.IndexOf('Verify compile-only dispatch boundary')
$portableIndex = $compileJobWorkflow.IndexOf('id: prepare_portable')
$swiftSetupIndex = $compileJobWorkflow.IndexOf('Install Swift toolchain')
$compileIndex = $compileJobWorkflow.IndexOf('Compile Swift sources and XCTest targets without running them')
$auditIndex = $compileJobWorkflow.IndexOf('Run static PE dependency audit without executing binaries')
Assert-True ($boundaryIndex -ge 0 -and $portableIndex -gt $boundaryIndex -and
  $swiftSetupIndex -gt $portableIndex -and $compileIndex -gt $swiftSetupIndex -and
  $auditIndex -gt $compileIndex) 'audit-runs-after-portable-then-compile'
$auditWorkflowIndex = $compileJobIndex + $auditIndex
$auditEnd = $workflow.IndexOf('      - name: Report package inventory-only status', $auditWorkflowIndex)
if ($auditEnd -lt 0) { throw 'assertion_failed_audit_workflow_boundary_missing' }
$auditWorkflowSection = $workflow.Substring($auditWorkflowIndex, $auditEnd - $auditWorkflowIndex)
Assert-True ($auditWorkflowSection -match "if: success\(\) && inputs\.test_mode == 'b1-dependency-audit-only'") 'audit-step-success-gated-and-mode-specific'
Assert-True ($auditWorkflowSection -notmatch 'swift\s+test|Start-Process|Invoke-McpVmGuestHarness|actions/upload-artifact') 'audit-step-never-runs-tests-service-vm-or-upload'
Assert-True ($workflow -notmatch '6c4d86c0cec892f69c27749f81690ed4b70d89d3') 'workflow-does-not-hardcode-parent-as-permitted-audit-sha'
foreach ($summaryField in @(
    'STATIC_IMPORT_AUDIT=', 'SOURCE_COMMIT=', 'HARNESS_GRAPH_STATUS=', 'PORTABLE_GRAPH_STATUS=',
    'RUNNER_BUILD_ASSOCIATION=', 'DEPENDENCY_NODE_COUNT=', 'IMPORT_EDGE_COUNT=',
    'DELAY_IMPORT_EDGE_COUNT=', 'UNRESOLVED_COUNT=', 'SOURCE_COLLISION_COUNT=', 'AUDIT_REPORT_SHA256='
  )) {
  Assert-True ($workflow.Contains($summaryField)) "workflow-persists-summary-field-$($summaryField.TrimEnd('='))"
}
Assert-True ($workflow -match 'GITHUB_STEP_SUMMARY') 'workflow-persists-sanitized-job-summary'
Assert-True ($workflow.Contains('"source_commit=$($head.ToLowerInvariant())" | Add-Content -LiteralPath $env:GITHUB_OUTPUT')) 'compile-boundary-exports-verified-source-sha'
$wrapperPath = Join-Path $PSScriptRoot '..\Invoke-McpStaticDependencyAudit.ps1'
$wrapper = Get-Content -LiteralPath $wrapperPath -Raw
Assert-True ($wrapper -match '\$reportDirectory\s*=\s*Join-Path\s+\$env:RUNNER_TEMP') 'detailed-audit-report-stays-in-runner-temp'
foreach ($outputKey in @('audit_status', 'source_commit', 'harness_graph_status', 'portable_graph_status', 'runner_build_association', 'dependency_node_count', 'import_edge_count', 'delay_import_edge_count', 'unresolved_count', 'source_collision_count', 'report_sha256')) {
  Assert-True ($wrapper.Contains("$outputKey =")) "wrapper-derives-summary-output-$outputKey"
}
Assert-True ($wrapper -match 'Add-Content\s+-LiteralPath\s+\$env:GITHUB_OUTPUT') 'wrapper-persists-audit-step-outputs'

function ConvertTo-PowerShellLiteral([string]$Value) {
  return "'" + $Value.Replace("'", "''") + "'"
}

function Get-StaticAuditSummaryScript([string]$WorkflowText) {
  $stepPattern = '(?ms)^      - name: Report static dependency audit status without packaging or execution\r?\n(?<step>.*?)(?=^      - (?:name|uses):|\z)'
  $stepMatch = [regex]::Match($WorkflowText, $stepPattern)
  if (-not $stepMatch.Success) { throw 'summary_step_missing' }
  $stepText = $stepMatch.Groups['step'].Value
  $runMatch = [regex]::Match($stepText, '(?m)^        run:\s*\|\r?\n')
  if (-not $runMatch.Success) { throw 'summary_run_block_missing' }
  $body = $stepText.Substring($runMatch.Index + $runMatch.Length)
  $scriptLines = foreach ($line in ($body -split '\r?\n')) {
    if ([string]::IsNullOrWhiteSpace($line)) {
      ''
    } elseif ($line.StartsWith('          ', [StringComparison]::Ordinal)) {
      $line.Substring(10)
    } else {
      throw 'summary_run_indentation_unexpected'
    }
  }
  return ($scriptLines -join [Environment]::NewLine)
}

$summaryRunScript = Get-StaticAuditSummaryScript $workflow
$summaryTestRoot = Join-Path $env:TEMP ('codex-bridge-audit-summary-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $summaryTestRoot -Force | Out-Null
$summaryDefaults = @{
  COMPILE_OUTCOME = 'success'
  COMPILE_STATUS = 'PASS'
  VERIFIED_SOURCE_COMMIT = ('a' * 40)
  PORTABLE_OUTCOME = 'success'
  AUDIT_OUTCOME = 'success'
  AUDIT_STATUS = 'PASS'
  AUDIT_SOURCE_COMMIT = ('a' * 40)
  HARNESS_GRAPH_STATUS = 'PASS'
  PORTABLE_GRAPH_STATUS = 'PASS'
  RUNNER_BUILD_ASSOCIATION = 'PASS'
  DEPENDENCY_NODE_COUNT = '12'
  IMPORT_EDGE_COUNT = '11'
  DELAY_IMPORT_EDGE_COUNT = '1'
  UNRESOLVED_COUNT = '0'
  SOURCE_COLLISION_COUNT = '0'
  REPORT_SHA256 = ('b' * 64)
}
$summaryEnvironmentKeys = @($summaryDefaults.Keys) + @('GITHUB_STEP_SUMMARY')
$pwshPath = (Get-Command pwsh -ErrorAction Stop).Source

function Invoke-StaticAuditSummaryFixture([string]$Name, [hashtable]$Overrides = @{}) {
  $fixtureDirectory = Join-Path $summaryTestRoot $Name
  New-Item -ItemType Directory -Path $fixtureDirectory -Force | Out-Null
  $summaryPath = Join-Path $fixtureDirectory 'summary.txt'
  $scriptPath = Join-Path $fixtureDirectory 'summary.ps1'
  $bootstrap = [Collections.Generic.List[string]]::new()
  $bootstrap.Add('$ErrorActionPreference = ''Stop''')
  foreach ($key in $summaryEnvironmentKeys) {
    if ($key -ceq 'GITHUB_STEP_SUMMARY') {
      $value = $summaryPath
    } elseif ($Overrides.ContainsKey($key)) {
      $value = $Overrides[$key]
    } else {
      $value = $summaryDefaults[$key]
    }
    if ($null -eq $value) {
      $bootstrap.Add("Remove-Item -LiteralPath 'Env:$key' -ErrorAction SilentlyContinue")
    } else {
      $bootstrap.Add('$env:' + $key + ' = ' + (ConvertTo-PowerShellLiteral ([string]$value)))
    }
  }
  $scriptText = (@($bootstrap) + @($summaryRunScript)) -join [Environment]::NewLine
  [IO.File]::WriteAllText($scriptPath, $scriptText, [Text.UTF8Encoding]::new($false))

  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $pwshPath
  foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $scriptPath)) {
    $startInfo.ArgumentList.Add($argument)
  }
  $startInfo.UseShellExecute = $false
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $child = [Diagnostics.Process]::Start($startInfo)
  if ($null -eq $child) { throw 'summary_fixture_process_start_failed' }
  $stdout = $child.StandardOutput.ReadToEnd()
  $stderr = $child.StandardError.ReadToEnd()
  if (-not $child.WaitForExit(20000)) {
    $child.Kill()
    [void]$child.WaitForExit(5000)
    throw 'summary_fixture_process_timeout'
  }
  $summaryText = if (Test-Path -LiteralPath $summaryPath -PathType Leaf) {
    Get-Content -LiteralPath $summaryPath -Raw
  } else {
    ''
  }
  return [pscustomobject]@{
    ExitCode = $child.ExitCode
    Summary = $summaryText
    Output = $stdout + $stderr
  }
}

function Assert-SummaryFixture([pscustomobject]$Fixture, [int]$ExpectedExit, [string[]]$ExpectedLines, [string]$Name) {
  Assert-True ($Fixture.ExitCode -eq $ExpectedExit) "$Name-exit-code"
  foreach ($line in $ExpectedLines) {
    Assert-True ($Fixture.Summary.Contains($line)) "$Name-$($line.Replace('=', '-'))"
  }
}

try {
  $portableFailure = Invoke-StaticAuditSummaryFixture 'portable-failure' @{
    PORTABLE_OUTCOME = 'failure'; COMPILE_OUTCOME = 'skipped'; COMPILE_STATUS = $null
    AUDIT_OUTCOME = 'skipped'; AUDIT_STATUS = $null
  }
  Assert-SummaryFixture $portableFailure 1 @('PORTABLE_SOURCE_STATUS=FAIL', 'COMPILE_STATUS=NOT_RUN', 'STATIC_IMPORT_AUDIT=NOT_RUN') 'portable-failure-before-compile'
  Complete-Test 'summary-portable-failure-before-compilation'

  $compileFailure = Invoke-StaticAuditSummaryFixture 'compile-failure' @{
    PORTABLE_OUTCOME = 'success'; COMPILE_OUTCOME = 'failure'; COMPILE_STATUS = 'FAIL'
    AUDIT_OUTCOME = 'skipped'; AUDIT_STATUS = $null
  }
  Assert-SummaryFixture $compileFailure 1 @('PORTABLE_SOURCE_STATUS=PASS', 'COMPILE_STATUS=FAIL', 'STATIC_IMPORT_AUDIT=NOT_RUN') 'portable-success-compile-failure'
  Complete-Test 'summary-portable-success-and-compile-failure'

  $auditIncomplete = Invoke-StaticAuditSummaryFixture 'audit-incomplete' @{
    PORTABLE_OUTCOME = 'success'; COMPILE_OUTCOME = 'success'; COMPILE_STATUS = 'PASS'
    AUDIT_OUTCOME = 'failure'; AUDIT_STATUS = 'INCOMPLETE'
  }
  Assert-SummaryFixture $auditIncomplete 1 @('PORTABLE_SOURCE_STATUS=PASS', 'COMPILE_STATUS=PASS', 'STATIC_IMPORT_AUDIT=INCOMPLETE') 'successful-compile-audit-incomplete'
  Complete-Test 'summary-compile-pass-audit-incomplete'

  $allSuccessful = Invoke-StaticAuditSummaryFixture 'all-successful' @{}
  Assert-SummaryFixture $allSuccessful 0 @('PORTABLE_SOURCE_STATUS=PASS', 'COMPILE_STATUS=PASS', 'STATIC_IMPORT_AUDIT=PASS') 'all-steps-successful'
  Complete-Test 'summary-all-steps-successful'

  $portableSkipped = Invoke-StaticAuditSummaryFixture 'portable-skipped' @{
    PORTABLE_OUTCOME = 'skipped'; COMPILE_OUTCOME = 'success'; COMPILE_STATUS = 'PASS'
    AUDIT_OUTCOME = 'skipped'; AUDIT_STATUS = 'PASS'
  }
  Assert-SummaryFixture $portableSkipped 1 @('PORTABLE_SOURCE_STATUS=NOT_RUN', 'COMPILE_STATUS=PASS', 'STATIC_IMPORT_AUDIT=NOT_RUN') 'portable-skipped'
  Complete-Test 'summary-portable-step-skipped'

  $unknownStatuses = Invoke-StaticAuditSummaryFixture 'unknown-statuses' @{
    PORTABLE_OUTCOME = 'unknown'; COMPILE_OUTCOME = 'success'; COMPILE_STATUS = $null
    AUDIT_OUTCOME = 'success'; AUDIT_STATUS = 'UNEXPECTED'
  }
  Assert-SummaryFixture $unknownStatuses 1 @('PORTABLE_SOURCE_STATUS=FAIL', 'COMPILE_STATUS=FAIL', 'STATIC_IMPORT_AUDIT=FAIL') 'unknown-and-missing-statuses'
  Assert-True (-not $unknownStatuses.Summary.Contains('PORTABLE_SOURCE_STATUS=PASS')) 'unknown-portable-outcome-cannot-pass'
  Assert-True (-not $unknownStatuses.Summary.Contains('COMPILE_STATUS=PASS')) 'missing-compile-status-cannot-pass'
  $missingStatuses = Invoke-StaticAuditSummaryFixture 'missing-statuses' @{
    PORTABLE_OUTCOME = $null; COMPILE_OUTCOME = 'success'; COMPILE_STATUS = 'INVALID'
    AUDIT_OUTCOME = 'success'; AUDIT_STATUS = $null
  }
  Assert-SummaryFixture $missingStatuses 1 @('PORTABLE_SOURCE_STATUS=FAIL', 'COMPILE_STATUS=FAIL', 'STATIC_IMPORT_AUDIT=FAIL') 'missing-and-invalid-statuses'
  Assert-True (-not $missingStatuses.Summary.Contains('COMPILE_STATUS=PASS')) 'invalid-compile-status-cannot-pass'
  Complete-Test 'summary-unknown-or-missing-status-fails-closed'
} finally {
  if (Test-Path -LiteralPath $summaryTestRoot -PathType Container) {
    Remove-Item -LiteralPath $summaryTestRoot -Recurse -Force
  }
}

Complete-Test 'workflow-audit-mode-has-no-runtime-or-artifact-upload'

$existingAuditTestCount = $script:passed
if ($existingAuditTestCount -ne 46) { throw 'assertion_failed_existing_static_audit_test_baseline_changed' }
$script:failureCategoryTestsPassed = 0
function Complete-FailureCategoryTest([string]$Name) {
  $script:failureCategoryTestsPassed++
  Complete-Test $Name
}

$untrustedFailureCategory = 'C:' + [char]92 + 'Synthetic' + [char]92 + 'Private category'
$syntheticToken = 'synthetic-' + 'not-a-real-token'
$syntheticBearer = 'Bea' + 'rer ' + $syntheticToken
$rawDiagnosticJson = ConvertTo-Json -InputObject ([ordered]@{
  authorization = $syntheticBearer
  path = $untrustedFailureCategory
  response = 'synthetic-body-sentinel'
}) -Compress
$classificationCases = @(
  [pscustomobject]@{ name = 'candidate-identity-failure-keeps-module-category'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = 'candidate_sha256_mismatch'; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_candidate_sha256_mismatch' }
  [pscustomobject]@{ name = 'dumpbin-unavailable-keeps-module-category'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = 'dumpbin_unavailable'; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_dumpbin_unavailable' }
  [pscustomobject]@{ name = 'malformed-dumpbin-output-keeps-module-category'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = 'dumpbin_format_unrecognized'; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_dumpbin_format_unrecognized' }
  [pscustomobject]@{ name = 'dependency-cycle-keeps-module-category'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = 'dependency_cycle'; dependencyNodeCount = 2; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_dependency_cycle' }
  [pscustomobject]@{ name = 'internal-failure-keeps-module-category'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = 'internal_audit_failure'; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_internal_audit_failure' }
  [pscustomobject]@{ name = 'missing-category-has-distinct-marker'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = $null; dependencyNodeCount = 3; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_failure_category_unavailable' }
  [pscustomobject]@{ name = 'malformed-untrusted-category-is-replaced'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = $untrustedFailureCategory; absolutePath = $untrustedFailureCategory; rawException = 'synthetic exception details'; rawDiagnosticJson = $rawDiagnosticJson; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_failure_category_unavailable' }
  [pscustomobject]@{ name = 'unlisted-ascii-category-is-rejected'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = 'unlisted_private_reason'; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_failure_category_unavailable' }
  [pscustomobject]@{ name = 'incomplete-with-verified-unresolved-dependencies'; report = [pscustomobject]@{ auditStatus = 'INCOMPLETE'; failureCategory = $null; dependencyNodeCount = 2; unresolvedCount = 2; unresolvedDependencies = @([pscustomobject]@{ graph = 'harness'; reason = 'no_approved_source' }, [pscustomobject]@{ graph = 'portable-service'; reason = 'COLLISION_UNRESOLVED' }) }; status = 'INCOMPLETE'; category = 'audit_unresolved_dependencies' }
  [pscustomobject]@{ name = 'incomplete-without-unresolved-evidence-is-not-mislabeled'; report = [pscustomobject]@{ auditStatus = 'INCOMPLETE'; failureCategory = $null; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'INCOMPLETE'; category = 'audit_incomplete_without_unresolved_evidence' }
  [pscustomobject]@{ name = 'fail-with-zero-nodes-does-not-claim-unresolved-dependencies'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = ''; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_failure_category_unavailable' }
  [pscustomobject]@{ name = 'fail-unresolved-category-requires-unresolved-evidence'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = 'unresolved_dependencies'; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_failure_category_unavailable' }
  [pscustomobject]@{ name = 'pass-with-no-failure-remains-pass'; report = [pscustomobject]@{ auditStatus = 'PASS'; failureCategory = $null; dependencyNodeCount = 4; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'PASS'; category = '' }
  [pscustomobject]@{ name = 'pass-with-null-unresolved-entry-cannot-pass'; report = [pscustomobject]@{ auditStatus = 'PASS'; failureCategory = $null; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = [object[]]@($null) }; status = 'FAIL'; category = 'audit_inconsistent_pass_result' }
  [pscustomobject]@{ name = 'pass-with-failure-evidence-cannot-report-pass'; report = [pscustomobject]@{ auditStatus = 'PASS'; failureCategory = 'candidate_sha256_mismatch'; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_inconsistent_pass_result' }
  [pscustomobject]@{ name = 'fail-is-not-promoted-to-incomplete'; report = [pscustomobject]@{ auditStatus = 'FAIL'; failureCategory = 'source_commit_mismatch'; dependencyNodeCount = 0; unresolvedCount = 0; unresolvedDependencies = @() }; status = 'FAIL'; category = 'audit_source_commit_mismatch' }
)

foreach ($case in $classificationCases) {
  $classification = Get-SanitizedAuditResultClassification -Report $case.report
  Assert-Equal ([string]$classification.auditStatus) $case.status "classification-status-$($case.name)"
  Assert-Equal ([string]$classification.failureCategory) $case.category "classification-category-$($case.name)"
  $serializedClassification = ConvertTo-Json -InputObject $classification -Compress
  if ($serializedClassification -match 'C:\\Synthetic|Private category|unlisted_private_reason|synthetic exception details|synthetic-body-sentinel' -or
      $serializedClassification.Contains($syntheticBearer) -or $serializedClassification.Contains($syntheticToken) -or
      $serializedClassification.Contains($rawDiagnosticJson)) {
    throw "assertion_failed_classification_leaks_untrusted_category_$($case.name)"
  }
  Complete-FailureCategoryTest $case.name
}

Assert-Equal (ConvertTo-SanitizedAuditFailureCategory -Category 'audit_candidate_sha256_mismatch' -HasAuditPrefix) `
  'audit_candidate_sha256_mismatch' 'prefixed-wrapper-category-is-allowlisted'
Complete-FailureCategoryTest 'prefixed-wrapper-category-is-allowlisted'
Assert-Equal (ConvertTo-SanitizedAuditFailureCategory -Category 'audit_unknown_private_value' -HasAuditPrefix) `
  'audit_failure_category_unavailable' 'unknown-prefixed-category-is-rejected'
Complete-FailureCategoryTest 'unknown-prefixed-category-is-rejected'

$moduleTextForCategoryCheck = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\McpStaticDependencyAudit.psm1'))
$moduleCategorySet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($match in [regex]::Matches($moduleTextForCategoryCheck, "throw\s+'audit_([a-z0-9_]+)'")) {
  [void]$moduleCategorySet.Add($match.Groups[1].Value)
}
foreach ($match in [regex]::Matches($moduleTextForCategoryCheck, "Get-CodexBridgeAuditFullPath[^\r\n]*'([a-z0-9_]+)'\)")) {
  [void]$moduleCategorySet.Add($match.Groups[1].Value)
}
if ($moduleCategorySet.Count -lt 50) { throw 'assertion_failed_module_failure_category_taxonomy_not_discovered' }
foreach ($moduleCategory in $moduleCategorySet) {
  if ((ConvertTo-SanitizedAuditFailureCategory -Category $moduleCategory) -cne "audit_$moduleCategory") {
    throw 'assertion_failed_module_failure_category_missing_from_allowlist'
  }
}
Complete-FailureCategoryTest 'all-module-failure-categories-are-allowlisted'

if ($script:failureCategoryTestsPassed -ne 19) { throw 'assertion_failed_failure_category_test_count' }
Write-Output "EXISTING_STATIC_AUDIT_TESTS=$existingAuditTestCount/46"
Write-Output "FAILURE_CATEGORY_TESTS=$script:failureCategoryTestsPassed/19"

Write-Output "TEST_SUMMARY executed=$script:passed failures=0"
