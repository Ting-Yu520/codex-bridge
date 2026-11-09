$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot '..\McpStaticDependencyAudit.psm1'
Import-Module $modulePath -Force
$fixedSchemaPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\schemas\mcp-2026-07-28.json'))
$fixedSchemaSha256 = 'EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203'.ToLowerInvariant()

function Assert-True([bool]$Value, [string]$Name) {
  if (-not $Value) { throw "assertion_failed_$Name" }
}

function Assert-Equal([string]$Actual, [string]$Expected, [string]$Name) {
  if ($Actual -cne $Expected) { throw "assertion_failed_$Name" }
}

$script:passed = 0
function Complete-Test([string]$Name) {
  $script:passed++
  Write-Output "PASS test=$Name"
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
Complete-Test 'workflow-audit-mode-has-no-runtime-or-artifact-upload'

Write-Output "TEST_SUMMARY executed=$script:passed failures=0"
