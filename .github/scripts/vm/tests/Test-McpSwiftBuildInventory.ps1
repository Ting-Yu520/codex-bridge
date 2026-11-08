$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot '..\McpSwiftBuildInventory.psm1'
Import-Module $modulePath -Force

function Assert-True([bool]$Value, [string]$Name) {
  if (-not $Value) { throw "assertion_failed_$Name" }
}

function Assert-ThrowsCategory([scriptblock]$Action, [string]$Category, [string]$Name) {
  $caught = $null
  try { & $Action } catch { $caught = $_ }
  Assert-True ($null -ne $caught) $Name
  Assert-True ($caught.Exception.Message -like "*$Category*") "$Name-category"
}

function Assert-SensitiveInventoryPathBlocked {
  param(
    [hashtable]$BaseIdentity,
    [string]$RelativePath,
    [string]$ExpectedClassification,
    [string]$ExpectedEntryType,
    [string]$Sentinel
  )

  $caseId = [Guid]::NewGuid().ToString('N')
  $caseRoot = Join-Path $BaseIdentity.BinPath 'BridgeCore_BridgeMCP.resources'
  $caseRoot = Join-Path $caseRoot 'FileTransfer'
  $caseRoot = Join-Path $caseRoot "s-$caseId"
  $caseRootFull = [IO.Path]::GetFullPath($caseRoot)
  $binRootFull = [IO.Path]::GetFullPath($BaseIdentity.BinPath).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $caseRootFull.StartsWith($binRootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'test_sensitive_case_root_outside_binpath'
  }

  $targetPath = Join-Path $caseRoot $RelativePath
  $parentPath = Split-Path -Parent $targetPath
  New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
  if ($ExpectedEntryType -ceq 'directory') {
    New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $targetPath 'payload.bin'), $Sentinel)
  } else {
    [IO.File]::WriteAllText($targetPath, $Sentinel)
  }
  try { [void][CodexBridgePathIdentity]::Read($targetPath) } catch { throw 'test_synthetic_file_identity_unavailable' }

  $caseOutput = Join-Path $BaseIdentity.RunnerTemp "inventory-sensitive-$caseId\inventory.json"
  $caseIdentity = $BaseIdentity.Clone()
  $caseIdentity.OutputPath = $caseOutput
  $failureMessage = $null
  try {
    try { New-CodexBridgeBuildInventory @caseIdentity | Out-Null } catch { $failureMessage = $_.Exception.Message }
    Assert-True ($null -ne $failureMessage) "sensitive-$ExpectedClassification-is-blocked"
    $failureCategory = if ($failureMessage -match 'inventory_[A-Za-z0-9_]+') { $Matches[0] } else { 'unclassified_error' }
    Assert-True ($failureCategory -ceq 'inventory_sensitive_filename_blocked') "sensitive-$ExpectedClassification-failure-category-$failureCategory"
    Assert-True ($failureMessage.Contains('inventory_sensitive_filename_blocked')) "sensitive-$ExpectedClassification-keeps-existing-failure-category"
    Assert-True ($failureMessage.Contains("classification=$ExpectedClassification")) "sensitive-$ExpectedClassification-safe-classification-is-reported"
    Assert-True ($failureMessage.Contains("entry_type=$ExpectedEntryType")) "sensitive-$ExpectedClassification-entry-type-is-reported"
    Assert-True (-not $failureMessage.Contains($RelativePath)) "sensitive-$ExpectedClassification-path-is-not-reported"
    Assert-True (-not $failureMessage.Contains($Sentinel)) "sensitive-$ExpectedClassification-content-is-not-reported"
    Assert-True (-not (Test-Path -LiteralPath $caseOutput -PathType Leaf)) "sensitive-$ExpectedClassification-manifest-is-not-created"
    return $failureMessage
  } finally {
    if (Test-Path -LiteralPath $caseRootFull) {
      Remove-Item -LiteralPath $caseRootFull -Recurse -Force -ErrorAction Stop
    }
    $caseOutputDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($caseOutput))
    $runnerTempFull = [IO.Path]::GetFullPath($BaseIdentity.RunnerTemp).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $caseOutputDirectory.StartsWith($runnerTempFull, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'test_sensitive_case_output_outside_runner_temp'
    }
    if (Test-Path -LiteralPath $caseOutputDirectory -PathType Container) {
      Remove-Item -LiteralPath $caseOutputDirectory -Recurse -Force -ErrorAction Stop
    }
  }
}

$workflowPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\workflows\windows.yml'))
$workflowText = [IO.File]::ReadAllText($workflowPath)
$workflowLines = $workflowText -split "`r?`n"
$beginMarker = '# BEGIN VCPKG SQLITE IDENTITY NORMALIZER'
$endMarker = '# END VCPKG SQLITE IDENTITY NORMALIZER'
$beginIndexes = @(
  for ($index = 0; $index -lt $workflowLines.Count; $index++) {
    if ($workflowLines[$index].Trim() -ceq $beginMarker) { $index }
  }
)
$endIndexes = @(
  for ($index = 0; $index -lt $workflowLines.Count; $index++) {
    if ($workflowLines[$index].Trim() -ceq $endMarker) { $index }
  }
)
Assert-True ($beginIndexes.Count -eq 1 -and $endIndexes.Count -eq 1 -and $endIndexes[0] -gt $beginIndexes[0]) 'sqlite-normalizer-markers-are-unique-and-ordered'

$normalizerLines = [Collections.Generic.List[string]]::new()
for ($index = $beginIndexes[0] + 1; $index -lt $endIndexes[0]; $index++) {
  $line = $workflowLines[$index]
  if ($line -match '^ {10}(.*)$') {
    $normalizerLines.Add($Matches[1])
  } elseif ([string]::IsNullOrWhiteSpace($line)) {
    $normalizerLines.Add('')
  } else {
    throw 'sqlite_normalizer_yaml_indentation_unexpected'
  }
}
. ([scriptblock]::Create($normalizerLines -join "`n"))

$acceptedSqliteCases = @(
  [pscustomobject]@{ Name = 'version-only'; Lines = [string[]]@('sqlite3:x64-windows 3.54.1'); Expected = 'sqlite3:x64-windows 3.54.1' }
  [pscustomobject]@{ Name = 'version-with-description'; Lines = [string[]]@('sqlite3:x64-windows 3.54.1 SQLite is a software library ...'); Expected = 'sqlite3:x64-windows 3.54.1' }
  [pscustomobject]@{ Name = 'version-revision-with-description'; Lines = [string[]]@('sqlite3:x64-windows 3.50.4#1 SQLite description'); Expected = 'sqlite3:x64-windows 3.50.4#1' }
)
foreach ($case in $acceptedSqliteCases) {
  $normalized = ConvertTo-VcpkgSqliteIdentity -ListOutput $case.Lines
  Assert-True ($normalized -ceq $case.Expected) "sqlite-$($case.Name)-normalizes-exactly"
  $environmentRecord = "VCPKG_SQLITE_PACKAGE=$normalized"
  Assert-True ($environmentRecord -ceq "VCPKG_SQLITE_PACKAGE=$($case.Expected)") "sqlite-$($case.Name)-environment-value-is-normalized"
}

$rejectedSqliteCases = @(
  [pscustomobject]@{ Name = 'wrong-triplet'; Lines = [string[]]@('sqlite3:arm64-windows 3.54.1') }
  [pscustomobject]@{ Name = 'missing-version'; Lines = [string[]]@('sqlite3:x64-windows') }
  [pscustomobject]@{ Name = 'unrecognized-package'; Lines = [string[]]@('unrecognized-package 3.54.1') }
  [pscustomobject]@{ Name = 'unknown-version'; Lines = [string[]]@('sqlite3:x64-windows latest') }
  [pscustomobject]@{ Name = 'newline-injection'; Lines = [string[]]@("sqlite3:x64-windows 3.54.1`r`nVCPKG_SQLITE_PACKAGE=untrusted") }
  [pscustomobject]@{ Name = 'multiple-output-lines'; Lines = [string[]]@('sqlite3:x64-windows 3.54.1', 'sqlite3:x64-windows 3.54.1') }
)
foreach ($case in $rejectedSqliteCases) {
  Assert-ThrowsCategory {
    ConvertTo-VcpkgSqliteIdentity -ListOutput $case.Lines
  } 'vcpkg_sqlite_identity_unverified' "sqlite-$($case.Name)-is-rejected"
}

$sqliteAssignmentMatches = [regex]::Matches($workflowText, '(?m)^\s*Add-Content \$env:GITHUB_ENV "VCPKG_SQLITE_PACKAGE=([^"]+)"')
Assert-True ($sqliteAssignmentMatches.Count -eq 1) 'sqlite-environment-is-written-once'
Assert-True ($sqliteAssignmentMatches[0].Groups[1].Value -ceq '$normalizedSqlitePackage') 'sqlite-environment-uses-normalized-value'
$inventoryModeIndex = $workflowText.LastIndexOf('if ($env:TEST_MODE -cin @("b1-package-inventory-only", "b1-dependency-audit-only")) {', $sqliteAssignmentMatches[0].Index, [StringComparison]::Ordinal)
$normalizerBeginOffset = $workflowText.IndexOf($beginMarker, [StringComparison]::Ordinal)
Assert-True ($inventoryModeIndex -ge 0 -and $inventoryModeIndex -lt $normalizerBeginOffset -and $normalizerBeginOffset -lt $sqliteAssignmentMatches[0].Index) 'sqlite-normalizer-is-scoped-to-inventory-mode'
Assert-True ($workflowText.Contains('if ($LASTEXITCODE -ne 0 -or $sqlitePackage.Count -ne 1 -or $sqlitePackage[0] -notmatch ''^sqlite3:x64-windows\s+'')')) 'existing-vcpkg-list-success-check-is-preserved'
Write-Output 'PASS test=vcpkg-sqlite-identity-synthetic accepted=3 rejected=6 failures=0'

function Write-SyntheticPE([string]$Path, [UInt16]$Machine) {
  $bytes = [byte[]]::new(128)
  $bytes[0] = 0x4d
  $bytes[1] = 0x5a
  [BitConverter]::GetBytes([int32]64).CopyTo($bytes, 0x3c)
  $bytes[64] = 0x50
  $bytes[65] = 0x45
  $bytes[66] = 0
  $bytes[67] = 0
  [BitConverter]::GetBytes($Machine).CopyTo($bytes, 68)
  [IO.File]::WriteAllBytes($Path, $bytes)
}

$tempBase = Join-Path ([IO.Path]::GetTempPath()) 'cb-bridge-inv'
$testRoot = Join-Path $tempBase ([Guid]::NewGuid().ToString('N'))
$workspace = Join-Path $testRoot 'workspace'
$binPath = Join-Path $workspace 'Packages\BridgeCore\.build\x86_64-unknown-windows-msvc\debug'
$runnerTemp = Join-Path $testRoot 'runner-temp'
$outputPath = Join-Path $runnerTemp 'inventory\inventory.json'

New-Item -ItemType Directory -Path $binPath -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $binPath 'BridgeCore_BridgeMCP.resources\FileTransfer') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $binPath 'BridgeCore_BridgeMCP.resources\LooseData') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $binPath 'Modules') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $binPath 'Unverified.resources') -Force | Out-Null
New-Item -ItemType Directory -Path $runnerTemp -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $workspace '.github\schemas') -Force | Out-Null
$testRunner = Join-Path $binPath 'BridgeMCPTests.exe'
$ordinaryExe = Join-Path $binPath 'bridge-helper.exe'
$xctestRuntime = Join-Path $binPath 'XCTest.dll'
$packageManifest = Join-Path $workspace 'Packages\BridgeCore\Package.swift'
$packageManifestDirectory = Split-Path -Parent $packageManifest
New-Item -ItemType Directory -Path $packageManifestDirectory -Force | Out-Null
$schemaInput = Join-Path $workspace '.github\schemas\mcp-2026-07-28.json'
Write-SyntheticPE $testRunner 0x8664
Write-SyntheticPE $ordinaryExe 0x8664
Write-SyntheticPE $xctestRuntime 0x8664
[IO.File]::WriteAllText((Join-Path $binPath 'BridgeCore_BridgeMCP.resources\FileTransfer\index.html'), 'synthetic resource')
[IO.File]::WriteAllText((Join-Path $binPath 'BridgeCore_BridgeMCP.resources\LooseData\extra.dat'), 'SYNTHETIC_UNDECLARED_RESOURCE_CONTENT')
[IO.File]::WriteAllText((Join-Path $binPath 'unknown-artifact.dat'), 'synthetic unknown')
[IO.File]::WriteAllText((Join-Path $binPath 'Modules\Token.swiftmodule'), 'SYNTHETIC_INTERMEDIATE_CONTENT')
[IO.File]::WriteAllText((Join-Path $binPath 'Unverified.resources\unreviewed.dat'), 'SYNTHETIC_UNVERIFIED_RESOURCE_CONTENT')
[IO.File]::WriteAllText($packageManifest, @'
import PackageDescription
let package = Package(
  name: "BridgeCore",
  targets: [
    .target(
      name: "BridgeMCP",
      dependencies: [],
      resources: [.copy("Resources/FileTransfer")]
    ),
    .testTarget(
      name: "BridgeMCPTests",
      dependencies: ["BridgeMCP"]
    )
  ]
)
'@)
[IO.File]::WriteAllText($schemaInput, '{"protocolVersion":"2026-07-28","synthetic":true}')
$syntheticSchemaHash = (Get-FileHash -LiteralPath $schemaInput -Algorithm SHA256).Hash.ToLowerInvariant()

$commit = 'af7a9401d1b4cbc57a62b2343342b774cc3dc55f'
$identity = @{
  WorkspaceRoot = $workspace
  BinPath = $binPath
  PeImportsProvider = { param($path) @('KERNEL32.dll', 'swiftCore.dll') }
  SchemaExpectedSha256 = $syntheticSchemaHash
  RunnerTemp = $runnerTemp
  OutputPath = $outputPath
  SourceCommit = $commit
  WorkflowRunId = '42256950217'
  SwiftVersion = '6.3.3'
  SwiftToolchainPathId = 'a' * 64
  SwiftInstallerSha256 = 'b' * 64
  VcpkgRevision = 'c' * 40
  VcpkgSqlitePackage = 'sqlite3:x64-windows 3.50.4#1'
  MsvcVersion = '14.44.35207'
  WindowsSdkVersion = '10.0.26100.0'
  WindowsRunnerImage = 'windows-2025'
  BridgeCoreLockSha256 = 'd' * 64
  McpSdkLockSha256 = 'e' * 64
  TargetTriple = 'x86_64-unknown-windows-msvc'
  BuildConfiguration = 'debug'
  BuildTests = $true
  ReleaseBinPath = (Join-Path $workspace 'Packages\BridgeCore\.build\synthetic-release-bin')
  BaseBuildArgumentsSha256 = '1' * 64
  CompileArgumentsSha256 = '2' * 64
  DebugBinPathQueryArgumentsSha256 = '3' * 64
  ReleaseBinPathQueryArgumentsSha256 = '4' * 64
}
$created = New-CodexBridgeBuildInventory @identity
$manifestJson = Get-Content -LiteralPath $outputPath -Raw
$manifest = $manifestJson | ConvertFrom-Json
$excludedFixturePaths = @(
  (Join-Path $binPath 'Modules\Token.swiftmodule'),
  (Join-Path $binPath 'unknown-artifact.dat'),
  (Join-Path $binPath 'Unverified.resources\unreviewed.dat'),
  (Join-Path $binPath 'BridgeCore_BridgeMCP.resources\LooseData\extra.dat')
)
$excludedFixtureHashes = @($excludedFixturePaths | ForEach-Object { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() })
$schemaOutputPath = Join-Path (Split-Path -Parent $outputPath) 'mcp-2026-07-28.json'
$sumsPath = Join-Path (Split-Path -Parent $outputPath) 'SHA256SUMS.txt'
$sumsShaPath = "$sumsPath.sha256"
$sumsContent = Get-Content -LiteralPath $sumsPath -Raw
$sumsShaContent = Get-Content -LiteralPath $sumsShaPath -Raw
Assert-True ($created.created -eq $true) 'inventory-created'
Assert-True ($manifest.sourceCommit -ceq $commit) 'source-commit-recorded'
Assert-True ($manifest.workflowRunId -ceq '42256950217') 'workflow-run-recorded'
Assert-True ($manifest.toolchain.swiftVersion -ceq '6.3.3') 'swift-version-recorded'
Assert-True ($manifest.toolchain.installerSha256 -ceq ('b' * 64)) 'toolchain-installer-hash-recorded'
Assert-True ($manifest.windowsBuildEnvironment.vcpkgRevision -ceq ('c' * 40)) 'vcpkg-revision-recorded'
Assert-True ($manifest.swiftpmLocks.bridgeCorePackageResolvedSha256 -ceq ('d' * 64)) 'bridgecore-lock-hash-recorded'
Assert-True ($manifest.swiftpmLocks.vendoredMcpSdkPackageResolvedSha256 -ceq ('e' * 64)) 'mcp-sdk-lock-hash-recorded'
Assert-True ($manifest.protocolSchema.protocolVersion -ceq '2026-07-28') 'schema-version-recorded'
Assert-True ($manifest.protocolSchema.sha256 -ceq $syntheticSchemaHash) 'schema-hash-recorded'
Assert-True ($manifest.inventoryScope -ceq 'SCOPED_RUNTIME_CANDIDATES') 'inventory-scope-is-explicit'
Assert-True ($manifest.coverageStatus -ceq 'COVERAGE_UNRESOLVED') 'coverage-is-not-claimed-complete'
Assert-True ($manifest.runtimeDependencyClosure -ceq 'NOT_VERIFIED') 'runtime-dependency-closure-is-not-claimed'
Assert-True ($manifest.candidateFiles.Count -eq 4) 'only-scoped-runtime-candidates-are-inventoried'
Assert-True ($manifest.outOfScopeFileCount -eq 4) 'out-of-scope-files-are-counted-only'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.sha256 -notmatch '^[0-9a-f]{64}$' }).Count -eq 0) 'scoped-candidates-have-hashes'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.extension -in @('.exe', '.dll') -and ($_.fileType -notin @('candidate-xctest-runner', 'ordinary-exe', 'dll') -or $_.peMachine -cne 'AMD64') }).Count -eq 0) 'pe-candidates-are-x64'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.extension -eq '.exe' -and $_.imports -notcontains 'swiftcore.dll' }).Count -eq 0) 'pe-imports-inventoried'
Assert-True ($manifest.packageEligible -eq $false) 'inventory-never-claims-package-ready'
Assert-True ($manifest.testPackageStatus -ceq 'NOT_CREATED') 'test-package-remains-not-created'
Assert-True ($manifest.executableClassification -ceq 'UNRESOLVED') 'executable-classification-remains-unresolved'
Assert-True ($manifest.gateB1Status -ceq 'NOT_PASSED') 'gate-b1-remains-not-passed'
Assert-True ($manifest.buildPath.configuration -ceq 'debug') 'debug-configuration-recorded'
Assert-True ($manifest.buildPath.targetTriple -ceq 'x86_64-unknown-windows-msvc') 'target-triple-recorded'
Assert-True ($manifest.buildPath.debugBinPathQueryArgumentsSha256 -ceq ('3' * 64)) 'debug-binpath-query-arguments-recorded'
Assert-True ($manifest.buildPath.releaseBinPathQueryArgumentsSha256 -ceq ('4' * 64)) 'release-binpath-query-arguments-recorded'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.fileType -ceq 'candidate-xctest-runner' }).Count -eq 1) 'test-target-match-is-only-a-runner-candidate'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.path -ceq 'bridge-helper.exe' -and $_.fileType -ceq 'ordinary-exe' }).Count -eq 1) 'ordinary-exe-is-not-test-runner'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.path -ceq 'XCTest.dll' -and $_.fileType -ceq 'dll' }).Count -eq 1) 'dll-has-independent-category'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.path -ceq 'BridgeCore_BridgeMCP.resources/FileTransfer/index.html' -and $_.fileType -ceq 'resource' }).Count -eq 1) 'manifest-declared-test-dependency-resource-is-classified'
Assert-True (@($manifest.declaredTestResourceBundles | Where-Object { $_.bundleName -ceq 'BridgeCore_BridgeMCP.resources' -and $_.resourceEntry -ceq 'FileTransfer' }).Count -eq 1) 'resource-bundle-evidence-includes-declared-copy-root'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.path -match 'Token\.swiftmodule$' -or $_.path -ceq 'unknown-artifact.dat' -or $_.path -match 'Unverified\.resources' }).Count -eq 0) 'out-of-scope-files-have-no-paths'
Assert-True (-not $manifestJson.Contains('SYNTHETIC_INTERMEDIATE_CONTENT')) 'intermediate-content-is-not-serialized'
Assert-True (-not $manifestJson.Contains('SYNTHETIC_UNVERIFIED_RESOURCE_CONTENT')) 'unverified-resource-content-is-not-serialized'
Assert-True (-not $manifestJson.Contains('SYNTHETIC_UNDECLARED_RESOURCE_CONTENT')) 'undeclared-subtree-content-is-not-serialized'
Assert-True (-not $manifestJson.Contains('unknown-artifact.dat')) 'out-of-scope-filename-is-not-serialized'
Assert-True (-not $manifestJson.Contains('Token.swiftmodule')) 'intermediate-filename-is-not-serialized'
Assert-True (-not $manifestJson.Contains('Unverified.resources')) 'unverified-resource-path-is-not-serialized'
Assert-True (-not $manifestJson.Contains('LooseData')) 'undeclared-resource-subtree-path-is-not-serialized'
Assert-True (@($excludedFixtureHashes | Where-Object { $manifestJson.Contains($_) }).Count -eq 0) 'out-of-scope-sha256-values-are-not-serialized'
Assert-True ($manifest.totalSizeBytes -eq [long](($manifest.candidateFiles | Measure-Object -Property sizeBytes -Sum).Sum)) 'size-total-covers-only-scoped-candidates'
Assert-True (-not $manifestJson.Contains($testRoot)) 'absolute-host-path-not-recorded'
Assert-True ((Get-FileHash -LiteralPath $schemaOutputPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $syntheticSchemaHash) 'schema-is-copied-byte-exact'
Assert-True ($sumsContent.Contains("$($created.manifestSha256)  inventory.json")) 'manifest-hash-in-sums'
Assert-True ($sumsContent.Contains("$syntheticSchemaHash  mcp-2026-07-28.json")) 'schema-hash-in-sums'
Assert-True ($sumsShaContent.Trim() -ceq "$($created.sumsSha256)  SHA256SUMS.txt") 'sums-sidecar-matches-file-hash'
Assert-True ($created.sumsChecksumFileSha256 -ceq (Get-FileHash -LiteralPath $sumsShaPath -Algorithm SHA256).Hash.ToLowerInvariant()) 'sums-sidecar-hash-recorded'
$artifactNames = @(Get-ChildItem -LiteralPath (Split-Path -Parent $outputPath) -File | Select-Object -ExpandProperty Name)
$expectedArtifactNames = @('inventory.json', 'mcp-2026-07-28.json', 'SHA256SUMS.txt', 'SHA256SUMS.txt.sha256')
$artifactNameDifferences = @(Compare-Object -ReferenceObject $expectedArtifactNames -DifferenceObject $artifactNames -CaseSensitive)
Assert-True ($artifactNames.Count -eq 4 -and $artifactNameDifferences.Count -eq 0) 'artifact-directory-remains-four-file-whitelist'
$actualPackageManifest = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\Packages\BridgeCore\Package.swift'))
$inventoryModule = Get-Module McpSwiftBuildInventory
$actualResourceEvidence = @(& $inventoryModule { param($path) Get-CodexBridgeDeclaredTestResourceBundles $path } $actualPackageManifest)
Assert-True (@($actualResourceEvidence | Where-Object { $_.bundleName -ceq 'BridgeCore_BridgeMCP.resources' -and $_.resourceEntry -ceq 'FileTransfer' -and $_.targetName -ceq 'BridgeMCP' }).Count -eq 1) 'actual-package-manifest-supports-resource-candidate'
Write-Output 'PASS test=inventory-captures-relative-file-hashes'

Assert-ThrowsCategory {
  $invalidBinPath = $identity.Clone()
  $invalidBinPath.BinPath = $runnerTemp
  New-CodexBridgeBuildInventory @invalidBinPath
} 'inventory_bin_path_outside_package_build' 'binpath-outside-package-build-is-rejected'
Write-Output 'PASS test=inventory-rejects-path-outside-package-build'

$junctionPath = Join-Path $binPath 'redirect.resources'
$junctionTarget = Join-Path $workspace 'junction-target'
New-Item -ItemType Directory -Path $junctionTarget -Force | Out-Null
$junctionCreated = $false
try {
  New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget -ErrorAction Stop | Out-Null
  $junctionCreated = $true
} catch {
  Write-Output 'NOT_TESTED test=inventory-reparse-point-rejection reason=junction_creation_unavailable'
}
if ($junctionCreated) {
  try {
    Assert-ThrowsCategory {
      $junctionIdentity = $identity.Clone()
      $junctionIdentity.OutputPath = Join-Path $runnerTemp 'inventory-junction\inventory.json'
      New-CodexBridgeBuildInventory @junctionIdentity
    } 'inventory_reparse_point_not_allowed' 'junction-inside-binpath-is-rejected'
    Write-Output 'PASS test=inventory-rejects-junction-inside-binpath'
  } finally {
    $junctionItem = Get-Item -LiteralPath $junctionPath -Force -ErrorAction SilentlyContinue
    if ($junctionItem -and ($junctionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Remove-Item -LiteralPath $junctionPath -Force -ErrorAction Stop
    }
  }
}

$symbolicLinkTarget = Join-Path $binPath 'synthetic-link-target.bin'
$symbolicLinkPath = Join-Path $binPath 'synthetic-link-alias.bin'
[IO.File]::WriteAllText($symbolicLinkTarget, 'synthetic symlink target')
$symbolicLinkCreated = $false
try {
  New-Item -ItemType SymbolicLink -Path $symbolicLinkPath -Target $symbolicLinkTarget -ErrorAction Stop | Out-Null
  $symbolicLinkCreated = $true
} catch {
  Write-Output 'NOT_TESTED test=inventory-file-symlink-rejection reason=creation_not_permitted'
}
if ($symbolicLinkCreated) {
  try {
    $symbolicLinkIdentity = $identity.Clone()
    $symbolicLinkIdentity.OutputPath = Join-Path $runnerTemp 'inventory-file-symlink\inventory.json'
    Assert-ThrowsCategory {
      New-CodexBridgeBuildInventory @symbolicLinkIdentity
    } 'inventory_reparse_point_not_allowed' 'file-symbolic-link-is-rejected-before-inventory'
    Assert-True (-not (Test-Path -LiteralPath $symbolicLinkIdentity.OutputPath -PathType Leaf)) 'file-symbolic-link-does-not-create-manifest'
    Write-Output 'PASS test=inventory-rejects-file-symbolic-link'
  } finally {
    $symbolicLinkItem = Get-Item -LiteralPath $symbolicLinkPath -Force -ErrorAction SilentlyContinue
    if ($symbolicLinkItem -and ($symbolicLinkItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Remove-Item -LiteralPath $symbolicLinkPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $symbolicLinkTarget -PathType Leaf) {
      Remove-Item -LiteralPath $symbolicLinkTarget -Force -ErrorAction Stop
    }
  }
} elseif (Test-Path -LiteralPath $symbolicLinkTarget -PathType Leaf) {
  Remove-Item -LiteralPath $symbolicLinkTarget -Force -ErrorAction Stop
}

Assert-ThrowsCategory {
  $wrongConfiguration = $identity.Clone()
  $wrongConfiguration.BuildConfiguration = 'release'
  New-CodexBridgeBuildInventory @wrongConfiguration
} 'inventory_build_configuration_invalid' 'release-configuration-is-rejected'
Write-Output 'PASS test=inventory-rejects-release-binpath-query'

Assert-ThrowsCategory {
  $wrongTarget = $identity.Clone()
  $wrongTarget.TargetTriple = 'aarch64-unknown-windows-msvc'
  New-CodexBridgeBuildInventory @wrongTarget
} 'inventory_target_triple_invalid' 'arm64-output-is-rejected'
Write-Output 'PASS test=inventory-rejects-arm64-output'

Assert-ThrowsCategory {
  $sameDebugAndRelease = $identity.Clone()
  $sameDebugAndRelease.ReleaseBinPath = $sameDebugAndRelease.BinPath
  New-CodexBridgeBuildInventory @sameDebugAndRelease
} 'inventory_debug_release_binpath_ambiguous' 'same-debug-and-release-binpath-is-rejected'
Write-Output 'PASS test=inventory-rejects-ambiguous-configuration-paths'

Assert-ThrowsCategory {
  $missingDumpbin = $identity.Clone()
  $missingDumpbin.PeImportsProvider = $null
  $missingDumpbin.DumpbinPath = Join-Path $testRoot 'missing-dumpbin.exe'
  New-CodexBridgeBuildInventory @missingDumpbin
} 'inventory_dumpbin_unavailable' 'missing-dumpbin-is-rejected'
Write-Output 'PASS test=inventory-rejects-missing-dumpbin'

$failedDumpbin = Join-Path $testRoot 'dumpbin-fail.cmd'
[IO.File]::WriteAllText($failedDumpbin, "@echo Image has the following dependencies:`r`n@exit /b 23`r`n")
Assert-ThrowsCategory {
  $dumpbinFailure = $identity.Clone()
  $dumpbinFailure.PeImportsProvider = $null
  $dumpbinFailure.DumpbinPath = $failedDumpbin
  New-CodexBridgeBuildInventory @dumpbinFailure
} 'inventory_dumpbin_failed' 'nonzero-dumpbin-is-rejected'
Write-Output 'PASS test=inventory-rejects-dumpbin-failure'

$syntheticSensitiveContent = 'SYNTHETIC_SECRET_SENTINEL_MUST_NOT_ENTER_MANIFEST'
$sensitivePathCases = @(
  [pscustomobject]@{ RelativePath = 'runtime-key.json'; Classification = 'runtime_key_keyword'; EntryType = 'file' }
  [pscustomobject]@{ RelativePath = 'Token.resource'; Classification = 'token_keyword'; EntryType = 'file' }
  [pscustomobject]@{ RelativePath = 'opaque-cookie.blob'; Classification = 'cookie_keyword'; EntryType = 'file' }
  [pscustomobject]@{ RelativePath = 'API_KEY.cache'; Classification = 'api_key_keyword'; EntryType = 'file' }
  [pscustomobject]@{ RelativePath = 'Api-Key.cache'; Classification = 'api_key_keyword'; EntryType = 'file' }
  [pscustomobject]@{ RelativePath = 'Api.Key.cache'; Classification = 'api_key_keyword'; EntryType = 'file' }
  [pscustomobject]@{ RelativePath = 'apikey.cache'; Classification = 'api_key_keyword'; EntryType = 'file' }
  [pscustomobject]@{ RelativePath = 'nested\Runtime_Key'; Classification = 'runtime_key_keyword'; EntryType = 'file' }
  [pscustomobject]@{ RelativePath = 'nested/Secret'; Classification = 'secret_keyword'; EntryType = 'file' }
)
foreach ($case in $sensitivePathCases) {
  $failureMessage = Assert-SensitiveInventoryPathBlocked `
    -BaseIdentity $identity `
    -RelativePath $case.RelativePath `
    -ExpectedClassification $case.Classification `
    -ExpectedEntryType $case.EntryType `
    -Sentinel $syntheticSensitiveContent
}
Assert-True (-not $manifestJson.Contains($syntheticSensitiveContent)) 'sensitive-content-never-enters-completed-manifest'
Write-Output 'PASS test=sensitive-path-cases executed=9 failures=0'

$binPrefix = [IO.Path]::GetFullPath($binPath).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$runnerPrefix = [IO.Path]::GetFullPath($runnerTemp).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$nonSeparatorCaseId = [Guid]::NewGuid().ToString('N')
$nonSeparatorRoot = Join-Path $binPath "synthetic-name-$nonSeparatorCaseId"
$nonSeparatorFile = Join-Path $nonSeparatorRoot 'apiXkey.swiftmodule'
$nonSeparatorSentinel = 'SYNTHETIC_NONCREDENTIAL_MODULE_CONTENT'
$nonSeparatorOutputDirectory = Join-Path $runnerTemp "inventory-name-$nonSeparatorCaseId"
$nonSeparatorIdentity = $identity.Clone()
$nonSeparatorIdentity.OutputPath = Join-Path $nonSeparatorOutputDirectory 'inventory.json'
$nonSeparatorRootFull = [IO.Path]::GetFullPath($nonSeparatorRoot)
$nonSeparatorOutputFull = [IO.Path]::GetFullPath($nonSeparatorOutputDirectory)
if (-not $nonSeparatorRootFull.StartsWith($binPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not $nonSeparatorOutputFull.StartsWith($runnerPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'test_nonseparator_case_path_outside_owned_roots'
}
try {
  New-Item -ItemType Directory -Path $nonSeparatorRootFull -Force | Out-Null
  [IO.File]::WriteAllText($nonSeparatorFile, $nonSeparatorSentinel)
  $nonSeparatorResult = New-CodexBridgeBuildInventory @nonSeparatorIdentity
  $nonSeparatorManifest = Get-Content -LiteralPath $nonSeparatorIdentity.OutputPath -Raw | ConvertFrom-Json
  Assert-True ($nonSeparatorResult.created -eq $true) 'nonseparator-api-key-like-name-is-not-treated-as-sensitive-keyword'
  Assert-True (@($nonSeparatorManifest.candidateFiles | Where-Object { $_.path -match 'apiXkey\.swiftmodule$' }).Count -eq 0) 'neutral-swiftmodule-name-remains-out-of-scope'
  Assert-True ($nonSeparatorManifest.outOfScopeFileCount -ge 1) 'neutral-name-does-not-promote-file-into-inventory'
  Assert-True (-not (Get-Content -LiteralPath $nonSeparatorIdentity.OutputPath -Raw).Contains($nonSeparatorSentinel)) 'nonseparator-file-content-is-not-serialized'
  Assert-True (-not (Get-Content -LiteralPath $nonSeparatorIdentity.OutputPath -Raw).Contains('apiXkey.swiftmodule')) 'neutral-name-and-hash-are-not-in-manifest'
  Write-Output 'PASS test=neutral-rename-remains-out-of-scope'
} finally {
  if (Test-Path -LiteralPath $nonSeparatorRootFull) { Remove-Item -LiteralPath $nonSeparatorRootFull -Recurse -Force -ErrorAction Stop }
  if (Test-Path -LiteralPath $nonSeparatorOutputFull -PathType Container) { Remove-Item -LiteralPath $nonSeparatorOutputFull -Recurse -Force -ErrorAction Stop }
}

$unknownPePath = Join-Path $binPath 'unclassified-payload.bin'
$unknownPeOutput = Join-Path $runnerTemp 'unknown-pe\inventory.json'
try {
  Write-SyntheticPE $unknownPePath 0x8664
  $unknownPeIdentity = $identity.Clone()
  $unknownPeIdentity.OutputPath = $unknownPeOutput
  $unknownPeFailureMessage = $null
  try { New-CodexBridgeBuildInventory @unknownPeIdentity | Out-Null } catch { $unknownPeFailureMessage = $_.Exception.Message }
  Assert-True ($null -ne $unknownPeFailureMessage -and $unknownPeFailureMessage.Contains('inventory_pe_file_type_unclassified')) 'unknown-pe-is-not-silently-omitted'
  Assert-True (-not $unknownPeFailureMessage.Contains('unclassified-payload.bin')) 'unknown-pe-error-does-not-reveal-filename'
  Assert-True (-not (Test-Path -LiteralPath $unknownPeOutput -PathType Leaf)) 'unknown-pe-does-not-create-manifest'
  Write-Output 'PASS test=inventory-rejects-unknown-pe-type'
} finally {
  if (Test-Path -LiteralPath $unknownPePath -PathType Leaf) { Remove-Item -LiteralPath $unknownPePath -Force -ErrorAction Stop }
}

$renameCaseId = [Guid]::NewGuid().ToString('N')
$renameRoot = Join-Path $binPath "synthetic-rename-$renameCaseId"
$renameRootFull = [IO.Path]::GetFullPath($renameRoot)
$renamedFile = Join-Path $renameRoot 'renamed.bin'
$renamedSentinel = 'SYNTHETIC_RENAMED_CONTENT_MUST_NOT_ENTER_MANIFEST'
$renameOutputDirectory = Join-Path $runnerTemp "inventory-renamed-$renameCaseId"
$renamedIdentity = $identity.Clone()
$renamedIdentity.OutputPath = Join-Path $renameOutputDirectory 'inventory.json'
if (-not $renameRootFull.StartsWith($binPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not [IO.Path]::GetFullPath($renameOutputDirectory).StartsWith($runnerPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'test_rename_case_path_outside_owned_roots'
}
try {
  New-Item -ItemType Directory -Path $renameRootFull -Force | Out-Null
  [IO.File]::WriteAllText($renamedFile, $renamedSentinel)
  $renamedResult = New-CodexBridgeBuildInventory @renamedIdentity
  $renamedManifestJson = Get-Content -LiteralPath $renamedIdentity.OutputPath -Raw
  $renamedManifest = $renamedManifestJson | ConvertFrom-Json
  Assert-True ($renamedResult.created -eq $true) 'scoped-inventory-created-with-out-of-scope-file'
  Assert-True ($renamedManifest.inventoryScope -ceq 'SCOPED_RUNTIME_CANDIDATES') 'neutral-rename-does-not-change-inventory-scope'
  Assert-True (@($renamedManifest.candidateFiles | Where-Object { $_.path -ceq 'renamed.bin' }).Count -eq 0) 'neutral-rename-does-not-enter-candidate-list'
  Assert-True ($renamedManifest.outOfScopeFileCount -ge 1) 'neutral-rename-is-represented-only-by-aggregate-count'
  Assert-True (-not $renamedManifestJson.Contains($renamedSentinel)) 'renamed-sensitive-content-is-not-serialized'
  Assert-True (-not $renamedManifestJson.Contains('renamed.bin')) 'neutral-rename-filename-and-hash-are-not-serialized'
  Write-Output 'PASS test=neutral-rename-remains-out-of-scope-content-not-inspected'
} finally {
  if (Test-Path -LiteralPath $renameRootFull) {
    Remove-Item -LiteralPath $renameRootFull -Recurse -Force -ErrorAction Stop
  }
  if (Test-Path -LiteralPath $renameOutputDirectory -PathType Container) {
    Remove-Item -LiteralPath $renameOutputDirectory -Recurse -Force -ErrorAction Stop
  }
}

$wrongSchema = $identity.Clone()
$wrongSchema.OutputPath = Join-Path $runnerTemp 'schema-mismatch\inventory.json'
$wrongSchema.SchemaExpectedSha256 = 'f' * 64
Assert-ThrowsCategory {
  New-CodexBridgeBuildInventory @wrongSchema
} 'inventory_fixed_schema_sha256_mismatch' 'fixed-schema-hash-is-enforced'
Write-Output 'PASS test=inventory-rejects-unpinned-schema-hash'

$wrongMachine = $identity.Clone()
$wrongMachine.OutputPath = Join-Path $runnerTemp 'inventory-arm64\inventory.json'
Write-SyntheticPE $testRunner 0xaa64
Assert-ThrowsCategory {
  New-CodexBridgeBuildInventory @wrongMachine
} 'inventory_pe_architecture_mismatch' 'wrong-architecture-is-identified-without-execution'
Write-Output 'PASS test=inventory-identifies-non-x64-pe-without-execution'

$resolvedRoot = [IO.Path]::GetFullPath($testRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$resolvedBase = [IO.Path]::GetFullPath($tempBase).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $resolvedRoot.StartsWith($resolvedBase, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'test_cleanup_path_outside_owned_temp_root'
}
Remove-Item -LiteralPath $testRoot -Recurse -Force
$executed = 20 + [int]$junctionCreated + [int]$symbolicLinkCreated
Write-Output "PASS test=package-inventory-synthetic-summary executed=$executed failures=0"
