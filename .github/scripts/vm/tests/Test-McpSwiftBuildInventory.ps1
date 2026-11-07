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

$tempBase = Join-Path ([IO.Path]::GetTempPath()) 'codex-bridge-package-inventory-tests'
$testRoot = Join-Path $tempBase ([Guid]::NewGuid().ToString('N'))
$workspace = Join-Path $testRoot 'workspace'
$binPath = Join-Path $workspace 'Packages\BridgeCore\.build\x86_64-unknown-windows-msvc\debug'
$runnerTemp = Join-Path $testRoot 'runner-temp'
$outputPath = Join-Path $runnerTemp 'inventory\inventory.json'

New-Item -ItemType Directory -Path $binPath -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $binPath 'BridgeMCP.resources\FileTransfer') -Force | Out-Null
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
[IO.File]::WriteAllText((Join-Path $binPath 'BridgeMCP.resources\FileTransfer\index.html'), 'synthetic resource')
[IO.File]::WriteAllText((Join-Path $binPath 'unknown-artifact.dat'), 'synthetic unknown')
[IO.File]::WriteAllText($packageManifest, @'
import PackageDescription
let package = Package(name: "BridgeCore", targets: [
  .testTarget(name: "BridgeMCPTests", dependencies: [])
])
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
Assert-True ($manifest.candidateFiles.Count -eq 5) 'all-binpath-files-inventoried'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.sha256 -notmatch '^[0-9a-f]{64}$' }).Count -eq 0) 'all-files-hashed'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.extension -in @('.exe', '.dll') -and ($_.fileType -notin @('candidate-xctest-runner', 'ordinary-exe', 'dll') -or $_.peMachine -cne 'AMD64') }).Count -eq 0) 'pe-candidates-are-x64'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.extension -eq '.exe' -and $_.imports -notcontains 'swiftcore.dll' }).Count -eq 0) 'pe-imports-inventoried'
Assert-True ($manifest.packageEligible -eq $false) 'inventory-never-claims-package-ready'
Assert-True ($manifest.executableClassification -ceq 'UNRESOLVED') 'executable-classification-remains-unresolved'
Assert-True ($manifest.buildPath.configuration -ceq 'debug') 'debug-configuration-recorded'
Assert-True ($manifest.buildPath.targetTriple -ceq 'x86_64-unknown-windows-msvc') 'target-triple-recorded'
Assert-True ($manifest.buildPath.debugBinPathQueryArgumentsSha256 -ceq ('3' * 64)) 'debug-binpath-query-arguments-recorded'
Assert-True ($manifest.buildPath.releaseBinPathQueryArgumentsSha256 -ceq ('4' * 64)) 'release-binpath-query-arguments-recorded'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.fileType -ceq 'candidate-xctest-runner' }).Count -eq 1) 'test-target-match-is-only-a-runner-candidate'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.path -ceq 'bridge-helper.exe' -and $_.fileType -ceq 'ordinary-exe' }).Count -eq 1) 'ordinary-exe-is-not-test-runner'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.path -ceq 'XCTest.dll' -and $_.fileType -ceq 'dll' }).Count -eq 1) 'dll-has-independent-category'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.path -match '\.resources/' -and $_.fileType -ceq 'resource' }).Count -eq 1) 'resource-bundle-file-is-classified'
Assert-True (@($manifest.candidateFiles | Where-Object { $_.path -ceq 'unknown-artifact.dat' -and $_.fileType -ceq 'unclassified' }).Count -eq 1) 'unknown-file-is-unclassified'
Assert-True (-not $manifestJson.Contains($testRoot)) 'absolute-host-path-not-recorded'
Assert-True ((Get-FileHash -LiteralPath $schemaOutputPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $syntheticSchemaHash) 'schema-is-copied-byte-exact'
Assert-True ($sumsContent.Contains("$($created.manifestSha256)  inventory.json")) 'manifest-hash-in-sums'
Assert-True ($sumsContent.Contains("$syntheticSchemaHash  mcp-2026-07-28.json")) 'schema-hash-in-sums'
Assert-True ($sumsShaContent.Trim() -ceq "$($created.sumsSha256)  SHA256SUMS.txt") 'sums-sidecar-matches-file-hash'
Assert-True ($created.sumsChecksumFileSha256 -ceq (Get-FileHash -LiteralPath $sumsShaPath -Algorithm SHA256).Hash.ToLowerInvariant()) 'sums-sidecar-hash-recorded'
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

$sensitiveName = Join-Path $binPath 'runtime-key-material.txt'
[IO.File]::WriteAllText($sensitiveName, 'synthetic name only')
Assert-ThrowsCategory {
  $invalidNames = $identity.Clone()
  $invalidNames.OutputPath = Join-Path $runnerTemp 'inventory-sensitive\inventory.json'
  New-CodexBridgeBuildInventory @invalidNames
} 'inventory_sensitive_filename_blocked' 'sensitive-looking-path-is-rejected'
Write-Output 'PASS test=inventory-rejects-sensitive-looking-filename'
Remove-Item -LiteralPath $sensitiveName -Force

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
$executed = if ($junctionCreated) { 11 } else { 10 }
Write-Output "PASS test=package-inventory-synthetic-summary executed=$executed failures=0"
