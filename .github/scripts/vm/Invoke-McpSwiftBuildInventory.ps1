$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-ArgumentListSha256([string[]]$Arguments) {
  $json = ConvertTo-Json -InputObject ([object[]]$Arguments) -Compress -Depth 3
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    return [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}

function Get-SwiftPMBinPath([string]$Configuration, [string[]]$BaseArguments, [string]$SwiftExecutable) {
  $queryArguments = @($BaseArguments) + @('-c', $Configuration, '--build-tests', '--show-bin-path')
  $output = @(& $SwiftExecutable build @queryArguments 2>&1)
  $exitCode = $LASTEXITCODE
  if ($exitCode -ne 0) {
    Write-Output "ERROR_CATEGORY=swift_show_bin_path_$Configuration exit_code=$exitCode"
    throw "swift_show_bin_path_failed_$Configuration"
  }

  $pathLines = @(
    $output |
      ForEach-Object { if ($_ -is [string]) { $_.Trim() } else { ([string]$_).Trim() } } |
      Where-Object { $_ -match '^(?:[A-Za-z]:[\\/]|\\\\)' }
  )
  if ($pathLines.Count -ne 1) { throw "swift_show_bin_path_output_unrecognized_$Configuration" }
  $fullPath = [IO.Path]::GetFullPath($pathLines[0])
  if ($Configuration -ceq 'debug') {
    if (-not (Test-Path -LiteralPath $fullPath -PathType Container)) { throw 'swift_debug_bin_path_missing' }
    $resolvedPath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $fullPath -ErrorAction Stop).Path)
    if (-not [string]::Equals($resolvedPath, $fullPath, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'swift_debug_bin_path_alias_not_allowed'
    }
  }
  return [pscustomobject]@{
    path = $fullPath
    arguments = $queryArguments
    argumentsSha256 = Get-ArgumentListSha256 (@('build') + $queryArguments)
  }
}

$head = (& git -C $env:GITHUB_WORKSPACE rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $env:SOURCE_COMMIT) {
  throw 'inventory_source_commit_changed'
}
$bridgeCoreLock = Join-Path $env:GITHUB_WORKSPACE 'Packages\BridgeCore\Package.resolved'
$mcpSdkLock = Join-Path $env:GITHUB_WORKSPACE 'Vendor\swift-sdk\Package.resolved'
$bridgeCoreLockSha256 = (Get-FileHash -LiteralPath $bridgeCoreLock -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
$mcpSdkLockSha256 = (Get-FileHash -LiteralPath $mcpSdkLock -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($bridgeCoreLockSha256 -cne $env:SWIFTPM_CORE_LOCK_SHA256 -or
    $mcpSdkLockSha256 -cne $env:SWIFTPM_SDK_LOCK_SHA256) {
  throw 'inventory_swiftpm_lock_identity_changed'
}

Import-Module "$env:GITHUB_WORKSPACE\.github\scripts\SwiftToolchainIdentity.psm1" -Force
$swiftExe = $env:SWIFT_EXE_PATH
if ([string]::IsNullOrWhiteSpace($swiftExe) -or
    -not (Test-Path -LiteralPath $swiftExe -PathType Leaf) -or
    $env:SWIFT_TOOLCHAIN_VERIFIED_VERSION -cne $env:SWIFT_VERSION -or
    $env:SWIFT_VERSION -cne '6.3.3') {
  throw 'swift_toolchain_binding_unverified'
}
$swiftExe = (Get-Item -LiteralPath $swiftExe -ErrorAction Stop).FullName
$binPathId = Get-SwiftToolchainPathId -Path $swiftExe
if ([string]::IsNullOrWhiteSpace($env:SWIFT_TOOLCHAIN_VERIFIED_PATH_ID) -or
    $binPathId -cne $env:SWIFT_TOOLCHAIN_VERIFIED_PATH_ID) {
  throw 'swift_toolchain_path_identity_changed'
}

. "$env:GITHUB_WORKSPACE\Scripts\windows-swift-arguments.ps1"
$baseArguments = @(Get-WindowsSwiftArguments `
  -VcpkgInstalledRoot "$env:VCPKG_INSTALLATION_ROOT\installed\x64-windows" `
  -TargetTriple $env:TARGET_TRIPLE `
  -LibraryPaths ($env:TARGET_LIBRARY_PATHS -split ';'))
$compileArguments = @($baseArguments) + @('-c', 'debug', '--build-tests')
$compileArgumentsSha256 = Get-ArgumentListSha256 (@('build') + $compileArguments)
if ($env:SWIFT_BUILD_ARGUMENTS_SHA256 -cne $compileArgumentsSha256) {
  throw 'inventory_compile_arguments_identity_changed'
}
$baseArgumentsSha256 = Get-ArgumentListSha256 $baseArguments
$debugBin = Get-SwiftPMBinPath -Configuration 'debug' -BaseArguments $baseArguments -SwiftExecutable $swiftExe
$releaseBin = Get-SwiftPMBinPath -Configuration 'release' -BaseArguments $baseArguments -SwiftExecutable $swiftExe
if ([string]::Equals($debugBin.path, $releaseBin.path, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'inventory_debug_release_binpath_ambiguous'
}

Import-Module "$env:GITHUB_WORKSPACE\.github\scripts\vm\McpSwiftBuildInventory.psm1" -Force
$inventoryPath = Join-Path $env:RUNNER_TEMP 'b1-package-inventory\inventory.json'
$inventory = New-CodexBridgeBuildInventory `
  -WorkspaceRoot $env:GITHUB_WORKSPACE `
  -BinPath $debugBin.path `
  -ReleaseBinPath $releaseBin.path `
  -DumpbinPath $env:MSVC_DUMPBIN_PATH `
  -RunnerTemp $env:RUNNER_TEMP `
  -OutputPath $inventoryPath `
  -SourceCommit $env:SOURCE_COMMIT `
  -WorkflowRunId $env:WORKFLOW_RUN_ID `
  -SwiftVersion $env:SWIFT_VERSION `
  -SwiftToolchainPathId $env:SWIFT_TOOLCHAIN_VERIFIED_PATH_ID `
  -SwiftInstallerSha256 $env:SWIFT_INSTALLER_SHA256 `
  -VcpkgRevision $env:VCPKG_REVISION `
  -VcpkgSqlitePackage $env:VCPKG_SQLITE_PACKAGE `
  -MsvcVersion $env:WINDOWS_MSVC_VERSION `
  -WindowsSdkVersion $env:WINDOWS_SDK_VERSION `
  -WindowsRunnerImage $env:WINDOWS_RUNNER_IMAGE `
  -BridgeCoreLockSha256 $env:SWIFTPM_CORE_LOCK_SHA256 `
  -McpSdkLockSha256 $env:SWIFTPM_SDK_LOCK_SHA256 `
  -TargetTriple $env:TARGET_TRIPLE `
  -BuildConfiguration 'debug' `
  -BuildTests $true `
  -BaseBuildArgumentsSha256 $baseArgumentsSha256 `
  -CompileArgumentsSha256 $compileArgumentsSha256 `
  -DebugBinPathQueryArgumentsSha256 $debugBin.argumentsSha256 `
  -ReleaseBinPathQueryArgumentsSha256 $releaseBin.argumentsSha256

if (-not $inventory.created -or -not $inventory.manifestComplete) {
  throw 'inventory_manifest_incomplete'
}
Write-Output "INVENTORY_MANIFEST=PASS files=$($inventory.candidateFileCount) bytes=$($inventory.totalSizeBytes) manifest_sha256=$($inventory.manifestSha256) schema_sha256=$($inventory.schemaSha256) sha256sums_sha256=$($inventory.sumsSha256) sidecar_sha256=$($inventory.sumsChecksumFileSha256)"
Add-Content -LiteralPath $env:GITHUB_OUTPUT 'inventory_created=true'
Add-Content -LiteralPath $env:GITHUB_OUTPUT 'manifest_complete=true'
Add-Content -LiteralPath $env:GITHUB_OUTPUT "manifest_sha256=$($inventory.manifestSha256)"
Add-Content -LiteralPath $env:GITHUB_OUTPUT "schema_sha256=$($inventory.schemaSha256)"
Add-Content -LiteralPath $env:GITHUB_OUTPUT "sha256sums_sha256=$($inventory.sumsSha256)"
Add-Content -LiteralPath $env:GITHUB_OUTPUT "sums_sidecar_sha256=$($inventory.sumsChecksumFileSha256)"
