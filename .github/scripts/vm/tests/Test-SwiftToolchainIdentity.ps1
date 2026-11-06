$ErrorActionPreference = 'Stop'

$scriptsRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$modulePath = Join-Path $scriptsRoot 'SwiftToolchainIdentity.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
  throw 'assertion_failed_swift_toolchain_identity_module_missing'
}
Import-Module $modulePath -Force

$script:executed = 0
$script:failures = 0

function Assert-Equal($Actual, $Expected, [string]$Name) {
  $script:executed++
  if ($Actual -cne $Expected) {
    $script:failures++
    throw "assertion_failed_$Name"
  }
  Write-Output "PASS test=$Name"
}

$standard = Get-SwiftToolchainVersionAssessment `
  -ExitCode 0 `
  -Output @('Swift version 6.3.3 (swift-6.3.3-RELEASE)', 'Target: x86_64-unknown-windows-msvc') `
  -ToolchainVariant '6.3.3'
Assert-Equal $standard.status 'PASS' 'official_swift_633_output_passes'
Assert-Equal $standard.detectedVersion '6.3.3' 'standard_version_is_reported'

$asserts = Get-SwiftToolchainVersionAssessment `
  -ExitCode 0 `
  -Output @('swift-driver version: 1.136.3', 'Apple Swift version 6.3.3+Asserts (swift-6.3.3-RELEASE)') `
  -ToolchainVariant '6.3.3+Asserts'
Assert-Equal $asserts.status 'PASS' 'official_swift_633_asserts_variant_passes'
Assert-Equal $asserts.detectedVersion '6.3.3+Asserts' 'asserts_version_is_reported'

$assertsWithoutSuffix = Get-SwiftToolchainVersionAssessment `
  -ExitCode 0 `
  -Output @('Swift version 6.3.3 (swift-6.3.3-RELEASE, +Asserts)') `
  -ToolchainVariant '6.3.3+Asserts'
Assert-Equal $assertsWithoutSuffix.status 'PASS' 'asserts_toolchain_accepts_base_version_banner'

$nonzero = Get-SwiftToolchainVersionAssessment `
  -ExitCode 7 `
  -Output @('Swift version 6.3.3 (swift-6.3.3-RELEASE)') `
  -ToolchainVariant '6.3.3'
Assert-Equal $nonzero.status 'SWIFT_EXECUTION_FAILED' 'nonzero_exit_fails'
Assert-Equal $nonzero.detectedVersion '6.3.3' 'nonzero_exit_keeps_safe_version_diagnostic'

$wrongVersion = Get-SwiftToolchainVersionAssessment `
  -ExitCode 0 `
  -Output @('Swift version 6.3.2 (swift-6.3.2-RELEASE)') `
  -ToolchainVariant '6.3.2'
Assert-Equal $wrongVersion.status 'SWIFT_VERSION_MISMATCH' 'wrong_version_fails'

$prerelease = Get-SwiftToolchainVersionAssessment `
  -ExitCode 0 `
  -Output @('Swift version 6.3.3-dev (swift-6.3.3-DEV)') `
  -ToolchainVariant '6.3.3'
Assert-Equal $prerelease.status 'SWIFT_VERSION_MISMATCH' 'prerelease_version_fails'

$empty = Get-SwiftToolchainVersionAssessment -ExitCode 0 -Output @() -ToolchainVariant '6.3.3'
Assert-Equal $empty.status 'SWIFT_OUTPUT_UNRECOGNIZED' 'empty_output_fails'
Assert-Equal $empty.detectedVersion 'unrecognized' 'empty_output_diagnostic_is_bounded'

$unrecognized = Get-SwiftToolchainVersionAssessment `
  -ExitCode 0 `
  -Output @('swift-driver version: 1.136.3', 'Target: x86_64-unknown-windows-msvc') `
  -ToolchainVariant '6.3.3'
Assert-Equal $unrecognized.status 'SWIFT_OUTPUT_UNRECOGNIZED' 'missing_swift_version_line_fails'

$unknownVariant = Get-SwiftToolchainVersionAssessment `
  -ExitCode 0 `
  -Output @('Swift version 6.3.3 (swift-6.3.3-RELEASE)') `
  -ToolchainVariant '6.3.3+Unknown'
Assert-Equal $unknownVariant.status 'SWIFT_VERSION_MISMATCH' 'unknown_toolchain_variant_fails'

$path = 'C:\Swift\Toolchains\6.3.3+Asserts\usr\bin\swift.exe'
$pathId = Get-SwiftToolchainPathId -Path $path
$samePathId = Get-SwiftToolchainPathId -Path $path.ToUpperInvariant()
Assert-Equal ($pathId -match '^[0-9a-f]{64}$') 'True' 'path_identifier_is_sha256'
Assert-Equal $samePathId $pathId 'path_identifier_is_case_insensitive'
Assert-Equal ($pathId.Contains('C:\')) $false 'path_identifier_does_not_reveal_path'

$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptsRoot)
$workflowPath = Join-Path $repoRoot '.github\workflows\windows.yml'
$workflow = Get-Content -LiteralPath $workflowPath -Raw
$compileJobMarker = '  mcp-exe-compile-only:'
$compileJobStart = $workflow.IndexOf($compileJobMarker, [StringComparison]::Ordinal)
if ($compileJobStart -lt 0) { throw 'assertion_failed_compile_job_missing' }
$compileJob = $workflow.Substring($compileJobStart)
$stepMarker = '      - name: Record Swift toolchain input identity'
$stepStart = $compileJob.IndexOf($stepMarker, [StringComparison]::Ordinal)
if ($stepStart -lt 0) { throw 'assertion_failed_version_step_missing' }
$stepEnd = $compileJob.IndexOf('      - name:', $stepStart + $stepMarker.Length, [StringComparison]::Ordinal)
if ($stepEnd -lt 0) { $stepEnd = $compileJob.Length }
$versionStep = $compileJob.Substring($stepStart, $stepEnd - $stepStart)
$setup = Get-Content -LiteralPath (Join-Path $scriptsRoot 'setup-windows-swift.ps1') -Raw
$resolveStepMarker = '      - name: Resolve pinned SwiftPM dependencies'
$resolveStepStart = $compileJob.IndexOf($resolveStepMarker, [StringComparison]::Ordinal)
if ($resolveStepStart -lt 0) { throw 'assertion_failed_resolve_step_missing' }
$resolveRunStart = $compileJob.IndexOf('        run: |', $resolveStepStart, [StringComparison]::Ordinal)
$resolveStepEnd = $compileJob.IndexOf('      - name:', $resolveRunStart, [StringComparison]::Ordinal)
if ($resolveRunStart -lt 0 -or $resolveStepEnd -lt 0) { throw 'assertion_failed_resolve_step_block_missing' }
$resolveStep = $compileJob.Substring($resolveRunStart, $resolveStepEnd - $resolveRunStart)
$compileStepMarker = '      - name: Compile Swift sources and XCTest targets without running them'
$compileStepStart = $compileJob.IndexOf($compileStepMarker, [StringComparison]::Ordinal)
if ($compileStepStart -lt 0) { throw 'assertion_failed_compile_step_missing' }
$compileRunStart = $compileJob.IndexOf('        run: |', $compileStepStart, [StringComparison]::Ordinal)
$compileStepEnd = $compileJob.IndexOf('      - name:', $compileRunStart, [StringComparison]::Ordinal)
if ($compileRunStart -lt 0 -or $compileStepEnd -lt 0) { throw 'assertion_failed_compile_step_block_missing' }
$compileStep = $compileJob.Substring($compileRunStart, $compileStepEnd - $compileRunStart)
Assert-Equal $versionStep.Contains('$env:SWIFT_EXE_PATH') 'True' 'workflow_uses_installer_resolved_exe'
Assert-Equal $versionStep.Contains('ProcessStartInfo') 'True' 'workflow_launches_exact_exe'
Assert-Equal $versionStep.Contains('ReadToEndAsync') 'True' 'workflow_captures_complete_output'
Assert-Equal $versionStep.Contains('$process.ExitCode') 'True' 'workflow_uses_process_exit_code'
Assert-Equal $versionStep.Contains('WaitForExit(30000)') 'True' 'version_check_has_bounded_timeout'
Assert-Equal $versionStep.Contains('MainModule.FileName') 'True' 'timeout_cleanup_checks_process_image'
Assert-Equal $versionStep.Contains('$process.Kill()') 'True' 'timeout_cleanup_targets_owned_process_object'
Assert-Equal $versionStep.Contains('WaitForExit(5000)') 'True' 'timeout_cleanup_wait_is_bounded'
Assert-Equal $versionStep.Contains('Select-Object -First 1') $false 'workflow_does_not_truncate_output'
Assert-Equal $versionStep.Contains('$LASTEXITCODE') $false 'workflow_does_not_use_stale_exit_code'
$tryStart = $versionStep.IndexOf("          try {", [StringComparison]::Ordinal)
$pathResolution = $versionStep.IndexOf('$swiftExe = (Get-Item', [StringComparison]::Ordinal)
Assert-Equal ($pathResolution -gt $tryStart) 'True' 'path_resolution_is_classified_as_execution_failure'
Assert-Equal $versionStep.Contains('Exception.Message') $false 'workflow_does_not_emit_raw_exception_details'
$identityFailure = $versionStep.IndexOf("throw 'swift_timeout_process_identity_unverified'", [StringComparison]::Ordinal)
$killCall = $versionStep.IndexOf('$process.Kill()', [StringComparison]::Ordinal)
$identityChecks = $versionStep.Contains('$process.Id -ne $startedProcessId') -and
  $versionStep.Contains('$actualStartTimeUtcTicks -ne $startedProcessStartTimeUtcTicks') -and
  $versionStep.Contains('$actualImagePath') -and $versionStep.Contains('$expectedImagePath')
Assert-Equal ($identityChecks -and $identityFailure -ge 0 -and $killCall -gt $identityFailure) 'True' 'timeout_kill_follows_identity_check'
$broadKill = $versionStep.Contains('Stop-Process') -or $versionStep.Contains('taskkill')
Assert-Equal $broadKill $false 'timeout_cleanup_avoids_name_based_kill'
Assert-Equal $versionStep.Contains('SWIFT_TOOLCHAIN_VERIFIED_PATH_ID=$pathId') 'True' 'successful_identity_exports_path_binding'
Assert-Equal $resolveStep.Contains('$env:SWIFT_EXE_PATH') 'True' 'resolve_checks_verified_exe_path'
Assert-Equal ($resolveStep.Contains('$env:SWIFT_TOOLCHAIN_VERIFIED_VERSION -cne $env:SWIFT_VERSION') -and $resolveStep.Contains("SWIFT_VERSION -cne '6.3.3'")) 'True' 'resolve_requires_successful_version_check'
Assert-Equal ($resolveStep.Contains('$resolvePathId = Get-SwiftToolchainPathId -Path $swiftExe') -and $resolveStep.Contains('$resolvePathId -cne $env:SWIFT_TOOLCHAIN_VERIFIED_PATH_ID')) 'True' 'resolve_requires_verified_path_identity'
Assert-Equal $resolveStep.Contains('& $swiftExe package') 'True' 'resolve_invokes_verified_exe'
Assert-Equal $resolveStep.Contains('& swift package') $false 'resolve_does_not_use_path_lookup'
Assert-Equal $compileStep.Contains('$env:SWIFT_EXE_PATH') 'True' 'compile_checks_verified_exe_path'
Assert-Equal ($compileStep.Contains('$env:SWIFT_TOOLCHAIN_VERIFIED_VERSION -cne $env:SWIFT_VERSION') -and $compileStep.Contains("SWIFT_VERSION -cne '6.3.3'")) 'True' 'compile_requires_successful_version_check'
Assert-Equal ($compileStep.Contains('$compilePathId = Get-SwiftToolchainPathId -Path $swiftExe') -and $compileStep.Contains('$compilePathId -cne $env:SWIFT_TOOLCHAIN_VERIFIED_PATH_ID')) 'True' 'compile_requires_verified_path_identity'
Assert-Equal $compileStep.Contains('& $swiftExe build') 'True' 'build_invokes_verified_exe'
Assert-Equal $compileStep.Contains('& swift build') $false 'build_does_not_use_path_lookup'
Assert-Equal $compileStep.Contains('& swift --version') $false 'compile_does_not_repeat_unbound_version_check'
Assert-Equal $setup.Contains('SWIFT_EXE_PATH=$swiftExeFull') 'True' 'setup_persists_exact_exe_path'
Assert-Equal $setup.Contains('SWIFT_TOOLCHAIN_VARIANT=$toolchainVariant') 'True' 'setup_persists_toolchain_variant'
Assert-Equal $setup.Contains('found swift at $swiftExe') $false 'setup_does_not_log_raw_swift_path'

Write-Output "TEST_SUMMARY executed=$script:executed failures=$script:failures"
if ($script:failures -ne 0) { exit 1 }
