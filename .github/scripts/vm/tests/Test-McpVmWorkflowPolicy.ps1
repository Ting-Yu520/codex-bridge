$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot '..\McpVmWorkflowPolicy.psm1'
Import-Module $modulePath -Force

function Assert-Equal($Actual, $Expected, [string]$Name) {
  if ($Actual -cne $Expected) { throw "assertion_failed_$Name`_actual=$Actual`_expected=$Expected" }
}

function Assert-Decision($Case) {
  $parameters = $Case.parameters
  $decision = Get-CodexBridgeWorkflowDecision @parameters
  Assert-Equal ([string]$decision.valid) ([string]$Case.valid) "$($Case.name)_valid"
  $actualJobs = @($decision.jobs | Sort-Object) -join ','
  Assert-Equal $actualJobs $Case.jobs "$($Case.name)_jobs"
  if ($Case.valid) {
    if ($Case.jobs -split ',' | Where-Object { $_ }) {
      if (($Case.jobs -split ',').Count -ne 1) { throw "assertion_failed_$($Case.name)_multiple_jobs" }
    }
  } elseif ([string]::IsNullOrWhiteSpace([string]$decision.errorCategory)) {
    throw "assertion_failed_$($Case.name)_missing_failure_category"
  }
}

$cases = @(
  @{ name = 'dispatch-standard-win-x64'; valid = $true; jobs = 'build'; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/win'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'x64' } },
  @{ name = 'dispatch-standard-win-arm64'; valid = $true; jobs = 'build'; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/win'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'arm64' } },
  @{ name = 'dispatch-standard-win-all'; valid = $true; jobs = 'build'; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/win'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'all' } },
  @{ name = 'dispatch-standard-platform-build'; valid = $true; jobs = 'build'; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/codex/platform-win-test'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'x64' } },
  @{ name = 'dispatch-standard-gate-a-x64'; valid = $true; jobs = 'mcp-route-tests'; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-route-tests-20261104'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'x64' } },
  @{ name = 'dispatch-standard-gate-b1-x64'; valid = $true; jobs = 'mcp-exe-process-tests'; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-exe-process-20261105'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'x64' } },
  @{ name = 'dispatch-compile-b1-arm64-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-exe-process-20261105'; HeadRef = ''; BaseRef = ''; TestMode = 'b1-compile-only'; Architecture = 'arm64' } },
  @{ name = 'dispatch-compile-b1-x64'; valid = $true; jobs = 'mcp-exe-compile-only'; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-exe-process-20261105'; HeadRef = ''; BaseRef = ''; TestMode = 'b1-compile-only'; Architecture = 'x64' } },
  @{ name = 'dispatch-package-inventory-b1-x64'; valid = $true; jobs = 'mcp-exe-compile-only'; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-exe-process-20261105'; HeadRef = ''; BaseRef = ''; TestMode = 'b1-package-inventory-only'; Architecture = 'x64' } },
  @{ name = 'dispatch-package-inventory-b1-arm64-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-exe-process-20261105'; HeadRef = ''; BaseRef = ''; TestMode = 'b1-package-inventory-only'; Architecture = 'arm64' } },
  @{ name = 'dispatch-package-inventory-wrong-branch-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/win'; HeadRef = ''; BaseRef = ''; TestMode = 'b1-package-inventory-only'; Architecture = 'x64' } },
  @{ name = 'dispatch-compile-win-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/win'; HeadRef = ''; BaseRef = ''; TestMode = 'b1-compile-only'; Architecture = 'x64' } },
  @{ name = 'dispatch-compile-gate-a-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-route-tests-20261104'; HeadRef = ''; BaseRef = ''; TestMode = 'b1-compile-only'; Architecture = 'x64' } },
  @{ name = 'dispatch-missing-mode-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/win'; HeadRef = ''; BaseRef = ''; TestMode = ''; Architecture = 'x64' } },
  @{ name = 'dispatch-invalid-mode-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/win'; HeadRef = ''; BaseRef = ''; TestMode = 'release'; Architecture = 'x64' } },
  @{ name = 'dispatch-missing-architecture-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/win'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = '' } },
  @{ name = 'dispatch-gate-a-arm64-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-route-tests-20261104'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'arm64' } },
  @{ name = 'dispatch-gate-a-all-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-route-tests-20261104'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'all' } },
  @{ name = 'dispatch-gate-b1-all-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/ci/mcp-cache-hints-exe-process-20261105'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'all' } },
  @{ name = 'dispatch-unknown-branch-invalid'; valid = $false; jobs = ''; parameters = @{ EventName = 'workflow_dispatch'; Ref = 'refs/heads/feature/other'; HeadRef = ''; BaseRef = ''; TestMode = 'standard'; Architecture = 'x64' } },
  @{ name = 'push-win-build-preserved'; valid = $true; jobs = 'build'; parameters = @{ EventName = 'push'; Ref = 'refs/heads/win'; HeadRef = ''; BaseRef = ''; TestMode = ''; Architecture = '' } },
  @{ name = 'push-b1-package-branch-stays-idle'; valid = $true; jobs = ''; parameters = @{ EventName = 'push'; Ref = 'refs/heads/ci/mcp-cache-hints-exe-process-20261105'; HeadRef = ''; BaseRef = ''; TestMode = ''; Architecture = '' } },
  @{ name = 'push-platform-build-preserved'; valid = $true; jobs = 'build'; parameters = @{ EventName = 'push'; Ref = 'refs/heads/codex/platform-win-test'; HeadRef = ''; BaseRef = ''; TestMode = ''; Architecture = '' } },
  @{ name = 'pull-request-win-build-preserved'; valid = $true; jobs = 'build'; parameters = @{ EventName = 'pull_request'; Ref = 'refs/pull/42/merge'; HeadRef = 'feature/ordinary'; BaseRef = 'win'; TestMode = ''; Architecture = '' } },
  @{ name = 'pull-request-gate-a-stays-excluded'; valid = $true; jobs = ''; parameters = @{ EventName = 'pull_request'; Ref = 'refs/pull/43/merge'; HeadRef = 'ci/mcp-cache-hints-route-tests-20261104'; BaseRef = 'win'; TestMode = ''; Architecture = '' } },
  @{ name = 'pull-request-gate-b1-stays-excluded'; valid = $true; jobs = ''; parameters = @{ EventName = 'pull_request'; Ref = 'refs/pull/44/merge'; HeadRef = 'ci/mcp-cache-hints-exe-process-20261105'; BaseRef = 'win'; TestMode = ''; Architecture = '' } }
)

$passed = 0
foreach ($case in $cases) {
  Assert-Decision $case
  $passed++
  Write-Output "PASS test=$($case.name)"
}

$compilePass = @(Get-CodexBridgeCompileStatusLines -SwiftExitCode 0 -CompileAttempted)
Assert-Equal ($compilePass -contains 'COMPILE_PASS') 'True' 'zero-exit-has-compile-pass-marker'
Assert-Equal ($compilePass -contains 'B1_COMPILE_STATUS=PASS') 'True' 'zero-exit-has-pass-status'
foreach ($label in @('B1_XCTEST_STATUS=NOT_RUN', 'B1_EXE_STATUS=NOT_RUN', 'B1_SCHEMA_STATUS=NOT_TESTED', 'B1_VM_STATUS=NOT_TESTED', 'B1_GATE_STATUS=NOT_PASSED')) {
  Assert-Equal ($compilePass -contains $label) 'True' "compile-pass-label-$label"
}
$passed++
Write-Output 'PASS test=compile-success-status-labels'

$compileFail = @(Get-CodexBridgeCompileStatusLines -SwiftExitCode 1 -CompileAttempted)
Assert-Equal ($compileFail -contains 'COMPILE_FAIL') 'True' 'nonzero-exit-has-compile-fail-marker'
Assert-Equal ($compileFail -contains 'B1_COMPILE_STATUS=FAIL') 'True' 'nonzero-exit-has-fail-status'
Assert-Equal ($compileFail -contains 'COMPILE_PASS') $false 'nonzero-exit-never-has-pass-marker'
Assert-Equal ($compileFail -contains 'B1_GATE_STATUS=NOT_PASSED') 'True' 'compile-failure-never-passes-gate'
$passed++
Write-Output 'PASS test=compile-failure-cannot-report-pass'

$compileNotReached = @(Get-CodexBridgeCompileStatusLines -SwiftExitCode 1)
Assert-Equal ($compileNotReached -contains 'COMPILE_PASS') $false 'skipped-compile-never-has-pass-marker'
Assert-Equal ($compileNotReached -contains 'B1_COMPILE_STATUS=FAIL') 'True' 'skipped-compile-fails-closed'
Assert-Equal ($compileNotReached -contains 'B1_COMPILE_PHASE=NOT_REACHED') 'True' 'skipped-compile-phase-explicit'
$passed++
Write-Output 'PASS test=compile-not-reached-is-not-pass'

$workflowPath = Join-Path $PSScriptRoot '..\..\..\workflows\windows.yml'
$workflow = Get-Content -LiteralPath $workflowPath -Raw
$policyPath = Join-Path $PSScriptRoot '..\McpVmWorkflowPolicy.psm1'
$policy = Get-Content -LiteralPath $policyPath -Raw
foreach ($job in @('build', 'mcp-route-tests', 'mcp-exe-process-tests', 'mcp-exe-compile-only')) {
  if ($workflow -notmatch "(?s)$job\s*:\s*\r?\n\s+needs:\s*dispatch-input-validation\b") {
    throw "assertion_failed_job_missing_dispatch_validation_$job"
  }
}
$jobOutputs = @{
  build = "needs.dispatch-input-validation.outputs.build_job == 'true'"
  'mcp-route-tests' = "needs.dispatch-input-validation.outputs.route_job == 'true'"
  'mcp-exe-process-tests' = "needs.dispatch-input-validation.outputs.b1_runtime_job == 'true'"
  'mcp-exe-compile-only' = "needs.dispatch-input-validation.outputs.b1_compile_job == 'true'"
}
foreach ($condition in $jobOutputs.Values) {
  if (-not $workflow.Contains($condition)) { throw "assertion_failed_job_output_gate_missing_$condition" }
}
if ($workflow -notmatch '(?s)dispatch-input-validation:.*?\r?\n\s+outputs:') { throw 'assertion_failed_validation_job_outputs_missing' }
if ($workflow -notmatch "test_mode:\s*\r?\n\s+description:.*\r?\n\s+required:\s*true") { throw 'assertion_failed_test_mode_not_required' }
if ($workflow -notmatch "architecture:\s*\r?\n\s+description:.*\r?\n\s+required:\s*true") { throw 'assertion_failed_architecture_not_required' }
$dispatchStart = $workflow.IndexOf('  workflow_dispatch:')
$permissionsStart = $workflow.IndexOf('permissions:', $dispatchStart)
$dispatchInputText = $workflow.Substring($dispatchStart, $permissionsStart - $dispatchStart)
if ($dispatchInputText -match '(?m)^\s+default:') { throw 'assertion_failed_dispatch_input_defaults_allow_missing_values' }
if ($dispatchInputText -notmatch 'options:\s*\[standard, b1-compile-only, b1-package-inventory-only\]') { throw 'assertion_failed_dispatch_mode_options_invalid' }
if ($workflow -match "inputs\.test_mode\s*!=\s*'b1-compile-only'") { throw 'assertion_failed_nonexclusive_test_mode_condition' }
$pushStart = $workflow.IndexOf('  push:')
$pullRequestStart = $workflow.IndexOf('  pull_request:', $pushStart)
if ($pushStart -lt 0 -or $pullRequestStart -lt 0) { throw 'assertion_failed_push_trigger_boundary_missing' }
$pushSection = $workflow.Substring($pushStart, $pullRequestStart - $pushStart)
if ($pushSection -notmatch "branches:\s*\[win, 'codex/platform-\*'\]") { throw 'assertion_failed_push_filter_changed' }
$compileSectionStart = $workflow.IndexOf('  mcp-exe-compile-only:')
if ($compileSectionStart -lt 0) { throw 'assertion_failed_compile_only_job_missing' }
$compileSection = $workflow.Substring($compileSectionStart)
foreach ($forbidden in @('Invoke-McpVmHostController', 'Invoke-McpVmGuestHarness', 'setup-windows-wix', 'Start-Process', 'VMN5')) {
  if ($compileSection.Contains($forbidden)) { throw "assertion_failed_compile_only_contains_$forbidden" }
}
if ($compileSection -match '(?im)^\s*(?:&\s*)?swift\s+test(?:\s|$)') { throw 'assertion_failed_compile_only_runs_xctest' }
if ($compileSection -notmatch "if: inputs\.test_mode == 'b1-package-inventory-only'") { throw 'assertion_failed_inventory_step_not_mode_gated' }
$prepareStart = $workflow.IndexOf('      - name: Prepare Windows Swift test libraries', $compileSectionStart)
$resolveStart = $workflow.IndexOf('      - name: Resolve pinned SwiftPM dependencies', $prepareStart)
if ($prepareStart -lt 0 -or $resolveStart -lt 0) { throw 'assertion_failed_package_inventory_prepare_step_boundary_missing' }
$prepareSection = $workflow.Substring($prepareStart, $resolveStart - $prepareStart)
if ($prepareSection -notmatch '(?s)if \(\$env:TEST_MODE -ceq "b1-package-inventory-only"\) \{\s+\$msvcRoot = .*?Add-Content \$env:GITHUB_ENV "MSVC_DUMPBIN_PATH=\$dumpbinPath"\s+\}') {
  throw 'assertion_failed_dumpbin_requirement_not_limited_to_inventory_mode'
}
if ($compileSection -notmatch 'Invoke-McpSwiftBuildInventory\.ps1' -or
    $compileSection -notmatch 'INVENTORY_PASS' -or
    $compileSection -notmatch 'TEST_PACKAGE_STATUS=NOT_CREATED' -or
    $compileSection -notmatch 'EXECUTABLE_CLASSIFICATION=UNRESOLVED' -or
    $compileSection -notmatch 'GATE_B1=NOT_PASSED') {
  throw 'assertion_failed_inventory_status_not_fail_closed'
}
$inventoryScriptPath = Join-Path $PSScriptRoot '..\Invoke-McpSwiftBuildInventory.ps1'
$inventoryScript = Get-Content -LiteralPath $inventoryScriptPath -Raw
$inventoryModulePath = Join-Path $PSScriptRoot '..\McpSwiftBuildInventory.psm1'
$inventoryModule = Get-Content -LiteralPath $inventoryModulePath -Raw
$inventoryRuntimeChecks = @(
  [pscustomobject]@{ name = 'source-commit'; passed = [bool](($inventoryScript -match 'rev-parse HEAD') -and ($inventoryScript -match 'inventory_source_commit_changed')) },
  [pscustomobject]@{ name = 'lock-identity'; passed = [bool]($inventoryScript -match 'inventory_swiftpm_lock_identity_changed') },
  [pscustomobject]@{ name = 'debug-release-query'; passed = [bool](($inventoryScript -match 'Configuration ''debug''') -and ($inventoryScript -match 'Configuration ''release''')) },
  [pscustomobject]@{ name = 'compile-argument-binding'; passed = [bool]($inventoryScript -match 'SWIFT_BUILD_ARGUMENTS_SHA256') },
  [pscustomobject]@{ name = 'no-xctest-or-service-run'; passed = [bool](($inventoryScript -notmatch '(?im)^\s*(?:&\s*)?swift\s+test(?:\s|$)') -and (-not $inventoryScript.Contains('Start-Process')) -and (-not $inventoryModule.Contains('Start-Process'))) },
  [pscustomobject]@{ name = 'dumpbin-and-pe-architecture'; passed = [bool](($inventoryModule -match '/dependents') -and ($inventoryModule -match 'inventory_pe_architecture_mismatch')) },
  [pscustomobject]@{ name = 'five-file-categories'; passed = [bool](($inventoryModule -match 'candidate-xctest-runner') -and ($inventoryModule -match 'ordinary-exe') -and ($inventoryModule -match 'fileType = ''dll''') -and ($inventoryModule -match 'fileType = ''resource''') -and ($inventoryModule -match 'fileType = ''unclassified''')) },
  [pscustomobject]@{ name = 'declared-test-target-evidence'; passed = [bool]($inventoryModule -match 'Get-CodexBridgeDeclaredTestTargetNames') },
  [pscustomobject]@{ name = 'configuration-and-replacement-guards'; passed = [bool](($inventoryModule -match 'inventory_debug_release_binpath_ambiguous') -and ($inventoryModule -match 'inventory_directory_replaced')) },
  [pscustomobject]@{ name = 'unresolved-and-ineligible'; passed = [bool](($inventoryModule -match 'packageEligible = \$false') -and ($inventoryModule -match "executableClassification = 'UNRESOLVED'")) },
  [pscustomobject]@{ name = 'fixed-schema-pin'; passed = [bool]($inventoryModule -match 'EF70B61F99B6D2E5E3B46863822EAB08DFF6A45BEDC7A08914E0E5B133F40203') }
)
$failedInventoryRuntimeChecks = @($inventoryRuntimeChecks | Where-Object { -not $_.passed })
if ($failedInventoryRuntimeChecks.Count -gt 0) {
  $failedInventoryRuntimeChecks | ForEach-Object { Write-Output "FAIL test=inventory-static-$($_.name)" }
  throw 'assertion_failed_inventory_script_runtime_boundary'
}
$inventoryStepStart = $compileSection.IndexOf('      - name: Inventory SwiftPM test build outputs without executing them')
$uploadStepStart = $compileSection.IndexOf('      - name: Upload inventory manifest only', $inventoryStepStart)
$finalInventoryReportStart = $compileSection.IndexOf('      - name: Report package inventory-only status', $uploadStepStart)
$compileReportStart = $compileSection.IndexOf('      - name: Report compile-only status without running tests', $finalInventoryReportStart)
if ($inventoryStepStart -lt 0 -or $uploadStepStart -lt $inventoryStepStart -or
    $finalInventoryReportStart -lt $uploadStepStart -or $compileReportStart -lt $finalInventoryReportStart) {
  throw 'assertion_failed_inventory_step_order'
}
$compileStepStart = $compileSection.IndexOf('      - name: Compile Swift sources and XCTest targets without running them')
if ($compileStepStart -lt 0 -or $compileStepStart -gt $inventoryStepStart) { throw 'assertion_failed_inventory_not_after_compile' }
$inventoryStepText = $compileSection.Substring($inventoryStepStart, $uploadStepStart - $inventoryStepStart)
if ($inventoryStepText -notmatch "if: inputs\.test_mode == 'b1-package-inventory-only'" -or
    $inventoryStepText -match 'if:.*always\(') {
  throw 'assertion_failed_inventory_may_run_after_compile_failure'
}
$finalInventoryReport = $compileSection.Substring($finalInventoryReportStart, $compileReportStart - $finalInventoryReportStart)
if ($finalInventoryReport -notmatch '\$compilePass\s*=.*COMPILE_OUTCOME.*success' -or
    $finalInventoryReport -notmatch '\$inventoryPass\s*=.*INVENTORY_OUTCOME.*success' -or
    $finalInventoryReport -notmatch '\$manifestPass\s*=.*MANIFEST_COMPLETE.*true' -or
    $finalInventoryReport -notmatch '\$uploadPass\s*=.*UPLOAD_OUTCOME.*success' -or
    $finalInventoryReport -notmatch "TEST_PACKAGE_STATUS=NOT_CREATED" -or
    $finalInventoryReport -notmatch "EXECUTABLE_CLASSIFICATION=UNRESOLVED" -or
    $finalInventoryReport -notmatch "GATE_B1=NOT_PASSED" -or
    $finalInventoryReport.IndexOf("Write-Output 'INVENTORY_PASS'") -lt 0 -or
    $finalInventoryReport.IndexOf("Write-Output 'INVENTORY_PASS'") -lt $finalInventoryReport.IndexOf('if (-not $compilePass)')) {
  throw 'assertion_failed_inventory_final_pass_not_bound_to_all_outcomes'
}
$compileReport = $compileSection.Substring($compileReportStart)
if ($compileReport -notmatch "if: always\(\) && inputs\.test_mode == 'b1-compile-only'" -or
    $compileReport -notmatch 'COMPILE_PASS') {
  throw 'assertion_failed_legacy_compile_report_mode_changed'
}
$inventoryOnlyCompileReport = $finalInventoryReport
if ($inventoryOnlyCompileReport -match 'COMPILE_PASS|B1_COMPILE_STATUS=PASS') {
  throw 'assertion_failed_inventory_mode_reports_compile_as_final_pass'
}
$passed++
Write-Output 'PASS test=inventory-status-requires-compile-manifest-upload'
$passed++
Write-Output 'PASS test=legacy-compile-only-report-remains-isolated'
$passed++
Write-Output 'PASS test=inventory-binpath-query-binds-debug-release-and-build-args'
$passed++
Write-Output 'PASS test=inventory-classification-requires-test-target-evidence'
$uploadStart = $compileSection.IndexOf('      - name: Upload inventory manifest only')
if ($uploadStart -lt 0) { throw 'assertion_failed_inventory_manifest_upload_missing' }
$uploadEnd = $compileSection.IndexOf('      - name: Report package inventory-only status', $uploadStart)
if ($uploadEnd -lt 0) { throw 'assertion_failed_inventory_manifest_upload_boundary_missing' }
$uploadSection = $compileSection.Substring($uploadStart, $uploadEnd - $uploadStart)
foreach ($required in @("inputs.test_mode == 'b1-package-inventory-only'", "steps.inventory.outputs.inventory_created == 'true'", "steps.inventory.outputs.manifest_complete == 'true'", 'actions/upload-artifact@v4', 'inventory.json', 'mcp-2026-07-28.json', 'SHA256SUMS.txt', 'SHA256SUMS.txt.sha256', 'retention-days: 1')) {
  if (-not $uploadSection.Contains($required)) { throw "assertion_failed_inventory_upload_contract_$required" }
}
if ($uploadSection -match '(?i)\.build|\*\*|\.exe|\.dll') { throw 'assertion_failed_inventory_upload_includes_build_files' }
$passed++
Write-Output 'PASS test=inventory-artifact-is-whitelisted-and-manifest-gated'
$passed++
Write-Output 'PASS test=inventory-step-is-success-gated-after-compile'
$runtimeStart = $workflow.IndexOf('  mcp-exe-process-tests:')
$compileJobStart = $workflow.IndexOf('  mcp-exe-compile-only:', $runtimeStart)
$runtimeSection = $workflow.Substring($runtimeStart, $compileJobStart - $runtimeStart)
if (-not $runtimeSection.Contains('levels.L4 -ne "PASS"') -or
    -not $runtimeSection.Contains('CODEX_BRIDGE_B1_ISOLATION_LEVEL')) {
  throw 'assertion_failed_existing_l4_guard_not_preserved'
}
foreach ($label in @('COMPILE_PASS', 'COMPILE_FAIL', 'B1_COMPILE_STATUS=PASS', 'B1_COMPILE_STATUS=FAIL', 'B1_XCTEST_STATUS=NOT_RUN', 'B1_EXE_STATUS=NOT_RUN', 'B1_SCHEMA_STATUS=NOT_TESTED', 'B1_VM_STATUS=NOT_TESTED', 'B1_GATE_STATUS=NOT_PASSED')) {
  if ($policy -notmatch [regex]::Escape($label) -or $compileSection -notmatch [regex]::Escape($label)) {
    throw "assertion_failed_compile_status_label_$label"
  }
}
if ($compileSection -notmatch 'if \(\$attempted -and \$env:COMPILE_STATUS -ceq ''PASS''\)') { throw 'assertion_failed_compile_pass_not_bound_to_success_status' }
$passed++
Write-Output 'PASS test=workflow-jobs-gated-and-compile-only-isolated'

$expected = $cases.Count + 10
if ($passed -ne $expected) { throw "workflow_policy_test_count_mismatch_$passed`_expected_$expected" }
Write-Output "PASS test=workflow-policy-summary executed=$passed failures=0"
