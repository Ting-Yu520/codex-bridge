$ErrorActionPreference = "Stop"

function Get-SafeDiagnostic([string]$Line) {
  $value = $Line.Trim()
  $value = [regex]::Replace($value, '(?i)github_pat_[A-Za-z0-9_]{20,}|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9]{20,}\b', '<redacted>')
  $value = [regex]::Replace($value, '(?i)\bBearer\s+\S+', 'Bearer <redacted>')
  $value = [regex]::Replace($value, '(?i)\b(Runtime[_ -]?Key|api[_ -]?key|token|cookie)\b\s*[:=]\s*\S+', '$1=<redacted>')
  $value = [regex]::Replace($value, '(?i)(?:[A-Z]:[\\/]|\\\\)[^\r\n]+|/(?:Users|home)/[^\r\n]+', '<path>')
  if ($value.Length -gt 220) { $value = $value.Substring(0, 220) }
  return $value
}

try {
  if (-not $env:RUNNER_TEMP -or -not $env:TARGET_TRIPLE -or -not $env:VCPKG_INSTALLATION_ROOT) {
    throw "test_environment_missing"
  }
  $securityStatePath = Join-Path $env:RUNNER_TEMP "codex-bridge-b1-egress-state.json"
  if (-not (Test-Path -LiteralPath $securityStatePath -PathType Leaf)) {
    Write-Output "BLOCKED stage=service-start error_category=security_state_missing"
    exit 1
  }
  try {
    $securityState = Get-Content -LiteralPath $securityStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable
  } catch {
    Write-Output "BLOCKED stage=service-start error_category=security_state_invalid"
    exit 1
  }
  if ($securityState.schema -ne "codex-bridge-b1-egress-recovery/v2" -or
      $securityState.network.levels.L4 -ne "PASS" -or
      $securityState.network.serviceStartAllowed -ne $true -or
      $securityState.phase -ne "guard-active") {
    Write-Output "BLOCKED stage=service-start error_category=process_tree_egress_isolation_unavailable"
    exit 1
  }
  foreach ($name in @(
    "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "OPENAI_API_KEY", "CODEX_BRIDGE_RUNTIME_KEY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy"
  )) {
    if (Test-Path -LiteralPath "Env:$name") { Remove-Item -LiteralPath "Env:$name" }
  }
  . "$env:GITHUB_WORKSPACE\Scripts\windows-swift-arguments.ps1"
  $baseArguments = Get-WindowsSwiftArguments `
    -VcpkgInstalledRoot "$env:VCPKG_INSTALLATION_ROOT\installed\x64-windows" `
    -TargetTriple $env:TARGET_TRIPLE `
    -LibraryPaths ($env:TARGET_LIBRARY_PATHS -split ";")
  $swiftArguments = @($baseArguments) + @(
    "-c", "debug", "--filter", "MCPWindowsExecutableProcessTests"
  )
  $logPath = Join-Path $env:RUNNER_TEMP "codex-bridge-b1-swift-test.log"
  $swiftOutput = @(& swift test @swiftArguments 2>&1 | ForEach-Object { [string]$_ })
  $swiftExitCode = $LASTEXITCODE
  [IO.File]::WriteAllLines($logPath, [string[]]$swiftOutput, [Text.UTF8Encoding]::new($false))

  $testCaseEvents = @()
  $summary = $null
  foreach ($line in $swiftOutput) {
    $text = [regex]::Replace($line, '\x1B\[[0-?]*[ -/]*[@-~]', '')
    if ($text -match '^B1_(PROCESS_START|IPC|MCP_INIT|MCP_ROUTE|MCP_CAPTURE_SUMMARY)\b') {
      Write-Output (Get-SafeDiagnostic $text)
    }
    $case = [regex]::Match($text, "Test Case '([^']+)' (started|passed|failed|skipped)\b")
    if ($case.Success) {
      $identity = $case.Groups[1].Value
      $method = [regex]::Match($identity, 'MCPWindowsExecutableProcessTests\.testWindowsPortableExecutableServesModernMCPRoutes')
      if ($method.Success) {
        $status = $case.Groups[2].Value.ToUpperInvariant()
        Write-Output "XCTEST method=testWindowsPortableExecutableServesModernMCPRoutes status=$status"
        if ($status -ne "STARTED") { $testCaseEvents += $status }
      }
    }
    if ($text -match 'Executed \d+ tests?, with \d+ failures?') { $summary = $text }

    $compiler = [regex]::Match($text, '^(?<path>.+?\.swift):(?<line>\d+)(?::(?<column>\d+))?:\s*error:\s*(?<message>.*)$')
    if ($compiler.Success) {
      $relative = $compiler.Groups["path"].Value
      $workspacePrefix = [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
      try {
        $full = [IO.Path]::GetFullPath($relative)
        if ($full.StartsWith($workspacePrefix, [StringComparison]::OrdinalIgnoreCase)) {
          $relative = $full.Substring($workspacePrefix.Length).Replace('\', '/')
        } else { $relative = [IO.Path]::GetFileName($full) }
      } catch { $relative = "<source>" }
      $message = Get-SafeDiagnostic $compiler.Groups["message"].Value
      Write-Output "COMPILER_DIAGNOSTIC source=$relative`:$($compiler.Groups['line'].Value) category=swift_compile_error message=$message"
    } elseif ($text -match '^\s*error:') {
      Write-Output "COMPILER_DIAGNOSTIC source=<location-unavailable> category=swift_compile_error"
    }
  }

  if (-not $summary) {
    Write-Output "ERROR_CATEGORY=swift_test_summary_missing"
    if ($swiftExitCode -ne 0) { exit $swiftExitCode }
    exit 1
  }
  $summaryMatch = [regex]::Match($summary, 'Executed (\d+) tests?, with (\d+) failures?')
  $executed = [int]$summaryMatch.Groups[1].Value
  $failures = [int]$summaryMatch.Groups[2].Value
  $skipped = @($testCaseEvents | Where-Object { $_ -eq "SKIPPED" }).Count
  Write-Output "B1_SWIFT_TEST_SUMMARY executed=$executed failures=$failures skipped=$skipped"
  if ($swiftExitCode -ne 0) {
    Write-Output "ERROR_CATEGORY=swift_test_command_failed"
    exit $swiftExitCode
  }
  if ($executed -ne 1 -or $failures -ne 0 -or $skipped -ne 0 -or
      $testCaseEvents.Count -ne 1 -or $testCaseEvents[0] -ne "PASSED") {
    Write-Output "ERROR_CATEGORY=swift_test_discovery_execution_or_assertion_failure"
    exit 1
  }
  Write-Output "PASS test=windows-exe-process-xctest discovered=1 executed=1"
} catch {
  Write-Output "ERROR_CATEGORY=windows_exe_process_test_runner_failed"
  exit 1
}
