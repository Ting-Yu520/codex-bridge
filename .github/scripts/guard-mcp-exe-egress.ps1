param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("Apply", "Cleanup")]
  [string]$Mode
)

$ErrorActionPreference = "Stop"
$statePath = Join-Path $env:RUNNER_TEMP "codex-bridge-b1-egress-state.json"
$serviceName = "codex-bridge-service.exe"
$expectedServiceDigest = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
$ipv4RemoteAddresses = @("0.0.0.0-126.255.255.255", "128.0.0.0-255.255.255.255")
$ipv6RemoteAddresses = @("::", "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
$auditSubcategory = "{0CCE9226-69AE-11D9-BED3-505054503030}"
$credentialTargetPrefix = "com.openai.codex-bridge.secrets"

function Normalize-Path([string]$Path) {
  return [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
}

function Get-ProgramProcesses([string[]]$Paths) {
  $pathSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $nameSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($path in $Paths) {
    [void]$pathSet.Add((Normalize-Path $path))
    [void]$nameSet.Add([IO.Path]::GetFileName($path))
  }
  $processes = Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, ExecutablePath, ParentProcessId -ErrorAction Stop
  $unresolved = @($processes | Where-Object {
    $nameSet.Contains([string]$_.Name) -and [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath)
  })
  if ($unresolved.Count -gt 0) { throw "protected_process_image_unavailable" }
  return @($processes | Where-Object {
    $_.ExecutablePath -and $pathSet.Contains((Normalize-Path $_.ExecutablePath))
  })
}

function Get-BridgeCredentialTargets {
  $cmdkey = Join-Path $env:SystemRoot "System32\cmdkey.exe"
  $targets = @(& $cmdkey /list 2>$null | ForEach-Object {
    if ([string]$_ -match '^\s*Target:\s*(?<target>.+)$') {
      $target = $Matches.target.Trim()
      if ($target -match '^(?:LegacyGeneric:)?target=(?<name>.+)$') {
        $target = $Matches.name.Trim()
      }
      if ($target.StartsWith($credentialTargetPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $target
      }
    }
  })
  if ($LASTEXITCODE -ne 0) { throw "credential_target_inventory_failed" }
  return $targets
}

function Assert-FreshRunner {
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
      [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne "X64") {
    throw "runner_identity_invalid"
  }
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "runner_firewall_privilege_unavailable"
  }
  $existing = @(Get-Process -ErrorAction Stop | Where-Object {
    $_.ProcessName -match '^(codex[-_.]?bridge|tunnel-client)'
  })
  if ($existing.Count -gt 0) { throw "existing_bridge_process" }

  try {
    $pipes = @(Get-ChildItem -LiteralPath "\\.\pipe\" -ErrorAction Stop)
  } catch {
    throw "named_pipe_namespace_unavailable"
  }
  $bridgePipes = @($pipes | Where-Object { $_.Name -match '^org\.codexbridge\.service\.' })
  if ($bridgePipes.Count -gt 0) { throw "existing_bridge_ipc_endpoint" }

  $appSupport = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
  if ([string]::IsNullOrWhiteSpace($appSupport)) { throw "legacy_root_unavailable" }
  $legacyRoot = Join-Path $appSupport "CodexBridge"
  if (Test-Path -LiteralPath $legacyRoot) { throw "legacy_configuration_present" }
  $credentialTargets = @(Get-BridgeCredentialTargets)
  if ($credentialTargets.Count -gt 0) {
    throw "preexisting_bridge_credential_target"
  }
}

function Add-ProgramBlockRules(
  [string]$Program,
  [string]$RulePrefix,
  [Collections.Generic.List[string]]$CreatedNames
) {
  $addressSets = @(
    [pscustomobject]@{ Suffix = "IPv4"; Addresses = $ipv4RemoteAddresses },
    [pscustomobject]@{ Suffix = "IPv6"; Addresses = $ipv6RemoteAddresses }
  )
  foreach ($addressSet in $addressSets) {
    $name = "$RulePrefix-$($addressSet.Suffix)"
    $CreatedNames.Add($name)
    $rule = New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound `
      -Action Block -Enabled True -Profile Any -Protocol Any -Program $Program `
      -RemoteAddress $addressSet.Addresses -ErrorAction Stop
    $created = Get-NetFirewallRule -Name $name -ErrorAction Stop
    $application = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $created -ErrorAction Stop
    if ($created.Enabled -ne "True" -or $created.Direction -ne "Outbound" -or
        $created.Action -ne "Block" -or
        (Normalize-Path $application.Program) -ne (Normalize-Path $Program)) {
      throw "firewall_rule_configuration_mismatch"
    }
  }
}

function New-MinimalEnvironment([string]$ProgramDirectory) {
  $root = $env:SystemRoot
  if ([string]::IsNullOrWhiteSpace($root)) { throw "system_root_missing" }
  return @{
    SystemRoot = $root
    WINDIR = $root
    USERPROFILE = $env:USERPROFILE
    APPDATA = $env:APPDATA
    LOCALAPPDATA = $env:LOCALAPPDATA
    TEMP = $env:RUNNER_TEMP
    TMP = $env:RUNNER_TEMP
    PATH = "$ProgramDirectory;$root\System32"
  }
}

function Invoke-IsolatedProbe([string]$ProbePath, [string]$CandidatePath) {
  $info = [Diagnostics.ProcessStartInfo]::new()
  $info.FileName = $ProbePath
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.Environment.Clear()
  foreach ($entry in (New-MinimalEnvironment (Split-Path -Parent $CandidatePath)).GetEnumerator()) {
    if (-not [string]::IsNullOrWhiteSpace($entry.Value)) { $info.Environment[$entry.Key] = $entry.Value }
  }
  $process = [Diagnostics.Process]::Start($info)
  if (-not $process) { throw "firewall_probe_start_failed" }
  $stdoutTask = $process.StandardOutput.ReadToEndAsync()
  $stderrTask = $process.StandardError.ReadToEndAsync()
  if (-not $process.WaitForExit(15000)) { throw "firewall_probe_timeout" }
  $null = $stdoutTask.GetAwaiter().GetResult()
  $null = $stderrTask.GetAwaiter().GetResult()
  if ($process.ExitCode -ne 0) { throw "firewall_probe_loopback_or_egress_failed" }
  return $process.Id
}

function Test-ExpectedBlockedEvent([int]$ProcessId, [DateTime]$StartTime) {
  $expectedDestinations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [void]$expectedDestinations.Add("192.0.2.1")
  [void]$expectedDestinations.Add("2001:db8::1")
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 5157; StartTime = $StartTime } -ErrorAction Stop)
    foreach ($event in $events) {
      [xml]$xml = $event.ToXml()
      $fields = @{}
      foreach ($field in $xml.Event.EventData.Data) {
        $fields[[string]$field.Name] = [string]$field.InnerText
      }
      $eventPid = 0
      $pidParsed = [int]::TryParse($fields["ProcessID"], [ref]$eventPid)
      $application = ([string]$fields["Application"]).ToLowerInvariant()
      if ($pidParsed -and $eventPid -eq $ProcessId -and
          $fields["DestAddress"] -and $expectedDestinations.Contains([string]$fields["DestAddress"]) -and
          $fields["DestPort"] -eq "65000" -and
          $application.EndsWith("\codex-bridge-service.exe")) {
        [void]$expectedDestinations.Remove([string]$fields["DestAddress"])
        if ($expectedDestinations.Count -eq 0) { return $true }
      }
    }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function Apply-EgressGuard {
  Assert-FreshRunner
  if (Test-Path -LiteralPath $statePath) { throw "existing_guard_state" }
  $candidateDirectory = [IO.Path]::GetFullPath($env:CODEX_BRIDGE_CANDIDATE_DIR)
  $servicePath = Join-Path $candidateDirectory $serviceName
  if (-not (Test-Path -LiteralPath $servicePath -PathType Leaf) -or
      (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedServiceDigest) {
    throw "candidate_service_identity_mismatch"
  }

  $prefix = "CodexBridgeB1-" + [Guid]::NewGuid().ToString("N")
  $auditBackup = Join-Path $env:RUNNER_TEMP ($prefix + "-audit.csv")
  $temporaryRoot = Join-Path $env:RUNNER_TEMP ($prefix + "-probe")
  $probeSource = Join-Path $env:GITHUB_WORKSPACE ".github\scripts\MCPProcessEgressProbe.cs"
  $probeBuild = Join-Path $temporaryRoot "MCPProcessEgressProbe.exe"
  $serviceBackup = Join-Path $temporaryRoot $serviceName
  $ruleNames = [Collections.Generic.List[string]]::new()
  $auditBackedUp = $false
  $probeStillRunning = $false
  New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop | Out-Null

  try {
    . (Join-Path $env:GITHUB_WORKSPACE "Scripts\windows-portable-support.ps1")
    $executables = @(Get-ChildItem -LiteralPath $candidateDirectory -File -Recurse -Filter "*.exe")
    if ($executables.Count -lt 2 -or -not ($executables.FullName -contains $servicePath)) {
      throw "portable_executable_set_invalid"
    }
    foreach ($executable in $executables) {
      if ((Get-PEMachine $executable.FullName) -ne [UInt16]0x8664) { throw "portable_executable_architecture_mismatch" }
      Add-ProgramBlockRules `
        -Program $executable.FullName `
        -RulePrefix ($prefix + "-" + $ruleNames.Count) `
        -CreatedNames $ruleNames
    }

    $auditpol = Join-Path $env:SystemRoot "System32\auditpol.exe"
    & $auditpol /backup /file:$auditBackup *> $null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $auditBackup)) { throw "audit_policy_backup_failed" }
    $auditBackedUp = $true
    & $auditpol /set /subcategory:$auditSubcategory /success:disable /failure:enable *> $null
    if ($LASTEXITCODE -ne 0) { throw "wfp_audit_enable_failed" }

    $compiler = Join-Path $env:SystemRoot "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if (-not (Test-Path -LiteralPath $compiler) -or -not (Test-Path -LiteralPath $probeSource)) {
      throw "egress_probe_compiler_or_source_missing"
    }
    & $compiler /nologo /target:exe "/out:$probeBuild" $probeSource *> $null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $probeBuild)) { throw "egress_probe_compile_failed" }

    if (Test-Path -LiteralPath $serviceBackup) { throw "probe_backup_collision" }
    Move-Item -LiteralPath $servicePath -Destination $serviceBackup -ErrorAction Stop
    $probePlaced = $false
    $probeProcessId = 0
    $probeStart = [DateTime]::UtcNow.AddSeconds(-2)
    try {
      Copy-Item -LiteralPath $probeBuild -Destination $servicePath -ErrorAction Stop
      $probePlaced = $true
      $probeProcessId = Invoke-IsolatedProbe -ProbePath $servicePath -CandidatePath $servicePath
    } catch {
      if ($_.Exception.Message -eq "firewall_probe_timeout") { $probeStillRunning = $true }
      throw
    } finally {
      if (-not $probeStillRunning) {
        if ($probePlaced -and (Test-Path -LiteralPath $servicePath)) { Remove-Item -LiteralPath $servicePath -Force }
        if (Test-Path -LiteralPath $serviceBackup) { Move-Item -LiteralPath $serviceBackup -Destination $servicePath -ErrorAction Stop }
      }
    }
    if ((Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedServiceDigest) {
      throw "candidate_service_restore_hash_mismatch"
    }
    if (-not (Test-ExpectedBlockedEvent -ProcessId $probeProcessId -StartTime $probeStart)) {
      throw "wfp_block_event_not_observed"
    }

    $state = [ordered]@{
      servicePath = $servicePath
      candidateDirectory = $candidateDirectory
      protectedExecutablePaths = @($executables.FullName)
      firewallRuleNames = @($ruleNames)
      auditBackup = $auditBackup
      temporaryRoot = $temporaryRoot
    }
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding utf8
    Write-Output "PASS test=egress-rule-paths count=$($executables.Count)"
    Write-Output "PASS test=network-guard loopback=ipv4-and-ipv6 external_block=ipv4-and-ipv6-verified event_id=5157"
  } catch {
    if (-not $probeStillRunning) {
      foreach ($name in $ruleNames) {
        Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Out-Null
      }
      if ($auditBackedUp) {
        $auditpol = Join-Path $env:SystemRoot "System32\auditpol.exe"
        & $auditpol /restore /file:$auditBackup *> $null
      }
      if ((Test-Path -LiteralPath $serviceBackup) -and -not (Test-Path -LiteralPath $servicePath)) {
        Move-Item -LiteralPath $serviceBackup -Destination $servicePath -ErrorAction SilentlyContinue
      }
      if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue }
      if (Test-Path -LiteralPath $auditBackup) { Remove-Item -LiteralPath $auditBackup -Force -ErrorAction SilentlyContinue }
    }
    throw "egress_guard_verification_failed"
  }
}

function New-ShutdownProcess([string]$ServicePath) {
  $info = [Diagnostics.ProcessStartInfo]::new()
  $info.FileName = $ServicePath
  [void]$info.ArgumentList.Add("--shutdown")
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.Environment.Clear()
  foreach ($entry in (New-MinimalEnvironment (Split-Path -Parent $ServicePath)).GetEnumerator()) {
    if (-not [string]::IsNullOrWhiteSpace($entry.Value)) { $info.Environment[$entry.Key] = $entry.Value }
  }
  return $info
}

function Cleanup-Runner {
  if (-not (Test-Path -LiteralPath $statePath)) {
    Write-Output "CLEANUP status=no-guard-state"
    return
  }
  $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable
  $servicePath = [string]$state.servicePath
  $runnerTemp = Normalize-Path $env:RUNNER_TEMP
  $candidateDirectory = Normalize-Path ([string]$state.candidateDirectory)
  $artifactRoot = Normalize-Path (Split-Path -Parent $candidateDirectory)
  if ((Normalize-Path (Split-Path -Parent $artifactRoot)) -ne $runnerTemp -or
      -not ([IO.Path]::GetFileName($artifactRoot)).StartsWith(
        "codex-bridge-b1-artifact-", [StringComparison]::OrdinalIgnoreCase) -or
      [IO.Path]::GetFileName($candidateDirectory) -ne "portable-payload" -or
      (Normalize-Path $servicePath) -ne (Normalize-Path (Join-Path $candidateDirectory $serviceName))) {
    throw "candidate_cleanup_boundary_violation"
  }
  foreach ($path in @($artifactRoot, $candidateDirectory)) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "candidate_cleanup_reparse_point"
    }
  }
  if ((Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedServiceDigest) {
    throw "candidate_service_identity_changed"
  }

  $protectedPaths = @($state.protectedExecutablePaths)
  $processes = @(Get-ProgramProcesses -Paths $protectedPaths)
  $serviceProcesses = @($processes | Where-Object { (Normalize-Path $_.ExecutablePath) -eq (Normalize-Path $servicePath) })
  if ($serviceProcesses.Count -gt 1) { throw "multiple_candidate_service_processes" }

  if ($env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE -and (Test-Path -LiteralPath $env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE)) {
    $record = Get-Content -LiteralPath $env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE -Raw | ConvertFrom-Json -AsHashtable
    if ($serviceProcesses.Count -eq 1 -and [int]$record.pid -gt 0 -and
        [int]$record.pid -ne [int]$serviceProcesses[0].ProcessId) {
      throw "service_pid_record_mismatch"
    }
  } elseif ($serviceProcesses.Count -gt 0) {
    throw "service_pid_record_missing"
  }

  if ($serviceProcesses.Count -eq 1) {
    $target = $serviceProcesses[0]
    if ((Normalize-Path $target.ExecutablePath) -ne (Normalize-Path $servicePath)) {
      throw "shutdown_image_identity_mismatch"
    }
    $shutdownInfo = New-ShutdownProcess -ServicePath $servicePath
    $shutdown = [Diagnostics.Process]::Start($shutdownInfo)
    if (-not $shutdown) { throw "graceful_shutdown_start_failed" }
    $stdoutTask = $shutdown.StandardOutput.ReadToEndAsync()
    $stderrTask = $shutdown.StandardError.ReadToEndAsync()
    if (-not $shutdown.WaitForExit(60000)) { throw "graceful_shutdown_timeout" }
    $null = $stdoutTask.GetAwaiter().GetResult()
    $null = $stderrTask.GetAwaiter().GetResult()
    if ($shutdown.ExitCode -ne 0) { throw "graceful_shutdown_nonzero" }
  }

  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  do {
    $remaining = @(Get-ProgramProcesses -Paths $protectedPaths)
    if ($remaining.Count -eq 0) { break }
    Start-Sleep -Milliseconds 250
  } while ([DateTime]::UtcNow -lt $deadline)
  if ($remaining.Count -gt 0) { throw "candidate_or_helper_process_remains" }

  foreach ($name in $state.firewallRuleNames) {
    Remove-NetFirewallRule -Name $name -ErrorAction Stop | Out-Null
  }
  foreach ($name in $state.firewallRuleNames) {
    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { throw "firewall_rule_cleanup_incomplete" }
  }
  if (Test-Path -LiteralPath $state.auditBackup) {
    $auditpol = Join-Path $env:SystemRoot "System32\auditpol.exe"
    & $auditpol /restore /file:$($state.auditBackup) *> $null
    if ($LASTEXITCODE -ne 0) { throw "audit_policy_restore_failed" }
  }

  $cmdkey = Join-Path $env:SystemRoot "System32\cmdkey.exe"
  foreach ($target in @(Get-BridgeCredentialTargets)) {
    & $cmdkey "/delete:$target" *> $null
    if ($LASTEXITCODE -ne 0) { throw "generated_bridge_credential_cleanup_failed" }
  }
  if (@(Get-BridgeCredentialTargets).Count -gt 0) {
    throw "generated_bridge_credential_cleanup_incomplete"
  }

  if ($env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE -and (Test-Path -LiteralPath $env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE)) {
    $record = Get-Content -LiteralPath $env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE -Raw | ConvertFrom-Json -AsHashtable
    foreach ($field in @("dataRoot", "profileRoot")) {
      $path = [string]$record[$field]
      if ([string]::IsNullOrWhiteSpace($path)) { throw "runner_temp_cleanup_path_missing" }
      $itemPath = Normalize-Path $path
      $parentPath = Normalize-Path (Split-Path -Parent $itemPath)
      $leafName = [IO.Path]::GetFileName($itemPath)
      $expectedPrefix = if ($field -eq "dataRoot") { "codex-bridge-b1-data-" } else { "codex-bridge-b1-profile-" }
      if ($parentPath -ne $runnerTemp -or -not $leafName.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "runner_temp_cleanup_boundary_violation"
      }
      if (Test-Path -LiteralPath $itemPath) {
        $item = Get-Item -LiteralPath $itemPath -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
          throw "runner_temp_cleanup_reparse_point"
        }
        Remove-Item -LiteralPath $itemPath -Recurse -Force
      }
    }
  }
  if ($env:CODEX_BRIDGE_MCP_PROCESS_CAPTURE_DIR -and (Test-Path -LiteralPath $env:CODEX_BRIDGE_MCP_PROCESS_CAPTURE_DIR)) {
    $capture = Get-Item -LiteralPath $env:CODEX_BRIDGE_MCP_PROCESS_CAPTURE_DIR -Force
    if ((Normalize-Path $capture.Parent.FullName) -ne $runnerTemp -or
        ($capture.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "capture_cleanup_boundary_violation"
    }
    Remove-Item -LiteralPath $capture.FullName -Recurse -Force
  }
  Remove-Item -LiteralPath $state.temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $state.auditBackup -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $artifactRoot -Recurse -Force
  Remove-Item -LiteralPath $statePath -Force
  $swiftLog = Join-Path $runnerTemp "codex-bridge-b1-swift-test.log"
  if (Test-Path -LiteralPath $swiftLog) { Remove-Item -LiteralPath $swiftLog -Force }
  if ($env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE -and (Test-Path -LiteralPath $env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE)) {
    Remove-Item -LiteralPath $env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE -Force
  }
  Write-Output "PASS test=process-shutdown image=verified-portable/codex-bridge-service.exe"
  Write-Output "PASS test=network-guard-cleanup status=restored"
}

try {
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { throw "runner_temp_missing" }
  if ($Mode -eq "Apply") {
    Apply-EgressGuard
  } else {
    Cleanup-Runner
  }
} catch {
  Write-Output ("ERROR_CATEGORY=" + $(if ($Mode -eq "Apply") { "network_isolation_or_preflight_failed" } else { "process_or_network_cleanup_failed" }))
  exit 1
}
