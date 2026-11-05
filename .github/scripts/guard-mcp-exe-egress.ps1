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
$recoveryModulePath = Join-Path $PSScriptRoot "McpEgressGuardRecovery.psm1"
Import-Module $recoveryModulePath -Force
$script:guardState = $null

function Save-GuardState {
  if ($null -eq $script:guardState) { throw "recovery_state_not_initialized" }
  Save-McpEgressGuardState -StatePath $statePath -State $script:guardState
}

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
  [string[]]$RemoteAddressesIPv4,
  [string[]]$RemoteAddressesIPv6
) {
  $addressSets = @(
    [pscustomobject]@{ Suffix = "IPv4"; Addresses = $RemoteAddressesIPv4 },
    [pscustomobject]@{ Suffix = "IPv6"; Addresses = $RemoteAddressesIPv6 }
  )
  foreach ($addressSet in $addressSets) {
    $name = "$RulePrefix-$($addressSet.Suffix)"
    if (@($script:guardState.firewall.ruleNames) -notcontains $name) {
      $script:guardState.firewall.ruleNames = @($script:guardState.firewall.ruleNames) + $name
      Save-GuardState
    }
    $null = New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound `
      -Action Block -Enabled True -Profile Any -Protocol Any -Program $Program `
      -RemoteAddress $addressSet.Addresses -ErrorAction Stop
    $createdRules = @(Get-NetFirewallRule -Name $name -ErrorAction Stop)
    if ($createdRules.Count -ne 1) { throw "firewall_rule_identity_ambiguous" }
    $created = $createdRules[0]
    $applications = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $created -ErrorAction Stop)
    $addresses = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $created -ErrorAction Stop)
    $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $created -ErrorAction Stop)
    if ($applications.Count -ne 1 -or $addresses.Count -ne 1 -or $ports.Count -ne 1) {
      throw "firewall_filter_identity_ambiguous"
    }
    $application = $applications[0]
    $address = $addresses[0]
    $port = $ports[0]
    $expectedSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $actualSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $actualLocalSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $addressSet.Addresses) { [void]$expectedSet.Add([string]$entry) }
    foreach ($entry in @($address.RemoteAddress)) { [void]$actualSet.Add([string]$entry) }
    foreach ($entry in @($address.LocalAddress)) { [void]$actualLocalSet.Add([string]$entry) }
    if ([string]$created.Name -ne $name -or
        -not ([string]$created.Enabled).Equals("True", [StringComparison]::OrdinalIgnoreCase) -or
        [string]$created.Direction -ne "Outbound" -or
        [string]$created.Action -ne "Block" -or [string]$created.Profile -ne "Any" -or
        (Normalize-Path $application.Program) -ne (Normalize-Path $Program)) {
      throw "firewall_rule_configuration_mismatch"
    }
    if ($expectedSet.Count -ne $actualSet.Count -or
        @($expectedSet | Where-Object { -not $actualSet.Contains($_) }).Count -gt 0) {
      throw "firewall_address_filter_mismatch"
    }
    if ($actualLocalSet.Count -ne 1 -or -not $actualLocalSet.Contains("Any")) {
      throw "firewall_local_address_filter_mismatch"
    }
    if ([string]$port.Protocol -ne "Any" -or [string]$port.LocalPort -ne "Any" -or
        [string]$port.RemotePort -ne "Any") {
      throw "firewall_port_filter_mismatch"
    }
    $script:guardState.firewall.verifiedRuleNames = @($script:guardState.firewall.verifiedRuleNames) + $name
    Save-GuardState
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
  $script:guardState.probe.startWindowUtc = [DateTime]::UtcNow.ToString("o")
  $script:guardState.probe.imagePath = [IO.Path]::GetFullPath($CandidatePath)
  $script:guardState.probe.imageSha256 = (Get-FileHash -LiteralPath $ProbePath -Algorithm SHA256).Hash.ToLowerInvariant()
  $script:guardState.probe.startAttempted = $true
  $script:guardState.probe.exitConfirmed = $false
  $script:guardState.phase = "probe-start-intent"
  Save-GuardState

  $process = [Diagnostics.Process]::Start($info)
  if (-not $process) { throw "firewall_probe_start_failed" }
  try {
    $script:guardState.probe.pid = $process.Id
    $script:guardState.probe.startedAtUtc = $process.StartTime.ToUniversalTime().ToString("o")
    Save-GuardState
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(15000)) { throw "firewall_probe_timeout" }
    $null = $stdoutTask.GetAwaiter().GetResult()
    $null = $stderrTask.GetAwaiter().GetResult()
    $script:guardState.probe.exitCode = $process.ExitCode
    $script:guardState.probe.exitConfirmed = $true
    Save-GuardState
    if ($process.ExitCode -ne 0) { throw "firewall_probe_loopback_or_egress_failed" }
    return $process.Id
  } finally {
    $process.Dispose()
  }
}

function Get-ProbeProcessIdentity([hashtable]$State) {
  try {
    $allProcesses = @(Get-CimInstance -ClassName Win32_Process `
      -Property ProcessId, Name, ExecutablePath, CreationDate -ErrorAction Stop)
  } catch {
    return [pscustomobject]@{ status = "unknown"; processId = 0 }
  }

  $imagePath = Normalize-Path ([string]$State.probe.imagePath)
  $serviceNamed = @($allProcesses | Where-Object {
    [string]$_.Name -ieq $serviceName
  })
  if (@($serviceNamed | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) }).Count -gt 0) {
    return [pscustomobject]@{ status = "unknown"; processId = 0 }
  }
  $pathProcesses = @($allProcesses | Where-Object {
    $_.ExecutablePath -and (Normalize-Path ([string]$_.ExecutablePath)) -eq $imagePath
  })

  if ([int]$State.probe.pid -gt 0) {
    $pidProcesses = @($allProcesses | Where-Object { [int]$_.ProcessId -eq [int]$State.probe.pid })
    if ($pidProcesses.Count -eq 0) {
      if ($pathProcesses.Count -eq 0) { return [pscustomobject]@{ status = "not-found"; processId = 0 } }
      return [pscustomobject]@{ status = "unknown"; processId = 0 }
    }
    if ($pidProcesses.Count -ne 1 -or
        -not $pidProcesses[0].ExecutablePath -or
        (Normalize-Path ([string]$pidProcesses[0].ExecutablePath)) -ne $imagePath) {
      return [pscustomobject]@{ status = "unknown"; processId = 0 }
    }
    $row = $pidProcesses[0]
  } else {
    if ($pathProcesses.Count -eq 0) { return [pscustomobject]@{ status = "not-found"; processId = 0 } }
    if ($pathProcesses.Count -ne 1) { return [pscustomobject]@{ status = "unknown"; processId = 0 } }
    $row = $pathProcesses[0]
  }

  try {
    $actualStart = if ($row.CreationDate -is [DateTime]) {
      ([DateTime]$row.CreationDate).ToUniversalTime()
    } else {
      [Management.ManagementDateTimeConverter]::ToDateTime([string]$row.CreationDate).ToUniversalTime()
    }
    if ($State.probe.startedAtUtc) {
      $expectedStart = [DateTime]::Parse([string]$State.probe.startedAtUtc).ToUniversalTime()
      if ([Math]::Abs(($actualStart - $expectedStart).TotalSeconds) -gt 3) {
        return [pscustomobject]@{ status = "unknown"; processId = 0 }
      }
    } elseif ($State.probe.startWindowUtc) {
      $windowStart = [DateTime]::Parse([string]$State.probe.startWindowUtc).ToUniversalTime().AddSeconds(-2)
      if ($actualStart -lt $windowStart -or $actualStart -gt [DateTime]::UtcNow.AddSeconds(1)) {
        return [pscustomobject]@{ status = "unknown"; processId = 0 }
      }
    } else {
      return [pscustomobject]@{ status = "unknown"; processId = 0 }
    }
    if ((Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        [string]$State.probe.imageSha256) {
      return [pscustomobject]@{ status = "unknown"; processId = 0 }
    }
    return [pscustomobject]@{
      status = "verified-running"
      processId = [int]$row.ProcessId
      path = $imagePath
      startedAtUtc = $actualStart.ToString("o")
      sha256 = [string]$State.probe.imageSha256
    }
  } catch {
    return [pscustomobject]@{ status = "unknown"; processId = 0 }
  }
}

function Stop-ProbeProcess([hashtable]$State, $Identity) {
  $processId = [int]$Identity.processId
  if ($processId -le 0 -or
      (Normalize-Path ([string]$Identity.path)) -ne (Normalize-Path ([string]$State.probe.imagePath)) -or
      [string]$Identity.sha256 -ne [string]$State.probe.imageSha256) {
    throw "probe_identity_unverified"
  }
  $process = Get-Process -Id $processId -ErrorAction Stop
  $actualPath = $null
  try { $actualPath = $process.Path } catch { }
  if ([string]::IsNullOrWhiteSpace([string]$actualPath)) {
    try { $actualPath = $process.MainModule.FileName } catch { }
  }
  if ([string]::IsNullOrWhiteSpace([string]$actualPath) -or
      (Normalize-Path ([string]$actualPath)) -ne (Normalize-Path ([string]$State.probe.imagePath)) -or
      (Get-FileHash -LiteralPath $actualPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        [string]$State.probe.imageSha256 -or
      [Math]::Abs(($process.StartTime.ToUniversalTime() -
        [DateTime]::Parse([string]$State.probe.startedAtUtc).ToUniversalTime()).TotalSeconds) -gt 3) {
    throw "probe_identity_unverified"
  }
  $process.Kill()
  if (-not $process.WaitForExit(10000)) { throw "probe_exit_unverified" }
}

function Restore-CandidateServiceBinary([hashtable]$State) {
  $servicePath = [IO.Path]::GetFullPath([string]$State.service.path)
  $serviceDirectory = [IO.Path]::GetDirectoryName($servicePath)
  $backupPath = [IO.Path]::GetFullPath([string]$State.service.backupPath)
  $stagePath = [IO.Path]::GetFullPath([string]$State.probe.stagingPath)
  if ([IO.Path]::GetDirectoryName($backupPath) -ne $serviceDirectory -or
      [IO.Path]::GetDirectoryName($stagePath) -ne $serviceDirectory) {
    throw "service_restore_boundary_violation"
  }

  $expectedServiceHash = [string]$State.service.sha256
  $probeHash = [string]$State.probe.imageSha256
  if ([IO.File]::Exists($stagePath)) {
    $stageHash = (Get-FileHash -LiteralPath $stagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($stageHash -ne $probeHash) { throw "probe_stage_identity_unverified" }
    [IO.File]::Delete($stagePath)
  }

  $backupExists = [IO.File]::Exists($backupPath)
  if ($backupExists -and
      (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedServiceHash) {
    throw "service_backup_identity_unverified"
  }

  if ([IO.File]::Exists($servicePath)) {
    $currentHash = (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($currentHash -eq $expectedServiceHash) {
      if ($backupExists) { [IO.File]::Delete($backupPath) }
    } elseif ($currentHash -eq $probeHash -and $backupExists) {
      [IO.File]::Delete($servicePath)
      [IO.File]::Move($backupPath, $servicePath)
    } else {
      throw "service_image_identity_unverified"
    }
  } elseif ($backupExists) {
    [IO.File]::Move($backupPath, $servicePath)
  } elseif ($State.service.originalMoveAttempted) {
    throw "service_backup_missing"
  } else {
    throw "service_image_missing"
  }

  if ((Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
      $expectedServiceHash) {
    throw "service_restore_hash_mismatch"
  }
  $State.service.originalRestored = $true
  Save-McpEgressGuardState -StatePath $statePath -State $State
}

function Get-RecoveryBackend {
  $getProbeIdentity = { param($State) Get-ProbeProcessIdentity -State $State }.GetNewClosure()
  $stopProbe = { param($State, $Identity) Stop-ProbeProcess -State $State -Identity $Identity }.GetNewClosure()
  $restoreService = { param($State) Restore-CandidateServiceBinary -State $State }.GetNewClosure()
  $verifyService = {
    param($State)
    $path = [string]$State.service.path
    return (Test-Path -LiteralPath $path -PathType Leaf) -and
      ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -eq [string]$State.service.sha256)
  }.GetNewClosure()
  $shutdownService = { param($State) Stop-VerifiedCandidateService -State $State }.GetNewClosure()
  $testFirewallRule = {
    param($RuleName)
    $matches = @(Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue)
    if ($matches.Count -gt 1) { throw "firewall_rule_identity_ambiguous" }
    return $matches.Count -gt 0
  }.GetNewClosure()
  $removeFirewallRule = {
    param($RuleName)
    Remove-NetFirewallRule -Name $RuleName -ErrorAction Stop | Out-Null
  }.GetNewClosure()
  $restoreAudit = { param($State) Restore-OriginalAuditPolicy -State $State }.GetNewClosure()
  return @{
    GetProbeIdentity = $getProbeIdentity
    StopProbe = $stopProbe
    RestoreService = $restoreService
    VerifyService = $verifyService
    ShutdownService = $shutdownService
    TestFirewallRule = $testFirewallRule
    RemoveFirewallRule = $removeFirewallRule
    RestoreAudit = $restoreAudit
  }
}

function Test-EventImagePathMatch([string]$EventPath, [string]$ExpectedPath) {
  $eventValue = $EventPath.Trim().Trim('"').Replace('/', '\').ToLowerInvariant()
  $expectedValue = Normalize-Path $ExpectedPath
  $suffix = $expectedValue.Substring(2).ToLowerInvariant()
  return $eventValue -eq $expectedValue -or $eventValue.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)
}

function Convert-WfpProcessId([string]$Value) {
  $text = $Value.Trim()
  if ($text -match '^0x(?<hex>[0-9a-fA-F]+)$') {
    try {
      return [pscustomobject]@{ success = $true; value = [Convert]::ToInt32($Matches.hex, 16) }
    } catch {
      return [pscustomobject]@{ success = $false; value = 0 }
    }
  }
  $parsed = 0
  $success = [int]::TryParse($text, [ref]$parsed)
  return [pscustomobject]@{ success = $success; value = $parsed }
}

function Test-ExpectedBlockedEvent([hashtable]$State) {
  $expectedDestinations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [void]$expectedDestinations.Add("192.0.2.1")
  [void]$expectedDestinations.Add("2001:db8::1")
  $processId = [int]$State.probe.pid
  if ($processId -le 0 -or -not $State.probe.startedAtUtc) { return $false }
  $startTime = [DateTime]::Parse([string]$State.probe.startedAtUtc).ToUniversalTime()
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 5157; StartTime = $StartTime } -ErrorAction Stop)
    foreach ($event in $events) {
      [xml]$xml = $event.ToXml()
      $fields = @{}
      foreach ($field in $xml.Event.EventData.Data) {
        $fields[[string]$field.Name] = [string]$field.InnerText
      }
      $pidResult = Convert-WfpProcessId ([string]$fields["ProcessID"])
      $eventPid = [int]$pidResult.value
      $pidParsed = [bool]$pidResult.success
      $application = ([string]$fields["Application"]).ToLowerInvariant()
      if ($pidParsed -and $eventPid -eq $ProcessId -and
          $fields["DestAddress"] -and $expectedDestinations.Contains([string]$fields["DestAddress"]) -and
          $fields["DestPort"] -eq "65000" -and
          (Test-EventImagePathMatch -EventPath $application -ExpectedPath ([string]$State.probe.imagePath))) {
        [void]$expectedDestinations.Remove([string]$fields["DestAddress"])
        if ($expectedDestinations.Count -eq 0) { return $true }
      }
    }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function New-GuardState(
  [string]$CandidateDirectory,
  [string]$ServicePath,
  [string[]]$ExecutablePaths,
  [string]$Prefix
) {
  $temporaryRoot = Join-Path $env:RUNNER_TEMP ($Prefix + "-recovery")
  $auditBackup = Join-Path $temporaryRoot "audit-policy.csv"
  $serviceBackup = Join-Path $CandidateDirectory (".b1-service-original-" + [guid]::NewGuid().ToString("N") + ".bin")
  $probeStage = Join-Path $CandidateDirectory (".b1-probe-stage-" + [guid]::NewGuid().ToString("N") + ".bin")
  $ruleNames = [Collections.Generic.List[string]]::new()
  for ($index = 0; $index -lt $ExecutablePaths.Count; $index++) {
    $rulePrefix = "$Prefix-$index"
    $ruleNames.Add("$rulePrefix-IPv4")
    $ruleNames.Add("$rulePrefix-IPv6")
  }
  return @{
    schema = "codex-bridge-b1-egress-recovery/v2"
    phase = "prepared"
    blockedReason = $null
    statePath = [IO.Path]::GetFullPath($statePath)
    candidateDirectory = [IO.Path]::GetFullPath($CandidateDirectory)
    artifactRoot = [IO.Path]::GetFullPath((Split-Path -Parent $CandidateDirectory))
    temporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
    protectedExecutablePaths = @($ExecutablePaths | ForEach-Object { [IO.Path]::GetFullPath($_) })
    service = @{
      path = [IO.Path]::GetFullPath($ServicePath)
      sha256 = $expectedServiceDigest
      backupPath = [IO.Path]::GetFullPath($serviceBackup)
      originalMoveAttempted = $false
      originalMoved = $false
      originalRestored = $true
    }
    probe = @{
      startAttempted = $false
      pid = 0
      startWindowUtc = $null
      startedAtUtc = $null
      imagePath = [IO.Path]::GetFullPath($ServicePath)
      imageSha256 = $null
      stagingPath = [IO.Path]::GetFullPath($probeStage)
      installedAtServicePath = $false
      exitConfirmed = $true
      terminationAttempted = $false
      terminated = $false
      exitCode = $null
    }
    firewall = @{
      ruleNames = @($ruleNames.ToArray())
      verifiedRuleNames = @()
      removedRuleNames = @()
    }
    audit = @{
      backupPath = [IO.Path]::GetFullPath($auditBackup)
      backupAttempted = $false
      backupCreated = $false
      backupSha256 = $null
      changeAttempted = $false
      restored = $false
    }
    network = @{
      levels = @{ L1 = "PENDING"; L2 = "PENDING"; L3 = "BLOCKED"; L4 = "BLOCKED" }
      l3Reason = "service_outbound_event_not_observed"
      l4Reason = "hosted_runner_path_rules_do_not_constrain_unknown_child_processes"
      serviceStartAllowed = $false
    }
    captureDirectory = [string]$env:CODEX_BRIDGE_MCP_PROCESS_CAPTURE_DIR
    pidRecordPath = [string]$env:CODEX_BRIDGE_MCP_PROCESS_PID_FILE
    cleanup = @{
      serviceStopped = $false
      temporaryFilesStarted = $false
      temporaryFilesComplete = $false
      completed = $false
    }
    createdAtUtc = [DateTime]::UtcNow.ToString("o")
  }
}

function Restore-OriginalAuditPolicy([hashtable]$State) {
  if (-not $State.audit.changeAttempted -or $State.audit.restored) { return }
  $backup = [string]$State.audit.backupPath
  if (-not $State.audit.backupCreated -or -not (Test-Path -LiteralPath $backup -PathType Leaf) -or
      (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        [string]$State.audit.backupSha256) {
    throw "audit_backup_identity_unverified"
  }
  $auditpol = Join-Path $env:SystemRoot "System32\auditpol.exe"
  & $auditpol /restore /file:$backup *> $null
  if ($LASTEXITCODE -ne 0) { throw "audit_policy_restore_failed" }
  $State.audit.restored = $true
  Save-GuardState
}

function Stop-VerifiedCandidateService([hashtable]$State) {
  $servicePath = Normalize-Path ([string]$State.service.path)
  $protectedPaths = @($State.protectedExecutablePaths)
  $processes = @(Get-ProgramProcesses -Paths $protectedPaths)
  $serviceProcesses = @($processes | Where-Object {
    (Normalize-Path ([string]$_.ExecutablePath)) -eq $servicePath
  })
  if ($serviceProcesses.Count -gt 1) { throw "multiple_candidate_service_processes" }

  $record = $null
  if ($State.pidRecordPath -and (Test-Path -LiteralPath ([string]$State.pidRecordPath))) {
    $pidPath = [IO.Path]::GetFullPath([string]$State.pidRecordPath)
    if ((Normalize-Path (Split-Path -Parent $pidPath)) -ne (Normalize-Path $env:RUNNER_TEMP)) {
      throw "service_pid_record_boundary_violation"
    }
    $record = Get-Content -LiteralPath $pidPath -Raw | ConvertFrom-Json -AsHashtable
    if ($serviceProcesses.Count -eq 1 -and [int]$record.pid -gt 0 -and
        [int]$record.pid -ne [int]$serviceProcesses[0].ProcessId) {
      throw "service_pid_record_mismatch"
    }
  } elseif ($serviceProcesses.Count -gt 0) {
    throw "service_pid_record_missing"
  }

  $rootProcessId = if ($serviceProcesses.Count -eq 1) {
    [int]$serviceProcesses[0].ProcessId
  } elseif ($null -ne $record) {
    [int]$record.pid
  } else {
    0
  }
  if ($rootProcessId -gt 0) {
    Assert-NoUncoveredChildProcess -RootProcessId $rootProcessId -ProtectedPaths $protectedPaths
  }

  if ($serviceProcesses.Count -eq 1) {
    if (-not (Test-Path -LiteralPath $servicePath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
          [string]$State.service.sha256) {
      throw "shutdown_image_identity_mismatch"
    }
    $shutdown = [Diagnostics.Process]::Start((New-ShutdownProcess -ServicePath $servicePath))
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
    if ($remaining.Count -eq 0) { return $true }
    if ($rootProcessId -gt 0) {
      Assert-NoUncoveredChildProcess -RootProcessId $rootProcessId -ProtectedPaths $protectedPaths
    }
    Start-Sleep -Milliseconds 250
  } while ([DateTime]::UtcNow -lt $deadline)
  throw "candidate_or_bundled_helper_process_remains"
}

function Assert-NoUncoveredChildProcess([int]$RootProcessId, [string[]]$ProtectedPaths) {
  $processes = @(Get-CimInstance -ClassName Win32_Process `
    -Property ProcessId, ParentProcessId, Name, ExecutablePath -ErrorAction Stop)
  $protected = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($path in $ProtectedPaths) { [void]$protected.Add((Normalize-Path $path)) }
  $visited = [Collections.Generic.HashSet[int]]::new()
  [void]$visited.Add($RootProcessId)
  $frontier = [Collections.Generic.Queue[int]]::new()
  $frontier.Enqueue($RootProcessId)
  while ($frontier.Count -gt 0) {
    $parent = $frontier.Dequeue()
    foreach ($child in $processes) {
      $childId = [int]$child.ProcessId
      if ([int]$child.ParentProcessId -ne $parent -or -not $visited.Add($childId)) { continue }
      if ([string]::IsNullOrWhiteSpace([string]$child.ExecutablePath)) {
        throw "service_child_image_unavailable"
      }
      if (-not $protected.Contains((Normalize-Path ([string]$child.ExecutablePath)))) {
        throw "service_child_process_outside_candidate_bundle"
      }
      $frontier.Enqueue($childId)
    }
  }
}

function Apply-EgressGuard {
  Assert-FreshRunner
  if (Test-Path -LiteralPath $statePath) { throw "recovery_state_already_exists" }
  $candidateDirectory = [IO.Path]::GetFullPath($env:CODEX_BRIDGE_CANDIDATE_DIR)
  $servicePath = Join-Path $candidateDirectory $serviceName
  if (-not (Test-Path -LiteralPath $servicePath -PathType Leaf) -or
      (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedServiceDigest) {
    throw "candidate_service_identity_mismatch"
  }

  . (Join-Path $env:GITHUB_WORKSPACE "Scripts\windows-portable-support.ps1")
  $executables = @(Get-ChildItem -LiteralPath $candidateDirectory -File -Recurse -Filter "*.exe")
  if ($executables.Count -lt 2 -or -not ($executables.FullName -contains $servicePath)) {
    throw "portable_executable_set_invalid"
  }
  foreach ($executable in $executables) {
    if ((Get-PEMachine $executable.FullName) -ne [UInt16]0x8664) {
      throw "portable_executable_architecture_mismatch"
    }
  }

  $prefix = "CodexBridgeB1-" + [Guid]::NewGuid().ToString("N")
  $script:guardState = New-GuardState `
    -CandidateDirectory $candidateDirectory `
    -ServicePath $servicePath `
    -ExecutablePaths @($executables.FullName) `
    -Prefix $prefix
  Save-GuardState

  try {
    New-Item -ItemType Directory -Path $script:guardState.temporaryRoot -ErrorAction Stop | Out-Null
    $ruleIndex = 0
    foreach ($executable in $executables) {
      Add-ProgramBlockRules `
        -Program $executable.FullName `
        -RulePrefix "$prefix-$ruleIndex" `
        -RemoteAddressesIPv4 $ipv4RemoteAddresses `
        -RemoteAddressesIPv6 $ipv6RemoteAddresses
      $ruleIndex++
    }
    $ipv4Verified = @($script:guardState.firewall.verifiedRuleNames | Where-Object { $_ -match '-IPv4$' }).Count
    $ipv6Verified = @($script:guardState.firewall.verifiedRuleNames | Where-Object { $_ -match '-IPv6$' }).Count
    if ($ipv4Verified -ne $executables.Count -or $ipv6Verified -ne $executables.Count) {
      throw "firewall_family_verification_incomplete"
    }
    $script:guardState.network.levels.L1 = "PASS"
    $script:guardState.phase = "l1-path-rules-verified"
    Save-GuardState
    Write-Output "PASS isolation_level=L1 candidate_paths=$($executables.Count) ipv4_rules=$ipv4Verified ipv6_rules=$ipv6Verified"

    $auditpol = Join-Path $env:SystemRoot "System32\auditpol.exe"
    $script:guardState.audit.backupAttempted = $true
    Save-GuardState
    & $auditpol /backup /file:$($script:guardState.audit.backupPath) *> $null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $script:guardState.audit.backupPath -PathType Leaf)) {
      throw "audit_policy_backup_failed"
    }
    $script:guardState.audit.backupCreated = $true
    $script:guardState.audit.backupSha256 =
      (Get-FileHash -LiteralPath $script:guardState.audit.backupPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Save-GuardState
    $script:guardState.audit.changeAttempted = $true
    Save-GuardState
    & $auditpol /set /subcategory:$auditSubcategory /success:disable /failure:enable *> $null
    if ($LASTEXITCODE -ne 0) { throw "wfp_audit_enable_failed" }

    $probeSource = Join-Path $env:GITHUB_WORKSPACE ".github\scripts\MCPProcessEgressProbe.cs"
    $probeBuild = Join-Path $script:guardState.temporaryRoot "MCPProcessEgressProbe.exe"
    $compiler = Join-Path $env:SystemRoot "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if (-not (Test-Path -LiteralPath $compiler) -or -not (Test-Path -LiteralPath $probeSource)) {
      throw "egress_probe_compiler_or_source_missing"
    }
    & $compiler /nologo /target:exe "/out:$probeBuild" $probeSource *> $null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $probeBuild -PathType Leaf)) {
      throw "egress_probe_compile_failed"
    }
    $script:guardState.probe.imageSha256 =
      (Get-FileHash -LiteralPath $probeBuild -Algorithm SHA256).Hash.ToLowerInvariant()
    Save-GuardState

    if (Test-Path -LiteralPath $script:guardState.service.backupPath) { throw "probe_backup_collision" }
    if (Test-Path -LiteralPath $script:guardState.probe.stagingPath) { throw "probe_stage_collision" }
    $script:guardState.service.originalMoveAttempted = $true
    $script:guardState.service.originalRestored = $false
    $script:guardState.phase = "service-backup-intent"
    Save-GuardState
    [IO.File]::Move($servicePath, [string]$script:guardState.service.backupPath)
    if ((Get-FileHash -LiteralPath $script:guardState.service.backupPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        $expectedServiceDigest) { throw "service_backup_hash_mismatch" }
    $script:guardState.service.originalMoved = $true
    $script:guardState.phase = "service-backed-up"
    Save-GuardState

    Copy-Item -LiteralPath $probeBuild -Destination $script:guardState.probe.stagingPath -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $script:guardState.probe.stagingPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
        [string]$script:guardState.probe.imageSha256) { throw "probe_stage_hash_mismatch" }
    $script:guardState.phase = "probe-staged"
    Save-GuardState
    [IO.File]::Move([string]$script:guardState.probe.stagingPath, $servicePath)
    $script:guardState.probe.installedAtServicePath = $true
    $script:guardState.phase = "probe-installed"
    Save-GuardState

    $probeProcessId = Invoke-IsolatedProbe -ProbePath $servicePath -CandidatePath $servicePath
    if ($probeProcessId -ne [int]$script:guardState.probe.pid -or
        -not (Test-ExpectedBlockedEvent -State $script:guardState)) {
      throw "wfp_probe_pid_path_event_mismatch"
    }
    Restore-CandidateServiceBinary -State $script:guardState
    $script:guardState.network.levels.L2 = "PASS"
    $script:guardState.phase = "l2-same-path-probe-verified"
    Save-GuardState
    Write-Output "PASS isolation_level=L2 probe_pid=$probeProcessId image=independent-csharp path_match=PASS wfp_event=5157 ipv4=blocked ipv6=blocked loopback=ipv4,ipv6"

    $script:guardState.network.levels.L3 = "BLOCKED"
    $script:guardState.network.levels.L4 = "BLOCKED"
    $script:guardState.network.serviceStartAllowed = $false
    $script:guardState.phase = "service-start-blocked"
    $script:guardState.blockedReason = "hosted_runner_cannot_prove_service_and_process_tree_egress_isolation"
    Save-GuardState
    if (Test-Path -LiteralPath $env:GITHUB_ENV -PathType Leaf) {
      Add-Content -LiteralPath $env:GITHUB_ENV -Value "CODEX_BRIDGE_B1_ISOLATION_LEVEL=L1_L2_ONLY"
    }
    Write-Output "BLOCKED isolation_level=L3 reason=service_outbound_attempt_not_observed"
    Write-Output "BLOCKED isolation_level=L4 reason=path_rules_do_not_constrain_unknown_process_tree_egress"
    throw "process_tree_isolation_unavailable"
  } catch {
    $failure = [string]$_.Exception.Message
    if ($failure -notmatch '^[a-z0-9_]{1,96}$') { $failure = "egress_guard_verification_failed" }
    if ($null -ne $script:guardState) {
      try {
        $script:guardState.failureCategory = $failure
        Save-GuardState
        Invoke-McpEgressGuardRecovery -StatePath $statePath -State $script:guardState -Backend (Get-RecoveryBackend) | Out-Null
        Write-Output "PASS test=apply-partial-recovery status=restored"
      } catch {
        $recovery = [string]$_.Exception.Message
        if ($recovery -notmatch '^[a-z0-9_]{1,96}$') { $recovery = "recovery_action_failed" }
        Write-Output "BLOCKED stage=apply-recovery error_category=$recovery"
        throw "apply_recovery_blocked"
      }
    }
    throw $failure
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

function Remove-SafeRunnerTree(
  [string]$Path,
  [string]$ExpectedParent,
  [string]$ExpectedPrefix,
  [string]$ExpectedLeaf = $null
) {
  $fullPath = [IO.Path]::GetFullPath($Path)
  if ((Normalize-Path (Split-Path -Parent $fullPath)) -ne (Normalize-Path $ExpectedParent)) {
    throw "runner_temp_cleanup_boundary_violation"
  }
  $leaf = [IO.Path]::GetFileName($fullPath)
  if ($ExpectedLeaf) {
    if ($leaf -ne $ExpectedLeaf) { throw "runner_temp_cleanup_boundary_violation" }
  } elseif (-not $leaf.StartsWith($ExpectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "runner_temp_cleanup_boundary_violation"
  }
  if (-not (Test-Path -LiteralPath $fullPath)) { return }
  $items = @(Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop) + @(
    Get-ChildItem -LiteralPath $fullPath -Force -Recurse -ErrorAction Stop
  )
  if (@($items | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -gt 0) {
    throw "runner_temp_cleanup_reparse_point"
  }
  Remove-Item -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop
}

function Remove-SafeRunnerFile([string]$Path, [string]$ExpectedParent, [string]$ExpectedLeaf) {
  $fullPath = [IO.Path]::GetFullPath($Path)
  if ((Normalize-Path (Split-Path -Parent $fullPath)) -ne (Normalize-Path $ExpectedParent) -or
      [IO.Path]::GetFileName($fullPath) -ne $ExpectedLeaf) {
    throw "runner_temp_cleanup_boundary_violation"
  }
  if (-not (Test-Path -LiteralPath $fullPath)) { return }
  $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "runner_temp_cleanup_reparse_point"
  }
  Remove-Item -LiteralPath $fullPath -Force -ErrorAction Stop
}

function Cleanup-Runner {
  if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    Write-Output "BLOCKED stage=cleanup reason=recovery_state_missing"
    throw "recovery_state_missing"
  }
  $stateItem = Get-Item -LiteralPath $statePath -Force -ErrorAction Stop
  if (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "recovery_state_identity_unverified"
  }
  try {
    $script:guardState = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable
  } catch {
    throw "recovery_state_invalid"
  }
  $state = $script:guardState
  $runnerTemp = Normalize-Path $env:RUNNER_TEMP
  $candidateDirectory = Normalize-Path ([string]$state.candidateDirectory)
  $artifactRoot = Normalize-Path ([string]$state.artifactRoot)
  $temporaryRoot = Normalize-Path ([string]$state.temporaryRoot)
  $servicePath = Normalize-Path ([string]$state.service.path)
  if ((Normalize-Path (Split-Path -Parent $statePath)) -ne $runnerTemp -or
      (Normalize-Path ([string]$state.statePath)) -ne (Normalize-Path $statePath) -or
      (Normalize-Path (Split-Path -Parent $artifactRoot)) -ne $runnerTemp -or
      -not ([IO.Path]::GetFileName($artifactRoot)).StartsWith(
        "codex-bridge-b1-artifact-", [StringComparison]::OrdinalIgnoreCase) -or
      [IO.Path]::GetFileName($candidateDirectory) -ne "portable-payload" -or
      (Normalize-Path (Split-Path -Parent $candidateDirectory)) -ne $artifactRoot -or
      (Normalize-Path $servicePath) -ne (Normalize-Path (Join-Path $candidateDirectory $serviceName)) -or
      (Normalize-Path (Split-Path -Parent $temporaryRoot)) -ne $runnerTemp -or
      -not ([IO.Path]::GetFileName($temporaryRoot)).StartsWith(
        "CodexBridgeB1-", [StringComparison]::OrdinalIgnoreCase) -or
      (Normalize-Path (Split-Path -Parent ([string]$state.service.backupPath))) -ne $candidateDirectory -or
      (Normalize-Path (Split-Path -Parent ([string]$state.probe.stagingPath))) -ne $candidateDirectory -or
      (Normalize-Path (Split-Path -Parent ([string]$state.audit.backupPath))) -ne $temporaryRoot) {
    throw "candidate_cleanup_boundary_violation"
  }

  $recovery = Invoke-McpEgressGuardRecovery `
    -StatePath $statePath `
    -State $state `
    -Backend (Get-RecoveryBackend)
  if ($recovery -notin @("guard-restored", "already-complete")) {
    throw "recovery_completion_unconfirmed"
  }
  $remaining = @(Get-ProgramProcesses -Paths @($state.protectedExecutablePaths))
  if ($remaining.Count -gt 0) { throw "candidate_or_bundled_helper_process_remains" }

  $cmdkey = Join-Path $env:SystemRoot "System32\cmdkey.exe"
  foreach ($target in @(Get-BridgeCredentialTargets)) {
    & $cmdkey "/delete:$target" *> $null
    if ($LASTEXITCODE -ne 0) { throw "generated_bridge_credential_cleanup_failed" }
  }
  if (@(Get-BridgeCredentialTargets).Count -gt 0) {
    throw "generated_bridge_credential_cleanup_incomplete"
  }

  $pidRecordPath = [string]$state.pidRecordPath
  if ($pidRecordPath -and (Test-Path -LiteralPath $pidRecordPath -PathType Leaf)) {
    $pidRecordPath = [IO.Path]::GetFullPath($pidRecordPath)
    if ((Normalize-Path (Split-Path -Parent $pidRecordPath)) -ne $runnerTemp -or
        [IO.Path]::GetFileName($pidRecordPath) -ne "codex-bridge-b1-service.pid.json") {
      throw "runner_temp_cleanup_boundary_violation"
    }
    $record = Get-Content -LiteralPath $pidRecordPath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable
    foreach ($field in @("dataRoot", "profileRoot")) {
      $path = [string]$record[$field]
      if ([string]::IsNullOrWhiteSpace($path)) { throw "runner_temp_cleanup_path_missing" }
      $itemPath = [IO.Path]::GetFullPath($path)
      $leaf = [IO.Path]::GetFileName($itemPath)
      $expectedPrefix = if ($field -eq "dataRoot") { "codex-bridge-b1-data-" } else { "codex-bridge-b1-profile-" }
      if ((Normalize-Path (Split-Path -Parent $itemPath)) -ne $runnerTemp -or
          -not $leaf.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "runner_temp_cleanup_boundary_violation"
      }
      Remove-SafeRunnerTree -Path $itemPath -ExpectedParent $runnerTemp -ExpectedPrefix $expectedPrefix
    }
  }

  $capturePath = [string]$state.captureDirectory
  if ($capturePath) {
    Remove-SafeRunnerTree `
      -Path $capturePath `
      -ExpectedParent $runnerTemp `
      -ExpectedPrefix "" `
      -ExpectedLeaf "codex-bridge-mcp-process-captures"
  }

  $script:guardState.cleanup.temporaryFilesStarted = $true
  $script:guardState.phase = "temporary-cleanup"
  Save-GuardState
  Remove-SafeRunnerTree `
    -Path $temporaryRoot `
    -ExpectedParent $runnerTemp `
    -ExpectedPrefix "CodexBridgeB1-"
  Remove-SafeRunnerTree `
    -Path $artifactRoot `
    -ExpectedParent $runnerTemp `
    -ExpectedPrefix "codex-bridge-b1-artifact-"
  Remove-SafeRunnerFile `
    -Path (Join-Path $runnerTemp "codex-bridge-b1-swift-test.log") `
    -ExpectedParent $runnerTemp `
    -ExpectedLeaf "codex-bridge-b1-swift-test.log"
  if ($pidRecordPath) {
    Remove-SafeRunnerFile `
      -Path $pidRecordPath `
      -ExpectedParent $runnerTemp `
      -ExpectedLeaf "codex-bridge-b1-service.pid.json"
  }

  $script:guardState.cleanup.temporaryFilesComplete = $true
  $script:guardState.cleanup.completed = $true
  $script:guardState.phase = "complete"
  $script:guardState.blockedReason = $null
  Save-GuardState
  Write-Output "PASS test=process-shutdown image=verified-portable/codex-bridge-service.exe"
  Write-Output "PASS test=network-guard-cleanup status=restored state=retained"
}

try {
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { throw "runner_temp_missing" }
  if ($Mode -eq "Apply") {
    Apply-EgressGuard
  } else {
    Cleanup-Runner
  }
} catch {
  $category = [string]$_.Exception.Message
  if ($category -notmatch '^[a-z0-9_]{1,96}$') { $category = "guard_operation_failed" }
  if (Test-Path -LiteralPath $statePath -PathType Leaf) {
    try {
      $stateFile = Get-Item -LiteralPath $statePath -Force -ErrorAction Stop
      if (($stateFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        $savedState = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable
        if ($savedState.schema -eq "codex-bridge-b1-egress-recovery/v2" -and
            (Normalize-Path ([string]$savedState.statePath)) -eq (Normalize-Path $statePath)) {
          $script:guardState = $savedState
          $script:guardState.phase = "blocked"
          $script:guardState.blockedReason = $category
          Save-GuardState
        }
      }
    } catch {
      $category = "recovery_state_write_failed"
    }
  }
  Write-Output "BLOCKED stage=$Mode error_category=$category"
  Write-Output "ERROR_CATEGORY=$category"
  exit 1
}
