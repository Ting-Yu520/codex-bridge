Set-StrictMode -Version Latest

function Convert-McpVmCreationTime([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  try {
    $local = [Management.ManagementDateTimeConverter]::ToDateTime($Value)
    return $local.ToUniversalTime().ToString("o")
  } catch { return $null }
}

function Get-McpVmProcessSnapshot {
  return @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      processId = [int]$_.ProcessId
      parentProcessId = [int]$_.ParentProcessId
      path = if ($_.ExecutablePath) { [string]$_.ExecutablePath } else { $null }
      createdAtUtc = Convert-McpVmCreationTime ([string]$_.CreationDate)
    }
  })
}

function Test-McpVmSameProcess($Actual, $Expected) {
  if ($null -eq $Actual -or $null -eq $Expected) { return $false }
  if ([int]$Actual.processId -ne [int]$Expected.processId) { return $false }
  if ([string]$Actual.path -ine [string]$Expected.path) { return $false }
  $actualStart = [DateTime]::Parse([string]$Actual.createdAtUtc).ToUniversalTime()
  $expectedStart = [DateTime]::Parse([string]$Expected.createdAtUtc).ToUniversalTime()
  return [Math]::Abs(($actualStart - $expectedStart).TotalSeconds) -le 4
}

function Assert-McpVmSafeTemporaryPath([string]$Path, [string]$RunnerTemp) {
  $root = [IO.Path]::GetFullPath($RunnerTemp).TrimEnd('\', '/')
  $full = [IO.Path]::GetFullPath($Path)
  if ([IO.Path]::GetDirectoryName($full).TrimEnd('\', '/') -ine $root) {
    throw "temporary_path_not_direct_child"
  }
  $leaf = [IO.Path]::GetFileName($full)
  if ($leaf -notmatch '^(codex-bridge-b1-data-|codex-bridge-b1-profile-|codex-bridge-mcp-process-captures(-|$)|codex-bridge-vm-source-|codex-bridge-vm-candidate-)') {
    throw "temporary_path_name_not_allowed"
  }
  return $full
}

function Remove-McpVmSafeTemporaryPath([string]$Path, [string]$RunnerTemp) {
  $full = Assert-McpVmSafeTemporaryPath $Path $RunnerTemp
  if (-not (Test-Path -LiteralPath $full)) { return }
  $rootItem = Get-Item -LiteralPath $full -Force -ErrorAction Stop
  if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "temporary_root_reparse_point"
  }
  if ($rootItem.PSIsContainer) {
    foreach ($item in @(Get-ChildItem -LiteralPath $full -Force -Recurse -ErrorAction Stop)) {
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "temporary_tree_reparse_point"
      }
    }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
  } else {
    Remove-Item -LiteralPath $full -Force -ErrorAction Stop
  }
  if (Test-Path -LiteralPath $full) { throw "temporary_path_remove_unconfirmed" }
}

function Remove-McpVmSafeTemporaryFile([string]$Path, [string]$RunnerTemp, [string]$ExpectedName) {
  if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($ExpectedName)) {
    throw 'temporary_file_identity_missing'
  }
  $root = [IO.Path]::GetFullPath($RunnerTemp).TrimEnd('\', '/')
  $full = [IO.Path]::GetFullPath($Path)
  if ([IO.Path]::GetDirectoryName($full).TrimEnd('\', '/') -ine $root -or
      [IO.Path]::GetFileName($full) -cne $ExpectedName) {
    throw 'temporary_file_identity_mismatch'
  }
  if (-not (Test-Path -LiteralPath $full)) { return }
  $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'temporary_file_type_unverified'
  }
  Remove-Item -LiteralPath $full -Force -ErrorAction Stop
  if (Test-Path -LiteralPath $full) { throw 'temporary_file_remove_unconfirmed' }
}

function New-McpVmProcessBackend {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$CandidatePath,
    [Parameter(Mandatory = $true)][string]$CandidateDirectory,
    [Parameter(Mandatory = $true)][string]$RunnerTemp,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256
  )

  $candidateFull = [IO.Path]::GetFullPath($CandidatePath)
  $candidateDirectoryFull = [IO.Path]::GetFullPath($CandidateDirectory)
  $runnerTempFull = [IO.Path]::GetFullPath($RunnerTemp)
  $getById = {
    param([int]$ProcessId)
    $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
    if ($null -eq $process) { return $null }
    return [pscustomobject]@{
      processId = [int]$process.ProcessId
      parentProcessId = [int]$process.ParentProcessId
      path = if ($process.ExecutablePath) { [string]$process.ExecutablePath } else { $null }
      createdAtUtc = Convert-McpVmCreationTime ([string]$process.CreationDate)
    }
  }.GetNewClosure()
  $getByPath = {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    return @(Get-McpVmProcessSnapshot | Where-Object { $_.path -ieq $full })
  }.GetNewClosure()
  $getDescendants = {
    param([int]$ProcessId, [string]$StartedAtUtc)
    $minimumStart = [DateTime]::Parse($StartedAtUtc).ToUniversalTime().AddSeconds(-1)
    $snapshot = @(Get-McpVmProcessSnapshot)
    $all = @{}
    foreach ($item in $snapshot) { $all[[int]$item.processId] = $item }
    $found = [Collections.Generic.List[object]]::new()
    $frontier = [Collections.Generic.Queue[int]]::new()
    $visited = [Collections.Generic.HashSet[int]]::new()
    $frontier.Enqueue($ProcessId)
    [void]$visited.Add($ProcessId)
    while ($frontier.Count -gt 0) {
      $parent = $frontier.Dequeue()
      foreach ($child in $snapshot) {
        if ([int]$child.parentProcessId -ne $parent -or $visited.Contains([int]$child.processId)) { continue }
        if ([string]::IsNullOrWhiteSpace([string]$child.createdAtUtc)) {
          [void]$visited.Add([int]$child.processId)
          $found.Add($child)
          $frontier.Enqueue([int]$child.processId)
          continue
        }
        $created = [DateTime]::Parse([string]$child.createdAtUtc).ToUniversalTime()
        if ($created -lt $minimumStart) { continue }
        [void]$visited.Add([int]$child.processId)
        $found.Add($child)
        $frontier.Enqueue([int]$child.processId)
      }
    }
    return $found.ToArray()
  }.GetNewClosure()
  $hash = {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  }.GetNewClosure()
  $shutdown = {
    param([string]$Path)
    if ([IO.Path]::GetFullPath($Path) -ine $candidateFull) { return $false }
    $actualHash = (Get-FileHash -LiteralPath $candidateFull -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actualHash -cne $ExpectedSha256.ToLowerInvariant()) { return $false }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $candidateFull
    $info.Arguments = "--shutdown"
    $info.WorkingDirectory = $candidateDirectoryFull
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.EnvironmentVariables.Clear()
    $info.EnvironmentVariables["SystemRoot"] = [Environment]::GetEnvironmentVariable("SystemRoot", "Machine")
    $info.EnvironmentVariables["WINDIR"] = [Environment]::GetEnvironmentVariable("WINDIR", "Machine")
    $process = [Diagnostics.Process]::Start($info)
    if ($null -eq $process) { return $false }
    try {
      if (-not $process.WaitForExit(60000)) { return $false }
      return $process.ExitCode -eq 0
    } finally { $process.Dispose() }
  }.GetNewClosure()
  $waitExit = {
    param([int]$ProcessId, [string]$StartedAtUtc, [int]$TimeoutSeconds)
    $expected = [pscustomobject]@{ processId = $ProcessId; path = $candidateFull; createdAtUtc = $StartedAtUtc }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
      $actual = & $getById $ProcessId
      if (-not (Test-McpVmSameProcess $actual $expected)) { return $true }
      Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
  }.GetNewClosure()
  $waitDescendants = {
    param([object[]]$Items, [int]$TimeoutSeconds)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
      $remaining = $false
      foreach ($item in $Items) {
        $actual = & $getById ([int]$item.processId)
        if (Test-McpVmSameProcess $actual $item) { $remaining = $true; break }
      }
      if (-not $remaining) { return $true }
      Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
  }.GetNewClosure()
  $remove = {
    param([string]$Path)
    Remove-McpVmSafeTemporaryPath $Path $runnerTempFull
  }.GetNewClosure()

  return @{
    GetProcessById = $getById
    GetProcessesByPath = $getByPath
    GetFileHash = $hash
    GetDescendants = $getDescendants
    RequestShutdown = $shutdown
    WaitForExit = $waitExit
    WaitForDescendantsExit = $waitDescendants
    RemoveTemporaryPath = $remove
  }
}

Export-ModuleMember -Function New-McpVmProcessBackend, Remove-McpVmSafeTemporaryFile
