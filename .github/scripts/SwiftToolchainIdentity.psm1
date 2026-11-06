Set-StrictMode -Version Latest

function Get-SwiftToolchainPathId {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { throw 'swift_path_missing' }
  $normalizedPath = [IO.Path]::GetFullPath($Path).Replace('/', '\').ToLowerInvariant()
  $sha256 = [Security.Cryptography.SHA256]::Create()
  try {
    $digest = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalizedPath))
    return [Convert]::ToHexString($digest).ToLowerInvariant()
  } finally {
    $sha256.Dispose()
  }
}

function Get-SwiftToolchainVersionAssessment {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][int]$ExitCode,
    [AllowEmptyCollection()][AllowNull()][string[]]$Output = @(),
    [AllowEmptyString()][string]$ToolchainVariant = ''
  )

  $variantIsSafe = $ToolchainVariant -match '^6\.3\.3(?:\+Asserts)?$'
  $safeVariant = if ($variantIsSafe) { $ToolchainVariant } else { 'unrecognized' }
  $combinedOutput = [string]::Join("`n", @($Output | ForEach-Object { [string]$_ }))
  $versionPattern = '(?im)^\s*(?:Apple\s+)?Swift\s+version\s+(?<version>\d+(?:\.\d+){1,3}(?:[+-][A-Za-z0-9.]+)?)(?=\s|\(|$)'
  $match = [regex]::Match($combinedOutput, $versionPattern)
  $detectedVersion = if ($match.Success) { $match.Groups['version'].Value } else { 'unrecognized' }

  if ($ExitCode -ne 0) {
    $status = 'SWIFT_EXECUTION_FAILED'
  } elseif (-not $match.Success) {
    $status = 'SWIFT_OUTPUT_UNRECOGNIZED'
  } elseif (-not $variantIsSafe -or $detectedVersion -notin @('6.3.3', '6.3.3+Asserts')) {
    $status = 'SWIFT_VERSION_MISMATCH'
  } else {
    $status = 'PASS'
  }

  return [pscustomobject]@{
    status = $status
    exitCode = $ExitCode
    detectedVersion = $detectedVersion
    toolchainVariant = $safeVariant
  }
}

Export-ModuleMember -Function Get-SwiftToolchainPathId, Get-SwiftToolchainVersionAssessment
