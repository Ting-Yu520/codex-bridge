param()

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$expectedRunId = 41665722609
$expectedCommit = "f2235028773e7d9e0da714218a5694c4eb8bfef3"
$expectedArtifactDigest = "a7f64d71df9826402748139329d6ab024b8c9bac0f4711a3ce3aaca84bf8ace8"
$expectedPortableZipDigest = "3e0b733f7c91602e1a18b3f3baf887e1ef22d28cdfeaea9f2046065721e7a92d"
$expectedServiceDigest = "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
$apiRoot = "https://api.github.com/repos/Ting-Yu520/codex-bridge"
$artifactName = "codex-bridge-windows-x64"
$script:ArtifactPreparationHttpStatus = "UNAVAILABLE"
$script:ArtifactPreparationHttpHop = "UNKNOWN"
$script:ArtifactPreparationMockHttpEnabled = $false
$script:ArtifactPreparationMockHttpHandler = $null

function Get-Sha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Download-ArtifactZip([string]$Uri, [string]$Destination) {
  $script:ArtifactPreparationHttpStatus = "UNAVAILABLE"
  $script:ArtifactPreparationHttpHop = "UNKNOWN"
  if ($script:ArtifactPreparationMockHttpEnabled) {
    $handler = $script:ArtifactPreparationMockHttpHandler
    if ($null -eq $handler) { throw "artifact_mock_http_handler_missing" }
  } else {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
  }
  $client = [System.Net.Http.HttpClient]::new($handler)
  $client.Timeout = [TimeSpan]::FromMinutes(10)
  try {
    $current = [Uri]::new($Uri)
    for ($redirect = 0; $redirect -le 5; $redirect++) {
      if ($current.Scheme -ne "https") { throw "artifact_download_non_https" }
      $requestHop = if ($redirect -eq 0 -and $current.Host -eq "api.github.com") {
        "API"
      } elseif ($redirect -gt 0) {
        "REDIRECTED"
      } else {
        "UNKNOWN"
      }
      $script:ArtifactPreparationHttpHop = $requestHop
      $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $current)
      [void]$request.Headers.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new("application/octet-stream"))
      if ($current.Host -eq "api.github.com") {
        [void]$request.Headers.UserAgent.ParseAdd("codex-bridge-b1-artifact-verifier/1.0")
        $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new("Bearer", $env:GITHUB_TOKEN)
        [void]$request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28")
      }
      $response = $client.SendAsync(
        $request,
        [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
      ).GetAwaiter().GetResult()
      try {
        if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) {
          if (-not $response.Headers.Location) { throw "artifact_redirect_location_missing" }
          $next = [Uri]::new($current, $response.Headers.Location)
          $redirectHost = $next.Host.ToLowerInvariant()
          $allowedHost = $redirectHost -eq "api.github.com" -or $redirectHost -eq "github.com" -or
            $redirectHost.EndsWith(".githubusercontent.com") -or $redirectHost.EndsWith(".blob.core.windows.net") -or
            $redirectHost.EndsWith(".actions.githubusercontent.com")
          if ($next.Scheme -ne "https" -or -not $allowedHost) { throw "artifact_redirect_host_not_allowed" }
          $current = $next
          continue
        }
        if (-not $response.IsSuccessStatusCode) {
          $statusCode = [int]$response.StatusCode
          if ($statusCode -ge 100 -and $statusCode -le 599) {
            $script:ArtifactPreparationHttpStatus = [string]$statusCode
          }
          throw "artifact_download_http_failure"
        }
        $source = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $destinationStream = [IO.File]::Create($Destination)
        try { $source.CopyTo($destinationStream) } finally { $destinationStream.Dispose(); $source.Dispose() }
        return
      } finally {
        $response.Dispose()
        $request.Dispose()
      }
    }
    throw "artifact_redirect_limit"
  } finally {
    $client.Dispose()
  }
}

function Assert-PathInside([string]$Root, [string]$Candidate) {
  $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  $candidatePath = [IO.Path]::GetFullPath($Candidate)
  if (-not $candidatePath.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw "unsafe_archive_path"
  }
  return $candidatePath
}

function Expand-SafeZip([string]$ArchivePath, [string]$Destination) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
  $root = [IO.Path]::GetFullPath($Destination)
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
  try {
    [long]$totalExpanded = 0
    foreach ($entry in $archive.Entries) {
      $name = $entry.FullName.Replace('\', '/')
      if ([string]::IsNullOrWhiteSpace($name) -or $name.StartsWith('/') -or $name.Contains(':')) {
        throw "unsafe_archive_entry"
      }
      $segments = @($name.TrimEnd('/') -split '/')
      if ($segments.Count -eq 0 -or $segments -contains '..' -or $segments -contains '.') {
        throw "unsafe_archive_entry"
      }
      $unixType = ([int]($entry.ExternalAttributes -shr 16)) -band 0xF000
      if ($unixType -eq 0xA000) { throw "archive_symlink_not_allowed" }
      $isDirectory = $entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')
      $target = Assert-PathInside $root (Join-Path $root ($name.Replace('/', [IO.Path]::DirectorySeparatorChar)))
      if (-not $seen.Add($target)) { throw "duplicate_archive_entry" }
      if ($isDirectory) {
        New-Item -ItemType Directory -Path $target -Force -ErrorAction Stop | Out-Null
        continue
      }
      $totalExpanded += $entry.Length
      if ($totalExpanded -gt 2GB) { throw "archive_expansion_limit" }
      $parent = Split-Path -Parent $target
      if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
      }
      $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
      if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "archive_reparse_point_not_allowed"
      }
      $input = $entry.Open()
      $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
    }
  } finally {
    $archive.Dispose()
  }
}

function Assert-PortableManifest([string]$PayloadRoot) {
  $manifestPath = Join-Path $PayloadRoot "SHA256SUMS.txt"
  $manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
  if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "manifest_reparse_point"
  }
  $manifestLines = [IO.File]::ReadAllLines($manifestPath, [Text.UTF8Encoding]::new($false, $true))
  $manifest = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($line in $manifestLines) {
    if ($line -notmatch '^([A-Fa-f0-9]{64})  (.+)$') { throw "manifest_format_invalid" }
    $relative = $Matches[2].Replace('\', '/')
    if ($relative.StartsWith('/') -or $relative.Contains(':') -or ($relative -split '/') -contains '..') {
      throw "manifest_path_invalid"
    }
    if (-not $manifest.TryAdd($relative, $Matches[1].ToLowerInvariant())) {
      throw "manifest_duplicate_path"
    }
  }
  $actual = @(Get-ChildItem -LiteralPath $PayloadRoot -File -Recurse -Force | Where-Object {
    [IO.Path]::GetFullPath($_.FullName) -ne [IO.Path]::GetFullPath($manifestPath)
  })
  if ($actual.Count -ne $manifest.Count) { throw "manifest_file_set_mismatch" }
  foreach ($file in $actual) {
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "payload_reparse_point" }
    $relative = $file.FullName.Substring($PayloadRoot.Length).TrimStart('\', '/').Replace('\', '/')
    if (-not $manifest.ContainsKey($relative)) { throw "manifest_file_missing" }
    if ((Get-Sha256 $file.FullName) -ne $manifest[$relative]) { throw "manifest_hash_mismatch" }
  }
  return $manifest.Count
}

$script:ArtifactPreparationStages = @(
  "PRECONDITION",
  "RUN_METADATA",
  "ARTIFACT_LIST",
  "ARTIFACT_DOWNLOAD",
  "OUTER_DIGEST",
  "OUTER_EXTRACTION",
  "PORTABLE_ZIP_IDENTITY",
  "PORTABLE_EXTRACTION",
  "PORTABLE_MANIFEST",
  "BUILD_INFO",
  "SERVICE_IDENTITY",
  "FINAL_VALIDATION"
)

function Get-SafeArtifactPreparationFailureKind(
  [string]$Stage,
  [System.Management.Automation.ErrorRecord]$ErrorRecord
) {
  $message = [string]$ErrorRecord.Exception.Message
  $knownKinds = @{
    "runner_or_read_token_missing" = "REQUIRED_RUNNER_INPUT_MISSING"
    "runner_not_x64" = "RUNNER_ARCHITECTURE_UNSUPPORTED"
    "runner_temp_collision" = "RUNNER_TEMP_COLLISION"
    "source_run_identity_mismatch" = "SOURCE_RUN_IDENTITY_MISMATCH"
    "source_artifact_missing_or_ambiguous" = "SOURCE_ARTIFACT_SELECTION_FAILED"
    "source_artifact_metadata_digest_mismatch" = "ARTIFACT_METADATA_DIGEST_MISMATCH"
    "artifact_download_non_https" = "DOWNLOAD_SCHEME_REJECTED"
    "artifact_redirect_location_missing" = "REDIRECT_LOCATION_MISSING"
    "artifact_redirect_host_not_allowed" = "REDIRECT_HOST_REJECTED"
    "artifact_download_http_failure" = "DOWNLOAD_HTTP_FAILURE"
    "artifact_redirect_limit" = "REDIRECT_LIMIT_EXCEEDED"
    "outer_artifact_digest_mismatch" = "OUTER_ARTIFACT_DIGEST_MISMATCH"
    "unsafe_archive_path" = "UNSAFE_ARCHIVE_PATH_REJECTED"
    "unsafe_archive_entry" = "UNSAFE_ARCHIVE_ENTRY_REJECTED"
    "archive_symlink_not_allowed" = "ARCHIVE_SYMLINK_REJECTED"
    "duplicate_archive_entry" = "DUPLICATE_ARCHIVE_ENTRY_REJECTED"
    "archive_expansion_limit" = "ARCHIVE_EXPANSION_LIMIT"
    "archive_reparse_point_not_allowed" = "ARCHIVE_REPARSE_POINT_REJECTED"
    "portable_zip_missing_or_ambiguous" = "PORTABLE_ZIP_SELECTION_FAILED"
    "portable_zip_digest_mismatch" = "PORTABLE_ZIP_DIGEST_MISMATCH"
    "manifest_reparse_point" = "MANIFEST_REPARSE_POINT_REJECTED"
    "manifest_format_invalid" = "MANIFEST_FORMAT_INVALID"
    "manifest_path_invalid" = "MANIFEST_PATH_INVALID"
    "manifest_duplicate_path" = "MANIFEST_DUPLICATE_PATH"
    "manifest_file_set_mismatch" = "MANIFEST_FILE_SET_MISMATCH"
    "payload_reparse_point" = "PAYLOAD_REPARSE_POINT_REJECTED"
    "manifest_file_missing" = "MANIFEST_FILE_MISSING"
    "manifest_hash_mismatch" = "MANIFEST_HASH_MISMATCH"
    "build_info_identity_mismatch" = "BUILD_INFO_IDENTITY_MISMATCH"
    "service_exe_digest_mismatch" = "SERVICE_EXE_DIGEST_MISMATCH"
    "service_exe_architecture_mismatch" = "SERVICE_EXE_ARCHITECTURE_MISMATCH"
    "portable_runtime_files_missing" = "PORTABLE_RUNTIME_FILES_MISSING"
    "portable_pe_architecture_mismatch" = "PORTABLE_PE_ARCHITECTURE_MISMATCH"
  }

  if ($knownKinds.ContainsKey($message)) { return $knownKinds[$message] }
  $exception = $ErrorRecord.Exception
  while ($null -ne $exception) {
    $exceptionType = $exception.GetType().FullName
    if ($Stage -in @("RUN_METADATA", "ARTIFACT_LIST") -and
        $exceptionType -in @(
          "Microsoft.PowerShell.Commands.HttpResponseException",
          "System.Net.Http.HttpRequestException",
          "System.Net.WebException"
        )) {
      return "GITHUB_API_REQUEST_FAILED"
    }
    if ($Stage -eq "ARTIFACT_DOWNLOAD" -and
        $exceptionType -in @("System.Net.Http.HttpRequestException", "System.Net.WebException")) {
      return "ARTIFACT_DOWNLOAD_FAILED"
    }
    $exception = $exception.InnerException
  }
  return "UNKNOWN"
}

function Write-ArtifactPreparationFailure(
  [string]$Stage,
  [System.Management.Automation.ErrorRecord]$ErrorRecord
) {
  $safeStage = if ($script:ArtifactPreparationStages -contains $Stage) { $Stage } else { "UNKNOWN" }
  $safeKind = Get-SafeArtifactPreparationFailureKind -Stage $safeStage -ErrorRecord $ErrorRecord
  Write-Output "ERROR_CATEGORY=candidate_artifact_preparation_failed"
  Write-Output "ARTIFACT_PREP_FAILED_STAGE=$safeStage"
  Write-Output "ARTIFACT_PREP_FAILURE_KIND=$safeKind"
  if ($safeStage -eq "ARTIFACT_DOWNLOAD") {
    $safeHttpStatus = "UNAVAILABLE"
    $candidateHttpStatus = [string]$script:ArtifactPreparationHttpStatus
    if ($candidateHttpStatus -match '^[1-5][0-9]{2}$') { $safeHttpStatus = $candidateHttpStatus }
    $safeHttpHop = if ($script:ArtifactPreparationHttpHop -in @("API", "REDIRECTED", "UNKNOWN")) {
      [string]$script:ArtifactPreparationHttpHop
    } else {
      "UNKNOWN"
    }
    Write-Output "ARTIFACT_PREP_HTTP_STATUS=$safeHttpStatus"
    Write-Output "ARTIFACT_PREP_HTTP_HOP=$safeHttpHop"
  }
  $script:ArtifactPreparationExitCode = 1
}

function Write-PreparedArtifactEnvironment(
  [string]$GitHubEnvPath,
  [string]$CandidateDirectory,
  [string]$CandidateSha256,
  [string]$CaptureDirectory,
  [string]$PidRecord
) {
  Add-Content -LiteralPath $GitHubEnvPath -Value "CODEX_BRIDGE_CANDIDATE_DIR=$CandidateDirectory"
  Add-Content -LiteralPath $GitHubEnvPath -Value "CODEX_BRIDGE_CANDIDATE_SHA256=$CandidateSha256"
  Add-Content -LiteralPath $GitHubEnvPath -Value "CODEX_BRIDGE_MCP_PROCESS_CAPTURE_DIR=$CaptureDirectory"
  Add-Content -LiteralPath $GitHubEnvPath -Value "CODEX_BRIDGE_MCP_PROCESS_PID_FILE=$PidRecord"
  Add-Content -LiteralPath $GitHubEnvPath -Value "CODEX_BRIDGE_ARTIFACT_VERIFICATION=PASS"
}

if ($MyInvocation.InvocationName -eq ".") {
  $script:ArtifactPreparationMockHttpEnabled = $true
  return
}
$script:ArtifactPreparationMockHttpEnabled = $false

$currentStage = "PRECONDITION"
try {
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
    throw "runner_or_read_token_missing"
  }
  if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne "X64") {
    throw "runner_not_x64"
  }

  $runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
  $workRoot = Join-Path $runnerTemp ("codex-bridge-b1-artifact-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $workRoot -ErrorAction Stop | Out-Null
  $outerZip = Join-Path $workRoot "github-artifact.zip"
  $outerExtract = Join-Path $workRoot "outer"
  $payloadRoot = Join-Path $workRoot "portable-payload"

  $headers = @{
    Authorization = "Bearer $env:GITHUB_TOKEN"
    Accept = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
  }
  $currentStage = "RUN_METADATA"
  $run = Invoke-RestMethod -Method Get -Uri "$apiRoot/actions/runs/$expectedRunId" -Headers $headers -MaximumRedirection 0
  if (([long]$run.id) -ne $expectedRunId -or $run.head_sha -ne $expectedCommit -or $run.head_branch -ne "ci/mcp-cache-hints") {
    throw "source_run_identity_mismatch"
  }

  $currentStage = "ARTIFACT_LIST"
  $artifactList = Invoke-RestMethod -Method Get -Uri "$apiRoot/actions/runs/$expectedRunId/artifacts?per_page=100" -Headers $headers -MaximumRedirection 0
  $matches = @($artifactList.artifacts | Where-Object { $_.name -eq $artifactName -and -not $_.expired })
  if ($matches.Count -ne 1) { throw "source_artifact_missing_or_ambiguous" }
  $artifact = $matches[0]
  $apiDigest = ([string]$artifact.digest -replace '^sha256:', '').ToLowerInvariant()
  if ($apiDigest -ne $expectedArtifactDigest) { throw "source_artifact_metadata_digest_mismatch" }

  $downloadUrl = "$apiRoot/actions/artifacts/$($artifact.id)/zip"
  $currentStage = "ARTIFACT_DOWNLOAD"
  Download-ArtifactZip -Uri $downloadUrl -Destination $outerZip

  $currentStage = "OUTER_DIGEST"
  $outerDigest = Get-Sha256 $outerZip
  if ($outerDigest -ne $expectedArtifactDigest) { throw "outer_artifact_digest_mismatch" }

  $currentStage = "OUTER_EXTRACTION"
  Expand-SafeZip -ArchivePath $outerZip -Destination $outerExtract
  $outerFiles = @(Get-ChildItem -LiteralPath $outerExtract -File -Recurse)

  $currentStage = "PORTABLE_ZIP_IDENTITY"
  $portableZipCandidates = @($outerFiles | Where-Object { $_.Name -eq "codex-bridge-windows-x64.zip" })
  if ($outerFiles.Count -ne 1 -or $portableZipCandidates.Count -ne 1) { throw "portable_zip_missing_or_ambiguous" }
  $portableZip = $portableZipCandidates[0].FullName
  $portableDigest = Get-Sha256 $portableZip
  if ($portableDigest -ne $expectedPortableZipDigest) { throw "portable_zip_digest_mismatch" }

  $currentStage = "PORTABLE_EXTRACTION"
  Expand-SafeZip -ArchivePath $portableZip -Destination $payloadRoot

  $currentStage = "PORTABLE_MANIFEST"
  $manifestFileCount = Assert-PortableManifest -PayloadRoot $payloadRoot

  $currentStage = "BUILD_INFO"
  $buildInfoPath = Join-Path $payloadRoot "BUILD-INFO.json"
  $buildInfo = Get-Content -LiteralPath $buildInfoPath -Raw | ConvertFrom-Json -AsHashtable
  if ($buildInfo.schema -ne "codex-bridge-windows-portable/v1" -or
      $buildInfo.appVersion -ne "2.2.3" -or
      $buildInfo.architecture -ne "x64" -or
      $buildInfo.targetTriple -ne "x86_64-unknown-windows-msvc" -or
      $buildInfo.gitCommit -ne $expectedCommit -or
      $buildInfo.swiftVersion -notmatch '^Swift version 6\.3\.3') {
    throw "build_info_identity_mismatch"
  }

  $currentStage = "SERVICE_IDENTITY"
  $servicePath = Join-Path $payloadRoot "codex-bridge-service.exe"
  if ((Get-Sha256 $servicePath) -ne $expectedServiceDigest) { throw "service_exe_digest_mismatch" }
  . (Join-Path $env:GITHUB_WORKSPACE "Scripts\windows-portable-support.ps1")
  if ((Get-PEMachine $servicePath) -ne [UInt16]0x8664) { throw "service_exe_architecture_mismatch" }

  $currentStage = "FINAL_VALIDATION"
  $portablePEFiles = @(Get-ChildItem -LiteralPath $payloadRoot -File -Recurse | Where-Object { $_.Extension -in @(".exe", ".dll") })
  if ($portablePEFiles.Count -lt 2) { throw "portable_runtime_files_missing" }
  foreach ($peFile in $portablePEFiles) {
    if ((Get-PEMachine $peFile.FullName) -ne [UInt16]0x8664) { throw "portable_pe_architecture_mismatch" }
  }

  $captureDirectory = Join-Path $runnerTemp "codex-bridge-mcp-process-captures"
  $pidRecord = Join-Path $runnerTemp "codex-bridge-b1-service.pid.json"
  if ((Test-Path -LiteralPath $captureDirectory) -or (Test-Path -LiteralPath $pidRecord)) {
    throw "runner_temp_collision"
  }
  $script:ArtifactPreparationExitCode = 0
  Write-PreparedArtifactEnvironment `
    -GitHubEnvPath $env:GITHUB_ENV `
    -CandidateDirectory $payloadRoot `
    -CandidateSha256 $expectedServiceDigest `
    -CaptureDirectory $captureDirectory `
    -PidRecord $pidRecord
  Write-Output "PASS test=source-run run_id=$expectedRunId commit=$expectedCommit"
  Write-Output "PASS test=artifact-outer-zip sha256=$outerDigest"
  Write-Output "PASS test=portable-zip sha256=$portableDigest"
  Write-Output "PASS test=service-exe architecture=x64 sha256=$expectedServiceDigest"
  Write-Output "PASS test=portable-manifest files=$manifestFileCount"
  Write-Output "PASS test=build-info version=$($buildInfo.appVersion) architecture=$($buildInfo.architecture)"
  return
} catch {
  Write-ArtifactPreparationFailure -Stage $currentStage -ErrorRecord $_
  exit 1
}
