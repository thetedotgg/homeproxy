param(
  [Parameter(Mandatory = $true)]
  [string]$ExpectedVersion,
  [Parameter(Mandatory = $true)]
  [string]$AppPath,
  [Parameter(Mandatory = $true)]
  [string]$InstallerPath,
  [Parameter(Mandatory = $true)]
  [string]$EmbeddedAppPath
)

$ErrorActionPreference = "Stop"

function Get-PeSubsystem {
  param([Parameter(Mandatory = $true)][string]$Path)

  $bytes = [System.IO.File]::ReadAllBytes($Path)
  if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
    throw "$Path is not a valid PE file."
  }
  $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
  if ($peOffset -lt 0 -or $peOffset + 96 -gt $bytes.Length) {
    throw "$Path has an invalid PE header offset."
  }
  if (
    $bytes[$peOffset] -ne 0x50 -or
    $bytes[$peOffset + 1] -ne 0x45 -or
    $bytes[$peOffset + 2] -ne 0 -or
    $bytes[$peOffset + 3] -ne 0
  ) {
    throw "$Path has no PE signature."
  }
  $optionalHeader = $peOffset + 24
  $magic = [BitConverter]::ToUInt16($bytes, $optionalHeader)
  if ($magic -ne 0x10b -and $magic -ne 0x20b) {
    throw "$Path has an unsupported PE optional header."
  }
  return [BitConverter]::ToUInt16($bytes, $optionalHeader + 68)
}

function Test-UnsignedGuiArtifact {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label does not exist: $Path"
  }
  $item = Get-Item -LiteralPath $Path
  if ($item.VersionInfo.ProductName -ne "HomeProxy") {
    throw "$Label ProductName is '$($item.VersionInfo.ProductName)', not HomeProxy."
  }
  if ($item.VersionInfo.ProductVersion -ne $ExpectedVersion) {
    throw "$Label ProductVersion is '$($item.VersionInfo.ProductVersion)', not $ExpectedVersion."
  }
  if ($item.VersionInfo.FileVersion -ne $ExpectedVersion) {
    throw "$Label FileVersion is '$($item.VersionInfo.FileVersion)', not $ExpectedVersion."
  }
  $signature = Get-AuthenticodeSignature -FilePath $Path
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned) {
    throw "$Label Authenticode status is $($signature.Status), not NotSigned."
  }
  $subsystem = Get-PeSubsystem -Path $Path
  if ($subsystem -ne 2) {
    throw "$Label PE subsystem is $subsystem, not Windows GUI (2)."
  }
  [pscustomobject]@{
    Label = $Label
    Path = $Path
    ProductName = $item.VersionInfo.ProductName
    ProductVersion = $item.VersionInfo.ProductVersion
    FileVersion = $item.VersionInfo.FileVersion
    Authenticode = $signature.Status.ToString()
    Subsystem = "WindowsGui"
  }
}

@(
  Test-UnsignedGuiArtifact -Path $AppPath -Label "Application"
  Test-UnsignedGuiArtifact -Path $InstallerPath -Label "Installer"
  Test-UnsignedGuiArtifact -Path $EmbeddedAppPath -Label "Embedded application"
) | ConvertTo-Json -Depth 3 -Compress
