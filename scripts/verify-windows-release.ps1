param(
  [Parameter(Mandatory = $true)]
  [string]$ExpectedVersion,
  [Parameter(Mandatory = $true)]
  [string]$AppPath,
  [Parameter(Mandatory = $true)]
  [string]$InstallerPath,
  [Parameter(Mandatory = $true)]
  [string]$PolicyPath
)

$ErrorActionPreference = "Stop"
$codeSigningOid = "1.3.6.1.5.5.7.3.3"

function Get-TrustedCertificateChain {
  param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [Parameter(Mandatory = $true)]
    [string]$Label
  )

  $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
  $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
  $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
  $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
  $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(15)
  $valid = $chain.Build($Certificate)
  if (-not $valid) {
    $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ","
    throw "$Label certificate chain is not publicly trusted and revocation-clean: $statuses"
  }
  if ($chain.ChainElements.Count -lt 2) {
    throw "$Label certificate is self-signed; a public Authenticode chain is required."
  }
  $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
  if ($root.Thumbprint -eq $Certificate.Thumbprint) {
    throw "$Label certificate is its own trust root; a public Authenticode chain is required."
  }
  return $root
}

function Get-CertificateSha256 {
  param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )

  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return (($sha256.ComputeHash($Certificate.RawData) | ForEach-Object { $_.ToString("X2") }) -join "")
  } finally {
    $sha256.Dispose()
  }
}

if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
  throw "Windows signing policy does not exist: $PolicyPath"
}
$policy = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json
$allowedSignerSubjects = @($policy.allowedSignerSubjects | Where-Object { $_ -is [string] -and $_.Length -gt 0 })
$allowedRootSha256 = @($policy.allowedRootSha256 | ForEach-Object { ($_ -replace "[^0-9A-Fa-f]", "").ToUpperInvariant() })
if ($allowedRootSha256 | Where-Object { $_ -notmatch "^[0-9A-F]{64}$" }) {
  throw "Windows signing policy contains an invalid root SHA-256 fingerprint."
}

$releaseSignerThumbprint = $null
$releaseSignerSubject = $null
$releaseRootSha256 = $null

$results = foreach ($artifact in @($AppPath, $InstallerPath)) {
  if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
    throw "Windows release artifact does not exist: $artifact"
  }

  $version = (Get-Item -LiteralPath $artifact).VersionInfo.ProductVersion
  if ($version -ne $ExpectedVersion) {
    throw "Unexpected product version '$version' for $artifact; expected $ExpectedVersion."
  }

  $signature = Get-AuthenticodeSignature -FilePath $artifact
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Authenticode status for $artifact is $($signature.Status), not Valid."
  }
  if ($signature.SignatureType -ne [System.Management.Automation.SignatureType]::Authenticode) {
    throw "Signature type for $artifact is $($signature.SignatureType), not Authenticode."
  }
  if ($null -eq $signature.SignerCertificate) {
    throw "Authenticode signer is missing for $artifact."
  }
  if ($null -eq $signature.TimeStamperCertificate) {
    throw "Trusted timestamp is missing for $artifact."
  }
  $eku = @($signature.SignerCertificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
  if ($eku -notcontains $codeSigningOid) {
    throw "Signer certificate for $artifact does not allow code signing."
  }
  $signerRoot = Get-TrustedCertificateChain -Certificate $signature.SignerCertificate -Label "Signer"
  $timestampRoot = Get-TrustedCertificateChain -Certificate $signature.TimeStamperCertificate -Label "Timestamp"
  $signerRootSha256 = Get-CertificateSha256 -Certificate $signerRoot
  if ($allowedSignerSubjects.Count -eq 0 -or $allowedSignerSubjects -notcontains $signature.SignerCertificate.Subject) {
    throw "Signer subject for $artifact is not pinned by the release policy."
  }
  if ($allowedRootSha256.Count -eq 0 -or $allowedRootSha256 -notcontains $signerRootSha256) {
    throw "Signer root for $artifact is not pinned by the release policy."
  }
  if ($null -eq $releaseSignerThumbprint) {
    $releaseSignerThumbprint = $signature.SignerCertificate.Thumbprint
    $releaseSignerSubject = $signature.SignerCertificate.Subject
    $releaseRootSha256 = $signerRootSha256
  } elseif (
    $releaseSignerThumbprint -ne $signature.SignerCertificate.Thumbprint -or
    $releaseSignerSubject -ne $signature.SignerCertificate.Subject -or
    $releaseRootSha256 -ne $signerRootSha256
  ) {
    throw "Application and installer were not signed by the same pinned identity."
  }

  [pscustomobject]@{
    Path = $artifact
    ProductVersion = $version
    Status = $signature.Status.ToString()
    SignatureType = $signature.SignatureType.ToString()
    SignerSubject = $signature.SignerCertificate.Subject
    SignerThumbprint = $signature.SignerCertificate.Thumbprint
    SignerRoot = $signerRoot.Subject
    SignerRootSha256 = $signerRootSha256
    TimestampSubject = $signature.TimeStamperCertificate.Subject
    TimestampRoot = $timestampRoot.Subject
  }
}

$results | ConvertTo-Json -Depth 3 -Compress
