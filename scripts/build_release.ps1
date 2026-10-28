<#
.SYNOPSIS
    Builds and packages cleaNclean v.1.0.0 for GitHub Releases into the .\dist\ folder:
    1. cleaNclean-v1.0.0-win-x64-standalone.zip  (Self-contained single-file .exe, no .NET runtime required)
    2. cleaNclean-v1.0.0-win-x64-lightweight.zip (Framework-dependent single-file .exe, requires .NET 8 Desktop Runtime)
    3. SHA256SUMS.txt                            (SHA-256 checksums for release verification)
#>

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$CsprojPath  = Join-Path $ProjectRoot "cleaNclean.csproj"
$DistDir     = Join-Path $ProjectRoot "dist"
$PublishRoot = Join-Path $ProjectRoot "publish"

# Locate dotnet CLI (Prefer user profile SDK install if present, otherwise system PATH)
$UserDotnet = Join-Path $env:USERPROFILE ".dotnet\dotnet.exe"
if (Test-Path $UserDotnet) {
    $DotnetExe = $UserDotnet
} elseif (Get-Command "dotnet" -ErrorAction SilentlyContinue) {
    $DotnetExe = "dotnet"
} else {
    throw "Could not find dotnet SDK."
}

$Version = "v1.0.0"

Write-Host "==> Cleaning previous publish/dist directories..." -ForegroundColor Cyan
if (Test-Path $PublishRoot) { Remove-Item $PublishRoot -Recurse -Force }
if (Test-Path $DistDir)     { Remove-Item $DistDir -Recurse -Force }
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

# 1. Build Standalone Self-Contained Single-File Executable (win-x64)
$StandaloneOut = Join-Path $PublishRoot "standalone"
Write-Host "==> Publishing Standalone Self-Contained Single-File (win-x64)..." -ForegroundColor Cyan
& $DotnetExe publish $CsprojPath `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -o $StandaloneOut

Copy-Item (Join-Path $ProjectRoot "README.md") -Destination $StandaloneOut -Force
Copy-Item (Join-Path $ProjectRoot "LICENSE")   -Destination $StandaloneOut -Force

$StandaloneZip = Join-Path $DistDir "cleaNclean-$Version-win-x64-standalone.zip"
Compress-Archive -Path "$StandaloneOut\*" -DestinationPath $StandaloneZip -Force

# 2. Build Lightweight Framework-Dependent Executable (win-x64)
$LightweightOut = Join-Path $PublishRoot "lightweight"
Write-Host "==> Publishing Lightweight Framework-Dependent Single-File (win-x64)..." -ForegroundColor Cyan
& $DotnetExe publish $CsprojPath `
    -c Release `
    -r win-x64 `
    --self-contained false `
    -p:PublishSingleFile=true `
    -o $LightweightOut

Copy-Item (Join-Path $ProjectRoot "README.md") -Destination $LightweightOut -Force
Copy-Item (Join-Path $ProjectRoot "LICENSE")   -Destination $LightweightOut -Force

$LightweightZip = Join-Path $DistDir "cleaNclean-$Version-win-x64-lightweight.zip"
Compress-Archive -Path "$LightweightOut\*" -DestinationPath $LightweightZip -Force

# 3. Generate SHA256SUMS.txt
$ChecksumFile = Join-Path $DistDir "SHA256SUMS.txt"
$HashLines = @()
foreach ($file in Get-ChildItem -Path $DistDir -Filter "*.zip") {
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $HashLines += "$hash  $($file.Name)"
}
Set-Content -Path $ChecksumFile -Value ($HashLines -join "`r`n") -Encoding UTF8

Write-Host "`n==> GitHub Release artifacts successfully created in: $DistDir" -ForegroundColor Green
Get-ChildItem -Path $DistDir | Select-Object Name, @{Name="Size (MB)";Expression={[math]::Round($_.Length / 1MB, 2)}} | Format-Table -AutoSize
