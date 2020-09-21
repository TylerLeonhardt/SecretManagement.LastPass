[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $Package,

    [Parameter()]
    [switch]
    $Publish
)

Push-Location $PSScriptRoot

if ($Package) {
    $outDir = Join-Path 'out' 'SecretManagement.LastPass'
    Remove-Item out -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

    @(
        'SecretManagement.LastPass.Extension'
        'SecretManagement.LastPass.psd1'
        'LICENSE.txt'
        'README.md'
    ) | ForEach-Object {
        Copy-Item -Path $_ -Destination (Join-Path $outDir $_) -Force -Recurse
    }
}

if ($Publish) {
    Write-Host -ForegroundColor Green "Publishing module... here are the details:"
    $moduleData = Import-Module -Force ./out/SecretManagement.LastPass -PassThru
    Write-Host "Version: $($moduleData.Version)"
    Write-Host "Prerelease: $($moduleData.PrivateData.PSData.Prerelease)"
    Write-Host -ForegroundColor Green "Here we go..."

    Publish-Module -Path ./out/SecretManagement.LastPass -NuGetApiKey (Get-Secret -Name PSGalleryApiKey -AsPlainText)
}

Pop-Location
