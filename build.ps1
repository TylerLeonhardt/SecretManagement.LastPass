[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $Package
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

Pop-Location
