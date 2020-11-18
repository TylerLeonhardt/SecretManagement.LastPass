#Legacy Windows 5.1
if ($null -eq $IsWindows) {
    Function ConvertFrom-SecureString([parameter(ValueFromPipeline)]$InputObject, [Switch]$AsPlainText) {
        return [pscredential]::new('MyUser', $InputObject).GetNetworkCredential().Password 
    }
}

if (Get-SecretVault 'LastPass.Tests' -ErrorAction Ignore) {
    Unregister-SecretVault 'LastPass.Tests'
}

$modules = 'SecretManagement.LastPass','Microsoft.PowerShell.SecretStore','Microsoft.PowerShell.SecretManagement'

foreach ($module in $modules) {
    if (Get-Module $module) {
        Remove-Module $module -Force
    }
}

$ModulePath = Join-Path "$PSScriptRoot/.."  'SecretManagement.LastPass.psd1'

if ($IsWindows -in @($true, $null)) {$Params = @{VaultParameters = @{wsl = $true}}}
Register-SecretVault $ModulePath -Name 'LastPass.Tests' @Params
Import-Module $ModulePath -Force

