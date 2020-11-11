if (Get-SecretVault 'LastPass.Tests' -ErrorAction Ignore) {
    Unregister-SecretVault 'LastPass.Tests'
}

$modules = 'SecretManagement.LastPass','Microsoft.PowerShell.SecretStore','Microsoft.PowerShell.SecretManagement'

foreach ($module in $modules) {
    if (Get-Module $module) {
        Remove-Module $module -Force
    }
}

Register-SecretVault (Join-Path $PSScriptRoot '..' 'SecretManagement.LastPass.psd1') -Name 'LastPass.Tests'

Import-Module (Join-Path $PSScriptRoot '..' 'SecretManagement.LastPass.psd1') -Force
