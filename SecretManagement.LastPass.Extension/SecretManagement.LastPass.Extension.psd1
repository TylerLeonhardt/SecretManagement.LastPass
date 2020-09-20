@{
    ModuleVersion = '1.0'
    RootModule = 'SecretManagement.LastPass.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault')
}
