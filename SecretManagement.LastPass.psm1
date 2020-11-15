# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using namespace Microsoft.PowerShell.SecretManagement

$ModuleName = 'SecretManagement.LastPass'

# The last segement (underscore + number (eg: _1)) is to view how many format args are expected.
$ErrorMessages = @{
    GetVaultParams0                 = "At least 1 vault implementing $ModuleName must be registered."
    GetVaultParamsMany_1            = "`$VaultName argument must be provided when multiple vault implementing $ModuleName exists: {0}"
    StayConnectedForceSwitchMissing = 'StayConnected is a sensitive operation that save the LastPass decryption key on your hard drive. If you want to proceed, reissue the command specifying the force parameter.'
    Unregister_NotLpass_1           = "The specified vault is not a $ModuleName vault (VaultType: {0}"
}

function Connect-LastPass {
    [CmdletBinding()]
    param (
        [String]$VaultName,
        [String]$User,
        [Switch]$Trust,
        [Switch]$StayConnected,
        [Switch]$Force 
    )
    $Arguments = [System.Collections.Generic.List[String]]@('login')
    if ($trust) { $Arguments.Add('--trust') }
    if ($StayConnected) { 
        if (! $Force) { Throw [System.Management.Automation.PSArgumentException] $ErrorMessages.StayConnectedForceSwitchMissing }
        $Arguments.Add('--plaintext-key') 
        $Arguments.Add('--force')
    }
    $Arguments.Add($User)
    $VaultParams = Get-VaultParams -VaultName $VaultName
    Invoke-lpass -Arguments $Arguments -VaultParams $VaultParams
}

function Disconnect-LastPass {
    [CmdletBinding()]
    param (
        [String]$VaultName
    )
    $Arguments = [System.Collections.Generic.List[String]]@('logout', '--force')
    $VaultParams = Get-VaultParams -VaultName $VaultName
    Invoke-lpass -Arguments $Arguments -VaultParams $VaultParams
}

function Register-LastPassVault {
    [CmdletBinding()]
    param (
        [String]$VaultName,
        [String]$Command,
        [String]$Path
    )

    $Params = @{
        ModuleName      = 'SecretManagement.LastPass'
        Name            = if ('' -ne $VaultName) {$VaultName} else {$ModuleName}
        VaultParameters = @{}
    }
    if ('' -ne $Command) { $Params.VaultParameters.Add('lpassCommand', $Command) }
    if ('' -ne $Path) { $Params.VaultParameters.Add('lpassPath', $Path) }
    if ($VerbosePreference -eq 'Continue') {$Params.add('Verbose',$true)}

    Register-SecretVault @Params
}
function Unregister-LastPassVault {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$VaultName
    )
    $Params = @{Name = if ('' -ne $VaultName) { $VaultName } else { $ModuleName }}
    if ($VerbosePreference -eq 'Continue') {$Params.Add('Verbose',$true)}
    
    $Vault = Get-SecretVault -Name $params.VaultName -ErrorAction Stop
    if ($Vault.ModuleName -ne $ModuleName) { Throw $ErrorMessages.Unregister_NotLpass_1 -f $Vault.ModuleName}
    Unregister-SecretVault @Params 
}

Function Get-VaultParams {
    Param($VaultName)
    if ([String]::IsNullOrEmpty($VaultName)) { 
        $AllVaults = Get-SecretVault | Where-Object ModuleName -eq $ModuleName
        switch ($AllVaults.count) {
            0 { Throw $ErrorMessages.GetVaultParams0; break }
            1 { return $AllVaults[0].VaultParameters }
            Default { Throw $ErrorMessages.GetVaultParamsMany_1 -f $AllVaults.Name -join ',' }
        }
    }

    $VaultParams = (Get-SecretVault -Name $VaultName -ErrorAction Stop).VaultParameters
    return $VaultParams

}

#region VaultNameArgumentCompleter
$VaultNameArgcompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    return (Get-SecretVault -Name "*$wordToComplete*") | Select-Object -ExpandProperty Name
}
$VaultNameLPArgcompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    return Get-SecretVault -Name "*$wordToComplete*" | Where-Object ModuleName -eq $ModuleName | Select-Object -ExpandProperty Name
}


Register-ArgumentCompleter -CommandName 'Register-LastPassVault' -ParameterName 'VaultName' -ScriptBlock $VaultNameArgcompleter
Register-ArgumentCompleter -CommandName 'Unregister-LastPassVault' -ParameterName 'VaultName' -ScriptBlock $VaultNameLPArgcompleter
#endregion
