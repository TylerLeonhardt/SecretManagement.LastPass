# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using namespace Microsoft.PowerShell.SecretManagement

$ModuleName = 'SecretManagement.LastPass'
function Connect-LastPass {
    [CmdletBinding()]
    param (
        [String]$VaultName,
        [String]$User,
        [Switch]$Trust
    )
    $Arguments = [System.Collections.Generic.List[String]]@('login')
    if ($trust) { $Arguments.Add('--trust') }
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
    if ($Vault.ModuleName -ne $ModuleName) {Throw "The specified vault is not a $ModuleName vault (VaultType: $($Vault.ModuleName)"}
    Unregister-SecretVault @Params 
}

Function Get-VaultParams {
    Param($VaultName)
    if ([String]::IsNullOrEmpty($VaultName)) { 
        $AllVaults = Get-SecretVault | Where-Object ModuleName -eq $ModuleName
        switch ($AllVaults.count) {
            0 { Throw "At least 1 vault implementing $ModuleName must be registered."; break }
            1 { return $AllVaults[0].VaultParameters }
            Default { Throw "`$VaultName argument must be provided when multiple vault implementing $ModuleName exists $($AllVaults.Name -join ',')" }
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
