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
    if ($trust) {$Arguments.Add('--trust')}
    $Arguments.Add($User)
    $VaultParams = Get-VaultParams -VaultName $VaultName
    Invoke-lpass -Arguments $Arguments -VaultParams $VaultParams
}

function Disconnect-LastPass {
    [CmdletBinding()]
    param (
        [String]$VaultName
    )
    $Arguments = [System.Collections.Generic.List[String]]@('logout')
    $VaultParams = Get-VaultParams -VaultName $VaultName
    Invoke-lpass -Arguments $Arguments -VaultParams $VaultParams
}

function Register-LastPassVault {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]$VaultName,
        [String]$Command,
        [String]$Path
    )
 
    $Params = @{
        ModuleName = 'SecretManagement.LastPass'
        Name = $VaultName
        VaultParameters = @{}
    }

    if ('' -ne $Command) { $Params.VaultParameters.Add('lpassCommand', $Command) }
    if ('' -ne $Path) { $Params.VaultParameters.Add('lpassPath', $Path) }

    Register-SecretVault @Params
}
function Unregister-LastPassVault {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$VaultName
    )
    Unregister-SecretVault -Name $VaultName 
}

Function Get-VaultParams($VaultName) {
    if ([String]::IsNullOrEmpty($VaultName)){ 
            $AllVaults = Get-SecretVault | Where-Object ModuleName -eq $ModuleName
            switch ($AllVaults.count) {
                0 { Throw "At least 1 vault implementing $ModuleName must be registered.";break }
                1 { return $AllVaults[0].VaultParameters }
                Default { Throw "`$VaultName argument must be provided when multiple vault implementing $ModuleName exists $($AllVaults.Name -join ',')" }
            }
    }

    $VaultParams = (Get-SecretVault -Name $VaultName -ErrorAction Stop).VaultParameters
    return $VaultParams

}