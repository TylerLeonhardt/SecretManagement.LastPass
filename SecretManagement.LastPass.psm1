# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using namespace Microsoft.PowerShell.SecretManagement

$ModuleName = 'SecretManagement.LastPass'

# The last segement (underscore + number (eg: _1)) is to view how many format args are expected.
$ErrorMessages = @{
    GetVaultParams0                 = "At least 1 vault implementing $ModuleName must be registered."
    GetVaultParamsMany_1            = "`$Vault argument must be provided when multiple vault implementing $ModuleName exists: {0}"
    Unregister_NotLpass_1           = "The specified vault is not a $ModuleName vault (VaultType: {0}"
}
<#
.SYNOPSIS
Connect the user to LastPass account.

.DESCRIPTION
Connect the user to LastPass account.

.PARAMETER Vault
Name of the vault to connect to.

.PARAMETER User
Username to connect with.

.PARAMETER Trust
Cause subsquent logins to not require multifactor authentication.

.PARAMETER StayConnected
Save the LastPass decryption key on the hard drive so re-entering password once the connection window close is not required anymore. 
This operation will prompt the user.

.PARAMETER Force
Force switch.

.EXAMPLE
PS> Connect-LastPass -Vault MyVault -User User@example.com -Trust

Connect the user User@example.com and disable future MFA prompt.
.EXAMPLE
PS> Connect-LastPass -Vault MyVault -User User@example.com -StayConnected -Force

Connect the user User@example.com and save the decryption key to disk. Password to connect will never be asked again.
#>
function Connect-LastPass {
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'High'
        )]
    param (
        [String]$Vault,
        [String]$User,
        [Switch]$Trust,
        [Switch]$StayConnected,
        [Switch]$Force 
    )
    $Arguments = [System.Collections.Generic.List[String]]@('login')
    if ($trust) { $Arguments.Add('--trust') }
    if ($StayConnected) { 
        if ($Force -and -not $Confirm) { $ConfirmPreference = 'None' }
        
        if ($PSCmdlet.ShouldProcess('Connect-LastPass','Saving LastPass account decryption key on disk')) {
            $Arguments.Add('--plaintext-key') 
            $Arguments.Add('--force')
        }
    }
    $Arguments.Add($User)
    $VaultParams = (Get-SelectedVault -Vault $Vault).VaultParameters
    Invoke-lpass -Arguments $Arguments -VaultParams $VaultParams
}

<#
.SYNOPSIS
Disconnect the user to LastPass account.

.DESCRIPTION
Disconnect the user to LastPass account.

.PARAMETER Vault
Name of the vault to perform the disconnect against.

.EXAMPLE
PS> Disconnect-LastPass
#>
function Disconnect-LastPass {
    [CmdletBinding()]
    param (
        [String]$Vault
    )
    $Arguments = [System.Collections.Generic.List[String]]@('logout', '--force')
    $VaultParams = (Get-SelectedVault -Vault $Vault).VaultParameters
    Invoke-lpass -Arguments $Arguments -VaultParams $VaultParams
}

<#
.SYNOPSIS
Register a SecretVault of type SecretManagement.LastPass

.DESCRIPTION
Register a SecretVault of type SecretManagement.LastPass

.PARAMETER Vault
Name of the vault to be registered. If no name is provided, SecretManagement.LastPass will be used.

.PARAMETER Wsl
Call lpass CLI through Windows Subsystem for Linux (WSL).

.PARAMETER Detailed
All records will be returned as hashtable. Notes and regular credentials. In turn, Notes and URL field from the credential will also be returned.

.PARAMETER Path
Custom path to the lpass CLI.

.EXAMPLE
PS> Register-LastPassVault

Register a vault called SecretManagement.LastPass

.EXAMPLE
PS> Register-LastPassVault -Vault MyVault -Wsl -Detailed

Register a vault called MyVault that will be called through wsl and work with the Detailed output type. 
#>
function Register-LastPassVault {
    [CmdletBinding()]
    param (
        [String]$Vault,
        [switch]$Wsl,
        [Switch]$Detailed,
        [String]$Path
    )

    $Params = @{
        ModuleName      = 'SecretManagement.LastPass'
        Name            = if ('' -ne $Vault) {$Vault} else {$ModuleName}
        Verbose         = $VerbosePreference -eq 'Continue'
        VaultParameters = @{
            wsl         = $Wsl.IsPresent
            outputType  = if ($Detailed) { 'Detailed' } else { 'Default' }
        }
    }

    if ($Path -ne '') { $Params.VaultParameters.Add('lpassPath', $Path) }

    Register-SecretVault @Params
}

<#
.SYNOPSIS
Unregister a SecretVault of type SecretManagement.LastPass.

.DESCRIPTION
Unregister a SecretVault of type SecretManagement.LastPass.

.PARAMETER Vault
Name of the vault to be unregistered.

.EXAMPLE
PS> Unregister-LastPassVault -Vault MyVault

Unregister the vault 'MyVault'.
#>
function Unregister-LastPassVault {
    [CmdletBinding()]
    param (
        [String]$Vault
    )
    $Params = @{
        Name = if ('' -ne $Vault) { $Vault } else { $ModuleName }
        Verbose = $VerbosePreference -eq 'Continue'
    }
    
    $Vault = Get-SecretVault -Name $params.Name -ErrorAction Stop
    if ($Vault.ModuleName -ne $ModuleName) { Throw $ErrorMessages.Unregister_NotLpass_1 -f $Vault.ModuleName }
    Unregister-SecretVault @Params 
}

<#
.SYNOPSIS
Synchronize the local cache with the LastPass servers.

.DESCRIPTION
Synchronize the local cache with the LastPass servers and does not exit until the local cache is synchronized or until an error occurs

.PARAMETER Vault
Name of the vault

.EXAMPLE
Sync-LastPass -Vault MyVault
#>
function Sync-LastPassVault {
    [CmdletBinding()]
    param ([String]$Vault)
    $VaultParams = (Get-SelectedVault -Vault $Vault).VaultParameters
    Invoke-lpass -Arguments 'sync' -VaultParams $VaultParams
}

function Get-SelectedVault {
    Param($Vault)
    if ([String]::IsNullOrEmpty($Vault)) { 
        $DefaultVault = Get-SecretVault -Name $ModuleName -ErrorAction SilentlyContinue
        if ($null -ne $DefaultVault) { return $DefaultVault }

        # If no vault name provided and SecretManagement.LastPass is not a valid vault
        # We pick the vault automatically if there's only one or throw an error.
        $AllVaults = Get-SecretVault | Where-Object ModuleName -eq $ModuleName
        switch ($AllVaults.count) {
            0 { Throw $ErrorMessages.GetVaultParams0; break }
            1 { return $AllVaults[0] }
            Default { Throw $ErrorMessages.GetVaultParamsMany_1 -f $AllVaults.Name -join ',' }
        }
    }

    $VaultParams = (Get-SecretVault -Name $Vault -ErrorAction Stop).VaultParameters
    return $VaultParams

}

<#
.SYNOPSIS
Show LastPass Grid view secrets then show the selected secret.

.DESCRIPTION
Show LastPass Grid view secrets then show the selected secret. 

.PARAMETER Vault
Name of the vault used for the lookup

.PARAMETER Filter
Pre-filter secrets based on the specified keywords

.PARAMETER KeepOpen
If set, the secrets GridView will be automatically reloaded after a secret is shown.

.PARAMETER PassThru
If set, Secret will be returned as is without formatting.

.EXAMPLE
Show-LastPassConsoleGridView -Vault MyVault -KeepOpen 

.NOTES
This cmdlet can make use of the improved Out-ConsoleGridView cmdlet if using Powershell 6.2 or newer and  Microsoft.PowerShell.ConsoleGuiTools is installed.
Otherwise, Out-GridView will be used.
#>
Function Show-LastPassConsoleGridView {
    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        [String]$Vault,
        [String]$Filter = '*',
        [Parameter(ParameterSetName = 'KeepOpen')]
        [Switch]$KeepOpen,
        [Parameter(ParameterSetName = 'PassThru')]
        [Switch]$PassThru
    )
    
    $UseConsoleGridView = $false
    try {
        import-module 'Microsoft.PowerShell.ConsoleGuiTools' -ErrorAction Stop
        $UseConsoleGridView = $true
    }
    catch {
        Write-Debug "Microsoft.Powershell.ConsoleGuiTools could not be loaded.`n$($_ | Out-String)"
    }

    if (!$UseConsoleGridView -and (Get-Command Out-GridView -ErrorAction Stop)){
        throw "Can't find a grid view cmdlet. Try installing the 'Microsoft.PowerShell.ConsoleGuiTools' module and try again."
    }

    $Vault = (Get-SelectedVault -Vault $Vault).Name
    $LastPassSecretInfoCache = Microsoft.Powershell.SecretManagement\Get-SecretInfo -Vault $Vault -Name "$Filter*"

    do {
        if ($UseConsoleGridView) {
            $Result = $LastPassSecretInfoCache | Out-ConsoleGridView -Title "LastPass ($Vault)" -OutputMode Single
        } else {
            $Result = $LastPassSecretInfoCache | Out-GridView -Title "LastPass ($Vault)" -OutputMode Single
        }
        
        if ($null -eq $Result) { break }
        $Result | ForEach-Object { 
            $Secret = Microsoft.Powershell.SecretManagement\Get-Secret -Vault $Vault -Name $_.Name -AsPlainText 
            if ($PassThru) {return $Secret}
                
            Write-host $_.Name -ForegroundColor Cyan
            if ($null -ne $Secret.Notes -and $Secret.Notes.IndexOf("`n") -ne -1) {
                $Notes = $Secret.Notes
                $Secret.Remove('Notes')
                $Secret
                "Notes:`n$Notes"
            } else {
                $Secret
            }
            if ($KeepOpen) { 
                Pause
                Clear-Host 
            }
        }

    } while ($Keepopen)
}

#region VaultNameArgumentCompleter
$VaultArgcompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    return (Get-SecretVault -Name "*$wordToComplete*") | Select-Object -ExpandProperty Name
}
$VaultLPArgcompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    return Get-SecretVault -Name "*$wordToComplete*" | Where-Object ModuleName -eq $ModuleName | Select-Object -ExpandProperty Name
}

Register-ArgumentCompleter -CommandName 'Register-LastPassVault' -ParameterName 'VaultName' -ScriptBlock $VaultArgcompleter
Register-ArgumentCompleter -CommandName 'Unregister-LastPassVault' -ParameterName 'VaultName' -ScriptBlock $VaultLPArgcompleter
#endregion
