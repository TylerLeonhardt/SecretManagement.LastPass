# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using namespace Microsoft.PowerShell.SecretManagement

# The capture groups are:
# 1. The ls short output (just the name & id)
# 2. The name of the secret
# 3. The username of the secret
$lsLongOutput = "\d\d\d\d-\d\d-\d\d \d\d:\d\d ((.*) \[id: \d*\]) \[username: (.*)\]"

function Invoke-lpass {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $Arguments,

        [Parameter(ValueFromPipeline)]
        [object]
        $InputObject
    )

    $lpassCommand = if ($null -ne $AdditionalParameters.lpassCommand){$AdditionalParameters.lpassCommand} else {''}
    $lpassPath = if ($null -ne $AdditionalParameters.lpassPath){"`"$($AdditionalParameters.lpassPath)`""} else {'lpass'}
   
    
    if ($lpassCommand -ne '' -and ((& "$lpassCommand" "$lpassPath" --version ) -like 'LastPass CLI*') ) {
        if ($InputObject) {
            $InputObject | & "$lpassCommand" $lpassPath @Arguments
        }
        else {
            return   & "$lpassCommand" $lpassPath @Arguments
        }
    } elseif (Get-Command $lpassPath) {
        if ($InputObject) {
            $InputObject | & $lpassPath @Arguments
        }
        else {
            return   & $lpassCommand $lpassPath @Arguments
        }
    }
    
    throw "lpass executable not found or installed."
}

function Get-Secret
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )

    # TODO error handling

    if ($Name -match ".* \(id: (\d*)\)") {
        $Name = $Matches[1]
    }

    $res = Invoke-lpass 'show','--name', $Name, '--password'
    if ([string]::IsNullOrWhiteSpace($res)) {
        $res = Invoke-lpass 'show', '--name', $Name, '--notes'
    } else {
        # We have a password, check for a username
        $username = Invoke-lpass 'show', '--name', $Name, '--username'
        if ($username) {
            $res = [System.Management.Automation.PSCredential]::new(
                $username,
                (ConvertTo-SecureString $res -AsPlainText -Force))
        }
    }

    return $res
}

function Set-Secret
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [object] $Secret,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    if($Secret -is [string]) {
        $Secret = @{
            URL = "http://sn"
            Notes = $Secret
        }
    }

    $sb = [System.Text.StringBuilder]::new()
    if($Secret.UserName) {
        $sb.Append("Username: ").AppendLine($Secret.UserName)
        $sb.Append("login: ").AppendLine($Secret.UserName)
    }

    if($Secret.Password) {
        $pass = $Secret.Password
        if ($Secret -is [pscredential]) {
            $pass = $Secret.GetNetworkCredential().password
        } elseif ($pass -is [securestring]) {
            $pass = $pass | ConvertFrom-SecureString
        }

        $sb.Append("Password: ").AppendLine($pass)
        $sb.Append("password: ").AppendLine($pass)
        $sb.Append("sudo_password: ").AppendLine($pass)
    }

    if($Secret.URL) {
        $sb.Append("URL: ").AppendLine($Secret.URL)
    }

    if($Secret.Notes) {
        $sb.AppendLine("Notes:").AppendLine($Secret.Notes)
    }

    try {
        $sb.ToString() | Invoke-lpass 'add', $Name, '--non-interactive'
    } catch {
        return $false
    }
    return $true
}

function Remove-Secret
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )

    if ($Name -match ".* \(id: (\d*)\)") {
        $Name = $Matches[1]
    }

    lpass rm $Name
    return $?
}

function Get-SecretInfo
{
    [CmdletBinding()]
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $Filter = "*$Filter"
    $pattern = [WildcardPattern]::new($Filter)
    Invoke-lpass 'ls','-l' |
        Where-Object { 
            $IsMatch = $_ -match $lsLongOutput 
            if (-not $IsMatch ) { Write-Debug -Message "No match for: $_ `nThis record will be ignored." }
            $IsMatch -and $pattern.IsMatch($Matches[2])
        } |
        ForEach-Object {
            $type = if ($Matches[3]) {
                [SecretType]::PSCredential
            } else {
                [SecretType]::SecureString
            }

            [SecretInformation]::new(
                ($Matches[1] -replace '\[(id: \d*?)\]$', '($1)'), 
                $type,
                $VaultName)
        }
}

function Test-SecretVault
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable] $AdditionalParameters
    )
    return (Get-Command lpass -ErrorAction SilentlyContinue) -and ((lpass status) -match "Logged in as .*")
}
