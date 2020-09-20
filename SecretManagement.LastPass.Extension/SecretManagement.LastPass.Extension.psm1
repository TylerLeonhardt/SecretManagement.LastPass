# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

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

    if (Get-Command lpass -ErrorAction SilentlyContinue) {
        if ($InputObject) {
            return $InputObject | & lpass @Arguments
        }
        return lpass @Arguments
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

    if ($Name -match ".* \[id: (\d*)\]") {
        $Name = $Matches[1]
    }

    $res = Invoke-lpass 'show','--name', $Name, '--password'
    if ([string]::IsNullOrWhiteSpace($res)) {
        $res = Invoke-lpass 'show', '--name', $Name, '--notes'
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

    if ($Name -match ".* \[id: (\d*)\]") {
        $Name = $Matches[1]
    }

    lpass rm $Name
    return $?
}

function Get-SecretInfo
{
    param (
        [string] $Filter,
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )

    $Filter = "*$Filter"
    $pattern = [WildcardPattern]::new($Filter)
    Invoke-lpass 'ls' |
        Where-Object { 
            $_ -match "(.*) \[id: \d*\]" | Out-Null
            $pattern.IsMatch($Matches[1])
        } |
        ForEach-Object {
            [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                $_,
                [Microsoft.PowerShell.SecretManagement.SecretType]::SecureString,
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
    return (Get-Command lpass -ErrorAction SilentlyContinue) -and (lpass status -match "Logged in as .*")
}
