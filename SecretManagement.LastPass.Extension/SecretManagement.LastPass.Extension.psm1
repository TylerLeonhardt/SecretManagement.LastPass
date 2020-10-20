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

    $lpassCommand = if ($null -ne $AdditionalParameters.lpassCommand){$AdditionalParameters.lpassCommand} else {'lpass'}
   
    if ((Invoke-Expression -Command "$lpassCommand --version" ) -like 'LastPass CLI*') {
        if ($InputObject) {
            return $InputObject | Invoke-Expression -Command "$lpassCommand @Arguments"
        }
        return Invoke-Expression -Command "$lpassCommand @Arguments"
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

    $res = Invoke-lpass 'show','--name', $Name, '--all'

    $Raw = ($res | Select-Object -Skip 1) -join "`n"

    if ($AdditionalParameters.outputType -eq 'Raw') {
        return $Raw
    }

    # Custom type cannot have the same case-sensitive name but Username / uSERname work.
    # That's why we don't parse it directly to a hashtable.
    $MyMatches = @([regex]::Matches($raw, '(?<key>.*?)\: (?<value>.*?)(?:\n|$)')  | ForEach-Object {
        [PSCustomObject]@{
            key        = $_.Groups.Item('key').value
            value      = $_.Groups.Item('value').value 
            valueIndex = $_.Groups.Item('value').index
        }
    })

    # Notes is always the last item. This is also the only field that can be multiline.
    $HasNote = $MyMatches[-1].key -ceq 'Notes' 
    if ($HasNote) {
        $start = $MyMatches[-1].valueIndex
        $Note = $raw.Substring($start)
    }
    $IsCustomType =  $AdditionalParameters.outputType -eq 'Detailed' -or $MyMatches.key.Contains('NoteType')


    If ($IsCustomType) {
        $Output = Get-ComplexSecret -Fields $MyMatches -Note $Note
    }
    else {
        $Output = Get-SimpleSecret -Fields $MyMatches -Note $Note
    }
    
    return $Output
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



function Get-SimpleSecret {
    [CmdletBinding()]
    param (
        $Fields,
        $Note
    )
    
    $IsCredentials = $Fields.where( { $_.key -in @('Username', 'Password') }, 'first').count -eq 1
    if ($IsCredentials) {
        $username = $Fields.Where( { $_.key -eq 'Username' }, 'first') | Select-Object -ExpandProperty value
        if ($null -eq $username) { $username = '' }
        $password = $Fields.Where( { $_.key -eq 'Password' }, 'first') | Select-Object -ExpandProperty value
        if ($null -eq $password) { $password = '' }
        if ("" -ne $password) { $password = $password | ConvertTo-SecureString -AsPlainText -Force }
        $output = [System.Management.Automation.PSCredential]::new($username, $password)
    }
    else {
        if ($null -eq $Note) { $output = "" } else { $output = $Note}
    }
    return $output
}

function Get-ComplexSecret {
    [CmdletBinding()]
    param (
        $Fields,
        $Note
    )
    $Dupes = ($Fields | Group-Object key).Where( { $_.Count -gt 1 })
    
    if ($Dupes.count -gt 0) {
        $Dupesstr = ($dupes | ForEach-Object { $_.Group.key -join ',' }) -join "`n"

        
        Write-Error -Message @"
The record contains multiple fields with the same name.
$Dupesstr
Please ensure your custom records have only one field with the same name or re-register your vault with outputType='Raw'  vault parameter to get the raw output
Secret will not be returned
"@

        Write-Debug -Message 'Duplicates field name were detected. "" will be returned'
        return "" 
    }


    $Output = @{}
    if (![String]::IsNullOrEmpty($Note)) { 
        $Output.Notes = $Note
        $Fields = $Fields | Select-Object -SkipLast 1
    }

    Foreach ($f in $Fields) {
        try {
            $Output.Add($f.key, $f.value) 
        }
        catch {
            Write-Warning "$($f.key) field was not added."
        }
    }
   
    return $Output
}