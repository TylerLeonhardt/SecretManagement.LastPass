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
   
    
    if ($lpassCommand -ne '' -and ((& "$lpassCommand" $lpassPath --version ) -like 'LastPass CLI*') ) {
        if ($InputObject) {
            return $InputObject | & "$lpassCommand" $lpassPath @Arguments 
        }
        else {
            return   & "$lpassCommand" $lpassPath @Arguments 
        }
    } elseif (Get-Command $lpassPath) {
        if ($InputObject) {
            return  $InputObject | & $lpassPath @Arguments 
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

    try {
        $res = Invoke-lpass 'show', '--name', $Name, '--all'
    }
    catch {
        Write-Error $_
        return 
    }
    
    $Raw = ($res | Select-Object -Skip 1) -join "`n"

    # Custom type cannot have the same case-sensitive name but Username / uSERname work.
    # That's why we don't parse it directly to a hashtable.
    $MyMatches = @([regex]::Matches($raw, '(?<key>.*?)\: (?<value>.*?)(?:\n|$)')  | ForEach-Object {
            [PSCustomObject]@{
                key        = $_.Groups.Item('key').value
                value      = $_.Groups.Item('value').value 
                valueIndex = $_.Groups.Item('value').index
            }
        })

        if ([String]::IsNullOrEmpty($Raw)) {
            return $null # Error will be returned.
        }

    # Notes is always the last item. This is also the only field that can be multiline.
    $HasNote = $MyMatches.key -ccontains 'Notes' 
    if ($HasNote) {
        $start = $MyMatches.Where({$_.Key -ceq 'Notes'},'Last')[0].valueIndex
        $Note = $raw.Substring($start)
    }
    $IsCustomType = $AdditionalParameters.outputType -eq 'Detailed' -or $MyMatches.key.Contains('NoteType')
    If ($IsCustomType) {
        $Output = Get-ComplexSecret -Fields $MyMatches -Note $Note -Raw $Raw
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
    $sb = [System.Text.StringBuilder]::new()
    
    
    if ($Secret -is [string]) {
        $Secret = @{Notes = $Secret}
    } elseif ($Secret -is [pscredential]) {
        $Secret = @{Username = $Secret.Username; Password = $Secret.GetNetworkCredential().password}
    }


    
    if ($Secret -is [hashtable]){
        $SpecialKeys = @('Language', 'NoteType', 'Notes')
        $Keys = $Secret.Keys.Where({$_ -notin $SpecialKeys })

        foreach ($k in $Keys) {
            if ($Secret.$k -is [securestring]) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret.$k)
                $Secret.$k = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            }
            [Void]($sb.AppendLine("$($k): $($Secret.$k)"))
        }

        # Notes need to be on a new line
        if ($null -ne $Secret.Notes) {
            if ($Secret.Notes -is [securestring]) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret.Notes)
                $Secret.Notes = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            }
            [Void]($sb.AppendLine("Notes: `n$($Secret.Notes)"))
        }
    } 
    
    try {
        $res = Invoke-lpass 'show', '--sync=now', '--name', $Name -ErrorAction Stop 
        $SecretExists = $null -ne $res 

        if ($SecretExists) {
            Write-Verbose "Editing secret" 
            $sb.ToString() | Invoke-lpass 'edit', '--non-interactive', $Name
        } else {
            Write-Verbose "Adding new secret" 
            $NoteTypeArgs = @()
            if ($null -ne $Secret.NoteType) {
                if ($Secret.NoteType -is [securestring]) { 
                    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret.NoteType)
                    $Secret.NoteType = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                }
                 $NoteTypeArgs = @("--note-type=$($Secret.NoteType.ToLower().replace(' ','-'))") 
            }
            $sb.ToString() | Invoke-lpass 'add', $Name, '--non-interactive', $NoteTypeArgs
        }
       
    }
    catch {
        Write-Error $_
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

    Invoke-lpass 'rm', $Name
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
            if ($AdditionalParameters.outputType -eq 'Detailed') {
                $type = [SecretType]::Hashtable
            } else {
                $type = if ($Matches[3]) {
                    [SecretType]::PSCredential
                }
                else {
                    [SecretType]::Unknown
                }
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
    $status = Invoke-lpass 'status' -ErrorAction SilentlyContinue
    return ($status -match "Logged in as .*")
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
        if ($null -eq $Note) { $output = "" } else { $output = $Note }
    }
    return $output
}

function Get-ComplexSecret {
    [CmdletBinding()]
    param (
        $Fields,
        $Note,
        $Raw
    )
    $Dupes = ($Fields | Group-Object key).Where( { $_.Count -gt 1 })
    
    if ($Dupes.count -gt 0) {
        Write-Verbose 'Creating case-sensitve hashtable'
        $Output = [hashtable]::new([System.StringComparer]::InvariantCulture)
    } else {
        $Output = @{}
    }
    
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