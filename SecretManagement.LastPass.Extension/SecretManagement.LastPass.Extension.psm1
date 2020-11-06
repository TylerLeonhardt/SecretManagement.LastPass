# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using namespace Microsoft.PowerShell.SecretManagement

# The capture groups are:
# 1. The ls short output (just the name & id)
# 2. The name of the secret
# 3. The username of the secret
$lsLongOutput = "\d\d\d\d-\d\d-\d\d \d\d:\d\d ((.*) \[id: \d*\]) \[username: (.*)\]"

    # Custom notes in lpass CLI are a bit of a mess.
    # For default types
    # Get operation will return the value
    # Set operation will only accept the key
    # This is to convert value obtained from Get when doing a Set. 
$DefaultNoteTypeMap = @{
    'Address'           = 'address'
    # 'amex' = ''       # Possibly deprecated            
    'Bank Account'      = 'bank'
    'Credit Card'       = 'credit-card'
    'Database'          = 'database'
    "Driver's License"  = 'drivers-license'
    'Email Account'     = 'email'
    'Health Insurance'  = 'health-insurance'
    'Instant Messenger' = 'im'
    'Insurance'         = 'insurance'
    #'mastercard' = ''  # Possibly deprecated
    'Membership'        = 'membership'
    'Passport'          = 'passport'
    'Server'            = 'server'
    'Software License'  = 'software-license'
    'SSH Key'           = 'ssh-key'
    'Social Security'   = 'ssn'
    #'visa' = ''        # Possibly deprecated
    'Wi-Fi Password'    = 'wifi'
} 
# These fields need special consideration when working with secrets.
# Language / NoteType are fields that are part of any custom notes and always appear last (before Notes)
#Notes field can appear in any secrets and is always the last field. It is also the only multiline field.
$SpecialKeys = @('Language', 'NoteType', 'Notes')

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
        return   & "$lpassCommand" $lpassPath @Arguments 
     } elseif (Get-Command $lpassPath) {
        if ($InputObject) {
            return  $InputObject | & $lpassPath @Arguments 
        }
        return   & $lpassCommand $lpassPath @Arguments 
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
        if ($null -eq $res) {
            # Returning nothing is not allowed. We leave error handling to SecretManagement
            return #Will produce "Get-Secret : The secret $Name was not found." error.
        }
        if ($res[0] -eq 'Multiple matches found.') {
            Write-Warning "Multiple matches found with the name $Name. `nThe first matching result will be returned."
            $Id = [regex]::Match($res[1], '\[id: (.*)\]').Groups[1].value
            $res = Invoke-lpass 'show', '--name', $Id, '--all'

        }
    }
    catch {
        Write-Error $_
        return 
    }
    #The first line contains the secret name and ID. We do not have any use for it.
    $Raw = ($res | Select-Object -Skip 1) -join "`n"

    if ([String]::IsNullOrEmpty($Raw)) {
        return ""
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

    # Notes is always the last item (lpass wise). This is also the only field that can be multiline.
    # Any matching items after the first "Notes" key need to be discarded as it is not an item,
    # but rather just part of the notes.
    $HasNote = $MyMatches.key -ccontains 'Notes' 
    if ($HasNote) {
        $start = $MyMatches.Where({$_.Key -ceq 'Notes'},'First')[0].valueIndex
        $Note = $raw.Substring($start)
        $MyMatches = $MyMatches.Where({$_.ValueIndex -lt $start})
    }
    $IsCustomType = $AdditionalParameters.outputType -eq 'Detailed' -or $MyMatches.key.Contains('NoteType')
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
    $sb = [System.Text.StringBuilder]::new()
    
    
    if ($Secret -is [string]) {
        $Secret = @{URL = ' http://sn';Notes = $Secret}
    } elseif ($Secret -is [pscredential]) {
        $Secret = @{Username = $Secret.Username; Password = $Secret.GetNetworkCredential().password}
    }


    
    if ($Secret -is [hashtable]){
        if ($Secret.Keys.count -eq 1 -and $null -ne $Secret.Notes) {
            $Secret.URL = 'http://sn'
        }

        $Keys = $Secret.Keys.Where({$_ -notin $SpecialKeys })
        foreach ($k in $Keys) {
            if ($Secret.$k -is [securestring]) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret.$k)
                $Secret.$k = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            }
            $sb.AppendLine("$($k): $($Secret.$k)") | Out-Null
        }

        # Notes need to be on a new line
        if ($null -ne $Secret.Notes) {
            if ($Secret.Notes -is [securestring]) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret.Notes)
                $Secret.Notes = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            }
            $sb.AppendLine("Notes: `n$($Secret.Notes)") | Out-Null
        }
    } 
    
    try {
        $res = Invoke-lpass 'show', '--sync=now', '--name', $Name, '2>/dev/null' -ErrorAction Stop 
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
                $NoteTypeArgs += "--note-type=$($Secret.NoteType)"
            }
            $sb.ToString() | Invoke-lpass 'add', $Name, '--non-interactive', $NoteTypeArgs
            #Explicit sync so calling set again do not duplicate the secret (add --sync=now not fast enough)
            Invoke-lpass 'sync' 
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
            $type = if ($AdditionalParameters.outputType -eq 'Detailed') {
                [SecretType]::Hashtable
            }
            elseif ($Matches[3]) {
                [SecretType]::PSCredential
            }
            else {
                [SecretType]::Unknown
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
    
    $username = $Fields.Where( { $_.key -eq 'Username' }, 'first') | Select-Object -ExpandProperty value
    $password = $Fields.Where( { $_.key -eq 'Password' }, 'first') | Select-Object -ExpandProperty value
    # Credentials 
    if ($username -or $password) {
        if ($null -eq $username) { $username = '' }
        if ($null -eq $password) { $password = '' }
        if ("" -ne $password) { $password = $password | ConvertTo-SecureString -AsPlainText -Force }
        return [System.Management.Automation.PSCredential]::new($username, $password)
    }
    # Secure Note
    if ($null -ne $Note) {
        return $Note
    }
    # Empty secret
    return ''
}

function Get-ComplexSecret {
    [CmdletBinding()]
    param (
        $Fields,
        $Note
    )
    $Dupes = ($Fields | Group-Object key).Where( { $_.Count -gt 1 })
    
    if ($Dupes.Count -gt 0) {
        Write-Verbose 'Creating case-sensitve hashtable'
        $Output = [hashtable]::new([System.StringComparer]::InvariantCulture)
    } else {
        $Output = @{}
    }
    
    if (![String]::IsNullOrEmpty($Note)) { 
        #The Notes field is ALWAYS the last field.
        #It is also the only field that can be multiline.
        #This is why we set the Notes to $Notes and ignore the last field when a Notes field exist.
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
    if ($null -ne $Output.NoteType -and $DefaultNoteTypeMap.ContainsKey($Output.NoteType)) {
        $Output.NoteType = $DefaultNoteTypeMap.Item($Output.NoteType)
    }
    return $Output
}
