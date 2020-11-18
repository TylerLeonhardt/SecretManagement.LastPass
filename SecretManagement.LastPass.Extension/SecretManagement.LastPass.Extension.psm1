# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using namespace Microsoft.PowerShell.SecretManagement

#region constants

# The capture groups are:
# 1. The date and time that the secret was stored
# 2. The ls short output (just the name & id)
# 3. The name of the secret
# 4. The username of the secret
$lsLongOutput = "(\d\d\d\d-\d\d-\d\d \d\d:\d\d)? *((.*) \[id: \d*\]) \[username: (.*)\]"

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

$lpassMessage = @{
    AccountNotFound = 'Error: Could not find specified account(s).'
    # Need to use wildcard since the path of lpass could be different
    LoggedOut = 'Error: Could not find decryption key. Perhaps you need to login with*'
    MultipleMatches = 'Multiple matches found.'
}

# These fields need special consideration when working with secrets.
# Language / NoteType are fields that are part of any custom notes and always appear last (before Notes)
#Notes field can appear in any secrets and is always the last field. It is also the only multiline field.
$SpecialKeys = @('Language', 'NoteType', 'Notes')

#endregion

function Invoke-lpassInternal {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        [object]$InputObject,
        [Switch]$UseNative,
        [String]$lpassPath,
        [string[]]$Arguments
    )

    if ($UseNative) {
        if ($InputObject) { return $InputObject | & $lpassPath @Arguments }
        return & $lpassPath @Arguments
    }
    # WSL
    if ($InputObject) { return $InputObject | & wsl $lpassPath @Arguments }
    return & wsl $lpassPath @Arguments
}

function Invoke-lpass {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$Arguments,
        [Parameter(ValueFromPipeline)]
        [object]$InputObject,
        #Only for root module functions
        [hashtable]$VaultParams
    )
     # Command from the root module do not contain $AdditionalParameters
    if ($null -ne $VaultParams) { $AdditionalParameters = $VaultParams }
    
    $UseWSL = $AdditionalParameters.wsl -eq $true
    $lpassPath = if ($null -ne $AdditionalParameters.lpassPath) { "`"$($AdditionalParameters.lpassPath)`"" } else { 'lpass' }
    $UseNative = -not $UseWSL

    if (($UseNative -and -not (Get-Command $lpassPath -EA 0)) -or 
        ($UseWSL -and (& wsl $lpassPath --version ) -notlike 'LastPass CLI*')) {
        throw "lpass executable not found or installed."
    }

    $Params = @{
        InputObject = $InputObject
        UseNative   = $UseNative
        lpassPath   = $lpassPath
        Arguments   = $Arguments
    }

    # If we do redirect on the command themselves, it doesn't work.
    # Doing redirect on the commands wrapped in a function work.
    
    if ($Arguments.Count -gt 0) {
        switch ($Arguments[0]) {
            'login' {  
                # We want the prompt always, so no redirect
                $result = Invoke-lpassInternal @Params
            }
            'show' {
                # We might want the prompt, but are not sure yet.
                $result = Invoke-lpassInternal @Params 2>&1
                # If we get the message stating we might be logged out, we reissue the command without redirect (for Prompt)
                if ($result -is [System.Management.Automation.ErrorRecord] -and [String]$result -like $lpassMessage.LoggedOut) {
                    $result2 = Invoke-lpassInternal @Params 2>&1
                    # If $null, something will have been printed in the console (because we disabled the redirect)
                    # We therefore want to keep the original $result "Logged out" so it is thrown later on
                    # If not $null, we want to evaluate $result2
                    if ($null -ne $result2) {$result = $result2}
                }
            }
            Default {
                # By default, we always redirect streams
                $result = Invoke-lpassInternal @Params 2>&1
            }
        }
    }

    if ($result -is [System.Management.Automation.ErrorRecord]) {
        switch -Wildcard ([string] $result) {
            $lpassMessage.LoggedOut { throw [PasswordRequiredException] $lpassMessage.LoggedOut }
            $lpassMessage.AccountNotFound { break }
            $lpassMessage.MultipleMatches { break }
            # We leave handling exceptions to SecretManagement
            default {
                # We do a Write-Error so it's more discoverable to the user
                # (but it will exist in the inner exception of the throw)
                Write-Error -ErrorRecord $result
                throw $result
            }
        }
    }

    # This should be a string or a collection of strings
    return $result
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

    if ($AdditionalParameters.Verbose) {
        $VerbosePreference = "Continue"
    }

    if ($Name -match ".* \(id: (\d*)\)") {
        $Name = $Matches[1]
    }

    $res = Invoke-lpass 'show', '--name', $Name, '--all'

    # We use ToString() here to turn the ErrorRecord into a string if we got an ErrorRecord
    if ($null -eq $res -or $res.ToString() -eq $lpassMessage.AccountNotFound) {
        # Will produce "Get-Secret : The secret $Name was not found." error.
        return
    }

    if ($res[0] -eq $lpassMessage.MultipleMatches) {
        Write-Warning "Multiple matches found with the name $Name. `nThe first matching result will be returned."
        $Id = [regex]::Match($res[1], '\[id: (.*)\]').Groups[1].value
        $res = Invoke-lpass 'show', '--name', $Id, '--all'

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
    if ($AdditionalParameters.Verbose) {
        $VerbosePreference = "Continue"
    }
    $sb = [System.Text.StringBuilder]::new()
    
    
    if ($Secret -is [string] -or $Secret -is [securestring]) {
        $Secret = @{
            URL = ' http://sn'
            Notes = $Secret
        }
    } elseif ($Secret -is [pscredential]) {
        $Secret = @{
            Username = $Secret.Username
            Password = $Secret.GetNetworkCredential().password
        }
    }

    if ($Secret -is [System.Collections.Specialized.OrderedDictionary] -or $Secret -is [hashtable]) {
        if ($Secret.Keys.count -eq 1 -and $null -ne $Secret.Notes) {
            $Secret.URL = 'http://sn'
        }

        $Keys = $Secret.Keys.Where({$_ -notin $SpecialKeys })
        foreach ($k in $Keys) {
            if ($Secret.$k -is [securestring]) {
                $Secret.$k = [System.Net.NetworkCredential]::new("", $Secret.$k).Password
            }
            $sb.AppendLine("$($k): $($Secret.$k)") | Out-Null
        }

        # Notes need to be on a new line
        if ($null -ne $Secret.Notes) {
            if ($Secret.Notes -is [securestring]) {
                $Secret.Notes = [System.Net.NetworkCredential]::new("", $Secret.Notes).Password
            }
            $sb.AppendLine("Notes: `n$($Secret.Notes)") | Out-Null
        }
    } 
    
    $res = Invoke-lpass 'show', '--sync=now', '--name', $Name

    # We use ToString() here to turn the ErrorRecord into a string if we got an ErrorRecord
    $SecretExists = switch -Wildcard ($res) {
        # This should never ever happen...
        "" {
            Write-Warning "Querying the secret $Name produced an unexpected result of `$Null"
            $false
            break
        }
        $lpassMessage.AccountNotFound {
            $false
            break
        }
        default {
            $true
            break
        }
    }

    if ($SecretExists) {
        Write-Verbose "Editing secret"
        $sb.ToString() | Invoke-lpass 'edit', '--non-interactive', $Name
    } else {
        Write-Verbose "Adding new secret"
        $NoteTypeArgs = @()
        if ($null -ne $Secret.NoteType) {
            if ($Secret.NoteType -is [securestring]) { 
                $Secret.NoteType = [System.Net.NetworkCredential]::new("", $Secret.NoteType).Password
            }
            $NoteTypeArgs += "--note-type=$($Secret.NoteType)"
        }
        $sb.ToString() | Invoke-lpass 'add', $Name, '--non-interactive', $NoteTypeArgs
    }

    # Explicit sync so calling set again does not duplicate the secret (add --sync=now not fast enough)
    Invoke-lpass 'sync'

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

    # Grab the id because that's more exact
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
    if ($AdditionalParameters.Verbose) {
        $VerbosePreference = "Continue"
    }

    $Filter = "*$Filter"
    $pattern = [WildcardPattern]::new($Filter,[System.Management.Automation.WildcardOptions]::IgnoreCase)
    Invoke-lpass 'ls','-l' |
        Where-Object { 
            $IsMatch = $_ -match $lsLongOutput 
            if (-not $IsMatch ) { Write-Verbose -Message "No match for: $_ `nThis record will be ignored." }
            $IsMatch -and $pattern.IsMatch($Matches[3])
        } |
        ForEach-Object {
            $type = if ($AdditionalParameters.outputType -eq 'Detailed') {
                [SecretType]::Hashtable
            }
            elseif ($Matches[4]) {
                [SecretType]::PSCredential
            }
            else {
                [SecretType]::Unknown
            }

            [SecretInformation]::new(
                ($Matches[2] -replace '\[(id: \d*?)\]$', '($1)'), 
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
    $status = Invoke-lpass 'status'
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
    # Notes is removed from the fields. If present, this mean we have another field using that name under a different case.
    $DupeNote = ($Fields.Contains('Notes') -and ![String]::IsNullOrEmpty($Note))
    if ($Dupes.Count -gt 0 -or $DupeNote) {
        Write-Verbose 'Creating case-sensitve hashtable'
        $Output = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::CurrentCultureIgnoreCase)
    } else {
        $Output = [Ordered]@{}
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

    if (![String]::IsNullOrEmpty($Note)) { 
        $Output.Notes = $Note
    }

    return $Output
}
