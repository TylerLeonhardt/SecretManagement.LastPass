# SecretManagement extension for LastPass

This is a
[SecretManagement](https://github.com/PowerShell/SecretManagement)
extension for
[LastPass](https://lastpass.com).
It leverages the [`lastpass-cli`](https://github.com/lastpass/lastpass-cli)
to interact with LastPass.

> **NOTE: This is not a maintained project and it's specifically not maintained _by_ LastPass.**
> **I work on it in my free time because I use LastPass personally.**
> The dream is that one day this would move under the LastPass organization.

## Prerequisites

* [PowerShell](https://github.com/PowerShell/PowerShell)
* The [`lastpass-cli`](https://github.com/lastpass/lastpass-cli)
* The [SecretManagement](https://github.com/PowerShell/SecretManagement) PowerShell module

You can get the `SecretManagement` module from the PowerShell Gallery:

Using PowerShellGet v2:

```pwsh
Install-Module Microsoft.PowerShell.SecretManagement -AllowPrerelease
```

Using PowerShellGet v3:

```pwsh
Install-PSResource Microsoft.PowerShell.SecretManagement -Prerelease
```

## Installation

You an install this module from the PowerShell Gallery:

Using PowerShellGet v2:

```pwsh
Install-Module SecretManagement.LastPass
```

Using PowerShellGet v3:

```pwsh
Install-PSResource SecretManagement.LastPass
```

## Registration

Once you have it installed,
you need to register the module as an extension:

```pwsh
Register-SecretVault -ModuleName SecretManagement.LastPass
```

Optionally, you can set it as the default vault by also providing the
`-DefaultVault`
parameter.


At this point,
you should be able to use
`Get-Secret`, `Set-Secret`
and all the rest of the
`SecretManagement`
commands!

### Vault parameters

The module also have the following vault parameter, that can be provided at registration.

#### [switch] Wsl

Call lpass CLI through Windows Subsystem for Linux (WSL). 

##### Examples


* Working with WSL

```pwsh
# Dedicated function
Register-LastPassVault -Vault 'MyVault' -Wsl

# Using SecretManagement interface
Register-SecretVault  -Vault 'MyVault' -ModuleName 'SecretManagement.LastPass' -VaultParameters @{
    wsl = $true
}
```


#### lpassPath

Allow to provide a custom lpass path location for the CLI

##### Examples

* Specifying a path

```pwsh
# Dedicated function
Register-LastPassVault -Vault 'MyVault' -Path "/usr/bin/some path/to/lpass"

# Using SecretManagement interface
Register-SecretVault -Vault 'MyVault' -ModuleName 'SecretManagement.LastPass' -VaultParameters @{
    lpassPath = "/usr/bin/some path/to/lpass"
}
```
#### outputType
(Accept: Default,Detailed) 

By default, regular credentials are returned as string (for notes) and PSCredential (for credentials) 
Setting this parameter to **Detailed** will always return a hashtable. Effectively, this mean that the URL / Notes parameter of the regular credential will be exposed. 

## Additional Functions

### Register-LastPassVault

Register a SecretVault of type SecretManagement.LastPass

#### Parameters
##### Vault
Name of the vault to be registered. If no name is provided, **SecretManagement.LastPass** will be used.

##### [switch] Wsl
Call lpass CLI through Windows Subsystem for Linux (WSL). 

##### [switch] Detailed
All records will be returned as hashtable. Notes and regular credentials. In turn, Notes and URL field from the credential will also be returned.

##### Path
Custom path to the lpass CLI


### Unregister-LastPassVault

Unregister a SecretVault of type SecretManagement.LastPass

#### Parameters
##### Vault
Name of the vault to be unregistered.

### Connect-LastPass
Connect the user to LastPass account.

#### Parameters
##### Vault
Name of the vault to connect to.

##### Username
Username to connect with.

##### [Switch] Trust
Cause subsquent logins to not require multifactor authentication.

##### [Switch] StayConnected
Save the LastPass decryption key on the hard drive so re-entering password once the connection window close is not required anymore. This operation will prompt the user.

### Disconnect-LastPass
Disconnect the user to LastPass account.

#### Parameters

##### Vault
Name of the vault to perform the disconnect against.


### Sync-LastPassVault
Forces a synchronization of the local cache with the LastPass servers, and does not exit until the local cache is synchronized or until an error occurs
#### Parameters

##### Vault
Name of the vault

### Show-LastPassConsoleGridView
Show LastPass GridView secrets then show the selected secret.
#### Parameters

##### Vault
Name of the vault used for the lookup

###### [Switch]KeepOpen
If set, the secret GridView will be automatically reloaded after a secret is shown

##### [Switch]Formatted
If set, Secret will be returned with the title and in a Format-Table -Wrap to show multiline note properly.

###### Notes
This cmdlet can make use of the improved Out-ConsoleGridView cmdlet if using Powershell 6.2 or newer and  Microsoft.PowerShell.ConsoleGuiTools is installed.
Otherwise, Out-GridView will be used.

## Extension Limitations

Some limitations exist on this module, inherent to the CLI they are based on. 

**Custom credential types**
- Custom notes can be read and edited but attempting to create a new item of a custom type will fail ([Open issue from 2016](https://github.com/lastpass/lastpass-cli/issues/190))
- Case-sensiive hashtables will be used if the fetched secret contain multiple time the same key name under different cases (eg: USERNAME,username)