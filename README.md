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

#### lpassCommand

This parameter allow the use of a custom command to be called before lpass (such as, but not limited to, wsl)

##### Examples


* Working with WSL

```pwsh
# Dedicated function
Register-LastPassVault -VaultName 'MyVault' -Command wsl

# Using SecretManagement interface
Register-SecretVault  -VaultName 'MyVault' -ModuleName 'SecretManagement.LastPass' -VaultParameters @{
    lpassCommand = 'wsl'
}
```


#### lpassPath

This parameter will allow to provide a custom lpass path location for the CLI

##### Examples

* Specifying a path

```pwsh
# Dedicated function
Register-LastPassVault -VaultName 'MyVault' -Path "/usr/bin/some path/to/lpass"

# Using SecretManagement interface
Register-SecretVault -VaultName 'MyVault' -ModuleName 'SecretManagement.LastPass' -VaultParameters @{
    lpassPath = "/usr/bin/some path/to/lpass"
}
```
#### outputType
(Accept: Default,Detailed) 

By default, regular credentials are returned as string (for notes) and PSCredential (for credentials) 
Setting this parameter to **Detailed** will always return a hashtable. Effectively, this mean that the URL / Notes parameter of the regular credential will be exposed. 

### Additional Functions

#### Register-LastPassVault

Register a SecretVault of type SecretManagement.LastPass

##### Parameters
###### VaultName
Name of the vault to be registered. If no name is provided, **SecretManagement.LastPass** will be used.

###### Command
Command that will call lpass CLI. This is mainly for Windows user, that need to use wsl to use the CLI.

###### Path
Custom path to the lpass CLI


#### Unregister-LastPassVault

Unregister a SecretVault of type SecretManagement.LastPass

##### Parameters
###### VaultName
Name of the vault to be unregistered.

#### Connect-LastPass
Initiate connection to the Last Pass account. 

##### Parameters
###### VaultName
Name of the vault to connect against.

###### Username
Username to connect with.

###### Trust
The trust switch will cause subsquent logins to not require multifactor authentication.

#### Disconnect-LastPass
##### Parameters

###### VaultName
Name of the vault to perform the disconnect against.

### Extension Limitations

Some limitations exist on this module, inherent to the CLI they are based on. 

**Custom credential types**
- Custom notes can be read and edited but attempting to create a new item of a custom type will fail ([Open issue from 2016](https://github.com/lastpass/lastpass-cli/issues/190))
- Case-sensiive hashtables will be used if the fetched secret contain multiple time the same key name under different cases (eg: USERNAME,username)