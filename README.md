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

If your lpass CLI is installed at a custom location or that you need to launch it using an alternate mean, such as WSL, this can be accomplished by providing the `lpassCommand`

##### Examples

* Specifying a path

```pwsh
Register-SecretVault -ModuleName 'SecretManagement.LastPass' -VaultParameters @{
    lpassCommand = "/usr/bin/path/to/lpass"
}
```

* Specifying a path with a space in it

```pwsh
Register-SecretVault -ModuleName 'SecretManagement.LastPass' -VaultParameters @{
    lpassCommand = "& '/usr/bin/Some Path With Spaces/lpass'"
}
```

* Working with WSL

```pwsh
Register-SecretVault -ModuleName 'SecretManagement.LastPass' -VaultParameters @{
    lpassCommand = '& wsl lpass'
}
```
#### outputType
##### Accepts: Default,Detailed,Raw
```
Register-SecretVault -ModuleName 'SecretManagement.LastPass' -VaultParameters @{
    outputType = 'Detailed'
```
###### Default
By default, standard credentials will return a PSCredentia, notes will be returned as a string and custom notes (Bank account, credit card, custom secret types) will be returned as a hashtable. 

###### Detailed
You can modify the default behavior so that notes and credentials also return as a hashtable. This has the advantage of exposing the URL and Notes field of credentials and also provide additional consistency for the Notes field should you want to compate multiple credentials Notes field (Simple notes Notes will also be in the Notes key)

###### Raw
This options return the items as is, with all fields and value in a multiline string
This is the only mode that support duplicate fields name in custom type.
```
URL: https://www.google.ca
Username: MyUser
Password: MyPwd
Notes: I am a note
Notes is the only field that can be multiline and always the last field (if present).
```

