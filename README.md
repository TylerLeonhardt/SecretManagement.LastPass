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

# Prerequisites

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

# Installation

You an install this module from the PowerShell Gallery:

Using PowerShellGet v2:

```pwsh
Install-Module SecretManagement.LastPass
```

Using PowerShellGet v3:

```pwsh
Install-PSResource SecretManagement.LastPass
```

Once you have it installed,
you need to register the module as an extension:

```pwsh
Register-SecretVault -ModuleName SecretManagement.LastPass
```

### Vault parameters
The module also have the following vault parameter, that can be provided at registration. 

#### lpassCommand 
If your lpass CLI is installed at a custom location or that you need to launch it using an alternate mean, such as WSL, this can be accomplished by providing the `lpassCommand`

Example 
```
# Custom path 
Register-SecretVault -ModuleName 'SecretManagement.LastPass' -VaultParameters @{lpassCommand = "& '/usr/bin/Some Path/lpass'" }

# WSL 
Register-SecretVault -ModuleName 'SecretManagement.LastPass' -VaultParameters @{lpassCommand = '& wsl lpass' }
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
