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

if you need to specify a custom path, you can provide the full path `lpassCommand` as a vault parameter.

This also work if you need to launc lastpass through another command, such as WSL.

```
# Custom path 
Register-SecretVault -ModuleName 'SecretManagement.LastPass' -VaultParameters @{lpassCommand = '/usr/bin/SomePath/lpass' }

# WSL or other executable
Register-SecretVault -ModuleName 'SecretManagement.LastPass' -VaultParameters @{lpassCommand = 'wsl lpass' }
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
