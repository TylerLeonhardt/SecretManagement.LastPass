# Change this to however you invoke lpass
$IsNotLoggedIn = (lpass status 2>&1) -notmatch "Logged in as .*"

Describe 'SecretManagement.LastPass tests' {
    BeforeAll {
        & $PSScriptRoot/reload.ps1
        $VaultName = 'LastPass.Tests'
    }

    BeforeEach {
        $secretName = "tests/$((New-Guid).Guid)"
    }

    It 'LastPass vault is registered' {
        Get-SecretVault $VaultName | Should -Not -BeNullOrEmpty
    }

    It 'Can store a string secret which is treated like a securestring' -Skip:$IsNotLoggedIn {
        $secretText = 'This is my string secret'
        Set-Secret -Name $secretName -Vault $VaultName -Secret $secretText

        $secretInfo = Get-SecretInfo -Name $secretName -Vault $VaultName
        $secretInfo.Name | Should -BeLike "$secretName (id:*)"
        $secretInfo.Type | Should -BeExactly 'Unknown'
        $secretInfo.VaultName | Should -BeExactly $VaultName
        $secret = Get-Secret -Name $secretName -AsPlainText -Vault $VaultName
        $secret | Should -BeExactly $secretText

        Remove-Secret -Name $secretName -Vault $VaultName
        { 
            Get-Secret -Name $secretName -Vault $VaultName -ErrorAction Stop
        } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    }

    It 'Can store a secure string secret' -Skip:$IsNotLoggedIn {
        $secretText = 'This is my securestring secret'
        Set-Secret -Name $secretName -Vault $VaultName -Secret ($secretText | ConvertTo-SecureString -AsPlainText)

        $secretInfo = Get-SecretInfo -Name $secretName -Vault $VaultName
        $secretInfo.Name | Should -BeLike "$secretName (id:*)"
        $secretInfo.Type | Should -BeExactly 'Unknown'
        $secretInfo.VaultName | Should -BeExactly $VaultName

        $secret = Get-Secret -Name $secretName -AsPlainText -Vault $VaultName
        $secret | Should -BeExactly $secretText

        Remove-Secret -Name $secretName -Vault $VaultName
        { Get-Secret -Name $secretName -Vault $VaultName -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    }

    It 'Can store a PSCredential secret' -Skip:$IsNotLoggedIn {
        $secretText = 'This is my pscredential secret'
        $secret = [PSCredential]::new('myUser', ($secretText | ConvertTo-SecureString -AsPlainText))
        Set-Secret -Name $secretName -Vault $VaultName -Secret $secret

        $secretInfo = Get-SecretInfo -Name $secretName -Vault $VaultName
        $secretInfo.Name | Should -BeLike "$secretName (id:*)"
        $secretInfo.Type | Should -BeExactly 'PSCredential'
        $secretInfo.VaultName | Should -BeExactly $VaultName

        $secret = Get-Secret -Name $secretName -Vault $VaultName
        $secret.UserName | Should -BeExactly 'myUser'
        $secret.Password | ConvertFrom-SecureString -AsPlainText | Should -BeExactly $secretText

        Remove-Secret -Name $secretName -Vault $VaultName
        { Get-Secret -Name $secretName -Vault $VaultName -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    }

    It 'Logged out works' -Skip:(!$IsNotLoggedIn) {
        { Get-Secret -Name "asdf" -Vault $VaultName -ErrorAction Stop } |
            Should -Throw -ExceptionType Microsoft.PowerShell.SecretManagement.PasswordRequiredException
    }

    #region Tests to add back in later from Steve's module

    # Skipping because I don't think this extension supports byte array.
    It 'Can store a byte array secret' -Skip {
        $secretText = 'This is my byte array secret'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($secretText)
        Set-Secret -Name $secretName -Vault $VaultName -Secret $bytes

        $secretInfo = Get-SecretInfo -Name $secretName
        $secretInfo.Name | Should -BeExactly $secretName
        $secretInfo.Type | Should -BeExactly 'ByteArray'
        $secretInfo.VaultName | Should -BeExactly $VaultName

        $secret = Get-Secret -Name $secretName
        [System.Text.Encoding]::UTF8.GetString($secret) | Should -BeExactly $secretText

        Remove-Secret -Name $secretName -Vault $VaultName
        { Get-Secret -Name $secretName -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    }

    # Skipping because I don't think this extension supports arbitrary hashtables.
    It 'Can store hashtable secret' -Skip {
        $secretText = 'This is my hashtable secret'
        $cred = [pscredential]::new('myUser', ($secretText | convertto-securestring -asplaintext))
        $securestring = $secretText | convertto-securestring -asplaintext
        $hashtable = @{
            a = 1
            b = $cred
            c = @{
                d = 'nested'
                e = $cred
                f = $securestring
            }
            g = $securestring
        }

        Set-Secret -Name $secretName -Vault $VaultName -Secret $hashtable
        $secretInfo = Get-SecretInfo -Name $secretName
        $secretInfo.Name | Should -BeExactly $secretName
        $secretInfo.Type | Should -BeExactly 'Hashtable'
        $secretInfo.VaultName | Should -BeExactly $VaultName

        $secret = Get-Secret -Name $secretName -AsPlainText
        $secret.a | Should -Be 1
        $secret.b | Should -BeOfType [PSCredential]
        $secret.b.UserName | Should -BeExactly 'myUser'
        $secret.b.Password | ConvertFrom-SecureString -AsPlainText | Should -BeExactly $secretText
        $secret.c | Should -BeOfType [Hashtable]
        $secret.c.d | Should -BeExactly 'nested'
        $secret.c.e | Should -BeOfType [PSCredential]
        $secret.c.e.UserName | Should -BeExactly 'myUser'
        $secret.c.e.Password | ConvertFrom-SecureString -AsPlainText | Should -BeExactly $secretText
        $secret.c.f | Should -BeExactly $secretText
        $secret.g | Should -BeExactly $secretText

        Remove-Secret -Name $secretName -Vault $VaultName
        { Get-Secret -Name $secretName -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    }

    #endregion
}
