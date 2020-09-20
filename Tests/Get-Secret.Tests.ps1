Describe "Get-Secret tests" {
    BeforeAll {
        if (Get-Module -Name Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue) {
            throw "Must run tests without SecretManagement loaded."
        }
        Join-Path $PSScriptRoot '..' 'SecretManagement.LastPass.Extension' | Import-Module -Force
        $PSDefaultParameterValues["*-Secret*:VaultName"] = "LastPass"
    }

    AfterAll {
        $PSDefaultParameterValues.Remove("*-Secret*:VaultName")
    }

    It "can get a secret" {
        $secretName = "foo"
        $expectedArgs = 'show','--name', $secretName, '--password'
        $mock = @{
            CommandName = 'Invoke-lpass'
            ModuleName = 'SecretManagement.LastPass.Extension'
            Verifiable = $true
            MockWith = { $Arguments -join "," }
            ParameterFilter = { $expectedArgs }
        }
        Mock @mock

        Get-Secret -Name $secretName | Should -Be ($expectedArgs -join ',')
        Should -InvokeVerifiable
    }

    It "can get a secret via the pipeline" {
        $secretName = "Tech/foo"
        $secretId = "[id: 1234]"

        $mock = @{
            CommandName = 'Invoke-lpass'
            ModuleName = 'SecretManagement.LastPass.Extension'
            Verifiable = $true
            MockWith = { @("$secretName $secretId") }
            ParameterFilter = { 'ls' }
        }
        Mock @mock

        $ls = Get-SecretInfo -Filter $secretName
        Should -InvokeVerifiable

        $expectedArgs = 'show','--name', '1234', '--password'
        $mock = @{
            CommandName = 'Invoke-lpass'
            ModuleName = 'SecretManagement.LastPass.Extension'
            Verifiable = $true
            MockWith = { $Arguments -join "," }
            ParameterFilter = { $expectedArgs }
        }
        Mock @mock

        $ls | Get-Secret | Should -Be ($expectedArgs -join ',')
        Should -InvokeVerifiable
    }
}
