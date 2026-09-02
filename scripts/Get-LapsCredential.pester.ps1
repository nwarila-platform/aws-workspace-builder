#Requires -Version 5.1
# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT
<#
    Pester spec for Get-LapsCredential.ps1 (org pair convention: every script
    ships with a sibling <Name>.pester.ps1; the pester-matrix workflow runs
    one leg per pair).

    Runs anywhere, Linux CI included: there is no directory and no LAPS
    module, so Get-LapsADPassword is stubbed as a function in this file and
    the script -- invoked as a child scope -- resolves the stub instead of the
    real cmdlet. The stub answers from $global:FakeEscrow (what the directory
    holds) or throws $global:FakeError (what the module said instead), which
    between them model every shape the read comes back in.

    Stub state lives in $global: variables because inside a function called
    from a child SCRIPT, $script: resolves to the child script's own scope, not
    this file's.

    Both transports are asserted: the standalone JSON emission and the $Ansible
    path via the inline context below (pairs are self-contained; no imports).
    Its Changed defaults to $True exactly like win_powershell -- so every test
    proves the script SETS Changed=$False rather than inheriting a default.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

BeforeAll {
  $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-LapsCredential.ps1'
  $script:Updated = [System.DateTime]::new(2026, 8, 31, 14, 5, 0, [System.DateTimeKind]::Utc)
  $script:Expires = $script:Updated.AddDays(30)

  # Inline $Ansible stand-in (org contract: pairs are self-contained, no
  # imports). Faithful to win_powershell: Changed defaults to $True, and only
  # the ratified surface (Changed, CheckMode, Failed, Result) is modeled.
  Function New-AnsibleContext {
    Param ([Switch]$CheckMode)
    $global:Ansible = [PSCustomObject]@{
      Changed   = $True
      CheckMode = $CheckMode.IsPresent
      Failed    = $False
      Result    = $Null
    }
    $global:Ansible
  }

  Function Remove-AnsibleContext {
    Remove-Variable -Name 'Ansible' -Scope 'Global' -Force -ErrorAction 'SilentlyContinue'
  }

  # The escrow object as Get-LapsADPassword -AsPlainText shapes it.
  Function New-FakeEscrow {
    Param ([System.String]$Value = 'Sup3r-S3cret-Passw0rd!')
    [PSCustomObject]@{
      ComputerName        = 'TCNAW-WSB01'
      DistinguishedName   = 'CN=TCNAW-WSB01,CN=Computers,DC=tcn,DC=trinitytechnicalservices,DC=com'
      Account             = 'Administrator'
      Password            = $Value
      PasswordUpdateTime  = $script:Updated
      ExpirationTimestamp = $script:Expires
      Source              = 'EncryptedPassword'
    }
  }

  Function Get-LapsADPassword {
    [CmdletBinding()]
    Param (
      [Parameter()] [System.String]$Identity,
      [Parameter()] [Switch]$AsPlainText
    )
    $global:FakeReads++
    $global:FakeIdentity = $Identity
    $global:FakePlainText = $AsPlainText.IsPresent
    If ($global:FakeError) {
      Throw $global:FakeError
    }
    Return $global:FakeEscrow
  }
}

AfterAll {
  Remove-Variable -Name 'FakeEscrow', 'FakeError', 'FakeReads', 'FakeIdentity', 'FakePlainText' `
    -Scope 'Global' -ErrorAction 'SilentlyContinue'
}

Describe 'Get-LapsCredential' {
  It 'declares SupportsShouldProcess so the module runs it in check mode' {
    (Get-Content -Raw (Join-Path $PSScriptRoot 'Get-LapsCredential.ps1')) |
      Should -Match '\[CmdletBinding\(SupportsShouldProcess'
  }

  BeforeEach {
    # The directory has escrowed nothing yet: the state a freshly joined machine starts in.
    $global:FakeEscrow = $Null
    $global:FakeError = $Null
    $global:FakeReads = 0
    $global:FakeIdentity = $Null
    $global:FakePlainText = $False
  }

  AfterEach {
    Remove-AnsibleContext
  }

  Context 'standalone JSON transport' {

    It 'reports not-yet-escrowed when the directory returns nothing, as a state rather than an error' {
      $Result = & $script:ScriptPath -Identity 'TCNAW-WSB01' | ConvertFrom-Json

      $Result.escrowed | Should -BeFalse
      $Result.changed | Should -BeFalse
      $Result.password | Should -BeNullOrEmpty
      $Result.msg | Should -Match 'not escrowed a credential for TCNAW-WSB01 yet'
    }

    It 'reports not-yet-escrowed when the object comes back without a password' {
      $global:FakeEscrow = New-FakeEscrow -Value ''

      $Result = & $script:ScriptPath -Identity 'TCNAW-WSB01' | ConvertFrom-Json

      $Result.escrowed | Should -BeFalse
      $Result.account | Should -BeNullOrEmpty
    }

    It 'returns the credential and its lifecycle once escrowed' {
      $global:FakeEscrow = New-FakeEscrow

      $Result = & $script:ScriptPath -Identity 'TCNAW-WSB01' | ConvertFrom-Json

      $Result.escrowed | Should -BeTrue
      $Result.changed | Should -BeFalse
      $Result.account | Should -Be 'Administrator'
      $Result.password | Should -Be 'Sup3r-S3cret-Passw0rd!'
      $Result.source | Should -Be 'EncryptedPassword'
      $Result.identity | Should -Be 'TCNAW-WSB01'
      $Result.msg | Should -Match 'has escrowed a credential'
    }

    It 'renders the timestamps as ISO 8601 in UTC so every transport reads them alike' {
      $global:FakeEscrow = New-FakeEscrow

      # Asserted on the wire, not after ConvertFrom-Json: PowerShell 7 turns an ISO string back
      # into a DateTime on the way in, 5.1 leaves it a string, and the contract is the text.
      $Emitted = (& $script:ScriptPath -Identity 'TCNAW-WSB01') -join "`n"

      $Emitted | Should -Match '"password_updated_time":\s*"2026-08-31T14:05:00\.0000000Z"'
      $Emitted | Should -Match '"expiration_timestamp":\s*"2026-09-30T14:05:00\.0000000Z"'
    }

    It 'passes the identity through to the directory as given' {
      & $script:ScriptPath -Identity 'TCNAW-WSB01' | Out-Null

      $global:FakeIdentity | Should -Be 'TCNAW-WSB01'
      $global:FakeReads | Should -Be 1
      # As plain text: a SecureString cannot cross the transport to the caller.
      $global:FakePlainText | Should -BeTrue
    }

    It 'treats a transient directory error as not-yet-escrowed, and says why' {
      $global:FakeError = 'The server is not operational'

      $Result = & $script:ScriptPath -Identity 'TCNAW-WSB01' 2>$null | ConvertFrom-Json

      $Result.escrowed | Should -BeFalse
      $Result.msg | Should -Match 'not operational'
    }

    It 'fails hard on an identity the directory does not know, because waiting would never fix it' {
      $global:FakeError = 'Cannot find an object with identity: ''NOPE-01'''

      { & $script:ScriptPath -Identity 'NOPE-01' 2>$null } | Should -Throw '*Cannot find*'
    }

    It 'rejects an identity that is not a computer name' {
      { & $script:ScriptPath -Identity 'CN=TCNAW-WSB01,DC=tcn' 2>$null } | Should -Throw
      { & $script:ScriptPath -Identity 'TCNAW-WSB01$' 2>$null } | Should -Throw
    }
  }

  Context '$Ansible transport' {

    It 'sets Changed=$False explicitly and publishes the credential through the result' {
      $global:FakeEscrow = New-FakeEscrow
      $Context = New-AnsibleContext

      $Emitted = & $script:ScriptPath -Identity 'TCNAW-WSB01'

      $Context.Changed | Should -BeFalse
      $Context.Failed | Should -BeFalse
      $Context.Result.escrowed | Should -BeTrue
      $Context.Result.password | Should -Be 'Sup3r-S3cret-Passw0rd!'
      # Everything goes through $Ansible.Result; the password may NEVER reach the output stream.
      $Emitted | Should -BeNullOrEmpty
    }

    It 'does not fail the task while the escrow is still pending' {
      $Context = New-AnsibleContext

      & $script:ScriptPath -Identity 'TCNAW-WSB01'

      $Context.Failed | Should -BeFalse
      $Context.Result.escrowed | Should -BeFalse
    }

    It 'reads in check mode too, and carries the mode through' {
      # -WhatIf reproduces the transport: win_powershell injects it for a SupportsShouldProcess
      # script in check mode, and the script must survive it rather than lose its New-Variable setup.
      $global:FakeEscrow = New-FakeEscrow
      $Context = New-AnsibleContext -CheckMode

      & $script:ScriptPath -Identity 'TCNAW-WSB01' -WhatIf | Out-Null

      $Context.Changed | Should -BeFalse
      $Context.Result.check_mode | Should -BeTrue
      $Context.Result.escrowed | Should -BeTrue
    }
  }
}
