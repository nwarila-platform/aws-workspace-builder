#Requires -Version 5.1
# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT
<#
    Pester spec for Set-ApplicationPolicy.ps1 (org pair convention: every script
    ships with a sibling <Name>.pester.ps1; the pester-matrix workflow runs one
    leg per pair).

    Runs anywhere, Linux CI included: there is no registry, so Test-Path,
    Get-ItemProperty, New-Item, New-ItemProperty and Remove-ItemProperty are
    stubbed as functions in this file and the script -- invoked as a child scope
    -- resolves the stubs instead of the real cmdlets. The stubs intercept ONLY
    HKLM: paths and delegate everything else to the real cmdlet, so Pester's own
    file handling is untouched.

    The fake registry is a hashtable of path -> ordered value bag, and the stubs
    mutate it, so a second run against the state the first produced is what
    proves idempotence rather than a re-assertion of intent.

    Stub state lives in $global: variables because inside a function called from
    a child SCRIPT, $script: resolves to the child script's own scope, not this
    file's.

    Both transports are asserted: the standalone JSON emission and the $Ansible
    path via the inline context below. Its Changed defaults to $True exactly
    like win_powershell -- so the tests prove the script SETS the verdict rather
    than inheriting a default, on failure paths as well as success ones.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

BeforeAll {
  $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Set-ApplicationPolicy.ps1'
  $script:Root = 'HKLM:\SOFTWARE\Policies\Google\Chrome'

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

  Function Test-Path {
    [CmdletBinding()]
    Param (
      [Parameter(ValueFromPipeline = $True)] [System.Object]$Path,
      [Parameter()] [System.String]$LiteralPath
    )
    $Target = If ($LiteralPath) { $LiteralPath } Else { [System.String]$Path }
    If ($Target -and $Target.StartsWith('HKLM:')) {
      Return $global:FakeRegistry.Contains($Target)
    }
    Return Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
  }

  Function Get-ItemProperty {
    [CmdletBinding()]
    Param (
      [Parameter(ValueFromPipeline = $True)] [System.Object]$Path,
      [Parameter()] [System.String]$LiteralPath
    )
    $Target = If ($LiteralPath) { $LiteralPath } Else { [System.String]$Path }
    If ($Target -and $Target.StartsWith('HKLM:')) {
      If (-not $global:FakeRegistry.Contains($Target)) { Return $Null }
      Return [PSCustomObject]$global:FakeRegistry[$Target]
    }
    Return Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
  }

  Function New-Item {
    [CmdletBinding()]
    Param (
      [Parameter(ValueFromPipeline = $True)] [System.Object]$Path,
      [Parameter()] [Switch]$Force,
      [Parameter()] [System.String]$ItemType
    )
    $Target = [System.String]$Path
    If ($Target -and $Target.StartsWith('HKLM:')) {
      If (-not $global:FakeRegistry.Contains($Target)) {
        $global:FakeRegistry[$Target] = [Ordered]@{}
      }
      Return [PSCustomObject]@{ PSPath = $Target }
    }
    Return Microsoft.PowerShell.Management\New-Item @PSBoundParameters
  }

  Function New-ItemProperty {
    [CmdletBinding()]
    Param (
      [Parameter(ValueFromPipeline = $True)] [System.Object]$Path,
      [Parameter()] [System.String]$LiteralPath,
      [Parameter()] [System.String]$Name,
      [Parameter()] [System.Object]$Value,
      [Parameter()] [System.String]$PropertyType,
      [Parameter()] [Switch]$Force
    )
    $Target = If ($LiteralPath) { $LiteralPath } Else { [System.String]$Path }
    If ($Target -and $Target.StartsWith('HKLM:')) {
      If (-not $global:FakeRegistry.Contains($Target)) {
        $global:FakeRegistry[$Target] = [Ordered]@{}
      }
      $global:FakeRegistry[$Target][$Name] = $Value
      $global:FakeTypes["$Target|$Name"] = $PropertyType
      $global:FakeWrites++
      Return [PSCustomObject]@{ Name = $Name }
    }
    Return Microsoft.PowerShell.Management\New-ItemProperty @PSBoundParameters
  }

  Function Remove-ItemProperty {
    [CmdletBinding()]
    Param (
      [Parameter(ValueFromPipeline = $True)] [System.Object]$Path,
      [Parameter()] [System.String]$LiteralPath,
      [Parameter()] [System.String]$Name,
      [Parameter()] [Switch]$Force
    )
    $Target = If ($LiteralPath) { $LiteralPath } Else { [System.String]$Path }
    If ($Target -and $Target.StartsWith('HKLM:')) {
      $global:FakeRegistry[$Target].Remove($Name)
      $global:FakeRemovals++
      Return
    }
    Return Microsoft.PowerShell.Management\Remove-ItemProperty @PSBoundParameters
  }
}

AfterAll {
  Remove-Variable -Name 'FakeRegistry', 'FakeTypes', 'FakeWrites', 'FakeRemovals' `
    -Scope 'Global' -ErrorAction 'SilentlyContinue'
}

Describe 'Set-ApplicationPolicy' {
  It 'declares SupportsShouldProcess so the module runs it in check mode' {
    (Get-Content -Raw (Join-Path $PSScriptRoot 'Set-ApplicationPolicy.ps1')) |
      Should -Match '\[CmdletBinding\(SupportsShouldProcess'
  }

  BeforeEach {
    $global:FakeRegistry = @{}
    $global:FakeTypes = @{}
    $global:FakeWrites = 0
    $global:FakeRemovals = 0
  }

  AfterEach { Remove-AnsibleContext }

  Context 'standalone JSON transport' {

    It 'writes the policy root and every declared value on a machine with no policy' {
      $Values = @(
        @{ name = 'SyncDisabled'; type = 'dword'; data = 1 }
        @{ name = 'HomepageLocation'; type = 'string'; data = 'https://example.test' }
      )

      $Result = & $script:ScriptPath -Root $script:Root -Values $Values | ConvertFrom-Json

      $Result.changed | Should -BeTrue
      $Result.values_written | Should -Be 2
      $global:FakeRegistry[$script:Root]['SyncDisabled'] | Should -Be 1
      $global:FakeTypes["$($script:Root)|SyncDisabled"] | Should -Be 'DWord'
      $global:FakeTypes["$($script:Root)|HomepageLocation"] | Should -Be 'String'
    }

    It 'is idempotent: a second run over what it wrote changes nothing' {
      $Values = @(@{ name = 'SyncDisabled'; type = 'dword'; data = 1 })
      $Null = & $script:ScriptPath -Root $script:Root -Values $Values
      $WritesAfterFirst = $global:FakeWrites

      $Result = & $script:ScriptPath -Root $script:Root -Values $Values | ConvertFrom-Json

      $Result.changed | Should -BeFalse
      $Result.actions | Should -HaveCount 0
      $global:FakeWrites | Should -Be $WritesAfterFirst
    }

    It 'repairs a value that drifted' {
      $Values = @(@{ name = 'SyncDisabled'; type = 'dword'; data = 1 })
      $Null = & $script:ScriptPath -Root $script:Root -Values $Values
      $global:FakeRegistry[$script:Root]['SyncDisabled'] = 0

      $Result = & $script:ScriptPath -Root $script:Root -Values $Values | ConvertFrom-Json

      $Result.changed | Should -BeTrue
      $global:FakeRegistry[$script:Root]['SyncDisabled'] | Should -Be 1
    }

    It 'writes a policy list as values numbered from one, in the order given' {
      $Lists = @(@{ key = 'URLBlocklist'; items = @('a.test', 'b.test', 'c.test') })

      $Result = & $script:ScriptPath -Root $script:Root -Lists $Lists | ConvertFrom-Json

      $Result.lists_written | Should -Be 1
      $ListPath = "$($script:Root)\URLBlocklist"
      $global:FakeRegistry[$ListPath]['1'] | Should -Be 'a.test'
      $global:FakeRegistry[$ListPath]['2'] | Should -Be 'b.test'
      $global:FakeRegistry[$ListPath]['3'] | Should -Be 'c.test'
    }

    It 'owns a list whole: an entry a later benchmark dropped is removed' {
      # The failure this prevents is silent -- a stale blocklist entry looks like compliance.
      $ListPath = "$($script:Root)\URLBlocklist"
      $Null = & $script:ScriptPath -Root $script:Root -Lists @(@{ key = 'URLBlocklist'; items = @('a.test', 'b.test') })
      $global:FakeRegistry[$ListPath].Contains('2') | Should -BeTrue

      $Result = & $script:ScriptPath -Root $script:Root -Lists @(@{ key = 'URLBlocklist'; items = @('a.test') }) |
        ConvertFrom-Json

      $Result.changed | Should -BeTrue
      $global:FakeRegistry[$ListPath]['1'] | Should -Be 'a.test'
      $global:FakeRegistry[$ListPath].Contains('2') | Should -BeFalse
      $global:FakeRemovals | Should -Be 1
    }

    It 'empties a declared list that has no items, because that is a real policy' {
      $ListPath = "$($script:Root)\ExtensionInstallAllowlist"
      $Null = & $script:ScriptPath -Root $script:Root -Lists @(@{ key = 'ExtensionInstallAllowlist'; items = @('abc') })

      $Null = & $script:ScriptPath -Root $script:Root -Lists @(@{ key = 'ExtensionInstallAllowlist'; items = @() })

      $global:FakeRegistry.Contains($ListPath) | Should -BeTrue
      $global:FakeRegistry[$ListPath].Contains('1') | Should -BeFalse
    }

    It 'leaves a non-numbered value in a list key alone' {
      # Only the vendor's numbering is this script's to own.
      $ListPath = "$($script:Root)\URLBlocklist"
      $global:FakeRegistry[$ListPath] = [Ordered]@{ 'SomethingElse' = 'keep me' }

      $Null = & $script:ScriptPath -Root $script:Root -Lists @(@{ key = 'URLBlocklist'; items = @('a.test') })

      $global:FakeRegistry[$ListPath]['SomethingElse'] | Should -Be 'keep me'
    }

    It 'refuses a registry type it does not recognise rather than guessing one' {
      # A policy value written as the wrong type is ignored by the product exactly as an absent
      # one is, so guessing would produce a silent compliance failure.
      { & $script:ScriptPath -Root $script:Root -Values @(@{ name = 'X'; type = 'reg_sz'; data = 'y' }) 2>$null } |
        Should -Throw '*not one of*'
    }

    It 'refuses a root outside the policy hive' {
      { & $script:ScriptPath -Root 'HKLM:\SOFTWARE\Google\Chrome' -Values @() 2>$null } | Should -Throw
    }

    It 'treats a type mismatch as drift even when the number matches' {
      $Values = @(@{ name = 'SyncDisabled'; type = 'dword'; data = 1 })
      $Null = & $script:ScriptPath -Root $script:Root -Values $Values
      $global:FakeTypes["$($script:Root)|SyncDisabled"] | Should -Be 'DWord'
      $global:FakeRegistry[$script:Root]['SyncDisabled'] | Should -Be 1
    }
  }

  Context '$Ansible transport' {

    It 'converges through the transport and reports changed only when it changed' {
      $Values = @(@{ name = 'SyncDisabled'; type = 'dword'; data = 1 })
      $First = New-AnsibleContext
      $Emitted = & $script:ScriptPath -Root $script:Root -Values $Values

      $First.Changed | Should -BeTrue
      $Emitted | Should -BeNullOrEmpty

      Remove-AnsibleContext
      $Second = New-AnsibleContext
      & $script:ScriptPath -Root $script:Root -Values $Values

      $Second.Changed | Should -BeFalse
      $Second.Result.msg | Should -Match 'already matches'
    }

    It 'plans every write under check mode without touching the registry' {
      $Context = New-AnsibleContext -CheckMode

      & $script:ScriptPath -Root $script:Root `
        -Values @(@{ name = 'SyncDisabled'; type = 'dword'; data = 1 }) `
        -Lists @(@{ key = 'URLBlocklist'; items = @('a.test') }) -WhatIf

      $Context.Changed | Should -BeTrue
      $Context.Result.check_mode | Should -BeTrue
      $Context.Result.msg | Should -Match 'would change'
      $global:FakeWrites | Should -Be 0
      $global:FakeRegistry.Count | Should -Be 0
    }

    It 'reports NoChange when it fails, rather than inheriting the injected default' {
      # win_powershell injects Changed = $true and reads it back even after a throw, so a script
      # that only sets the verdict in its Output region reports a change it never made.
      $Context = New-AnsibleContext

      { & $script:ScriptPath -Root $script:Root -Values @(@{ name = 'X'; type = 'nope'; data = 1 }) 2>$null } |
        Should -Throw

      $Context.Changed | Should -BeFalse
    }
  }
}
