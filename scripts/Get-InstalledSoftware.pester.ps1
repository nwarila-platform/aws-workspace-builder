#Requires -Version 5.1
# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT
<#
    Pester spec for Get-InstalledSoftware.ps1 (org pair convention: every
    script ships with a sibling <Name>.pester.ps1; the pester-matrix workflow
    runs one leg per pair).

    Runs anywhere, Linux CI included: there is no registry, so Test-Path,
    Get-ChildItem and Get-ItemProperty are stubbed as functions in this file
    and the script -- invoked as a child scope -- resolves the stubs instead of
    the real cmdlets. The stubs intercept ONLY HKLM: paths and delegate
    everything else to the real cmdlet, so Pester's own file handling is
    untouched. The script owns the uninstall roots outright -- where Windows
    registers software is not a caller's choice -- so the spec models those
    exact paths rather than injecting its own.

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
  $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Get-InstalledSoftware.ps1'

  $script:Native = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
  $script:Wow    = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

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

  # In-memory stand-in for the uninstall hives. $global:FakeRegistry maps a
  # root path to an ordered list of subkeys; each subkey is a property bag, and
  # a bag that omits DisplayName models the ordinary no-name neighbour.
  Function Test-Path {
    [CmdletBinding()]
    Param (
      [Parameter(ValueFromPipeline = $True)] [System.Object]$Path,
      [Parameter()] [System.String]$LiteralPath
    )

    If ($LiteralPath -and $LiteralPath.StartsWith('HKLM:')) {
      Return $global:FakeRegistry.Contains($LiteralPath)
    }
    Return Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
  }

  Function Get-ChildItem {
    [CmdletBinding()]
    Param (
      [Parameter(ValueFromPipeline = $True)] [System.Object]$Path,
      [Parameter()] [System.String]$LiteralPath
    )

    If ($LiteralPath -and $LiteralPath.StartsWith('HKLM:')) {
      $global:FakeReads++
      If ($global:FakeDenied) {
        Throw ('Requested registry access is not allowed: {0}' -f $LiteralPath)
      }
      If (-not $global:FakeRegistry.Contains($LiteralPath)) {
        Return @()
      }
      # An empty root must yield nothing. Guarded explicitly because 0..(0-1)
      # counts DOWN in PowerShell and would fabricate keys 0 and -1.
      $Subkeys = @($global:FakeRegistry[$LiteralPath])
      If ($Subkeys.Count -eq 0) {
        Return @()
      }
      # Only PSPath is consumed by the script; it is the handle passed to
      # Get-ItemProperty below.
      Return @(
        0..($Subkeys.Count - 1) | ForEach-Object {
          $Reg = $Subkeys[$PSItem]
          $KeyName = If ($Reg.Contains('PSChildName')) { $Reg['PSChildName'] } Else { [System.String]$PSItem }
          [PSCustomObject]@{ PSPath = ('{0}##{1}' -f $LiteralPath, $PSItem); PSChildName = $KeyName }
        }
      )
    }
    Return Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
  }

  Function Get-ItemProperty {
    [CmdletBinding()]
    Param (
      [Parameter(ValueFromPipeline = $True)] [System.Object]$Path,
      [Parameter()] [System.String]$LiteralPath
    )

    If ($LiteralPath -and $LiteralPath.StartsWith('HKLM:')) {
      $Parts = $LiteralPath -split '##'
      Return [PSCustomObject]$global:FakeRegistry[$Parts[0]][[System.Int32]$Parts[1]]
    }
    Return Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
  }
}

AfterAll {
  Remove-Variable -Name 'FakeRegistry', 'FakeReads' -Scope 'Global' -ErrorAction 'SilentlyContinue'
}

Describe 'Get-InstalledSoftware' {
  It 'declares SupportsShouldProcess so the module runs it in check mode' {
    (Get-Content -Raw (Join-Path $PSScriptRoot 'Get-InstalledSoftware.ps1')) |
      Should -Match '\[CmdletBinding\(SupportsShouldProcess'
  }


  BeforeEach {
    # Both roots exist and hold only unrelated neighbours by default. The first
    # neighbour deliberately carries NO DisplayName, which is the common shape
    # in a real uninstall hive and the case strict mode makes fatal if the
    # script reads properties directly.
    $global:FakeRegistry = [Ordered]@{
      $script:Native = @(
        @{ SomeOtherValue = 'no DisplayName here' },
        @{ DisplayName = 'Unrelated Product'; DisplayVersion = '1.0.0.0'; InstallLocation = 'C:\Other' }
      )
      $script:Wow = @()
    }
    $global:FakeReads = 0
    $global:FakeDenied = $False
  }

  AfterEach {
    Remove-AnsibleContext
  }

  Context 'standalone JSON transport' {

    It 'reports NoChange and no entries when the product is not registered' {
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' |
        ConvertFrom-Json

      $Result.changed | Should -BeFalse
      $Result.count | Should -Be 0
      $Result.entries | Should -HaveCount 0
    }

    It 'survives subkeys that carry no DisplayName' {
      # The default hive leads with a no-name neighbour; reaching the match at
      # all proves the scan did not abort on it.
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'; InstallLocation = 'C:\PDQ'
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' |
        ConvertFrom-Json

      $Result.count | Should -Be 1
      $Result.entries[0].DisplayVersion | Should -Be '20.1.8.0'
    }

    It 'returns the version and location of a single registration' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'; InstallLocation = 'C:\PDQ'
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' |
        ConvertFrom-Json

      $Result.changed | Should -BeFalse
      $Result.count | Should -Be 1
      $Result.entries[0].DisplayVersion | Should -Be '20.1.8.0'
      $Result.entries[0].InstallLocation | Should -Be 'C:\PDQ'
    }

    It 'returns the whole registration so one read answers many questions' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName     = 'PDQ Deploy'
        DisplayVersion  = '20.1.8.0'
        InstallLocation = 'C:\PDQ'
        Publisher       = 'PDQ.com'
        InstallDate     = '20260814'
        EstimatedSize   = 123456
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json

      $Result.entries[0].Publisher | Should -Be 'PDQ.com'
      $Result.entries[0].InstallDate | Should -Be '20260814'
      $Result.entries[0].EstimatedSize | Should -Be 123456
      $Result.entries[0].DisplayVersion | Should -Be '20.1.8.0'
    }

    It 'fails closed when a root cannot be read, never reporting absent' {
      $global:FakeDenied = $True
      { & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' 2>$null } | Should -Throw '*not allowed*'
    }

    It 'takes the ProductCode from the key name, not a tampered uninstall string' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'
        PSChildName = '{4E9FA177-A200-4DFC-9DC6-9D0290FCAAC2}'
        UninstallString = 'MsiExec.exe /X{DEADBEEF-0000-0000-0000-000000000000}'
      }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json
      $Result.entries[0].product_id | Should -Be '{4E9FA177-A200-4DFC-9DC6-9D0290FCAAC2}'
    }

    It 'treats only the braced {GUID} key name as a ProductCode, not a bare GUID' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'
        PSChildName = '4E9FA177-A200-4DFC-9DC6-9D0290FCAAC2'
      }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json
      $Result.entries[0].product_id | Should -BeNullOrEmpty
    }

    It 'reports ambiguity without crashing when a duplicate lacks a version' {
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'; PSChildName = 'a' }
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; PSChildName = 'b' }
      $Context = New-AnsibleContext
      & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0'
      $Context.Failed | Should -BeTrue
      $Context.Result.count | Should -Be 2
    }

    It 'rejects a version that is not four parts' {
      { & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8' 2>$null } | Should -Throw
    }

    It 'drops PowerShell path bookkeeping, which is not registry data' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName    = 'PDQ Deploy'
        DisplayVersion = '20.1.8.0'
        PSPath         = 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\...'
        PSChildName    = '{GUID}'
        PSProvider     = 'Microsoft.PowerShell.Core\Registry'
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json

      ($Result.entries[0].PSObject.Properties.Name -match '^PS') | Should -BeNullOrEmpty
    }

    It 'reads only the uninstall roots, never the vendor product tree' {
      # The vendor tree is where License and Secure Key live. This script must never walk it;
      # the roots it reads are fixed, so a secret can only appear if a vendor writes one into
      # its own uninstall key.
      $global:FakeRegistry['HKLM:\SOFTWARE\Admin Arsenal\PDQ Deploy'] = @(
        @{ DisplayName = 'PDQ Deploy'; License = 'SECRET-LICENCE-KEY'; 'Secure Key' = 'SECRET-SECURE-KEY' }
      )
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'
      }

      $Emitted = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0'

      $Emitted | Should -Not -Match 'SECRET-LICENCE-KEY'
      $Emitted | Should -Not -Match 'SECRET-SECURE-KEY'
    }

    It 'reports the MSI ProductCode so a caller can uninstall through win_package' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName     = 'PDQ Deploy'
        DisplayVersion  = '20.1.8.0'
        PSChildName = '{4E9FA177-A200-4DFC-9DC6-9D0290FCAAC2}'
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json

      $Result.entries[0].product_id | Should -Be '{4E9FA177-A200-4DFC-9DC6-9D0290FCAAC2}'
    }

    It 'reports an empty ProductCode for a non-MSI product' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName     = 'PDQ Deploy'
        DisplayVersion  = '20.1.8.0'
        PSChildName = 'PDQ Deploy'
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json

      $Result.entries[0].product_id | Should -BeNullOrEmpty
    }

    It 'reads past a bundle that also registers its own MSI, hidden' {
      # The real shape this exists for: an installer bundle registers itself (visible) and the
      # MSI it wraps (SystemComponent=1, hidden from Programs and Features) under one name and
      # one version. Both are the same install, so the read must answer rather than refuse.
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'Amazon SSM Agent'; DisplayVersion = '3.3.4851.0'; SystemComponent = 1
        PSChildName = '{1C1593B7-10E6-4745-9E59-8FB311CC92F4}'
      }
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'Amazon SSM Agent'; DisplayVersion = '3.3.4851.0'
        PSChildName = '{a535ae3f-ae28-4e8a-9174-b918c3355ee0}'
      }

      $Result = & $script:ScriptPath -DisplayName 'Amazon SSM Agent' -Version '3.3.4851.0' | ConvertFrom-Json

      $Result.ambiguous | Should -BeFalse
      $Result.count | Should -Be 1
      $Result.action_required | Should -BeFalse
      # The VISIBLE registration is the one kept -- the bundle, not the wrapped MSI.
      $Result.entries[0].product_id | Should -Be '{a535ae3f-ae28-4e8a-9174-b918c3355ee0}'
    }

    It 'still answers from a hidden registration when it is the only one' {
      # Dropping it would report a present product as absent, which is worse than reading it.
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'; SystemComponent = 1
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json

      $Result.count | Should -Be 1
      $Result.action_required | Should -BeFalse
    }

    It 'reports the keys to repair when the product is hidden from Add/Remove Programs' {
      # A product registered only as SystemComponent does not appear in Programs and Features, so
      # inventory tooling that reads ARP cannot see it. The read names the keys; repairing them is
      # the caller's job, because a read never changes the machine.
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'; SystemComponent = 1
        PSChildName = '{4E9FA177-A200-4DFC-9DC6-9D0290FCAAC2}'
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json

      $Result.arp_hidden | Should -BeTrue
      $Result.hidden_registry_keys | Should -HaveCount 1
      $Result.hidden_registry_keys[0] | Should -Be ($script:Native + '\{4E9FA177-A200-4DFC-9DC6-9D0290FCAAC2}')
    }

    It 'names no keys to repair when a visible registration already exists' {
      # The bundle is listed, so the product is not hidden. Unhiding the MSI it wraps would put one
      # install in the list twice and make the next read ambiguous.
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'Amazon SSM Agent'; DisplayVersion = '3.3.4851.0'; SystemComponent = 1
        PSChildName = '{1C1593B7-10E6-4745-9E59-8FB311CC92F4}'
      }
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'Amazon SSM Agent'; DisplayVersion = '3.3.4851.0'
        PSChildName = '{a535ae3f-ae28-4e8a-9174-b918c3355ee0}'
      }

      $Result = & $script:ScriptPath -DisplayName 'Amazon SSM Agent' -Version '3.3.4851.0' | ConvertFrom-Json

      $Result.arp_hidden | Should -BeFalse
      $Result.hidden_registry_keys | Should -HaveCount 0
    }

    It 'still refuses when two VISIBLE registrations claim the same product' {
      # The hidden-entry rule must not become a way to silently pick one of two real installs.
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0' }
      $global:FakeRegistry[$script:Wow] = @(
        @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '19.3.254.0' }
      )

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json

      $Result.ambiguous | Should -BeTrue
      $Result.count | Should -Be 2
    }

    It 'refuses to answer when two registrations claim the same product' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'
      }
      $global:FakeRegistry[$script:Wow] = @(
        @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '19.3.254.0' }
      )

      # Standalone still emits the evidence before exiting non-zero: an error that hides what it
      # saw costs a second run to diagnose.
      $Emitted = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0'
      $ExitCode = $LASTEXITCODE
      $Result = $Emitted | ConvertFrom-Json

      $ExitCode | Should -Be 2
      $Result.ambiguous | Should -BeTrue
      $Result.count | Should -Be 2
      $Result.msg | Should -Match 'choosing one would be a guess'
      $Result.entries.DisplayVersion | Should -Be @('19.3.254.0', '20.1.8.0')
    }

    It 'reports action_required when the product is absent' {
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json
      $Result.action_required | Should -BeTrue
      $Result.installed_version | Should -BeNullOrEmpty
    }

    It 'reports action_required when the installed version is older than the pin' {
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '19.3.254.0' }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json
      $Result.action_required | Should -BeTrue
      $Result.installed_version | Should -Be '19.3.254.0'
    }

    It 'reports no action ONLY when the installed version equals the pin' {
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0' }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json
      $Result.action_required | Should -BeFalse
      $Result.comparison | Should -Be 'equal'
      $Result.downgrade_required | Should -BeFalse
    }

    It 'reports action when the installed version is NEWER than the pin, and says a removal is needed' {
      # The pin is exact: an image that accepted anything newer would not be reproducible, and two
      # desktops built weeks apart would carry different software and both claim to be converged.
      # Ahead of the pin is fixed differently from behind it, so the caller is told which.
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '21.0.0.0' }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json
      $Result.action_required | Should -BeTrue
      $Result.comparison | Should -Be 'newer'
      $Result.downgrade_required | Should -BeTrue
    }

    It 'reports an in-place upgrade when the installed version is older than the pin' {
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '19.3.254.0' }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json
      $Result.action_required | Should -BeTrue
      $Result.comparison | Should -Be 'older'
      # Behind the pin an installer upgrades over the top; nothing has to come off first.
      $Result.downgrade_required | Should -BeFalse
    }

    It 'reports the product absent as its own comparison' {
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json
      $Result.comparison | Should -Be 'absent'
      $Result.downgrade_required | Should -BeFalse
    }

    It 'pads a short registered version before comparing, so "22.23.2" meets a pin of 22.23.2.0' {
      # System.Version reads a missing component as -1, so without padding a vendor that
      # registers three parts would sit forever "behind" the four-part pin and reinstall on
      # every run. A vendor omitting a trailing component means zero, not unknown.
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '22.23.2' }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '22.23.2.0' | ConvertFrom-Json
      $Result.action_required | Should -BeFalse
      # The report carries the machine's answer verbatim; only the comparison pads.
      $Result.installed_version | Should -Be '22.23.2'
    }

    It 'pads a two-part registered version the same way' {
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '26.02' }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '26.2.0.0' | ConvertFrom-Json
      $Result.action_required | Should -BeFalse
    }

    It 'still reports action when the padded short version is genuinely behind the pin' {
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = '22.23.2' }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '22.23.2.1' | ConvertFrom-Json
      $Result.action_required | Should -BeTrue
    }

    It 'treats an unparseable installed version as needing action' {
      # A registration that cannot say what version it is cannot be trusted to be current.
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy'; DisplayVersion = 'not-a-version' }
      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' | ConvertFrom-Json
      $Result.action_required | Should -BeTrue
    }

    It 'matches the display name exactly rather than by substring' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy Console'; DisplayVersion = '9.9.9.9'; InstallLocation = 'C:\Console'
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' |
        ConvertFrom-Json

      $Result.count | Should -Be 0
    }

    It 'skips a root that does not exist instead of failing' {
      # A 32-bit-only host carries no Wow6432Node hive at all. The script must
      # read the root that exists and pass over the one that does not.
      $global:FakeRegistry.Remove($script:Wow)
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'; InstallLocation = 'C:\PDQ'
      }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' |
        ConvertFrom-Json

      $Result.count | Should -Be 1
      # The absent root was never enumerated; only the real one was read.
      $global:FakeReads | Should -Be 1
    }

    It 'tolerates a registration missing its version and location' {
      $global:FakeRegistry[$script:Native] += @{ DisplayName = 'PDQ Deploy' }

      $Result = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' |
        ConvertFrom-Json

      $Result.count | Should -Be 1
      # Assert the properties are ABSENT rather than reading them: a registration that never
      # carried them yields an entry that does not either, and reading a property that is not
      # there is fatal under strict mode on some PowerShell versions.
      $Result.entries[0].PSObject.Properties.Name | Should -Not -Contain 'DisplayVersion'
      $Result.entries[0].PSObject.Properties.Name | Should -Not -Contain 'InstallLocation'
    }
  }

  Context '$Ansible transport' {

    It 'sets Changed=$False explicitly, because a read never changes anything' {
      $global:FakeRegistry[$script:Native] += @{
        DisplayName = 'PDQ Deploy'; DisplayVersion = '20.1.8.0'; InstallLocation = 'C:\PDQ'
      }
      $Context = New-AnsibleContext

      $Emitted = & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0'

      $Context.Changed | Should -BeFalse
      $Context.Result.count | Should -Be 1
      $Context.Result.msg | Should -Match 'Found 1 registration'
      # Everything goes through $Ansible.Result; nothing may leak to output.
      $Emitted | Should -BeNullOrEmpty
    }

    It 'reports NoChange in check mode too, and carries the mode through' {
      # -WhatIf reproduces the transport: win_powershell injects it for a SupportsShouldProcess
      # script in check mode, and the script must survive it rather than lose its New-Variable setup.
      $Context = New-AnsibleContext -CheckMode

      & $script:ScriptPath -DisplayName 'PDQ Deploy' -Version '20.1.8.0' -WhatIf | Out-Null

      $Context.Changed | Should -BeFalse
      $Context.Result.check_mode | Should -BeTrue
    }
  }
}
