#Requires -Version 5.1
# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT
<#
    Pester spec for Set-RemoteManagementPolicy.ps1 (org pair convention: every
    script ships with a sibling <Name>.pester.ps1; the pester-matrix workflow
    runs one leg per pair).

    Runs anywhere, Linux CI included: there is no directory, no GPMC and no
    firewall, so every cmdlet the script reaches for -- the ActiveDirectory,
    GroupPolicy and NetSecurity surfaces -- is stubbed as a function in this
    file, and the script, invoked as a child scope, resolves the stubs instead
    of the real cmdlets (functions outrank cmdlets even where the modules
    exist). The stubs share one fake directory in $global: variables: a GPO
    list, a registry-policy table, one firewall rule with its filters, the
    GPO's AD attributes, the OU's links, and a SYSVOL folder under TestDrive
    that the script's own file writes land in. Writes mutate that state, so a
    second run against it proves idempotence the same way the playbook does.

    Stub state lives in $global: variables because inside a function called
    from a child SCRIPT, $script: resolves to the child script's own scope,
    not this file's.

    Both transports are asserted: the standalone JSON emission and the
    $Ansible path via the inline context below (pairs are self-contained; no
    imports). Its Changed defaults to $True exactly like win_powershell -- so
    the idempotence tests prove the script SETS Changed=$False rather than
    inheriting a default.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

BeforeAll {
  $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'Set-RemoteManagementPolicy.ps1'
  $script:GpoName = 'WorkSpaces Remote Management'
  $script:TargetOU = 'OU=WorkSpaces,OU=Domain Workstations,DC=tcn,DC=example,DC=test'
  $script:Operator = '203.0.113.10'
  $script:DomainSid = 'S-1-5-21-1000000000-2000000000-3000000000'
  $script:RootSid = 'S-1-5-21-4000000000-5000000000-6000000000'

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

  # Where the script's template lands inside the fake SYSVOL. Built with the
  # same Combine call the script uses, so the assertion holds on a platform
  # where the backslashes are one long filename just as it does where they
  # are directories.
  Function Get-FakeTemplatePath {
    [System.IO.Path]::Combine($global:FakeSysvol, 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf')
  }

  #region ------ [ The fake directory ] ------------------------------------ #
  # Only $global: state in these: they are resolved from the child script.

  Function Get-ADDomain {
    [CmdletBinding()]
    Param (
      [Parameter(Position = 0)] [System.String]$Identity,
      [Parameter()] [System.String]$Server
    )
    If ($Identity) {
      Return [PSCustomObject]@{
        DNSRoot   = 'root.example.test'
        DomainSID = [PSCustomObject]@{ Value = $global:FakeRootSid }
      }
    }
    [PSCustomObject]@{
      DNSRoot   = 'tcn.example.test'
      DomainSID = [PSCustomObject]@{ Value = $global:FakeDomainSid }
    }
  }

  Function Get-ADForest {
    [CmdletBinding()]
    Param ()
    [PSCustomObject]@{ RootDomain = 'root.example.test' }
  }

  Function Get-ADOrganizationalUnit {
    [CmdletBinding()]
    Param (
      [Parameter()] [System.String]$Identity,
      [Parameter()] [System.String]$Server
    )
    If (-not $global:FakeOUExists) {
      Throw ('Cannot find an object with identity: ''{0}''' -f $Identity)
    }
    [PSCustomObject]@{ DistinguishedName = $Identity }
  }

  Function Get-GPO {
    [CmdletBinding()]
    Param (
      [Parameter()] [Switch]$All,
      [Parameter()] [System.String]$Domain
    )
    $global:FakeGpos
  }

  Function New-GPO {
    [CmdletBinding()]
    Param (
      [Parameter()] [System.String]$Name,
      [Parameter()] [System.String]$Comment,
      [Parameter()] [System.String]$Domain
    )
    $Gpo = [PSCustomObject]@{
      DisplayName = $Name
      Id          = [System.Guid]::NewGuid()
      Path        = 'CN={0},CN=Policies,CN=System,DC=tcn,DC=example,DC=test' -f [System.Guid]::NewGuid()
      GpoStatus   = 'AllSettingsEnabled'
      Comment     = $Comment
    }
    $global:FakeGpos.Add($Gpo)
    $Gpo
  }

  Function Get-GPRegistryValue {
    [CmdletBinding()]
    Param (
      [Parameter()] $Guid,
      [Parameter()] [System.String]$Domain,
      [Parameter()] [System.String]$Key,
      [Parameter()] [System.String]$ValueName
    )
    $Slot = '{0}|{1}' -f $Key, $ValueName
    If (-not $global:FakeRegistry.ContainsKey($Slot)) {
      Return $Null
    }
    [PSCustomObject]$global:FakeRegistry[$Slot]
  }

  Function Set-GPRegistryValue {
    [CmdletBinding()]
    Param (
      [Parameter()] $Guid,
      [Parameter()] [System.String]$Domain,
      [Parameter()] [System.String]$Key,
      [Parameter()] [System.String]$ValueName,
      [Parameter()] [System.String]$Type,
      [Parameter()] $Value
    )
    $global:FakeRegistry['{0}|{1}' -f $Key, $ValueName] = @{ Type = $Type; Value = $Value }
    $global:FakeRegistryWrites++
  }

  Function Get-NetFirewallRule {
    [CmdletBinding()]
    Param (
      [Parameter()] [System.String]$PolicyStore,
      [Parameter()] [System.String]$Name
    )
    $global:FakeRuleStore = $PolicyStore
    $global:FakeRule
  }

  Function New-NetFirewallRule {
    [CmdletBinding()]
    Param (
      [Parameter()] [System.String]$PolicyStore,
      [Parameter()] [System.String]$Name,
      [Parameter()] [System.String]$DisplayName,
      [Parameter()] [System.String]$Group,
      [Parameter()] [System.String]$Description,
      [Parameter()] [System.String]$Direction,
      [Parameter()] [System.String]$Action,
      [Parameter()] [System.String]$Enabled,
      [Parameter()] [System.String]$Profile,
      [Parameter()] [System.String]$Protocol,
      [Parameter()] $LocalPort,
      [Parameter()] $RemoteAddress
    )
    $global:FakeRule = [PSCustomObject]@{
      Name      = $Name
      Enabled   = $Enabled
      Direction = $Direction
      Action    = $Action
      Profile   = $Profile
    }
    $global:FakeRulePort = [PSCustomObject]@{ Protocol = $Protocol; LocalPort = [System.String]$LocalPort }
    $global:FakeRuleAddress = [PSCustomObject]@{ RemoteAddress = [System.String]$RemoteAddress }
    $global:FakeRuleCreates++
  }

  Function Set-NetFirewallRule {
    [CmdletBinding()]
    Param (
      [Parameter()] [System.String]$PolicyStore,
      [Parameter()] [System.String]$Name,
      [Parameter()] [System.String]$Direction,
      [Parameter()] [System.String]$Action,
      [Parameter()] [System.String]$Enabled,
      [Parameter()] [System.String]$Profile,
      [Parameter()] [System.String]$Protocol,
      [Parameter()] $LocalPort,
      [Parameter()] $RemoteAddress
    )
    $global:FakeRule.Enabled = $Enabled
    $global:FakeRule.Direction = $Direction
    $global:FakeRule.Action = $Action
    $global:FakeRule.Profile = $Profile
    $global:FakeRulePort.Protocol = $Protocol
    $global:FakeRulePort.LocalPort = [System.String]$LocalPort
    $global:FakeRuleAddress.RemoteAddress = [System.String]$RemoteAddress
    $global:FakeRuleUpdates++
  }

  Function Get-NetFirewallPortFilter {
    [CmdletBinding()]
    Param ([Parameter(ValueFromPipeline)] $InputObject)
    $global:FakeRulePort
  }

  Function Get-NetFirewallAddressFilter {
    [CmdletBinding()]
    Param ([Parameter(ValueFromPipeline)] $InputObject)
    $global:FakeRuleAddress
  }

  Function Get-ADObject {
    [CmdletBinding()]
    Param (
      [Parameter()] [System.String]$Identity,
      [Parameter()] [System.String]$Server,
      [Parameter()] [System.String[]]$Properties
    )
    [PSCustomObject]@{
      gPCFileSysPath           = $global:FakeSysvol
      gPCMachineExtensionNames = $global:FakeAdExtensionNames
      versionNumber            = $global:FakeAdVersion
    }
  }

  Function Set-ADObject {
    [CmdletBinding()]
    Param (
      [Parameter()] [System.String]$Identity,
      [Parameter()] [System.String]$Server,
      [Parameter()] [System.Collections.Hashtable]$Replace
    )
    If ($Replace.ContainsKey('gPCMachineExtensionNames')) {
      $global:FakeAdExtensionNames = [System.String]$Replace['gPCMachineExtensionNames']
    }
    If ($Replace.ContainsKey('versionNumber')) {
      $global:FakeAdVersion = [System.Int32]$Replace['versionNumber']
    }
  }

  Function Get-GPInheritance {
    [CmdletBinding()]
    Param (
      [Parameter()] [System.String]$Target,
      [Parameter()] [System.String]$Domain
    )
    [PSCustomObject]@{ GpoLinks = @($global:FakeLinks) }
  }

  Function New-GPLink {
    [CmdletBinding()]
    Param (
      [Parameter()] $Guid,
      [Parameter()] [System.String]$Target,
      [Parameter()] [System.String]$Domain,
      [Parameter()] [System.String]$LinkEnabled
    )
    $global:FakeLinks.Add([PSCustomObject]@{ GpoId = [System.String]$Guid; Enabled = $True })
    $global:FakeLinkCreates++
  }

  Function Set-GPLink {
    [CmdletBinding()]
    Param (
      [Parameter()] $Guid,
      [Parameter()] [System.String]$Target,
      [Parameter()] [System.String]$Domain,
      [Parameter()] [System.String]$LinkEnabled
    )
    ForEach ($Link In $global:FakeLinks) {
      If ($Link.GpoId -eq [System.String]$Guid) {
        $Link.Enabled = $True
      }
    }
  }

  #endregion --- [ The fake directory ] ------------------------------------ #

  # One standalone converge with the spec's constants, parsed off the wire.
  Function Invoke-ConvergeJson {
    (& $script:ScriptPath -Name $script:GpoName -TargetOU $script:TargetOU -OperatorAddress $script:Operator) |
      ConvertFrom-Json
  }
}

AfterAll {
  Remove-Variable -Name @(
    'FakeGpos', 'FakeRegistry', 'FakeRegistryWrites', 'FakeRule', 'FakeRulePort', 'FakeRuleAddress'
    'FakeRuleStore', 'FakeRuleCreates', 'FakeRuleUpdates', 'FakeAdExtensionNames', 'FakeAdVersion'
    'FakeLinks', 'FakeLinkCreates', 'FakeOUExists', 'FakeSysvol', 'FakeDomainSid', 'FakeRootSid'
  ) -Scope 'Global' -ErrorAction 'SilentlyContinue'
}

Describe 'Set-RemoteManagementPolicy' {
  It 'declares SupportsShouldProcess so the module runs it in check mode' {
    (Get-Content -Raw (Join-Path $PSScriptRoot 'Set-RemoteManagementPolicy.ps1')) |
      Should -Match '\[CmdletBinding\(SupportsShouldProcess'
  }

  BeforeEach {
    # An empty test directory: OU present (the caller creates it first), no
    # GPO, no policy, no rule, no template, and a fresh SYSVOL to write into.
    $global:FakeGpos = [System.Collections.Generic.List[System.Object]]::new()
    $global:FakeRegistry = @{}
    $global:FakeRegistryWrites = 0
    $global:FakeRule = $Null
    $global:FakeRulePort = $Null
    $global:FakeRuleAddress = $Null
    $global:FakeRuleStore = $Null
    $global:FakeRuleCreates = 0
    $global:FakeRuleUpdates = 0
    $global:FakeAdExtensionNames = $Null
    $global:FakeAdVersion = 0
    $global:FakeLinks = [System.Collections.Generic.List[System.Object]]::new()
    $global:FakeLinkCreates = 0
    $global:FakeOUExists = $True
    $global:FakeDomainSid = $script:DomainSid
    $global:FakeRootSid = $script:RootSid
    $global:FakeSysvol = Join-Path -Path $TestDrive -ChildPath ([System.Guid]::NewGuid().ToString('N'))
    $Null = New-Item -Path $global:FakeSysvol -ItemType 'Directory'
  }

  AfterEach {
    Remove-AnsibleContext
  }

  Context 'standalone JSON transport' {

    It 'builds the whole policy from an empty directory and says what it did' {
      $Result = Invoke-ConvergeJson

      $Result.changed | Should -BeTrue
      $Result.msg | Should -Match 'converged'
      $Result.gpo_name | Should -Be $script:GpoName
      $Result.gpo_id | Should -Not -BeNullOrEmpty
      $Result.operator_address | Should -Be $script:Operator
      $Result.target_ou | Should -Be $script:TargetOU
      # Create, four registry values, the rule, the template, the extension,
      # the version bump, the link: the full build, each write named.
      $Result.actions | Should -HaveCount 10
      $Result.actions | Should -Contain ('create GPO "{0}"' -f $script:GpoName)
      $Result.actions | Should -Contain ('link to {0}' -f $script:TargetOU)
      $global:FakeRegistryWrites | Should -Be 4
      $global:FakeRuleCreates | Should -Be 1
      $global:FakeLinkCreates | Should -Be 1
      $global:FakeRuleStore | Should -Be ('tcn.example.test\{0}' -f $script:GpoName)
    }

    It 'is idempotent: a second run over what it built changes nothing' {
      $Null = Invoke-ConvergeJson
      $WritesAfterBuild = @($global:FakeRegistryWrites, $global:FakeRuleCreates, $global:FakeRuleUpdates)

      $Result = Invoke-ConvergeJson

      $Result.changed | Should -BeFalse
      $Result.actions | Should -HaveCount 0
      $Result.msg | Should -Match 'already carries'
      @($global:FakeRegistryWrites, $global:FakeRuleCreates, $global:FakeRuleUpdates) |
        Should -Be $WritesAfterBuild
    }

    It 'writes the deny lists back without the local-account SIDs' {
      $Null = Invoke-ConvergeJson

      $TemplatePath = Get-FakeTemplatePath
      [System.IO.File]::Exists($TemplatePath) | Should -BeTrue
      $Template = [System.IO.File]::ReadAllText($TemplatePath, [System.Text.Encoding]::Unicode)
      $Template | Should -Match 'SeDenyNetworkLogonRight'
      $Template | Should -Match 'SeDenyRemoteInteractiveLogonRight'
      # Guests, Domain Admins and Enterprise Admins stay denied ...
      $Template | Should -Match ([regex]::Escape('*S-1-5-32-546'))
      $Template | Should -Match ([regex]::Escape('*{0}-512' -f $script:DomainSid))
      $Template | Should -Match ([regex]::Escape('*{0}-519' -f $script:RootSid))
      # ... and the local-account SIDs the STIG image denies are gone.
      $Template | Should -Not -Match 'S-1-5-114'
      $Template | Should -Not -Match 'S-1-5-113'
    }

    It 'registers the Security extension beside the groups already there and bumps the machine version' {
      # The Registry CSE pair, as a console that configured something else would leave it.
      $Seeded = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
      $global:FakeAdExtensionNames = $Seeded

      $Null = Invoke-ConvergeJson

      $global:FakeAdExtensionNames | Should -Match ([regex]::Escape($Seeded))
      $global:FakeAdExtensionNames | Should -Match (
        [regex]::Escape('[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]')
      )
      $global:FakeAdVersion | Should -Be 1
      $GptIni = [System.IO.File]::ReadAllText([System.IO.Path]::Combine($global:FakeSysvol, 'GPT.ini'))
      $GptIni | Should -Match '(?m)^Version=1'
    }

    It 'updates a drifted operator address in place rather than leaving the old one open' {
      $Null = Invoke-ConvergeJson
      $global:FakeRuleAddress.RemoteAddress = '198.51.100.7'

      $Result = Invoke-ConvergeJson

      $Result.changed | Should -BeTrue
      $Result.actions | Should -HaveCount 1
      $Result.actions[0] | Should -Be ('update firewall rule WorkSpaces-WinRM-HTTP-Operator for {0}' -f $script:Operator)
      $global:FakeRuleAddress.RemoteAddress | Should -Be $script:Operator
      $global:FakeRuleUpdates | Should -Be 1
    }

    It 'reads a /32 as the plain address rather than churning the rule' {
      $Null = Invoke-ConvergeJson
      $global:FakeRuleAddress.RemoteAddress = '{0}/32' -f $script:Operator

      $Result = Invoke-ConvergeJson

      $Result.changed | Should -BeFalse
      $global:FakeRuleUpdates | Should -Be 0
    }

    It 'refuses a name that resolves to more than one GPO' {
      $Null = Invoke-ConvergeJson
      $Null = New-GPO -Name $script:GpoName -Comment 'the double' -Domain 'tcn.example.test'

      { Invoke-ConvergeJson 2>$Null 3>$Null } | Should -Throw '*more than one object*'
    }

    It 'refuses to run when the target OU is missing, because the caller creates it first' {
      $global:FakeOUExists = $False

      { Invoke-ConvergeJson 2>$Null 3>$Null } | Should -Throw '*does not exist*'
    }

    It 'rejects an operator address or OU that does not parse' {
      { & $script:ScriptPath -Name $script:GpoName -TargetOU $script:TargetOU `
          -OperatorAddress '203.0.113.256' 2>$Null } | Should -Throw
      { & $script:ScriptPath -Name $script:GpoName -TargetOU 'not-a-dn' `
          -OperatorAddress $script:Operator 2>$Null } | Should -Throw
    }
  }

  Context '$Ansible transport' {

    It 'converges through the transport, emits nothing, and reports changed only when it changed' {
      $First = New-AnsibleContext
      $Emitted = & $script:ScriptPath -Name $script:GpoName -TargetOU $script:TargetOU `
        -OperatorAddress $script:Operator

      $First.Changed | Should -BeTrue
      $First.Failed | Should -BeFalse
      $First.Result.actions.Count | Should -BeGreaterThan 0
      # Everything goes through $Ansible.Result; the output stream stays empty.
      $Emitted | Should -BeNullOrEmpty

      Remove-AnsibleContext
      $Second = New-AnsibleContext
      & $script:ScriptPath -Name $script:GpoName -TargetOU $script:TargetOU `
        -OperatorAddress $script:Operator

      $Second.Changed | Should -BeFalse
      $Second.Result.msg | Should -Match 'already carries'
    }

    It 'plans the full build under check mode without touching anything' {
      $Context = New-AnsibleContext -CheckMode

      # -WhatIf reproduces the transport: win_powershell injects it for a
      # SupportsShouldProcess script in check mode, and the script must
      # survive it rather than lose its New-Variable setup.
      & $script:ScriptPath -Name $script:GpoName -TargetOU $script:TargetOU `
        -OperatorAddress $script:Operator -WhatIf

      $Context.Changed | Should -BeTrue
      $Context.Result.check_mode | Should -BeTrue
      $Context.Result.msg | Should -Match 'would change'
      $Context.Result.gpo_id | Should -BeNullOrEmpty
      $Context.Result.actions | Should -Contain ('create GPO "{0}"' -f $script:GpoName)
      $Context.Result.actions | Should -Contain ('link to {0}' -f $script:TargetOU)
      $global:FakeGpos.Count | Should -Be 0
      $global:FakeRegistryWrites | Should -Be 0
      $global:FakeRuleCreates | Should -Be 0
      $global:FakeLinkCreates | Should -Be 0
      [System.IO.File]::Exists((Get-FakeTemplatePath)) | Should -BeFalse
    }

    It 'tolerates a missing OU under check mode alone, reporting the link it would make' {
      $global:FakeOUExists = $False
      $Context = New-AnsibleContext -CheckMode

      & $script:ScriptPath -Name $script:GpoName -TargetOU $script:TargetOU `
        -OperatorAddress $script:Operator -WhatIf

      $Context.Result.check_mode | Should -BeTrue
      $Context.Result.actions | Should -Contain ('link to {0}' -f $script:TargetOU)
    }
  }
}
