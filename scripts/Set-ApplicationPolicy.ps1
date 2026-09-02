#Requires -Version 5.1
# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT

<#
    .SYNOPSIS
        Writes one application's enterprise policy into the registry as machine
        state, and reports what it had to change.

    .DESCRIPTION
        Bakes application hardening into the image. The settings this writes are
        the ones that must SURVIVE capture: the builder OU blocks GPO
        inheritance and its one build policy is unlinked before the image is
        taken, so anything delivered by Group Policy is gone from the captured
        bundle by design. Values written directly under
        HKLM\SOFTWARE\Policies\... are machine state on C:, so they are captured
        and ship inside the bundle. A production GPO managing the same product
        later simply wins on precedence, which is the correct outcome: the image
        carries a compliant floor and the domain can still tighten it.

        Two shapes, because enterprise policy has two. A scalar POLICY VALUE is
        a single registry value under the product's policy root. A POLICY LIST
        -- an extension blocklist, a URL allowlist -- is a subkey whose values
        are named '1', '2', '3' in order; that numbering is the vendor's
        contract, not a convention this script invents.

        THE LISTS ARE OWNED WHOLE. A list subkey is made to match the declared
        items exactly, and any numbered value beyond them is removed. A list
        that only ever appended would silently keep an entry a later benchmark
        dropped, which is the failure mode a compliance artifact can least
        afford.

        The caller supplies the policy document; this script neither reads nor
        interprets a benchmark. Provenance -- which rule each value satisfies,
        and which release it was reconciled against -- stays in that document,
        beside the values, where it is reviewable in git.

        Org scripts are a single straightforward process stage in the org script
        template's architecture: one [ Script ] region carrying
        [ Initialization ] (strict mode, transport detection, constants),
        [ Main ] (compare and converge -> build ONE result object), and
        [ Output ] (the same object to $Ansible or as JSON).

        Every write compares first, so a second run reports no change; under
        check mode nothing is written and every would-be change is reported.

        Shipped by the org three-file convention: developed under scripts/ with
        its sibling Set-ApplicationPolicy.pester.ps1 spec, while each role that
        hardens a product carries files/Set-ApplicationPolicy.ps1.stub, which
        the build resolves by dropping this file into the role.

    .PARAMETER DebugLevel
        Three-digit control string configuring independent debugging
        functions, one digit each. First digit: ErrorActionPreference
        (0 SilentlyContinue, 1 Stop, 2 Continue, 3 Inquire, 4 Ignore,
        5 Suspend). Second digit: Set-PSDebug (0 off, 1 trace 1, 2 trace 2,
        3 trace 1 + step, 4 trace 2 + step). Third digit: Set-StrictMode
        (0 off, 1-3 that version). Default '103'.

    .PARAMETER LogLevel
        Six-digit control string mapping the Verbose, Debug, Information,
        Warning, Error, and Fatal streams (in that order) to an
        ActionPreference value per digit. Default '002223'.

    .PARAMETER Root
        The product's policy key, e.g.
        'HKLM:\SOFTWARE\Policies\Google\Chrome'. Created if absent.

    .PARAMETER Values
        Scalar policy values. Each entry carries name, type (dword, qword,
        string, expandstring, multistring, binary) and data.

    .PARAMETER Lists
        Policy lists. Each entry carries key -- the subkey under Root -- and
        items, written as values named '1'..'n' in the order given. A declared
        list with no items still empties its subkey, which is a real state: it
        means "this list is defined and allows nothing".

    .EXAMPLE
        PS> ./Set-ApplicationPolicy.ps1 -Root 'HKLM:\SOFTWARE\Policies\Google\Chrome' `
              -Values @(@{ name = 'SyncDisabled'; type = 'dword'; data = 1 })

    .OUTPUTS
        One object carrying actions, changed, check_mode, msg, root,
        values_written and lists_written.
    #>
[CmdletBinding(SupportsShouldProcess)]
[OutputType([System.Void])]
Param (
  [Parameter(
    DontShow = $False,
    Mandatory = $False,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [ValidatePattern('^[0-5][0-4][0-3]$')]
  [System.String]
  $DebugLevel = '103',

  [Parameter(
    DontShow = $False,
    Mandatory = $False,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [ValidatePattern('^[0-5]{6}$')]
  [System.String]
  $LogLevel = '002223',

  [Parameter(
    DontShow = $False,
    Mandatory = $True,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [ValidatePattern('^HKLM:\\SOFTWARE\\Policies\\')]
  [System.String]
  $Root,

  [Parameter(
    DontShow = $False,
    Mandatory = $False,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [System.Object[]]
  $Values = @(),

  [Parameter(
    DontShow = $False,
    Mandatory = $False,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [System.Object[]]
  $Lists = @()
)

#region ------ [ Script ] -------------------------------------------------------------------- #

#region ------ [ Initialization ] ------------------------------------------------------------ #
Write-Debug -Message:'Entering Stage: Initialization'

# The module runs this script in check mode because it declares SupportsShouldProcess, and injects
# -WhatIf when it does. This script decides check mode from $Ansible.CheckMode, so -WhatIf is
# neutralised here; left on, it would suppress the New-Variable setup below.
$WhatIfPreference = $false

# Initialize STATIC log level names, indexed by LogLevel digit position.
New-Variable -Force -Name:'LOG_LEVELS' -Option:('Private', 'ReadOnly') -Value:(
  [System.String[]]@('Verbose', 'Debug', 'Information', 'Warning', 'Error', 'Fatal')
)

# The registry types this script accepts, mapped to what New-ItemProperty calls them. A type
# outside this set is refused rather than guessed at: writing a policy value with the wrong type
# is indistinguishable from not writing it, because the product simply ignores it.
New-Variable -Force -Name:'VALUE_TYPES' -Option:('Private', 'ReadOnly') -Value:(
  @{
    'dword'        = 'DWord'
    'qword'        = 'QWord'
    'string'       = 'String'
    'expandstring' = 'ExpandString'
    'multistring'  = 'MultiString'
    'binary'       = 'Binary'
  }
)

# Initialize the custom stream preferences; the built-in ones already exist.
New-Variable -Verbose:$False -Force -Name:'ErrorPreference' -Value:(
  [System.Management.Automation.ActionPreference]::Stop
)
New-Variable -Verbose:$False -Force -Name:'FatalPreference' -Value:(
  [System.Management.Automation.ActionPreference]::Stop
)

# Configure log levels based on the LogLevel parameter.
For ($L = 0; $L -lt 6; $L++) {
  Set-Variable -Verbose:$False -Force -Name:('{0}Preference' -f $LOG_LEVELS[$L]) -Value:(
    [System.Int32]::Parse([System.String]$LogLevel[$L]) -as [System.Management.Automation.ActionPreference]
  )
}

# Configure the debug levels: first digit ErrorActionPreference, second digit Set-PSDebug,
# third digit Set-StrictMode.
$ErrorActionPreference = [System.Management.Automation.ActionPreference][System.Int32]::Parse($DebugLevel.Substring(0, 1))
Switch ($DebugLevel.Substring(1, 1)) {
  '0' { Set-PSDebug -Off }
  '1' { Set-PSDebug -Trace:1 }
  '2' { Set-PSDebug -Trace:2 }
  '3' { Set-PSDebug -Trace:1 -Step }
  '4' { Set-PSDebug -Trace:2 -Step }
}
If ($DebugLevel.Substring(2, 1) -eq '0') {
  Set-StrictMode -Off
} Else {
  Set-StrictMode -Version:([System.String]$DebugLevel.Substring(2, 1))
}

# Universal trap used to help with debugging efforts.
Trap {
  Try {
    If ($PSItem.Exception.PSObject.Properties.Name -contains 'ErrorRecord') {
      Write-Debug -Message:(
        'Failed to execute command: {0}' -f [System.String]$PSItem.Exception.ErrorRecord.InvocationInfo.Line
      )
    }
    Write-Warning -Message:(
      '[{0:0000}] {1} [{2}]' -f @(
        [System.Int64]$PSItem.InvocationInfo.ScriptLineNumber
        [System.String]$PSItem.Exception.Message
        [System.String]$PSItem.Exception.GetBaseException().GetType().FullName
      )
    )
  } Catch {
    Write-Debug -Message:'Trap diagnostics unavailable for this error record.'
  }
  Break
}

# Under win_powershell the transport provides $Ansible; standalone (a dev shell or a Pester spec)
# it does not, so the script creates a faithful stub.
$StandaloneRun = $Null -eq (Get-Variable -Name:'Ansible' -ValueOnly -ErrorAction:'SilentlyContinue')
If ($StandaloneRun) {
  $Ansible = [PSCustomObject]@{
    Changed   = $True
    CheckMode = $False
    Failed    = $False
    Result    = $Null
  }
}

# The transport injects Changed = $true. Every failure below is a Throw, which never reaches the
# Output region, so the verdict has to be honest from here rather than at the end: a script that
# threw changed nothing it had not already recorded.
$Ansible.Changed = $False

#endregion --- [ Initialization ] ------------------------------------------------------------ #

#region ------ [ Main ] ---------------------------------------------------------------------- #
Write-Debug -Message:'Entering Stage: Main'

$CheckMode = [System.Boolean]$Ansible.CheckMode
$Actions = [System.Collections.Generic.List[System.String]]::new()

# READ A MEMBER OFF EITHER SHAPE. The transport may hand these entries over as PSCustomObjects or
# as Hashtables depending on how the caller declared them, and the two do not answer the same way:
# PSObject.Properties finds a member on the first and finds Count/Keys/Values on the second. An
# absent member is $null either way, because absent is an ordinary state here rather than an error.
Function Get-EntryMember {
  Param ([System.Object]$Entry, [System.String]$Name)
  If ($Entry -is [System.Collections.IDictionary]) {
    If ($Entry.Contains($Name)) {
      Return $Entry[$Name]
    }
    Return $Null
  }
  $Property = $Entry.PSObject.Properties[$Name]
  If ($Null -eq $Property) {
    Return $Null
  }
  Return $Property.Value
}

# Read a property through the property bag rather than as a property: strict mode makes reading an
# absent one fatal, and "absent" is the ordinary state on a first run.
Function Get-RegistryValue {
  Param ([System.String]$Path, [System.String]$Name)
  If (-not (Test-Path -LiteralPath:$Path)) {
    Return $Null
  }
  $Item = Get-ItemProperty -LiteralPath:$Path -ErrorAction:'SilentlyContinue'
  If ($Null -eq $Item) {
    Return $Null
  }
  $Property = $Item.PSObject.Properties[$Name]
  If ($Null -eq $Property) {
    Return $Null
  }
  Return $Property.Value
}

Function Set-PolicyKey {
  Param ([System.String]$Path)
  If (Test-Path -LiteralPath:$Path) {
    Return $False
  }
  If (-not $CheckMode) {
    $Null = New-Item -Path:$Path -Force
  }
  Return $True
}

# The product's policy root. Everything below hangs off it, so it is created first and its
# creation is itself a reportable change on a machine that had no policy at all.
If (Set-PolicyKey -Path:$Root) {
  $Actions.Add(('create policy key {0}' -f $Root))
}

#region ------ [ Main: Scalar Policy Values ] ------------------------------------------------- #
# Compared by VALUE AND TYPE. A value of the right number written as the wrong type is ignored by
# the product exactly as an absent one is, so a type mismatch has to count as drift.

$ValuesWritten = 0
ForEach ($Value In @($Values)) {
  $Name = [System.String](Get-EntryMember -Entry:$Value -Name:'name')
  $DeclaredType = ([System.String](Get-EntryMember -Entry:$Value -Name:'type')).ToLowerInvariant()
  If (-not $VALUE_TYPES.ContainsKey($DeclaredType)) {
    Throw (
      'Policy value {0} declares registry type "{1}", which is not one of: {2}.' -f @(
        $Name
        [System.String](Get-EntryMember -Entry:$Value -Name:'type')
        (($VALUE_TYPES.Keys | Sort-Object) -join ', ')
      )
    )
  }
  $RegistryType = [System.String]$VALUE_TYPES[$DeclaredType]
  $Desired = Get-EntryMember -Entry:$Value -Name:'data'

  $Current = Get-RegistryValue -Path:$Root -Name:$Name
  $InSync = $False
  If ($Null -ne $Current) {
    # Compared as text so an Int32 and an Int64 carrying the same number agree, which is what the
    # product sees; a multistring compares as its joined members for the same reason.
    $CurrentText = If ($Current -is [System.Array]) { ($Current -join "`n") } Else { [System.String]$Current }
    $DesiredText = If ($Desired -is [System.Array]) { ($Desired -join "`n") } Else { [System.String]$Desired }
    $InSync = $CurrentText -ceq $DesiredText
  }

  If (-not $InSync) {
    If (-not $CheckMode) {
      $Null = New-ItemProperty -LiteralPath:$Root -Name:$Name -Value:$Desired `
        -PropertyType:$RegistryType -Force
    }
    $Actions.Add(('set {0}\{1}' -f $Root, $Name))
    $ValuesWritten++
  }
}

#endregion --- [ Main: Scalar Policy Values ] ------------------------------------------------- #

#region ------ [ Main: Policy Lists ] --------------------------------------------------------- #
# A list is a subkey whose values are named '1'..'n' in order -- the vendor's contract. The subkey
# is owned WHOLE: numbered values beyond the declared items are removed, so a list never silently
# keeps an entry a later benchmark dropped.

$ListsWritten = 0
ForEach ($List In @($Lists)) {
  $ListKey = [System.String](Get-EntryMember -Entry:$List -Name:'key')
  $ListPath = '{0}\{1}' -f $Root, $ListKey
  # Assigned in two statements rather than from an If expression: PowerShell unrolls an empty
  # array returned from one, so '$Items = If (...) { @() } ...' yields $null and every later
  # $Items.Count is a strict-mode failure. An empty list is a state this script must handle.
  $DeclaredItems = Get-EntryMember -Entry:$List -Name:'items'
  $Items = @()
  If ($Null -ne $DeclaredItems) {
    $Items = @($DeclaredItems)
  }

  $ListChanged = $False
  If (Set-PolicyKey -Path:$ListPath) {
    $ListChanged = $True
  }

  For ($Index = 0; $Index -lt $Items.Count; $Index++) {
    $Name = [System.String]($Index + 1)
    $Desired = [System.String]$Items[$Index]
    $Current = Get-RegistryValue -Path:$ListPath -Name:$Name
    If ([System.String]$Current -cne $Desired) {
      If (-not $CheckMode) {
        $Null = New-ItemProperty -LiteralPath:$ListPath -Name:$Name -Value:$Desired `
          -PropertyType:'String' -Force
      }
      $ListChanged = $True
    }
  }

  # Anything numbered past the end of the declared list is a leftover from a previous benchmark.
  If (Test-Path -LiteralPath:$ListPath) {
    $Item = Get-ItemProperty -LiteralPath:$ListPath -ErrorAction:'SilentlyContinue'
    If ($Null -ne $Item) {
      ForEach ($Property In $Item.PSObject.Properties) {
        $Number = 0
        If (-not [System.Int32]::TryParse($Property.Name, [Ref]$Number)) {
          Continue
        }
        If ($Number -gt $Items.Count) {
          If (-not $CheckMode) {
            Remove-ItemProperty -LiteralPath:$ListPath -Name:$Property.Name -Force
          }
          $ListChanged = $True
        }
      }
    }
  }

  If ($ListChanged) {
    $Actions.Add(('converge policy list {0} ({1} item(s))' -f $ListKey, $Items.Count))
    $ListsWritten++
  }
}

#endregion --- [ Main: Policy Lists ] --------------------------------------------------------- #

$Changed = $Actions.Count -gt 0
$Message = If (-not $Changed) {
  'Application policy under {0} already matches the declared baseline.' -f $Root
} ElseIf ($CheckMode) {
  '{0} would change: {1}.' -f $Root, ($Actions -join '; ')
} Else {
  '{0} converged: {1} value(s) and {2} list(s) written.' -f $Root, $ValuesWritten, $ListsWritten
}

$Result = [PSCustomObject]@{
  actions        = [System.String[]]$Actions.ToArray()
  changed        = $Changed
  check_mode     = $CheckMode
  lists_written  = $ListsWritten
  msg            = $Message
  root           = $Root
  values_written = $ValuesWritten
}

#endregion --- [ Main ] ---------------------------------------------------------------------- #

#region ------ [ Output ] -------------------------------------------------------------------- #
Write-Debug -Message:'Entering Stage: Output'

$Ansible.Changed = $Result.changed
$Ansible.Result = $Result

If ($StandaloneRun) {
  $Ansible.Result | ConvertTo-Json -Depth:4
}

Write-Debug -Message:'Exiting Script'
#endregion --- [ Output ] -------------------------------------------------------------------- #

#endregion --- [ Script ] -------------------------------------------------------------------- #
