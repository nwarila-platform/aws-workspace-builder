#Requires -Version 5.1
# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT

<#
    .SYNOPSIS
        Reads Add/Remove Programs for one product and reports every matching
        registration, without changing anything.

    .DESCRIPTION
        Answers "is this installed, and at what version" from the authoritative
        Windows source. Add/Remove Programs carries the version and the install
        location together and Windows removes the entry on uninstall, so it can
        answer the question a vendor product key cannot: the vendor key survives
        uninstall with no install-path value.

        Org scripts are a single straightforward process stage in the org script
        template's architecture: one [ Script ] region carrying
        [ Initialization ] (strict mode, transport detection, input
        normalization), [ Main ] (read -> build ONE result object), and
        [ Output ] (the same object to $Ansible or as JSON).

        This script only ever reads, so its verdict is always NoChange.

        Two registrations of one product cannot both own the install, and
        choosing between them would be a guess, so the script refuses to answer
        instead: it reports ambiguous, fails under the Ansible transport, and
        exits 2 standalone. Refusing here rather than in each caller means every
        consumer inherits the same answer. The evidence is published either way,
        so a failure does not hide what it saw.

        Each entry is the whole uninstall registration, minus PowerShell's own
        PS* path bookkeeping, so one read answers publisher, install date,
        estimated size and anything else a caller needs without growing a field
        per question. Only the uninstall roots are read -- never a vendor's
        product tree, which is where secret material such as a licence key
        lives.

        An MSI product also reports product_id, the ProductCode -- taken from the uninstall
        SUBKEY NAME per Windows Installer's own contract, never reverse-parsed from a mutable
        uninstall string -- which win_package needs to remove it; empty for a non-MSI product.

        The uninstall roots are not a parameter. Where Windows registers
        installed software is a property of Windows, not a caller's choice, and
        there is no correct second setting to offer.

        Shipped by the org three-file convention: developed under scripts/ with
        its sibling Get-InstalledSoftware.pester.ps1 spec, while each catalog
        role carries files/Get-InstalledSoftware.ps1.stub, which the build
        resolves by dropping this file into the role.

    .PARAMETER DebugLevel
        Three-digit control string configuring independent debugging
        functions, one digit each. First digit: ErrorActionPreference
        (0 SilentlyContinue, 1 Stop, 2 Continue, 3 Inquire, 4 Ignore,
        5 Suspend). Second digit: Set-PSDebug (0 off, 1 trace 1, 2 trace 2,
        3 trace 1 + step, 4 trace 2 + step). Third digit: Set-StrictMode
        (0 off, 1-3 that version). Default '103': stop on error, no tracing,
        strict mode 3.0.

    .PARAMETER LogLevel
        Six-digit control string mapping the Verbose, Debug, Information,
        Warning, Error, and Fatal streams (in that order) to an
        ActionPreference value per digit (0 SilentlyContinue, 1 Stop,
        2 Continue, 3 Inquire, 4 Ignore, 5 Suspend). Default '002223'.

    .PARAMETER DisplayName
        Exact Add/Remove Programs display name to match. Compared with -eq, so
        the match is exact and case-insensitive; a substring match would collect
        unrelated products that merely share a prefix.

    .PARAMETER Version
        The pinned version the caller intends to have installed. The script
        compares it against what is registered and reports action_required, so
        the comparison is made once, under test, instead of in each caller's
        template expressions.

    .EXAMPLE
        PS> ./Get-InstalledSoftware.ps1 -DisplayName 'PDQ Deploy' -Version '20.1.8.0'

    .OUTPUTS
        One object carrying action_required, changed, check_mode, count, entries,
        installed_version and msg.
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
  [ValidateNotNullOrEmpty()]
  [System.String]
  $DisplayName,

  [Parameter(
    DontShow = $False,
    Mandatory = $True,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
  [System.String]
  $Version
)

#region ------ [ Script ] -------------------------------------------------------------------- #

#region ------ [ Initialization ] ------------------------------------------------------------ #
Write-Debug -Message:'Entering Stage: Initialization'

# The module runs this script in check mode because it declares SupportsShouldProcess, and injects
# -WhatIf when it does. This script decides check mode from $Ansible.CheckMode, so -WhatIf is
# neutralised here; left on, it would suppress the New-Variable setup below and the cleanups.
$WhatIfPreference = $false

# Initialize STATIC log level names, indexed by LogLevel digit position.
New-Variable -Force -Name:'LOG_LEVELS' -Option:('Private', 'ReadOnly') -Value:(
  [System.String[]]@('Verbose', 'Debug', 'Information', 'Warning', 'Error', 'Fatal')
)

# Where Windows registers installed software. Both roots are read because a
# 32-bit product on a 64-bit host registers under the redirected one, so the
# answer never depends on which the installer chose.
New-Variable -Force -Name:'UNINSTALL_ROOTS' -Option:('Private', 'ReadOnly') -Value:(
  [System.String[]]@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )
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

# Configure the debug levels: first digit ErrorActionPreference, second digit
# Set-PSDebug, third digit Set-StrictMode.
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

# Universal trap used to help with debugging efforts. The original template's
# Wait-Debugger/Exit are interactive-host machinery; under the Ansible
# transport the trap logs and rethrows (Break) so the task fails honestly.
Trap {
  # Diagnostics are wrapped so a partially-populated error record can never
  # replace the original failure with a StrictMode property error.
  Try {
    # Write debug statement if the invoking line is available.
    If ($PSItem.Exception.PSObject.Properties.Name -contains 'ErrorRecord') {
      Write-Debug -Message:(
        'Failed to execute command: {0}' -f [System.String]$PSItem.Exception.ErrorRecord.InvocationInfo.Line
      )
    }

    # Write the error text. The original template uses Write-Host red here;
    # PSAvoidUsingWriteHost is ratified, so the warning stream carries it.
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

# Under win_powershell the transport provides $Ansible; standalone (a dev
# shell or a Pester spec) it does not, so the script creates a faithful stub.
# Either way the rest of the script has exactly ONE code path: the outcome is
# always written to $Ansible, and Output serializes the stub as JSON when the
# script created it. Changed defaults to $True like the real transport and is
# set explicitly on every path.
$StandaloneRun = $Null -eq (Get-Variable -Name:'Ansible' -ValueOnly -ErrorAction:'SilentlyContinue')
If ($StandaloneRun) {
  $Ansible = [PSCustomObject]@{
    Changed   = $True
    CheckMode = $False
    Failed    = $False
    Result    = $Null
  }
}

#endregion --- [ Initialization ] ------------------------------------------------------------ #

#region ------ [ Main ] ---------------------------------------------------------------------- #
Write-Debug -Message:'Entering Stage: Main'

# Walk each root that exists and collect every registration whose display name
# matches exactly. A missing root is skipped: a 32-bit-only machine has no
# Wow6432Node hive, which is a fact about the machine, not a failure. A root that
# exists but cannot be READ is fatal, not skipped -- a denied or truncated read
# could hide the installed product and report it absent, authorising a reinstall
# over a working copy. That is why the reads below carry no error suppression.
$Entries = @(
  ForEach ($Root In $UNINSTALL_ROOTS) {
    If (-Not (Test-Path -LiteralPath:$Root)) {
      Write-Debug -Message:('Skipping absent uninstall root: {0}' -f $Root)
      Continue
    }

    ForEach ($Key In (Get-ChildItem -LiteralPath:$Root)) {
      $Registration = Get-ItemProperty -LiteralPath:$Key.PSPath
      If ($Null -eq $Registration) {
        Continue
      }

      # Exact match, not a substring: 'PDQ Deploy Console' is a different
      # product from 'PDQ Deploy' and must not be collected as one.
      #
      # Read through the property collection rather than as a property: strict mode makes
      # reading an absent one fatal, and an uninstall root is mostly subkeys carrying no
      # DisplayName at all -- patches and components register there too. Indexing a missing
      # name yields $Null instead, so an ordinary neighbour cannot abort the scan.
      $DisplayNameProperty = $Registration.PSObject.Properties['DisplayName']
      If ($Null -eq $DisplayNameProperty -or $DisplayNameProperty.Value -ne $DisplayName) {
        Continue
      }

      # The ProductCode ansible.windows.win_package needs to remove the product is the uninstall
      # SUBKEY NAME -- Windows Installer's own contract -- read from the machine, never pinned (the
      # GUID changes with every release) and never reverse-parsed from an uninstall string a
      # tampered registration could redirect. Matched only in the braced {GUID} form the installer
      # writes, so an ordinary key whose name merely looks like a GUID is not mistaken for one;
      # empty for a non-MSI product. The raw UninstallString stays in the registration for callers.
      $ProductId = [System.String]::Empty
      $Guid = [System.Guid]::Empty
      If ([System.Guid]::TryParseExact($Key.PSChildName, 'B', [Ref]$Guid)) {
        $ProductId = $Key.PSChildName
      }

      # The whole registration, so one read answers publisher, install date, estimated size and
      # anything else a caller needs, rather than growing a new field per question. PS* entries
      # are PowerShell's own path bookkeeping, not registry values, so they are dropped.
      $Entry = [Ordered]@{}
      ForEach ($Property In ($Registration.PSObject.Properties | Sort-Object -Property:'Name')) {
        If ($Property.Name -notmatch '^PS') {
          $Entry[$Property.Name] = $Property.Value
        }
      }
      $Entry['product_id'] = $ProductId

      [PSCustomObject]$Entry
    }
  }
)

# Sorted so the payload is diffable across runs: registry enumeration order is
# not contractual, and an unstable list would look like drift to a reader.
$Entries = @($Entries | Sort-Object -Property:@('DisplayVersion', 'InstallLocation'))

# Two registrations of one product cannot both own the install, and choosing between them would
# be a guess. Refusing here rather than in each caller means every consumer inherits the same
# answer: the read either identifies exactly one product, or it does not answer at all.
$Ambiguous = $Entries.Count -gt 1

If ($Ambiguous) {
  $Message = (
    'Found {0} registrations named {1} ({2}). Two registrations of one product cannot both own ' +
    'the install, and choosing one would be a guess.'
  ) -f $Entries.Count, $DisplayName, (($Entries | ForEach-Object { If ($_.PSObject.Properties['DisplayVersion']) { $_.DisplayVersion } Else { '?' } }) -join ', ')
} Else {
  $Message = 'Found {0} registration(s) named {1}.' -f $Entries.Count, $DisplayName
}

# Compare against the pinned version HERE rather than in each caller. The comparison is the same
# question every caller asks -- "is this machine already at or beyond the pin" -- and answering it
# once, under test, keeps it out of template expressions that nothing exercises.
#
# An unparseable or missing DisplayVersion is treated as 0.0.0.0: a registration that cannot say
# what version it is cannot be trusted to be current.
$InstalledVersion = [System.String]::Empty
If ($Entries.Count -eq 1) {
  $DisplayVersionProperty = $Entries[0].PSObject.Properties['DisplayVersion']
  If ($Null -ne $DisplayVersionProperty) {
    $InstalledVersion = [System.String]$DisplayVersionProperty.Value
  }
}

$Installed = [System.Version]::new(0, 0, 0, 0)
If (-not [System.Version]::TryParse($InstalledVersion, [Ref]$Installed)) {
  $Installed = [System.Version]::new(0, 0, 0, 0)
}

$Desired = [System.Version]::new(0, 0, 0, 0)
If (-not [System.Version]::TryParse($Version, [Ref]$Desired)) {
  Throw ('Version must be a parseable version string; received {0}.' -f $Version)
}

# A read never changes the machine, so the verdict is NoChange on every path.
$Result = [PSCustomObject]@{
  action_required   = ($Entries.Count -eq 0) -or ($Installed -lt $Desired)
  ambiguous         = $Ambiguous
  changed           = $False
  check_mode        = $Ansible.CheckMode
  count             = $Entries.Count
  entries           = $Entries
  installed_version = $InstalledVersion
  msg               = $Message
}

#endregion --- [ Main ] ---------------------------------------------------------------------- #

#region ------ [ Output ] -------------------------------------------------------------------- #
Write-Debug -Message:'Entering Stage: Output'

$Ansible.Changed = $Result.changed
$Ansible.Result = $Result

# The result is published either way, so a caller can see WHAT was found before the failure is
# raised -- an error that hides its own evidence costs a second run to diagnose.
If ($Result.ambiguous) {
  $Ansible.Failed = $True
}

If ($StandaloneRun) {
  $Ansible.Result | ConvertTo-Json -Depth:4
  If ($Result.ambiguous) {
    Exit 2
  }
}

Write-Debug -Message:'Exiting Script'
#endregion --- [ Output ] -------------------------------------------------------------------- #

#endregion --- [ Script ] -------------------------------------------------------------------- #
