#Requires -Version 5.1
# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT

<#
    .SYNOPSIS
        Reads one computer's Windows LAPS escrow from Active Directory and
        reports whether a credential is there yet, without changing anything.

    .DESCRIPTION
        Runs ON A DOMAIN CONTROLLER (or any host carrying the LAPS module and
        a line of sight to one). Answers the one question a freshly joined
        machine's operator has: "has LAPS escrowed the built-in Administrator
        password to the computer object yet, and what is it". A WorkSpace --
        and the EC2 stand-in that mirrors one -- is born domain-joined with no
        credential anybody knows, and the GPO-delivered LAPS policy escrows
        one on its own schedule; until it does, nothing can log in. So the
        answer is a STATE, escrowed or not yet, that a caller polls until it
        turns, rather than an error that would end the wait.

        Get-LapsADPassword does the reading, and does it on the DC because the
        escrow is encrypted to the domain (ADPasswordEncryptionEnabled is the
        default on a 2016+ functional level) and only a domain member holding
        the right key can decrypt it. A computer object that does not exist is
        a hard failure -- polling would never fix a wrong name -- while every
        other way the read can come back empty (no attributes yet, a transient
        directory error) is reported as not-yet-escrowed with the reason
        attached, so a caller's wait loop keeps waiting and a reader can see
        why the last attempt returned nothing.

        This script only ever reads, so its verdict is always NoChange.

        THE PASSWORD IS IN THE RESULT. Under the Ansible transport that is the
        point -- the caller sets it as the connection password for the next
        play, under no_log. Standalone it is printed as JSON to the shell that
        asked, which is a developer's own terminal and their own choice.

        Org scripts are a single straightforward process stage in the org
        script template's architecture: one [ Script ] region carrying
        [ Initialization ] (strict mode, transport detection, input
        normalization), [ Main ] (read -> build ONE result object), and
        [ Output ] (the same object to $Ansible or as JSON).

        Shipped by the org three-file convention: developed under scripts/
        with its sibling Get-LapsCredential.pester.ps1 spec, while the role
        that needs it carries files/Get-LapsCredential.ps1.stub, which the
        build resolves by dropping this file into the role.

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

    .PARAMETER NotBefore
        The moment the caller knows this machine existed -- resolved before the
        domain join. An escrow written at or before it belongs to a previous
        occupant of a reused computer object, not to this one, and is reported
        as not-yet-escrowed so a poll keeps waiting instead of handing back a
        credential that will not authenticate. Windows LAPS rotates only when
        there is no valid escrowed expiration, so a reused object inside its
        password age is not rotated and this is the only thing standing between
        the caller and the previous instance's password. Omitted, the freshness
        check is skipped and any non-empty escrow satisfies the read.

    .PARAMETER Identity
        The computer's name as Active Directory knows it -- its
        sAMAccountName without the trailing dollar, which is the NetBIOS
        computer name. Passed to Get-LapsADPassword as given.

    .EXAMPLE
        PS> ./Get-LapsCredential.ps1 -Identity 'TCNAW-WSB01'

    .OUTPUTS
        One object carrying account, changed, check_mode, escrowed,
        expiration_timestamp, identity, msg, password, password_updated_time
        and source.
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
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,14}$')]
  [System.String]
  $Identity,

  [Parameter(
    DontShow = $False,
    Mandatory = $False,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [System.DateTime]
  $NotBefore = [System.DateTime]::MinValue
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

# The exception TYPES that mean "the directory does not know this name". Matching the message
# text instead was wrong in both directions: 'does not exist' also appears in "The specified
# domain either does not exist or could not be contacted" -- the transient error a just-joined
# machine provokes, and the one case where waiting is exactly the right answer -- while a
# localized domain controller returns a genuine not-found in words no English pattern matches.
# A type is not translated and does not overlap.
New-Variable -Force -Name:'NOT_FOUND_TYPES' -Option:('Private', 'ReadOnly') -Value:(
  [System.String[]]@(
    'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
    'Microsoft.ActiveDirectory.Management.ADIdentityResolutionException'
  )
)

# A name this host cannot resolve at all is also unfixable by waiting: it means the LAPS module
# is not installed on the machine running this script, which no amount of polling installs.
New-Variable -Force -Name:'UNRESOLVED_COMMAND_TYPE' -Option:('Private', 'ReadOnly') -Value:(
  'System.Management.Automation.CommandNotFoundException'
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

# One read. -AsPlainText because the caller needs the string itself, not a SecureString that
# cannot cross the transport. The read is wrapped so that a not-yet-escrowed object, however the
# module chooses to report it, becomes a state rather than an exception -- EXCEPT for an identity
# the directory does not know, which is rethrown: a wrong name is not fixed by waiting.
$Escrow = $Null
$Reason = [System.String]::Empty
Try {
  $Escrow = Get-LapsADPassword -Identity:$Identity -AsPlainText
} Catch {
  # Classified on the exception's own type. Anything else -- a domain that could not be
  # contacted, a directory that is momentarily unavailable, a replication delay -- is a state to
  # keep waiting through, which is the entire purpose of the caller's poll.
  $ExceptionType = [System.String]$PSItem.Exception.GetBaseException().GetType().FullName
  If ($NOT_FOUND_TYPES -contains $ExceptionType -or $ExceptionType -eq $UNRESOLVED_COMMAND_TYPE) {
    Throw
  }
  $Reason = [System.String]$PSItem.Exception.Message
}

# The escrow object's shape depends on the module build: a field may be absent, or present and
# empty, and the timestamps come back as DateTime. Every field is read through the property bag
# so an absent one is an empty string under strict mode rather than an exception, and a timestamp
# is rendered as ISO 8601 UTC so the result serializes the same way on every transport.
$Fields = @{}
ForEach ($FieldName In @('Account', 'ExpirationTimestamp', 'Password', 'PasswordUpdateTime', 'Source')) {
  $FieldValue = [System.String]::Empty
  If ($Null -ne $Escrow) {
    $Property = $Escrow.PSObject.Properties[$FieldName]
    If ($Null -ne $Property -and $Null -ne $Property.Value) {
      If ($Property.Value -is [System.DateTime]) {
        $FieldValue = ([System.DateTime]$Property.Value).ToUniversalTime().ToString('o')
      } Else {
        $FieldValue = [System.String]$Property.Value
      }
    }
  }
  $Fields[$FieldName] = $FieldValue
}

# Escrowed means the object came back carrying a password. The module has returned an object
# with an empty Password for an attribute-less computer in some builds and nothing at all in
# others; both are the same state to a caller.
$Password = [System.String]$Fields['Password']
$HasPassword = $Password.Length -gt 0

# AND IT MUST BE THIS MACHINE'S PASSWORD. Windows LAPS rotates only when there is no valid
# escrowed expiration, so a computer object reused inside its password age still holds the
# PREVIOUS instance's credential -- and a caller polling for "non-empty" is handed it instantly,
# authenticates with it, and fails against a machine that has already given up every other way
# in. NotBefore is the moment the caller knows this instance existed; an escrow written before
# that belongs to something else and is reported as not-yet-escrowed so the poll keeps waiting.
$Stale = $False
If ($HasPassword -and $NotBefore -ne [System.DateTime]::MinValue) {
  $UpdatedText = [System.String]$Fields['PasswordUpdateTime']
  $Updated = [System.DateTime]::MinValue
  If ([System.DateTime]::TryParse($UpdatedText, [Ref]$Updated)) {
    $Stale = $Updated.ToUniversalTime() -le $NotBefore.ToUniversalTime()
  } Else {
    # A credential that cannot say when it was written cannot be shown to be this machine's.
    $Stale = $True
  }
}
$Escrowed = $HasPassword -and -not $Stale

If ($Escrowed) {
  $Account = [System.String]$Fields['Account']
  $ExpirationTimestamp = [System.String]$Fields['ExpirationTimestamp']
  $PasswordUpdatedTime = [System.String]$Fields['PasswordUpdateTime']
  $Source = [System.String]$Fields['Source']
  $Message = 'LAPS has escrowed a credential for {0} (account {1}, updated {2}, expires {3}).' -f @(
    $Identity
    $Account
    $PasswordUpdatedTime
    $ExpirationTimestamp
  )
} Else {
  # WITHHELD, NOT MERELY FLAGGED. A stale escrow is a real password, and a caller that read
  # .password without first checking .escrowed would authenticate with the previous occupant's
  # credential -- the exact failure the freshness check exists to prevent. It never leaves here.
  $Password = [System.String]::Empty
  $Account = [System.String]::Empty
  $ExpirationTimestamp = [System.String]::Empty
  $PasswordUpdatedTime = [System.String]::Empty
  $Source = [System.String]::Empty
  $Message = If ($Reason.Length -gt 0) {
    'LAPS has not escrowed a credential for {0} yet: {1}' -f $Identity, $Reason
  } Else {
    'LAPS has not escrowed a credential for {0} yet.' -f $Identity
  }
}

# A read never changes the machine, so the verdict is NoChange on every path.
$Result = [PSCustomObject]@{
  account               = $Account
  changed               = $False
  check_mode            = $Ansible.CheckMode
  escrowed              = $Escrowed
  expiration_timestamp  = $ExpirationTimestamp
  identity              = $Identity
  msg                   = $Message
  password              = $Password
  password_updated_time = $PasswordUpdatedTime
  source                = $Source
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
