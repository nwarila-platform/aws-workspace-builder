#Requires -Version 5.1
# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT

<#
    .SYNOPSIS
        Ensures the Group Policy Object that opens a WorkSpace to its operator
        exists, carries its settings, and is linked to the OU the WorkSpace
        is placed in.

    .DESCRIPTION
        Runs ON A DOMAIN CONTROLLER. A WorkSpace -- and the EC2 stand-in that
        proves its image -- is born domain-joined with no way in except what
        the domain delivers by Group Policy: the WinRM listener, the firewall
        opening that reaches it, the unfiltered remote token that lets the
        LAPS-managed local administrator use it, and the logon rights that let
        that account arrive over the network. In production those settings are
        the directory team's standing configuration; in a test domain nothing
        stands until something writes it, and this script is what writes it,
        idempotently, so the playbook can PROVE the domain delivers the way in
        rather than building one on the guest.

        One GPO, resolved by display name and created when absent, carrying:

          * Registry policy, through the GroupPolicy cmdlets: WinRM service
            AllowAutoConfig with both address filters wide open (the listener),
            and LocalAccountTokenFilterPolicy (the remote token).
          * One inbound firewall rule, through the NetSecurity cmdlets against
            the GPO's policy store: TCP 5985 from the operator address ALONE.
            The address is the per-run part -- it is the same source address
            the deployment's security group admits, resolved by the caller.
          * A security template (GptTmpl.inf) that replaces the STIG image's
            "Deny access to this computer from the network" and "Deny log on
            through Remote Desktop Services" lists with the same lists MINUS
            the local-account SIDs (S-1-5-114 and S-1-5-113): Guests, Domain
            Admins and Enterprise Admins stay denied, the LAPS-managed local
            administrator is not. No cmdlet writes user rights, so the file is
            written by hand, the Security client-side extension is registered
            on the GPO, and the machine version is bumped so clients reapply.
            THE TEMPLATE IS OWNED WHOLE: it is compared and rewritten as one
            file, so anything added to it through the console is replaced.
          * An enabled link to the target OU, which must already exist -- the
            caller creates it natively before this script runs.

        What this GPO deliberately does NOT carry: the LAPS policy itself (the
        test domain's Default Domain Policy delivers it domain-wide, as a
        production directory would), any startup type for the WinRM service
        (the AMI already runs it), and any allowance for the runner (the
        runner's readiness client cannot seal HTTP, so it keeps 5986 alone).

        Every step compares before it writes, so a second run reports no
        change; under check mode every write is skipped and reported as an
        action that would have happened.

        Org scripts are a single straightforward process stage in the org
        script template's architecture: one [ Script ] region carrying
        [ Initialization ] (strict mode, transport detection, constants),
        [ Main ] (compare and converge -> build ONE result object), and
        [ Output ] (the same object to $Ansible or as JSON).

        Shipped by the org three-file convention: developed under scripts/
        with its sibling Set-RemoteManagementPolicy.pester.ps1 spec, while
        the role that needs it carries files/Set-RemoteManagementPolicy.ps1.stub,
        which the build resolves by dropping this file into the role.

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

    .PARAMETER Name
        The GPO's display name. Resolved by name on every run; a name that
        resolves to more than one GPO is refused rather than guessed at.

    .PARAMETER TargetOU
        Distinguished name of the organizational unit the GPO is linked to:
        the OU the WorkSpace's computer object is created in. Must exist.

    .PARAMETER OperatorAddress
        The IPv4 address the operator's converge arrives from. The only
        remote address the firewall rule admits to TCP 5985.

    .PARAMETER Comment
        The comment recorded on the GPO when it is created, so a reader of
        the console learns what owns it.

    .EXAMPLE
        PS> ./Set-RemoteManagementPolicy.ps1 -Name 'WorkSpaces Remote Management' `
              -TargetOU 'OU=WorkSpaces,OU=Domain Workstations,DC=tcn,DC=trinitytechnicalservices,DC=com' `
              -OperatorAddress '203.0.113.10'

    .OUTPUTS
        One object carrying actions, changed, check_mode, domain, gpo_id,
        gpo_name, msg, operator_address and target_ou.
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
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$')]
  [System.String]
  $Name,

  [Parameter(
    DontShow = $False,
    Mandatory = $True,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [ValidatePattern('^OU=[^,]+(,(OU|DC)=[^,]+)+$')]
  [System.String]
  $TargetOU,

  [Parameter(
    DontShow = $False,
    Mandatory = $True,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [ValidatePattern('^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$')]
  [System.String]
  $OperatorAddress,

  [Parameter(
    DontShow = $False,
    Mandatory = $False,
    ParameterSetName = 'default',
    ValueFromPipeline = $False,
    ValueFromPipelineByPropertyName = $False
  )]
  [ValidateNotNullOrEmpty()]
  [System.String]
  $Comment = 'Opens a WorkSpace to its operator. Managed by aws-workspace-builder.'
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

# The Security client-side extension and its editing tool, the pair GPMC records on the GPO's
# gPCMachineExtensionNames when a security template is present. The registry and firewall
# settings arrive through cmdlets that maintain that attribute themselves; the template does not.
New-Variable -Force -Name:'SECURITY_EXTENSION' -Option:('Private', 'ReadOnly') -Value:(
  '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
)
New-Variable -Force -Name:'SECURITY_EXTENSION_TOOL' -Option:('Private', 'ReadOnly') -Value:(
  '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'
)

# The firewall rule's fixed identity inside the GPO, which is what makes a later run find and
# compare it rather than add a second one.
New-Variable -Force -Name:'FIREWALL_RULE_NAME' -Option:('Private', 'ReadOnly') -Value:(
  'WorkSpaces-WinRM-HTTP-Operator'
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

# The transport injects Changed = $true and reads it back even after a throw, so a script that
# only sets its verdict in the Output region reports a change it never made. Settled here, before
# anything can fail.
$Ansible.Changed = $False

#endregion --- [ Initialization ] ------------------------------------------------------------ #

#region ------ [ Main ] ---------------------------------------------------------------------- #
Write-Debug -Message:'Entering Stage: Main'

# Every write is recorded here by what it did (or, under check mode, would have done); the
# verdict is simply whether anything was recorded.
$CheckMode = [System.Boolean]$Ansible.CheckMode
$Actions = [System.Collections.Generic.List[System.String]]::new()

# The directory this policy lives in. The deny lists below are written as SIDs, not names, so the
# domain's own SID and the forest root's (Enterprise Admins is a forest-root group) are resolved
# once here rather than looked up by localizable name.
$Domain = Get-ADDomain
$DnsRoot = [System.String]$Domain.DNSRoot
$DomainSid = [System.String]$Domain.DomainSID.Value
$RootDomainSid = [System.String](Get-ADDomain -Identity:(Get-ADForest).RootDomain).DomainSID.Value

# The target OU is the caller's to create, natively, before this script runs; a missing one is a
# broken contract, not something a policy script should quietly create on its way past. Under
# check mode the caller has only reported that it would create it, so a missing OU is not a
# broken contract there: it is the one thing the link below cannot be compared against, and the
# link is reported as the action it would be.
$TargetOUExists = $True
Try {
  $Null = Get-ADOrganizationalUnit -Identity:$TargetOU -Server:$DnsRoot
} Catch {
  $TargetOUExists = $False
}
If (-not ($TargetOUExists -or $CheckMode)) {
  Throw (
    'The target OU {0} does not exist in {1}; the caller creates it before this script runs.' -f $TargetOU, $DnsRoot
  )
}

# The GPO, by display name. GPMC allows two GPOs with one name, and a name that means two objects
# cannot be managed by name, so that case is refused rather than resolved by taking the first.
$Candidates = @(Get-GPO -All -Domain:$DnsRoot | Where-Object { $PSItem.DisplayName -eq $Name })
If ($Candidates.Count -gt 1) {
  Throw (
    '{0} GPOs in {1} are named "{2}"; a name that resolves to more than one object cannot be managed by name.' -f @(
      $Candidates.Count
      $DnsRoot
      $Name
    )
  )
}
$Gpo = $Null
If ($Candidates.Count -eq 1) {
  $Gpo = $Candidates[0]
} Else {
  If (-not $CheckMode) {
    $Gpo = New-GPO -Name:$Name -Comment:$Comment -Domain:$DnsRoot
  }
  $Actions.Add(('create GPO "{0}"' -f $Name))
}

If ($Null -eq $Gpo) {
  # Check mode against a GPO that does not exist yet: nothing can be compared, and everything
  # below would be written, so the report says so without pretending to have looked.
  $Actions.Add('set the WinRM listener and remote-token registry policy')
  $Actions.Add(('create firewall rule {0} for {1}' -f $FIREWALL_RULE_NAME, $OperatorAddress))
  $Actions.Add('write the security template and register the Security extension')
  $Actions.Add(('link to {0}' -f $TargetOU))
} Else {
  # A GPO with computer settings disabled delivers nothing, however right its contents.
  If ([System.String]$Gpo.GpoStatus -ne 'AllSettingsEnabled') {
    If (-not $CheckMode) {
      $Gpo.GpoStatus = 'AllSettingsEnabled'
    }
    $Actions.Add('enable all settings on the GPO')
  }

  # Registry policy. AllowAutoConfig with open filters is the policy behind "Allow remote server
  # management through WinRM": the WinRM service creates and maintains an HTTP listener on every
  # address from it. LocalAccountTokenFilterPolicy lets a local administrator's remote logon keep
  # its elevated token, without which the LAPS-managed account authenticates and then can do
  # nothing. Each value is compared by type and value and written only when it differs.
  $WinRmServiceKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
  $SystemPoliciesKey = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $RegistryValues = @(
    @{ Key = $WinRmServiceKey; ValueName = 'AllowAutoConfig'; Type = 'DWord'; Value = 1 }
    @{ Key = $WinRmServiceKey; ValueName = 'IPv4Filter'; Type = 'String'; Value = '*' }
    @{ Key = $WinRmServiceKey; ValueName = 'IPv6Filter'; Type = 'String'; Value = '*' }
    @{ Key = $SystemPoliciesKey; ValueName = 'LocalAccountTokenFilterPolicy'; Type = 'DWord'; Value = 1 }
  )
  ForEach ($Desired In $RegistryValues) {
    $Current = Get-GPRegistryValue -Guid:$Gpo.Id -Domain:$DnsRoot -Key:$Desired.Key -ValueName:$Desired.ValueName `
      -ErrorAction:'SilentlyContinue'
    $InSync = $False
    If ($Null -ne $Current) {
      $TypeMatches = [System.String]$Current.Type -eq $Desired.Type
      $ValueMatches = [System.String]$Current.Value -eq [System.String]$Desired.Value
      $InSync = $TypeMatches -and $ValueMatches
    }
    If (-not $InSync) {
      If (-not $CheckMode) {
        $Null = Set-GPRegistryValue -Guid:$Gpo.Id -Domain:$DnsRoot -Key:$Desired.Key -ValueName:$Desired.ValueName `
          -Type:$Desired.Type -Value:$Desired.Value
      }
      $Actions.Add(('set registry value {0}\{1}' -f $Desired.Key, $Desired.ValueName))
    }
  }

  # The firewall rule, in the GPO's own policy store. One rule, one port, one remote address:
  # the operator's. It is found by its fixed name and compared field by field, so a changed
  # operator address updates the rule in place rather than leaving the old address open.
  $PolicyStore = '{0}\{1}' -f $DnsRoot, $Name
  $Rule = Get-NetFirewallRule -PolicyStore:$PolicyStore -Name:$FIREWALL_RULE_NAME -ErrorAction:'SilentlyContinue'
  If ($Null -eq $Rule) {
    If (-not $CheckMode) {
      $Null = New-NetFirewallRule -PolicyStore:$PolicyStore -Name:$FIREWALL_RULE_NAME `
        -DisplayName:'Windows Remote Management (HTTP-In) - Operator' -Group:$Name `
        -Description:'Admits the operator address, and nothing else, to the WinRM HTTP listener Group Policy delivers.' `
        -Direction:'Inbound' -Action:'Allow' -Enabled:'True' -Profile:'Any' `
        -Protocol:'TCP' -LocalPort:5985 -RemoteAddress:$OperatorAddress
    }
    $Actions.Add(('create firewall rule {0} for {1}' -f $FIREWALL_RULE_NAME, $OperatorAddress))
  } Else {
    $PortFilter = $Rule | Get-NetFirewallPortFilter
    $AddressFilter = $Rule | Get-NetFirewallAddressFilter
    # A single address is stored plain in one build and as a /32 in another; both mean the same.
    $RemoteAddresses = @(
      @($AddressFilter.RemoteAddress) | ForEach-Object { ([System.String]$PSItem) -replace '/32$', '' }
    )
    $Checks = [System.Boolean[]]@(
      [System.String]$Rule.Enabled -eq 'True'
      [System.String]$Rule.Direction -eq 'Inbound'
      [System.String]$Rule.Action -eq 'Allow'
      [System.String]$Rule.Profile -eq 'Any'
      [System.String]$PortFilter.Protocol -eq 'TCP'
      [System.String]$PortFilter.LocalPort -eq '5985'
      $RemoteAddresses.Count -eq 1
      [System.String]$RemoteAddresses[0] -eq $OperatorAddress
    )
    $InSync = $Checks -notcontains $False
    If (-not $InSync) {
      If (-not $CheckMode) {
        $Null = Set-NetFirewallRule -PolicyStore:$PolicyStore -Name:$FIREWALL_RULE_NAME `
          -Direction:'Inbound' -Action:'Allow' -Enabled:'True' -Profile:'Any' `
          -Protocol:'TCP' -LocalPort:5985 -RemoteAddress:$OperatorAddress
      }
      $Actions.Add(('update firewall rule {0} for {1}' -f $FIREWALL_RULE_NAME, $OperatorAddress))
    }
  }

  # The security template. The STIG image denies Guests, Domain Admins, Enterprise Admins and
  # every local account (S-1-5-114 / S-1-5-113) the network and Remote Desktop logons; a domain
  # user-rights assignment replaces the local list entirely, so the same list is written back
  # without the local-account SIDs. Read after the writes above, because each of them bumped the
  # GPO's version and the bump below must build on the current value.
  $GpoObject = Get-ADObject -Identity:$Gpo.Path -Server:$DnsRoot `
    -Properties:@('gPCFileSysPath', 'gPCMachineExtensionNames', 'versionNumber')
  $SysvolPath = [System.String]$GpoObject.gPCFileSysPath
  $TemplatePath = [System.IO.Path]::Combine($SysvolPath, 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf')
  $DenyList = '*S-1-5-32-546,*{0}-512,*{1}-519' -f $DomainSid, $RootDomainSid
  $Template = (@(
      '[Unicode]'
      'Unicode=yes'
      '[Version]'
      'signature="$CHICAGO$"'
      'Revision=1'
      '[Privilege Rights]'
      ('SeDenyNetworkLogonRight = {0}' -f $DenyList)
      ('SeDenyRemoteInteractiveLogonRight = {0}' -f $DenyList)
    ) -join "`r`n") + "`r`n"
  $CurrentTemplate = [System.String]::Empty
  If ([System.IO.File]::Exists($TemplatePath)) {
    $CurrentTemplate = [System.IO.File]::ReadAllText($TemplatePath, [System.Text.Encoding]::Unicode)
  }
  $TemplateChanged = $CurrentTemplate -cne $Template
  If ($TemplateChanged) {
    If (-not $CheckMode) {
      $Null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($TemplatePath))
      [System.IO.File]::WriteAllText($TemplatePath, $Template, [System.Text.Encoding]::Unicode)
    }
    $Actions.Add('write the security template')
  }

  # The Security extension must be registered on the GPO for the client to process the
  # template at all. The attribute is a list of [{extension}{tool}...] groups; the existing
  # groups are kept as they are and the pair is added only when it is missing, compared as a set
  # so that the console's own ordering of the attribute is never fought over.
  $ExtensionGroups = @{}
  $ExtensionProperty = $GpoObject.PSObject.Properties['gPCMachineExtensionNames']
  $ExtensionNames = [System.String]::Empty
  If ($Null -ne $ExtensionProperty -and $Null -ne $ExtensionProperty.Value) {
    $ExtensionNames = [System.String]$ExtensionProperty.Value
  }
  ForEach ($Group In [regex]::Matches($ExtensionNames, '\[((?:\{[0-9A-Fa-f-]{36}\})+)\]')) {
    $Guids = @(
      [regex]::Matches($Group.Groups[1].Value, '\{[0-9A-Fa-f-]{36}\}') | ForEach-Object { $PSItem.Value.ToUpperInvariant() }
    )
    If (-not $ExtensionGroups.ContainsKey($Guids[0])) {
      $ExtensionGroups[$Guids[0]] = @{}
    }
    ForEach ($Tool In @($Guids | Select-Object -Skip:1)) {
      $ExtensionGroups[$Guids[0]][$Tool] = $True
    }
  }
  $ExtensionRegistered = $False
  If ($ExtensionGroups.ContainsKey($SECURITY_EXTENSION)) {
    $ExtensionRegistered = $ExtensionGroups[$SECURITY_EXTENSION].ContainsKey($SECURITY_EXTENSION_TOOL)
  }
  If (-not $ExtensionRegistered) {
    If (-not $ExtensionGroups.ContainsKey($SECURITY_EXTENSION)) {
      $ExtensionGroups[$SECURITY_EXTENSION] = @{}
    }
    $ExtensionGroups[$SECURITY_EXTENSION][$SECURITY_EXTENSION_TOOL] = $True
    $ExtensionKeys = [System.String[]]@($ExtensionGroups.Keys)
    [System.Array]::Sort($ExtensionKeys, [System.StringComparer]::OrdinalIgnoreCase)
    $Serialized = [System.Text.StringBuilder]::new()
    ForEach ($Extension In $ExtensionKeys) {
      $ToolKeys = [System.String[]]@($ExtensionGroups[$Extension].Keys)
      [System.Array]::Sort($ToolKeys, [System.StringComparer]::OrdinalIgnoreCase)
      $Null = $Serialized.Append('[').Append($Extension).Append(($ToolKeys -join '')).Append(']')
    }
    If (-not $CheckMode) {
      Set-ADObject -Identity:$Gpo.Path -Server:$DnsRoot -Replace:@{ gPCMachineExtensionNames = $Serialized.ToString() }
    }
    $Actions.Add('register the Security extension on the GPO')
  }

  # A client reapplies a GPO only when its version moves, and the cmdlet-driven writes above
  # move it themselves; the hand-written template needs the same done for it. The machine half
  # lives in the low sixteen bits, in Active Directory and in GPT.ini alike.
  If ($TemplateChanged -or -not $ExtensionRegistered) {
    $Version = [System.Int32]$GpoObject.versionNumber
    $MachineVersion = $Version -band 0xFFFF
    $UserVersion = ($Version -shr 16) -band 0xFFFF
    If ($MachineVersion -ge 0xFFFF) {
      Throw ('The machine version of GPO "{0}" is exhausted at {1}; it cannot be bumped.' -f $Name, $MachineVersion)
    }
    $NewVersion = ($UserVersion -shl 16) -bor ($MachineVersion + 1)
    If (-not $CheckMode) {
      $GptIniPath = [System.IO.Path]::Combine($SysvolPath, 'GPT.ini')
      $GptIni = "[General]`r`n"
      If ([System.IO.File]::Exists($GptIniPath)) {
        $GptIni = [System.IO.File]::ReadAllText($GptIniPath)
      }
      If ($GptIni -match '(?m)^Version=') {
        $GptIni = [regex]::Replace($GptIni, '(?m)^Version=[^\r\n]*', ('Version={0}' -f $NewVersion))
      } Else {
        $GptIni = '{0}{1}Version={2}{1}' -f $GptIni.TrimEnd(), "`r`n", $NewVersion
      }
      [System.IO.File]::WriteAllText($GptIniPath, $GptIni, [System.Text.Encoding]::ASCII)
      Set-ADObject -Identity:$Gpo.Path -Server:$DnsRoot -Replace:@{ versionNumber = $NewVersion }
    }
    $Actions.Add(('bump the machine version to {0}' -f ($MachineVersion + 1)))
  }

  # The link. Ensured last, so a GPO that is being created is complete before anything can
  # apply it. Enforcement is left alone: nothing above it is expected to contradict it. An OU
  # that is absent here is check mode's alone (the caller would create it this run), so there is
  # no link to compare and the one that would be made is reported.
  If (-not $TargetOUExists) {
    $Actions.Add(('link to {0}' -f $TargetOU))
  } Else {
    $Inheritance = Get-GPInheritance -Target:$TargetOU -Domain:$DnsRoot
    $Links = @(
      $Inheritance.GpoLinks | Where-Object { [System.String]$PSItem.GpoId -eq [System.String]$Gpo.Id }
    )
    If ($Links.Count -eq 0) {
      If (-not $CheckMode) {
        $Null = New-GPLink -Guid:$Gpo.Id -Target:$TargetOU -Domain:$DnsRoot -LinkEnabled:'Yes'
      }
      $Actions.Add(('link to {0}' -f $TargetOU))
    } ElseIf (-not [System.Boolean]$Links[0].Enabled) {
      If (-not $CheckMode) {
        $Null = Set-GPLink -Guid:$Gpo.Id -Target:$TargetOU -Domain:$DnsRoot -LinkEnabled:'Yes'
      }
      $Actions.Add(('enable the link to {0}' -f $TargetOU))
    }
  }
}

$Changed = $Actions.Count -gt 0
$GpoId = [System.String]::Empty
If ($Null -ne $Gpo) {
  $GpoId = [System.String]$Gpo.Id
}
$Message = If (-not $Changed) {
  'GPO "{0}" already carries the remote management policy for {1} and is linked to {2}.' -f @(
    $Name
    $OperatorAddress
    $TargetOU
  )
} ElseIf ($CheckMode) {
  'GPO "{0}" would change: {1}.' -f $Name, ($Actions -join '; ')
} Else {
  'GPO "{0}" converged: {1}.' -f $Name, ($Actions -join '; ')
}

$Result = [PSCustomObject]@{
  actions          = [System.String[]]$Actions.ToArray()
  changed          = $Changed
  check_mode       = $CheckMode
  domain           = $DnsRoot
  gpo_id           = $GpoId
  gpo_name         = $Name
  msg              = $Message
  operator_address = $OperatorAddress
  target_ou        = $TargetOU
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
