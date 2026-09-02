# `laps_admin` role

Hands the built-in Administrator account to Windows LAPS with Active Directory as the escrow.
This is the mechanism that connects the WorkSpace stand-in to its domain controller and sets the
`BUILTIN\Administrator` password **from LAPS**: the role converges the LAPS policy registry, a
handler runs `Invoke-LapsPolicyProcessing` exactly when a policy value moved, and that
processing pass generates the password on the guest, sets it locally, and escrows it to the
computer object on the DC — all in one act the directory itself audits.

> **Scope:** policy and processing only. No password crosses Ansible in either direction — the
> role neither knows, sets, nor reads the credential. An administrator retrieves it with
> `Get-LapsADPassword` (or ADUC's LAPS tab); the guest can write its escrow but never read it
> back, by LAPS design.

## Composition and prerequisites

Runs from the composed tree under the pinned ansible-framework loader (`tasks/main.yml`,
byte-identical to the fleet loader). Windows Server 2022 carries LAPS natively (2023-04
update); the STIG base AMI is patched monthly, so the CSP and cmdlets are present on every
launch. The play runs `domain_member` first — an unjoined host fails the processing pass.

**Forest-side prerequisites (one-time, not this role's to perform):**

1. `Update-LapsADSchema` — extends the schema with the `ms-LAPS-*` attributes.
2. `Set-LapsADComputerSelfPermission -Identity <OU>` — grants SELF the password-write on the
   OU holding the stand-in computer objects.

A directory missing either fails the handler's processing pass loudly; that failure is the
role's precondition check, deliberately not softened into a skip.

## What the caller supplies

Nothing is required. The policy is fully defaulted and a site overrides it in the playbook:

| Input | Default | Meaning |
|---|---|---|
| `policy.password_length` | `24` | Generated password length (8-64). |
| `policy.password_complexity` | `4` | LAPS complexity class 1-4 (4 = full character set). |
| `policy.password_age_days` | `30` | Rotation age before LAPS rotates on its own. |

## Configuration

`BackupDirectory` is written literally as `2` (Active Directory) — the escrow target is a
design invariant, not a knob. `AdministratorAccountName` is converged **absent**: unset, LAPS
manages the built-in administrator by its well-known RID-500 SID, which survives a rename; a
leftover named value would silently manage the wrong account.

## State

`present` converges the policy, processes it when changed, and proves the key verbatim. No
`absent` leg exists yet: un-managing a credential is a deliberate act that belongs to the step
that first needs it.

## Design invariants

- The handler pattern is the idempotence: four policy writes notify one topic, processing runs
  once per converge that moved anything, and a converged host never contacts the DC at all.
- Handlers are flushed at the end of the stage AND in `always:`, so END reads post-processing
  state and a policy write that landed before a later failure still reaches the DC.
- END re-reads the policy key and asserts every value verbatim, including the load-bearing
  absence of `AdministratorAccountName`.

## Verification

On the converged host the LAPS operational log (`Microsoft-Windows-LAPS/Operational`) shows the
policy-processing pass and the Active Directory update; on the DC,
`Get-LapsADPassword -Identity <computer> -AsPlainText` returns the escrowed credential to an
authorized administrator. A finishing step may promote the event-log read into a first-class
scripted END proof once the DC leg is exercised in CI.
