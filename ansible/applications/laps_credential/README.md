# `laps_credential` role

Waits for Active Directory to escrow the Windows LAPS credential for one computer, and publishes
it to the play.

This is the hinge of the WorkSpace replication. [`workspace_baseline`](../workspace_baseline/README.md)
has just revoked the launch key, so the guest is reachable by nothing the build holds. The only
credential that can bring it back is the one the directory escrows for its built-in
Administrator — exactly the situation a production WorkSpace is in from the moment it is created.

> **This role runs on a domain controller, not on the guest.** `Get-LapsADPassword` reads the
> directory, so the read happens where the directory is. The machine being waited on is never
> contacted and does not have to be reachable. That is the point.

## Composition and prerequisites

Runs from the composed tree under the pinned ansible-framework loader (`tasks/main.yml`,
byte-identical to the fleet loader). Targets the `domain_controllers` inventory group over SSH as
`Administrator`, with the LAPS PowerShell module present (in-box on a supported domain
controller). Collections: `ansible.windows`, core.

The role executes a materialized copy of `scripts/Get-LapsCredential.ps1`; run
`scripts/materialize-role-scripts.sh` before lint or converge (the role tracks only
`files/Get-LapsCredential.ps1.stub`).

## What the caller supplies

| Input | Meaning |
|---|---|
| `identity` | The computer object to read, as its `sAMAccountName` **without** the trailing `$`. |

An EC2 Windows instance is **not** renamed at launch, so the name Active Directory knows it by is
the AMI-generated one (`EC2AMAZ-…`), not the inventory hostname. The playbook reads it from the
guest with a `platform` fact gather *before* sealing the host, and passes it here.

## What the caller gets back

The registered result `__laps_credential_read__`. The next play authenticates with
`.result.password` and `.result.account`; the role's own `END` stage reports only the metadata —
account, last-set time, expiry.

## Nothing here triggers the escrow

The LAPS policy arrives by Group Policy and Windows LAPS processes it on its own background
cycle, so the credential appears when the guest gets round to it. Waiting is the entire job. The
default budget is two hours (`wait.attempts: 120`, `wait.delay_seconds: 60`), which covers a
90-minute Group Policy refresh interval plus the LAPS processing that follows.

A domain that does not carry the LAPS GPO will escrow nothing and burn the whole budget before
failing. That is what the playbook's `laps_policy_source: local` is for — it runs the guest-side
[`laps_admin`](../laps_admin/README.md) role, which writes the policy and forces a processing
pass, instead of waiting on a policy that is never coming.

## The wait is silent, on purpose

The polling task is `no_log`, and `until` prints nothing under `no_log` — so a long wait looks
like a stalled task. It is not. A LAPS password is the credential for the built-in Administrator
of a domain-joined machine and may not appear in a log, a retry line, a callback or a job
artifact; the budget is stated in the task name, and `END` reports the metadata once the wait is
over.

## State

`present` reads. There is no `absent` leg: this role does not own the escrow, it observes one.

## First-class PowerShell

`Get-LapsCredential.ps1` (with its `Get-LapsCredential.pester.ps1` spec) exists for one
distinction the `until` loop depends on: a credential that has **not been escrowed yet** is a
state to wait on, while an identity **the directory does not know** is a failure no amount of
waiting fixes. It reports the first as a result and re-raises the second.
