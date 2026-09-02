# `openssh_server` role

Gives a sealed host its SSH transport back — over WinRM, authenticated with the LAPS credential.

This is the deliberate reverse of [`workspace_baseline`](../workspace_baseline/README.md), and the
two are a matched pair. At the moment this role starts, the guest has no OpenSSH, no authorized
key and no port 22; the only thing that reaches it is a WinRM listener and the password Active
Directory escrowed for its built-in Administrator. That is exactly what a production WorkSpace
offers, and this role is the build working with it.

> **Scope:** one transport. The role installs a capability, a key, a service and a firewall rule.
> It configures no `sshd_config`, no shell and no user; flipping OpenSSH's `DefaultShell` to
> PowerShell belongs to the framework's `os_bootstrap`, which runs on the SSH play that follows.

## Composition and prerequisites

Runs from the composed tree under the pinned ansible-framework loader (`tasks/main.yml`,
byte-identical to the fleet loader). Windows Server 2022, reached over **WinRM/5986 with NTLM**
as the LAPS-managed local Administrator. Collections: `ansible.windows`, `community.windows`,
core. The controller needs `pywinrm` and its dependencies — they are pinned in
`requirements-quality.txt`.

The role executes a materialized copy of `scripts/Set-WindowsCapabilityState.ps1`; run
`scripts/materialize-role-scripts.sh` before lint or converge (the role tracks only
`files/Set-WindowsCapabilityState.ps1.stub`).

## The key comes from IMDS, not from the controller

The framework's `user_data` read the launch key pair's public half from the metadata service at
launch. This role reads it from the same place, so the key restored here **is** the key that was
revoked — proved by the source rather than asserted by a comment. The private half never moves,
and the controller hands the guest nothing.

IMDSv2 only: the instance runs with `imds_hop_limit = 1` and no v1 fallback, so a session token
is requested first. Both metadata tasks are `no_log` because their *arguments* carry that token —
a short-lived credential for the instance's own role. The public key is not a secret, and every
task that reasons about it is ungated.

## The ACL is not optional

Windows `sshd` reads administrative keys from one file —
`C:\ProgramData\ssh\administrators_authorized_keys` — for every member of the local
Administrators group, and **silently ignores** it if any account outside `Administrators` and
`SYSTEM` can write it. The failure mode is a key that is installed, correct, and rejected. So
inherited access is stripped (`win_acl_inheritance` with `reorganize: false`) rather than merely
supplemented, and only the principals in `authorized_keys.principals` are granted.

## Configuration

| Input | Default | Meaning |
|---|---|---|
| `capability.name` | `OpenSSH.Server~~~~0.0.1.0` | The DISM identity `workspace_baseline` removed. |
| `capability.source` | *(empty)* | Features on Demand payload path; empty installs from Windows Update. |
| `service.name` | `sshd` | |
| `firewall.rule_name` / `.port` | `OpenSSH SSH Server` / `22` | The rule `user_data` created, by the name it used. |
| `authorized_keys.path` / `.principals` | see above | Compiled into the shipped `sshd_config`. |
| `imds.*` | link-local `/latest` | Token TTL, key index and timeout. |

`capability.source` is the one value a site may genuinely have to supply: where WSUS policy
forbids optional features from Windows Update, point it at a mounted Features on Demand ISO and
the role adds `-LimitAccess` so DISM does not fall back to the network it was told not to use.
Naming one site's ISO path as though it were universal would be worse than a documented failure.

## State

`present` restores the transport. There is no `absent` leg here: removing OpenSSH is
`workspace_baseline`'s job, and it does it as a deferred scheduled task because the session being
removed is the one doing the removing.

## First-class PowerShell

`Set-WindowsCapabilityState.ps1` (with its `Set-WindowsCapabilityState.pester.ps1` spec) converges
the capability. DISM reports four states that are not `Installed` and only one of them means the
capability is simply absent — that distinction is what an idempotent converge turns on, so the
read, the decision and the act are one pair-tested script rather than three guesses.

## Verification

END re-reads the capability with the same script `PROCESS` used, proves the authorized keys file
exists and is not empty (existence and size only — reading a key file into a task result
publishes it to every callback for no gain), and proves from the **controller** that port 22
answers. That last one matters: a host that answers itself proves nothing about a security group,
and every remaining play in the build arrives over this transport.
