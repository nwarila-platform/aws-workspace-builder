# `workspace_baseline` role

Makes the EC2 stand-in match the posture of a real AWS WorkSpace: reachable over WinRM, and not
reachable with the launch key.

A production WorkSpace has no key pair and no `user_data` hook. It is born domain-joined, and the
only credential that ever reaches it is the one Windows LAPS escrows on the computer object. The
EC2 stand-in is born the opposite way — the framework's `user_data` installs the launch key from
IMDS and opens OpenSSH — which is a convenience production does not have. This role removes it,
so everything the build does afterwards has to earn its way in the way production does.

> **Scope:** posture only. The role builds one transport and revokes another; it installs no
> software and configures no application state. Re-installing OpenSSH afterwards belongs to
> [`openssh_server`](../openssh_server/README.md), which is the point of the exercise.

## Composition and prerequisites

Runs from the composed tree under the pinned ansible-framework loader (`tasks/main.yml`,
byte-identical to the fleet loader). Windows Server 2022, over the SSH transport `os_bootstrap`
has already repaired, on a host that is already domain-joined. Collections: `ansible.windows`,
`community.windows`, core.

The role executes a materialized copy of `scripts/Set-WinRmHttpsListener.ps1`; run
`scripts/materialize-role-scripts.sh` before lint or converge (the role tracks only
`files/Set-WinRmHttpsListener.ps1.stub`).

**The controller's address must be permitted to reach 5986** — in this repository that is the
framework's `debug_ip`, resolved by the deploy workflow from `AWS_DEBUG_HOSTNAME`. The role
proves that reachability from the controller *before* revoking anything, so a missing grant fails
while SSH still works.

## The order is the safety

| Stage | What it does | Why there |
|---|---|---|
| BEGIN | Converges the WinRM HTTPS listener and service settings | The new way in, built first |
| PROCESS | Starts WinRM, opens 5986, **proves 5986 from the controller** | The last moment a mistake is cheap |
| END | Asserts the listener, removes the launch key, closes 22, schedules the uninstall | Last, so any failure above leaves a reachable host |

A role that closed the door first and tested afterwards would turn every mistake into a dead
instance. This one cannot: every revocation is in `END`, after the replacement transport has
answered a TCP connection from the machine that will need it.

## The deferred uninstall

OpenSSH is carrying the session that would uninstall it, so `Remove-WindowsCapability` cannot run
inline — it would kill the connection mid-task and fail the play for doing exactly what it was
asked. The final task registers a one-shot scheduled task instead: **registration-triggered** with
a delay (`PT3M` by default), running as `SYSTEM`, which stops `sshd`, removes the capability and
unregisters itself.

The trigger is registration-with-delay rather than a wall-clock start boundary on purpose: a
boundary would be written by the controller in *its* timezone and read by the guest in the
guest's, and those are not the same machine. The delay is measured by the scheduler, from a
moment the scheduler observed.

Nothing in the role waits for the result. Port 22 falling silent is the proof, and the playbook
waits for that from the controller — the same thing a person would check.

## What is deliberately left alone

`C:\ProgramData\ssh` is **not** removed. The host keys live there, and the controller reaches
this host with `StrictHostKeyChecking=accept-new`; keys that survive the round trip mean the SSH
plays after the WinRM detour connect to a host the controller still recognises. (The playbook
purges the `known_hosts` entry anyway, because a capability removal is entitled to take the
directory with it.)

## Configuration

Every value carries a real default because every value is a Windows or OpenSSH contract rather
than a site choice: `winrm.port` (5986), `winrm.firewall_rule_name`, `ssh.authorized_keys_path`,
`ssh.firewall_rule_name`, `ssh.capability_name`, and the `removal_task` name, path and delay.
`winrm.reachability_timeout_seconds` bounds the controller-side proof.

## State

`present` seals the host. No `absent` leg exists: the stand-in is ephemeral, and "un-sealing" a
host is what the `openssh_server` role does deliberately, over the transport this role built.

## First-class PowerShell

`Set-WinRmHttpsListener.ps1` (with its `Set-WinRmHttpsListener.pester.ps1` spec) converges the
listener, because a listener is a compound object — certificate, port and binding together — that
no single Ansible module owns. It deliberately does **not** touch the service or the firewall:
those are modules' work, and a script re-implementing one would only be a second opinion.

## Verification

END asserts, from the script's own report, that exactly one HTTPS listener answers on the
expected port with a certificate behind it — and does so before anything is revoked.
