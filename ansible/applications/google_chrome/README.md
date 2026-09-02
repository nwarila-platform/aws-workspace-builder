# `google_chrome` role

Installs Google Chrome at a pinned version onto the WorkSpace image, and serves as the exemplar
for the image's per-product catalog roles: every product in the catalog carries this same shape —
an ARP identity, a `<version>`-keyed artifact layout, a controller-side S3 fetch, a guest-side
digest verification, a bounded silent install, and an Add/Remove Programs proof — and differs
only in its identity, layout and any post-install state the product itself owns.

> **Scope:** one product, install-to-pin only. The role does not manage browser policy, updates
> or shortcuts; it proves the pinned artifact is the registered product and nothing more. Each
> catalog role is 100% independent: shared shape, no shared code beyond the fleet loader and the
> pair-tested ARP reader.

## Composition and prerequisites

Runs from the composed tree under the pinned ansible-framework loader (`tasks/main.yml`,
byte-identical to the fleet loader). Windows Server 2022, reached over the transport
`os_bootstrap` has already repaired. Collections: `ansible.windows`, `amazon.aws`, core.

The role executes a materialized copy of `scripts/Get-InstalledSoftware.ps1`; run
`scripts/materialize-role-scripts.sh` before lint or converge (the role tracks only
`files/Get-InstalledSoftware.ps1.stub`).

## What the caller supplies

The playbook supplies every deployment-specific value; `tasks/validate.yml` enforces the shapes.

| Input | Meaning |
|---|---|
| `installer.bucket` | The application-repository bucket (carries the account id). |
| `installer.version` | Four-part pinned version; the idempotence comparison against ARP. |
| `installer.sha256` | Lowercase 64-char digest of the exact object, verified on the guest. |

The artifact must exist in the bucket at
`Google LLC/Google Chrome/<version>/googlechromestandaloneenterprise64.msi` before the role is
wired into the play; a missing digest fails `validate.yml` on the controller at zero cost.

## Configuration

`install.staging_dir` places the transient guest copy (overridden where application control
permits execution only from named paths); `install.timeout_seconds` bounds the silent install so
a wedged installer fails inside Ansible. `arp.display_name` and `installer.path` are product
identity and are not expected to change per site.

## State

`present` installs or upgrades to the pin and proves the registration. No `absent` leg exists
yet: the stand-in is ephemeral, and removal semantics belong to the catalog step that first
needs them.

## Design invariants

- Everything moves through the runner: the controller holds the S3 credentials and hands the
  file to the guest, which never receives any reach into S3.
- The digest is verified on the guest, because that is the copy that executes.
- Idempotence is judged from Add/Remove Programs — the machine's record — never from the
  installer's exit code, which is only the installer's opinion.
- Return code 3010 is a success that requests a restart; the role reboots exactly when asked.

## First-class PowerShell

`Get-InstalledSoftware.ps1` (with its `Get-InstalledSoftware.pester.ps1` spec) is the one guest
script: a read-only ARP query that reports `action_required` and the installed version, refusing
to answer when two registrations both claim the product.

## Verification

END re-reads Add/Remove Programs with the same script BEGIN used and asserts the product is
registered at or above the pin. Staged copies are removed on the guest and the controller in
`always:`, so a failed converge leaves no installer behind.
