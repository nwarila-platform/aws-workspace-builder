# aws-workspace-builder

Ansible roles and playbook building AWS WorkSpaces virtual desktop images on the nwarila platform.

The production target is an AWS WorkSpace (Windows Server 2022 experience) created through the
WorkSpaces API. That API surface does not exist on a test account, so the image build is proved on
an **ephemeral EC2 stand-in** that mirrors a WorkSpace as far as EC2 can: the same guest OS
generation, a root volume standing in for the bundle's `C:`, a standalone user volume standing in
for `D:`, and — the part that takes work — the same way in.

## The credential path is the design

A WorkSpace joins its directory automatically and takes no `user_data`. There is no hook to install
a key through and no launch credential to install; the only way in is the password Windows LAPS
escrows on the computer object. EC2 hands us the opposite — a key pair written from IMDS by the
framework's `user_data` — which is a convenience production does not have, so the run gives it up
on purpose. The playbook is seven plays for that reason:

| # | Play | Reached over |
|---|---|---|
| 1 | Validate the inventory contract | — (localhost) |
| 2 | Configure: readiness, bootstrap, tunnel, domain join | SSH, launch key |
| 3 | **Seal:** build the WinRM listener, prove it, then revoke the launch key | SSH, launch key |
| 4 | **Wait:** read the LAPS escrow from a domain controller | SSH to the DC |
| 5 | **Re-enter:** restore OpenSSH from IMDS | WinRM, LAPS credential |
| 6 | Converge: bootstrap, disks | SSH, restored key |
| 7 | Record the stand-in manifest, then the application catalog | SSH, restored key |

Plays 3 to 5 are the replication; everything around them is an ordinary build. The three roles that
carry it are [`workspace_baseline`](ansible/applications/workspace_baseline/README.md),
[`laps_credential`](ansible/applications/laps_credential/README.md) and
[`openssh_server`](ansible/applications/openssh_server/README.md).

Nothing after play 5 knows or cares that the transport was taken away and given back. That is the
measure of whether the replication worked.

## Running the build

**CI launches; you converge.** The `aws-deploy` workflow applies Terraform, holds the instance and
destroys it. It does not run the playbook, because play 4 reads the LAPS escrow from a domain
controller on the private network — an address no GitHub runner has a route to, and one no ingress
rule can create. So the converge runs from an operator workstation on that network.

1. Dispatch **AWS Deploy** with a `hold_minutes` long enough for the run (default `240`). A held
   dispatch is refused unless `AWS_DEBUG_HOSTNAME` is configured: that secret resolves to the
   address the security group admits, and it is the address your converge arrives from.
2. When apply finishes, the job summary prints the exact local command with this run's values
   filled in. It looks like this:

   ```bash
   export GITHUB_REPOSITORY_ID='...' GITHUB_RUN_ID='...' GITHUB_REPOSITORY='...' ENVIRONMENT='test'

   scripts/compose-and-run.sh \
     -i "${PWD}/ansible/inventory/domain_controllers.yml" \
     -e aws_account_id=<the deployment account id> \
     -e aws_region=us-east-1 -e env=test -e state=present
   ```

   The `GITHUB_*` values are not decoration: the dynamic inventory reads them from the environment
   to select this run's instance, and a `lookup('env')` has no command-line equivalent.
3. The run takes as long as Windows LAPS takes to escrow a credential. Up to two hours of it is
   **one silent task** — the polling read is `no_log`, and `until` prints nothing under `no_log`,
   because a LAPS password may not appear in a log, a retry line or a callback. It is not hung.

`hold_minutes: 0` — what the push and schedule triggers use — proves the launch lifecycle only:
apply, tag, destroy, no guest configuration.

## Prerequisites for a local run

* On the LAN, with SSH to the domain controller in `ansible/inventory/domain_controllers.yml`
  (via your own `ssh-agent`/`~/.ssh/config` — no key is named in this repository).
* AWS credentials for the deployment account, so the dynamic inventory can describe the instance.
* The launch key pair's private half at `~/.ssh/nwarila-ec2-key`, or `CI_PRIVATE_KEY` pointing at
  it. The workflow asserts at launch that the org secret still matches the key pair, so a mismatch
  is found before you wait on it.
* `requirements-quality.txt` installed, which pins `pywinrm` and its dependencies for play 5.

## Known limits

* **The AMI is a sentinel.** `terraform/aws.tfvars` carries `ami-RESOLVE-WS2022-STIG`, which fails
  closed on purpose; resolve it before the first apply with the `describe-images` command in that
  file's header.
* **The domain must carry the Windows LAPS GPO.** Nothing in the playbook triggers the escrow — the
  policy arrives by Group Policy and LAPS processes it on its own cycle. Against a domain without
  the GPO, pass `-e laps_policy_source=local` and the build writes the policy on the guest itself
  and forces a processing pass.
* **STIG policy can refuse the WinRM logon.** A hardened image that denies local administrators a
  network logon will reject the LAPS credential in play 5. It is the same exposure the SSH-as-
  Administrator path already has, and it surfaces named, in `host_readiness`, rather than as a
  confusing failure further in.
* **`Add-WindowsCapability` needs Windows Update.** Play 5 installs OpenSSH from Windows Update over
  the instance's HTTPS egress rule. Where WSUS policy forbids optional features from Windows
  Update, point `openssh_server`'s `capability.source` at a mounted Features on Demand payload.
* **Teardown is best-effort.** The 330-minute job budget covers a four-hour hold with margin, but
  abnormal delay can exhaust it before `terraform destroy` and strand paid resources.

## Layout

| Path | What it is |
|---|---|
| `ansible/playbooks/` | The one playbook; its header carries the production-to-stand-in mapping |
| `ansible/applications/` | One role per concern, each 100% independent under the shared v3 loader |
| `ansible/inventory/` | `aws_ec2.yml` (discovered guest) and `domain_controllers.yml` (written down) |
| `scripts/` | First-class PowerShell, each with a `<Name>.pester.ps1` spec, plus the composer |
| `terraform/` | Data only — a plain tfvars; resources live in the pinned aws-terraform-framework |
