# `aws_cfn_bootstrap` role

**Stub.** Reserves the WorkSpace image catalog product `Amazon-Web-Services_aws-cfn-bootstrap` at fleet pin `2.0.34`.

> **Scope:** none yet. The role is not wired into the playbook, and its present leg refuses
> loudly if invoked, so wiring it in early fails by name at zero cost.

## Finishing checklist

1. Stage the installer in the application repository at
   `<ARP Publisher>/<ARP Product>/<version>/<file>` (vendor folder spelled exactly as the
   product's Add/Remove Programs Publisher) and record the object's lowercase sha256.
2. Clone the `google_chrome` pattern: measured ARP display name, the artifact layout, the
   product's silent behavior and timeout, plus any post-install state the product owns.
   Track `files/Get-InstalledSoftware.ps1.stub` for the shared pair-tested ARP reader.
3. Replace `tasks/present_windows.yml`, extend `tasks/validate.yml` to the full input
   contract, and rewrite this README per the role documentation convention.
4. Wire the role into `ansible/playbooks/aws-workspace-builder-aws.yml` (third play) with its
   `bucket`, `version` and `sha256`, in install order.
