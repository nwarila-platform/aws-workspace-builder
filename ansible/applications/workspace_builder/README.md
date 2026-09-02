# `workspace_builder` role

Records the WorkSpace stand-in identity on the guest. The production path creates a real AWS
WorkSpace and ends holding a WorkSpace id, a ComputerName and a backing instance id read from the
WorkSpaces API; this role publishes the equivalent identity from the EC2 side — one JSON manifest
in ProgramData carrying the production WorkSpace this host mirrors beside what the host actually
is — and proves the manifest round-trips.

> **Scope:** identity recording only. The role does not call the WorkSpaces API, rename the host,
> create users or provision disks. The stand-in's network join is `domain_member`'s job, its user
> volume is `windows_disk_manager`'s, and the software load belongs to the per-product application
> roles.

## Composition and prerequisites

Runs from the composed tree under the pinned ansible-framework loader (`tasks/main.yml`,
byte-identical to the fleet loader). Windows Server 2022, reached over the transport
`os_bootstrap` has already repaired. No collections beyond `ansible.windows` and core.

## What the caller supplies

The playbook supplies every deployment-specific value; `tasks/validate.yml` enforces the shapes.

| Input | Meaning |
|---|---|
| `workspace.directory_id` | Directory the production WorkSpace registers in (`d-...`). |
| `workspace.bundle_id` | Bundle whose image this build reproduces (`wsb-...`). |
| `workspace.user_name` | User the reference flow feeds to `create-workspaces`. |
| `identity.workspace_id` | This run's EC2 instance id, standing in for the WorkSpace id. |
| `identity.computer_name` | The Name-tag hostname, standing in for ComputerName. |
| `identity.image_id` | AMI the stand-in launched from. |
| `identity.private_ip` | The launch-assigned private IPv4. |

## Configuration

`manifest.directory` (default `C:\ProgramData\AWSWorkspaceBuilder`) and `manifest.filename`
(default `workspace.json`) place the manifest. ProgramData because the manifest is machine state:
it must survive every profile and be readable by anything on the host.

## State

`present` writes the directory and the manifest. No `absent` leg exists yet: the stand-in is
ephemeral and torn down by Terraform, so there is nothing durable to remove.

## Design invariants

- The manifest is the merged configuration serialized directly — no template file, so there is no
  second copy of the mapping to drift.
- END reads the file that actually landed and compares it to the declaration, so a mangled or
  hand-edited manifest fails the converge instead of surfacing later as a parse error.
- No secret crosses the role; everything recorded is already visible in the run's inventory.

## Verification

END slurps the published manifest and asserts the parsed `workspace` and `identity` maps equal
the declared ones. Under `--check` the proof is skipped honestly: the file it reads legitimately
does not exist yet.
