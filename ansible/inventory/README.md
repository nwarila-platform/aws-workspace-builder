# ansible/inventory/

## Two inventories, and the split is the point

The guest is **ephemeral**: every run creates a new instance, converges it, and destroys it. An
instance id written into a file here would be wrong the moment the run that produced it ended, so
that host is discovered — `aws_ec2.yml`.

The domain controller is the opposite. It is standing infrastructure that outlives every run, it
has no run tags to be discovered by, and the playbook needs it precisely when the guest has been
made unreachable on purpose. So it is written down — `domain_controllers.yml`.

**Both are required.** The playbook's first play refuses a run that carries only one of them,
because the alternative is discovering the omission in play 4, after the guest has already been
sealed against every credential the run holds.

## `aws_ec2.yml` — one run's instance, describing itself

The file is in two parts. The first is the only part that is about this repository: the region, the
four tag filters that select one run's instance — `RepositoryId`, `RunId` and `Repository` from the
workflow's own environment, and `Environment` from `ENVIRONMENT` or `test` — and the `workspace_servers`
group the play addresses. Everything below that is carried unchanged by any repository deploying a
host this way.

Hosts are named by their **Name tag**, which is the hostname Terraform declares, so
`inventory_hostname` is the system's own name and nothing downstream has to be told it again. Every
attribute the plugin publishes is namespaced with `aws_`, which keeps the EC2 instance `state` from
colliding with the role input that selects `present_windows.yml` or `absent_windows.yml`.

## Everything else is derived from the instance

| Value | Derived from |
|---|---|
| Operating system, login account, shell type | `platform_details`, which every instance carries and which names the platform it is licensed as |
| Connection, port, address, SSM proxy | the `Connection` tag |
| `ENV` (the framework loader's input) | the `Environment` tag |
| Private key | `CI_PRIVATE_KEY` when the workflow staged one, else the account key pair |

The `Connection` tag takes four values, and absent means `ssh-direct`:

| Value | Reaches the host by |
|---|---|
| `ssh-direct` | SSH to the routable address on 22 |
| `ssh-ssm` | SSH to the instance id, tunnelled by an SSM `ProxyCommand`; needs no inbound rule |
| `winrm-direct` | WinRM over HTTPS to the routable address on 5986 |
| `winrm-ssm` | WinRM over HTTPS to a local port an SSM port-forwarding session already holds open |

A WinRM leg also needs a password, because WinRM has no key authentication; the SSH legs
authenticate with the key pair. This repository reaches the guest over **both**, in one run: SSH
with the launch key before the host is sealed, WinRM with the Windows LAPS credential after. The
`Connection` tag stays absent — the WinRM leg's variables are set on the one play that uses them,
because they are true of that play and no other.

## `domain_controllers.yml` — where the credential is read from

Halfway through the run the guest is sealed to match a real WorkSpace: no launch key, no OpenSSH,
nothing the build holds a credential for. The only credential that reaches it is the one Windows
LAPS escrows on its computer object, and that lives in Active Directory — so it is read from a
domain controller with `Get-LapsADPassword`, over SSH, by the `laps_credential` role. The guest is
not contacted by that play and does not have to be reachable, which is the entire reason the read
happens there.

The address is on the **private network**, which is why the playbook runs from an operator
workstation on the LAN rather than from the CI runner. No key file is named: the connection uses
whatever the operator's `ssh-agent` or `~/.ssh/config` supplies, so a domain controller credential
is never written into this repository, staged by a workflow, or held anywhere a run could publish
it.

## Running the playbook

By hand is the **only** way this playbook runs: the `aws-deploy` workflow launches the instance and
holds it, and the converge happens locally. Export `GITHUB_REPOSITORY_ID`, `GITHUB_RUN_ID`,
`GITHUB_REPOSITORY` and `ENVIRONMENT` — the dynamic inventory reads them from the environment, and
a `lookup('env')` has no command-line equivalent — plus AWS credentials, then pass **both**
inventories while the instance still exists:

```bash
scripts/compose-and-run.sh \
  -i "${PWD}/ansible/inventory/domain_controllers.yml" \
  -e aws_account_id=<the deployment account id> \
  -e aws_region=us-east-1 -e env=test -e state=present
```

`compose-and-run.sh` supplies `aws_ec2.yml` itself; the `-i` above adds the second inventory beside
it. The held run's job summary prints this command with the run's own values already filled in. The
play asserts its ownership contract, so a run whose tags do not match fails closed.
