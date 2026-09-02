# =========================================================================================== #
# File: 'terraform/aws.tfvars'
# --- [ Description ] ----------------------------------------------------------------------- #
#
# Variable input for the pinned aws-terraform-framework (SHA in .github/terraform-framework-pin).
# Plain tfvars — the workflow passes this file to terraform verbatim. This repository declares
# NO .tf files of its own: resources live in the pinned framework, configuration in the pinned
# ansible-framework plus this repository's roles.
#
# THE HOST IS A WORKSPACE STAND-IN. The production deployment is an AWS WorkSpace (Windows
# Server 2022 experience) created through the WorkSpaces API; this repository proves the image
# build on an EC2 instance that mirrors that WorkSpace as far as EC2 can: the same guest OS
# generation, one root volume standing in for the bundle's C:, and one STANDALONE user volume
# standing in for the WorkSpace's D:. refresh mirrors the WorkSpaces Rebuild semantic — bumping
# the framework's refresh_serial replaces the OS instance while the user volume detaches and
# re-attaches, exactly as a Rebuild restores C: and preserves D:.
#
# REACHABILITY — DIRECT SSH AND WinRM OVER A PUBLIC IPv4. The workflow discovers the runner's
# public IPv4 and passes it as the framework's runtime-only runner_ip variable, and resolves the
# configured operator hostname into debug_ip, which adds RDP. The framework attaches one security
# group carrying both to every interface. The instance receives a public IPv4 at launch; no Elastic
# IP is involved. The account has no NAT and no VPC endpoints.
#
# THE OPERATOR ADDRESS IS LOAD-BEARING, NOT A DEBUGGING CONVENIENCE. The playbook is run from an
# operator workstation on the LAN, not from the runner, because midway through the build it reads
# the Windows LAPS escrow from a domain controller at a private address — so debug_ip is the source
# address the ENTIRE converge arrives from, over both transports. The workflow refuses a held
# dispatch that resolves no operator address rather than launching a host nobody can reach.
#
# BOTH TRANSPORTS ARE USED, IN ONE RUN. SSH on 22 before the guest is sealed, WinRM over HTTP on
# 5985 after — the listener Group Policy delivers to a domain-joined host, which is the only one a
# real WorkSpace has. The framework opens 5985 for debug_ip ALONE: the operator's client seals
# every message under NTLM, which is why HTTP is safe from that seat and why the runner, whose
# readiness client cannot seal, keeps 5986 only. Nothing here builds a listener: this deployment's
# connection_type is "ssh", so the guest boots with the OpenSSH branch, and the playbook's
# workspace_baseline role PROVES the domain's listener answers -- from the guest, then from the
# operator's seat -- before revoking the launch key. That ordering is the safety, and it belongs in
# a play that can prove the replacement transport works before removing the old one.
#
# The dependency worth knowing: MapPublicIpOnLaunch is an attribute of a shared subnet no
# repository owns. Direct SSH requires the instance's launch-time public address as well as the
# runner-scoped security group.
#
# readiness_gate is FALSE by design: the playbook owns the bounded direct-SSH readiness check.
# The OpenSSH DefaultShell boots as cmd; the playbook's bootstrap play flips it to PowerShell on
# first contact, and every play after that declares the PowerShell shell type.
#
# =========================================================================================== #

# environment and the deployment identity (repository, repository_id, commit_sha, run_id) are
# deliberately NOT in this file: the workflow passes them as -var flags placed AFTER this file on
# the command line. Terraform resolves repeated command-line assignments in the order given, so it
# is that ordering, not the kind of flag, that keeps this file from renaming the deployment.

all_systems = [
  {
    region   = "us_east_1"
    hostname = "tcnaw-wsb01"
    # The ratified availability-zone spec lock, and a subnet in this account's only VPC.
    availability_zone = "us-east-1c"
    subnet_id         = "subnet-03a855e712be7b399"
    # The framework CONSUMES key pairs and never creates them, so this names the standing
    # account key pair. user_data installs its public half by reading IMDS; the private half
    # lives only in the AWS_EC2_SSH_PRIVATE_KEY organization secret and the runner's
    # temporary directory.
    key_name = "nwarila-ec2-key"
    # The org EC2 baseline plus read-only access to the application repository bucket, which is
    # what lets this host pull its own repository contents down rather than receiving them from
    # the controller. The runner role only reads and passes whichever profile is named here.
    iam_instance_profile = "nwarila-ec2-apprepo-profile"
    aws_kms_alias        = "aws/ebs"
    # Windows_Server-2022-English-STIG-Full-2026.08.12, owner 801119661308 — the WS2022 sibling
    # of the hardened base the Golden Repo deploys, matching the production WorkSpaces' Windows
    # Server 2022 guest. A literal id is an exact pin: Amazon republishes this image monthly
    # under a new id, so refresh it deliberately, never by lookup at plan time:
    #   aws ec2 describe-images --owners 801119661308 --region us-east-1 \
    #     --filters "Name=name,Values=Windows_Server-2022-English-STIG-Full*" \
    #     --query 'sort_by(Images,&CreationDate)[-1].[ImageId,Name]' --output text
    # The image ships WITHOUT the OpenSSH.Server capability, as every stock Server 2022 image
    # does; the framework's user_data installs it at boot from the staged cab that
    # windows_fod_source names (see the end of this file).
    ami = "ami-037678cc5b867c64e"
    # OS-DRIVE REPLACEMENT (immutable-OS pattern), which is also the WorkSpaces Rebuild
    # stand-in: refresh=true makes this host's OS instance swap-eligible, so bumping the
    # framework's refresh_serial variable (0 -> 1 -> ...) replaces the OS instance in place while
    # the standalone user volume below detaches and re-attaches to the replacement — C: rebuilt,
    # D: preserved, exactly the contract a WorkSpace Rebuild gives its user. It is a no-op until
    # refresh_serial actually changes, so the ephemeral apply -> converge -> destroy path is
    # unaffected.
    refresh = true
    # The production bundle's hardware class (2 vCPU / 8 GiB); the desktop application load the
    # image build installs needs the memory more than the build itself does.
    instance_type = "t3.large"
    # Direct SSH reaches the launch-time public IPv4 through the runner-scoped framework SG.
    connection_type = "ssh"
    readiness_user  = null

    readiness_gate             = false
    readiness_command          = null
    readiness_script_dir       = null
    readiness_private_key_path = null
    imds_hop_limit             = 1
    set_state                  = null

    tags = {
      Function = "workspace"
      Backup   = false
    }

    # The framework fixes delete_on_termination and encryption itself; neither is an input.
    root_block_device = {
      iops        = null
      tags        = {}
      throughput  = null
      volume_type = "gp3"
      # The stand-in for the WorkSpace bundle's root (C:) volume, sized for the full desktop
      # application catalog the image build installs — Office-class suites, Anaconda and four
      # JDK lines do not fit the AMI's native 30.
      volume_size = "80"
    }

    # ONE RAW data disk: the stand-in for the WorkSpace's user (D:) volume. The deploy layer owns
    # the hardware; the composed play's windows_disk_manager formats it and assigns D:. The
    # Function tag is the identity the disk role resolves a volume by (resolve_aws.yml), because
    # a volume id only exists after apply. It is a STANDALONE volume whose lifecycle is
    # independent of the OS instance, so an OS replacement (refresh above) detaches and
    # re-attaches the SAME volume instead of recreating it — the Rebuild-preserves-D: semantic.
    # It survives a refresh, not a `terraform destroy`: the framework tears every standalone
    # volume down with the deployment, which is what the ephemeral proof wants.
    ebs_block_devices = [
      {
        resource_key = "wsuservol"
        device_index = 0
        iops         = null
        snapshot_id  = null
        tags         = { Function = "WSUSERVOL" }
        throughput   = null
        volume_type  = "gp3"
        volume_size  = "50"
      }
    ]

    ami_block_device_overrides = []

    network_interfaces = [
      {
        description     = "tcnaw-wsb01 CI firewall"
        interface_type  = null
        private_ip      = null
        security_groups = []
        ingress         = []
        egress = [
          {
            description                  = "HTTPS out"
            ip_protocol                  = "tcp"
            from_port                    = 443
            to_port                      = 443
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          },
          # The VPN tunnel that carries the host onto the private network. Scoped by port rather
          # than by address: the profile names its endpoint by DNS, and that address changes.
          {
            description                  = "OpenVPN tunnel out"
            ip_protocol                  = "udp"
            from_port                    = 1194
            to_port                      = 1194
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          }
        ]
        tags = {}
      }
    ]

    # No Elastic IP: the subnet auto-assigns the launch-time public IPv4 used for direct SSH.
    associate_public_ip = false
  }
]

all_databases      = []
all_load_balancers = []

# windows_fod_source is NOT set here, on purpose. The Server 2022 image above ships without the
# OpenSSH.Server capability, so the framework's user_data installs it at boot from the cab staged
# in the account's application repository bucket -- and that bucket's name carries the account
# id, which this public file must not. The workflow passes the whole object as a -var built from
# the AWS_ACCOUNT_ID secret:
#   windows_fod_source = { bucket = "<account>-apprepo", region = "us-east-1", key_prefix = "fod" }
# with the cab at fod/20348/OpenSSH-Server-Package~31bf3856ad364e35~amd64~~.cab. The instance
# profile named above already reads that bucket. Left null, a boot on this image fails loudly in
# the EC2Launch log rather than stranding an instance nothing can reach.
