# =========================================================================================== #
# File: 'terraform/aws.tfvars'
# --- [ Description ] ----------------------------------------------------------------------- #
#
# Variable input for the pinned aws-terraform-framework (SHA in .github/terraform-framework-pin).
# Plain tfvars — the workflow passes this file to terraform verbatim. This repository declares
# NO .tf files of its own: resources live in the pinned framework, configuration in the pinned
# ansible-framework plus this repository's roles.
#
# REACHABILITY — DIRECT SSH OVER A PUBLIC IPv4. The workflow discovers the runner's public IPv4
# and passes it as the framework's runtime-only runner_ip variable. When an operator hostname is
# configured it resolves that too and passes debug_ip, which adds RDP for a person working on the
# host. The framework attaches one security group carrying both to every interface. The instance
# receives a public IPv4 at launch; no Elastic IP is involved. The account has no NAT and no VPC
# endpoints.
#
# The dependency worth knowing: MapPublicIpOnLaunch is an attribute of a shared subnet no
# repository owns. Direct SSH requires the instance's launch-time public address as well as the
# runner-scoped security group.
#
# readiness_gate is FALSE by design: the playbook owns the bounded direct-SSH readiness check.
# The host is Linux; SSH lands on the AMI's ec2-user and the composed play's bootstrap takes it
# from there.
#
# =========================================================================================== #

# environment and the deployment identity (repository, repository_id, commit_sha, run_id) are
# deliberately NOT in this file: the workflow passes them as -var flags placed AFTER this file on
# the command line. Terraform resolves repeated command-line assignments in the order given, so it
# is that ordering, not the kind of flag, that keeps this file from renaming the deployment.

all_systems = [
  {
    region   = "us_east_1"
    hostname = "tcnaw-keycloak01"
    # The ratified availability-zone spec lock, and a subnet in this account's only VPC.
    availability_zone = "us-east-1c"
    subnet_id         = "subnet-03a855e712be7b399"
    # The framework CONSUMES key pairs and never creates them, so this names the standing
    # account key pair. user_data installs its public half by reading IMDS; the private half
    # lives only in the AWS_EC2_SSH_PRIVATE_KEY organization secret and the runner's
    # temporary directory.
    key_name = "nwarila-ec2-key"
    # The org EC2 baseline: SSM, the administrator's backup connection, and nothing else. The
    # controller fetches every artifact and hands the guest a verified copy, so the guest needs
    # no read of the application repository.
    iam_instance_profile = "nwarila-ec2-profile"
    aws_kms_alias        = "aws/ebs"
    # CIS Red Hat Enterprise Linux 8 — the same hardened base the secure-wazuh Linux legs use.
    ami = "ami-0ca8a2e788e4c5869"
    # No standalone data volumes yet, so the OS instance is not swap-eligible; a future
    # persistent deployment declares its data volumes below and flips this to true.
    refresh = false
    # Starting size for the application proof; resize when the application's real footprint
    # is measured.
    instance_type = "t3.medium"
    # Direct SSH reaches the launch-time public IPv4 through the runner-scoped framework SG.
    connection_type = "ssh"
    readiness_user  = "ec2-user"

    readiness_gate             = false
    readiness_command          = null
    readiness_script_dir       = null
    readiness_private_key_path = null
    imds_hop_limit             = 1
    set_state                  = null

    tags = {
      Function = "keycloak"
      Backup   = false
    }

    root_block_device = {
      iops        = null
      tags        = {}
      throughput  = null
      volume_type = "gp3"
      volume_size = "50"
    }

    # The CIS RHEL 8 AMI ships TWO devices: /dev/sda1 (root, handled by root_block_device, which
    # the framework forces encrypted) and a 40 GiB /dev/sdf the image defines and Terraform would
    # otherwise never see. Restating it here re-renders the mapping with encrypted = true, which
    # is the only declarative way to encrypt a device the AMI ships unencrypted. No collision
    # with ebs_block_devices: the framework assigns those suffixes starting at 'd'.
    ami_block_device_overrides = [
      {
        device_name = "/dev/sdf"
        iops        = "3000"
        throughput  = "125"
        volume_size = "40"
        volume_type = "gp3"
      }
    ]

    ebs_block_devices = []

    network_interfaces = [
      {
        description    = "tcnaw-keycloak01 CI firewall"
        interface_type = null
        private_ip     = null
        # Membership the load balancer and the database admit (dependencies/aws/estate.yml).
        security_groups = ["sg-REPLACE-keycloak-node"]
        # Peers by group, never by address: only the load balancer reaches Keycloak, and only the
        # other node reaches the cluster ports.
        ingress = [
          {
            description                  = "Keycloak HTTP from the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 8080
            to_port                      = 8080
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-alb"
          },
          {
            description                  = "Keycloak health from the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 9000
            to_port                      = 9000
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-alb"
          },
          {
            description                  = "Cluster cache traffic from the other node"
            ip_protocol                  = "tcp"
            from_port                    = 7800
            to_port                      = 7800
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-node"
          },
          {
            description                  = "Cluster failure detection from the other node"
            ip_protocol                  = "tcp"
            from_port                    = 57800
            to_port                      = 57800
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-node"
          }
        ]
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
          {
            description                  = "PostgreSQL to the database"
            ip_protocol                  = "tcp"
            from_port                    = 5432
            to_port                      = 5432
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-db"
          },
          {
            description                  = "Cluster cache traffic to the other node"
            ip_protocol                  = "tcp"
            from_port                    = 7800
            to_port                      = 7800
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-node"
          },
          {
            description                  = "Cluster failure detection to the other node"
            ip_protocol                  = "tcp"
            from_port                    = 57800
            to_port                      = 57800
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-node"
          },
          {
            description                  = "HTTP to the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 80
            to_port                      = 80
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-alb"
          }
        ]
        tags = {}
      }
    ]

    # No Elastic IP: the subnet auto-assigns the launch-time public IPv4 used for direct SSH.
    associate_public_ip = false
  },
  {
    region   = "us_east_1"
    hostname = "tcnaw-keycloak02"
    # The second zone: the cluster's nodes, its load balancer and its database subnet group
    # span us-east-1c and us-east-1a, so losing either zone leaves a node serving.
    availability_zone = "us-east-1a"
    subnet_id         = "subnet-0dbb7770d19f253ad"
    # The framework CONSUMES key pairs and never creates them, so this names the standing
    # account key pair. user_data installs its public half by reading IMDS; the private half
    # lives only in the AWS_EC2_SSH_PRIVATE_KEY organization secret and the runner's
    # temporary directory.
    key_name = "nwarila-ec2-key"
    # The org EC2 baseline: SSM, the administrator's backup connection, and nothing else. The
    # controller fetches every artifact and hands the guest a verified copy, so the guest needs
    # no read of the application repository.
    iam_instance_profile = "nwarila-ec2-profile"
    aws_kms_alias        = "aws/ebs"
    # CIS Red Hat Enterprise Linux 8 — the same hardened base the secure-wazuh Linux legs use.
    ami = "ami-0ca8a2e788e4c5869"
    # No standalone data volumes yet, so the OS instance is not swap-eligible; a future
    # persistent deployment declares its data volumes below and flips this to true.
    refresh = false
    # Starting size for the application proof; resize when the application's real footprint
    # is measured.
    instance_type = "t3.medium"
    # Direct SSH reaches the launch-time public IPv4 through the runner-scoped framework SG.
    connection_type = "ssh"
    readiness_user  = "ec2-user"

    readiness_gate             = false
    readiness_command          = null
    readiness_script_dir       = null
    readiness_private_key_path = null
    imds_hop_limit             = 1
    set_state                  = null

    tags = {
      Function = "keycloak"
      Backup   = false
    }

    root_block_device = {
      iops        = null
      tags        = {}
      throughput  = null
      volume_type = "gp3"
      volume_size = "50"
    }

    # The CIS RHEL 8 AMI ships TWO devices: /dev/sda1 (root, handled by root_block_device, which
    # the framework forces encrypted) and a 40 GiB /dev/sdf the image defines and Terraform would
    # otherwise never see. Restating it here re-renders the mapping with encrypted = true, which
    # is the only declarative way to encrypt a device the AMI ships unencrypted. No collision
    # with ebs_block_devices: the framework assigns those suffixes starting at 'd'.
    ami_block_device_overrides = [
      {
        device_name = "/dev/sdf"
        iops        = "3000"
        throughput  = "125"
        volume_size = "40"
        volume_type = "gp3"
      }
    ]

    ebs_block_devices = []

    network_interfaces = [
      {
        description    = "tcnaw-keycloak02 CI firewall"
        interface_type = null
        private_ip     = null
        # Membership the load balancer and the database admit (dependencies/aws/estate.yml).
        security_groups = ["sg-REPLACE-keycloak-node"]
        # Peers by group, never by address: only the load balancer reaches Keycloak, and only the
        # other node reaches the cluster ports.
        ingress = [
          {
            description                  = "Keycloak HTTP from the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 8080
            to_port                      = 8080
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-alb"
          },
          {
            description                  = "Keycloak health from the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 9000
            to_port                      = 9000
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-alb"
          },
          {
            description                  = "Cluster cache traffic from the other node"
            ip_protocol                  = "tcp"
            from_port                    = 7800
            to_port                      = 7800
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-node"
          },
          {
            description                  = "Cluster failure detection from the other node"
            ip_protocol                  = "tcp"
            from_port                    = 57800
            to_port                      = 57800
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-node"
          }
        ]
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
          {
            description                  = "PostgreSQL to the database"
            ip_protocol                  = "tcp"
            from_port                    = 5432
            to_port                      = 5432
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-db"
          },
          {
            description                  = "Cluster cache traffic to the other node"
            ip_protocol                  = "tcp"
            from_port                    = 7800
            to_port                      = 7800
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-node"
          },
          {
            description                  = "Cluster failure detection to the other node"
            ip_protocol                  = "tcp"
            from_port                    = 57800
            to_port                      = 57800
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-node"
          },
          {
            description                  = "HTTP to the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 80
            to_port                      = 80
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-keycloak-alb"
          }
        ]
        tags = {}
      }
    ]

    # No Elastic IP: the subnet auto-assigns the launch-time public IPv4 used for direct SSH.
    associate_public_ip = false
  }
]

# The database every node shares, and through jdbc-ping the registry by which they find each
# other. Single-AZ for routine runs: the cheapest database that proves the cluster. multi_az =
# true adds a standby in a second zone and requires availability_zone = null. The shape matches
# what the runner may create (dependencies/aws/policies/nwarila-platform_keycloak_runner_rds.json):
# postgres, db.t4g.micro, 20 GiB, no storage autoscaling, encrypted, not public, RDS-managed
# password. ca_cert_identifier stays null: a non-default one makes the provider modify the
# instance after creating it, which the runner may not.
all_databases = [
  {
    region                 = "us_east_1"
    availability_zone      = "us-east-1c"
    multi_az               = false
    db_name                = "keycloak"
    db_subnet_group_name   = "keycloak"
    vpc_security_group_ids = ["sg-REPLACE-keycloak-db"]
    engine                 = "postgres"
    # The major release is the pin: RDS creates the current minor of PostgreSQL 17, which
    # Keycloak 26.7 supports, and the runner may reference only PostgreSQL 17's default groups.
    engine_version                      = "17"
    instance_class                      = "db.t4g.micro"
    username                            = "keycloak"
    manage_master_user_password         = true
    iam_database_authentication_enabled = false
    # Both keys are AWS managed and free. An AWS managed key works only through its own service,
    # so the master secret cannot share the storage key.
    aws_kms_alias                = "aws/rds"
    master_user_secret_kms_alias = "aws/secretsmanager"
    allocated_storage            = "20"
    max_allocated_storage        = "0"
    storage_type                 = "gp3"
    dedicated_log_volume         = false
    blue_green_update            = false
    ca_cert_identifier           = null
    # Ephemeral: nothing is kept after the run.
    backup_retention_period  = "0"
    backup_window            = null
    delete_automated_backups = true
    deletion_protection      = false
    skip_final_snapshot      = true

    tags = {
      Function = "keycloak-db"
      Backup   = false
    }
  }
]

# Internal by the framework's rule and the runner's: every client is inside the VPC. It spans both
# node zones, checks each node's readiness on the management port, and keeps a browser on the
# node that holds its login flow, as Keycloak recommends.
all_load_balancers = [
  {
    region          = "us_east_1"
    resource_key    = "keycloak"
    name            = "keycloak"
    name_prefix     = null
    security_groups = ["sg-REPLACE-keycloak-alb"]
    subnets         = ["subnet-03a855e712be7b399", "subnet-0dbb7770d19f253ad"]
    subnet_mapping  = []

    access_logs                                                  = null
    client_keep_alive                                            = null
    connection_logs                                              = null
    customer_owned_ipv4_pool                                     = null
    desync_mitigation_mode                                       = null
    dns_record_client_routing_policy                             = null
    drop_invalid_header_fields                                   = true
    enable_cross_zone_load_balancing                             = null
    enable_deletion_protection                                   = false
    enable_http2                                                 = null
    enable_tls_version_and_cipher_suite_headers                  = null
    enable_waf_fail_open                                         = null
    enable_xff_client_port                                       = null
    enable_zonal_shift                                           = null
    enforce_security_group_inbound_rules_on_private_link_traffic = null
    health_check_logs                                            = null
    idle_timeout                                                 = null
    internal                                                     = true
    ip_address_type                                              = "ipv4"
    ipam_pools                                                   = null
    load_balancer_type                                           = "application"
    minimum_load_balancer_capacity                               = null
    preserve_host_header                                         = null
    secondary_ips_auto_assigned_per_subnet                       = null
    tags                                                         = {}
    timeouts                                                     = null
    # Keycloak trusts the leftmost X-Forwarded-For entry, which a client can write: the load
    # balancer removes the header, so Keycloak records an address no client chose.
    xff_header_processing_mode = "remove"

    target_groups = [
      {
        resource_key = "keycloak"
        # Targets attach by Function tag within this VPC: both nodes.
        function = "keycloak"
        vpc_id   = "vpc-0724440de2891a1ee"
        port     = 8080
        protocol = "HTTP"
        # Short, so a destroy does not wait out the default five minutes.
        deregistration_delay              = 30
        protocol_version                  = null
        target_type                       = "instance"
        slow_start                        = null
        load_balancing_algorithm_type     = null
        load_balancing_anomaly_mitigation = null
        load_balancing_cross_zone_enabled = null
        preserve_client_ip                = null
        proxy_protocol_v2                 = null
        connection_termination            = null
        ip_address_type                   = null
        health_check = {
          enabled             = true
          healthy_threshold   = 2
          interval            = 10
          matcher             = "200"
          path                = "/health/ready"
          port                = "9000"
          protocol            = "HTTP"
          timeout             = 5
          unhealthy_threshold = 2
        }
        stickiness = {
          type            = "lb_cookie"
          cookie_duration = 3600
          cookie_name     = null
          enabled         = true
        }
        tags = {}
      }
    ]

    listeners = [
      {
        resource_key                = "http"
        port                        = 80
        protocol                    = "HTTP"
        ssl_policy                  = null
        alpn_policy                 = null
        certificate_arn             = null
        additional_certificate_arns = []
        default_action = {
          type             = "forward"
          target_group_key = "keycloak"
          redirect         = null
          fixed_response   = null
        }
        rules = []
      }
    ]
  }
]
