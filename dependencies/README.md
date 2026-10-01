# Dependency declarations

This tree is this repository's declared dependency contract for the organization estates.
`dependencies/aws/` is desired state. Unlike the trees it was copied from, it has never been
reconciled against a live export: this repository's IAM has not been exported, so `manifest.json`
records a null export date and null versions rather than claiming an equality nobody measured. The
owner reviews this tree before any AWS apply.

The layout is the one `nwarila-platform/secure-wazuh` introduced and `nwarila-platform/nessus`
extended; see "Copy this pattern" below.

## Layout

`aws/policies/` contains one desired customer-managed IAM document per object. Policy metadata
lives in `aws/manifest.json`. There is no `aws/proposed/` tree: desired changes are made in the
real policy files and recorded in the manifest's `divergence` block until they are applied.

`aws/roles/` pairs each desired trust document with a role sidecar. The sidecar carries session
duration, customer and AWS-managed attachments, the trust filename, path, nullable description
and ownership.

`aws/manifest.json` keeps the export date and the authoritative role-to-policy attachments for
the closed set: three roles, zero profiles, and twenty customer-managed policies. Its `policies`
and `divergence` objects are declared local extensions to the golden manifest schema.

`aws/artifacts.yml` declares the exactly consumed S3 objects: the Keycloak release archive, with
its SHA-256 pin, and the administrator password, deliberately without a digest.

`aws/estate.yml` is new in this repository. It declares the standing, zero-cost objects the pinned
aws-terraform-framework consumes but never creates:
- the RDS and Elastic Load Balancing service-linked roles, which a first create needs;
- the `keycloak` DB subnet group, whose subnets resolve at apply time to the subnets
  `terraform/aws.tfvars` places systems in, so a subnet is named in exactly one file;
- three security groups. `keycloak-node` is a rule-less membership group the nodes carry, and
  `keycloak-alb` and `keycloak-db` admit only that group. Reachability is by membership, not by
  address, so nothing else in a shared subnet reaches the load balancer or the database. The
  nodes' own rules are run-scoped and live in `terraform/aws.tfvars`.

There is no `ad/` directory because this repository's Active Directory footprint is empty: the
Keycloak nodes join no directory.

## Changes from the fleet baseline

Every document not listed here is the fleet skeleton baseline, renamed to this repository. This
repository is the organization's first RDS and load balancer consumer, so every document below is
new to the fleet.

**`nwarila-platform_keycloak_runner_rds`** creates, reads and deletes exactly one database,
`keycloak`, and reads the master secret RDS manages for it.
- Creation requires the deploy identity tags, and also pins the database's shape:
  - engine `postgres`;
  - class `db.t4g.micro`;
  - initial storage at most 20 GiB;
  - storage encrypted;
  - not publicly accessible;
  - master password managed by RDS.

  A plan that drifts from that shape is denied, not billed. Storage autoscaling
  (`max_allocated_storage`) has no condition key, so the database declaration in
  `terraform/aws.tfvars` must keep it disabled.
- The subnet group must be `keycloak` from `estate.yml`. The default parameter and option groups
  of PostgreSQL 17 are the only other groups it may reference.
- Deletion requires the identity tags.
- No snapshot actions are granted. The ephemeral deploy skips the final snapshot, and a grant to
  take one would let a destroy leave billable state behind.
- No `ModifyDBInstance` is granted. The provider calls it while creating only for a non-default
  `ca_cert_identifier`, so the database declaration must leave it null.
- The master secret statements live here, not in a `secretsmanager` policy of their own, because
  they exist only for this database. That also keeps the runner at IAM's default quota of ten
  managed policies.
  - RDS creates the secret through the caller, so `CreateSecret` and `TagResource` are allowed only
    on `rds!db-*` names and only when the call arrives through RDS (`aws:CalledVia`).
  - `GetSecretValue` is allowed only on the secret whose RDS ownership tag names this database,
    matched with the global `aws:ResourceTag` key (see "Measured" below).
- No new KMS grant is needed. Storage uses `aws/rds` and the secret uses `aws/secretsmanager`.
  Naming a separate key for the secret needs the aws-terraform-framework's
  `master_user_secret_kms_alias`, which the pin in `.github/terraform-framework-pin` must reach
  before a database is declared.
  Both are AWS managed keys whose key policies admit the account's principals through their own
  service, and both are free. The `kms:DescribeKey` RDS requires on them comes from the baseline
  `runner_kms`. The provider's alias lookup is itself a DescribeKey, which associates an AWS
  managed key the account has not used before.

**`nwarila-platform_keycloak_runner_elb`** creates and deletes one application load balancer,
`keycloak`, with its listeners and its provider-named (`tf-`) target groups.
- Creation requires the deploy identity tags, and the load balancer must be internal. This
  restates the framework's own rule in the role, so an internet-facing balancer is denied even
  from a modified framework.
- Listeners may be created only on the `keycloak` load balancer.
- Tags may be written only during creation.
- Modify, register, deregister and delete require the identity tags.
- Describe actions support no resource scoping and are granted on `*`.

**`nwarila-platform_keycloak_runner_ec2`** launches only `t3.medium` instances. The fleet
baseline's tagged-creation statement is split in two: `ec2:InstanceType` exists on the instance
resource and not on the volume, so one statement carrying it would deny every volume. A tfvars that
drifts to a larger size is denied, not billed.

**`nwarila-platform_keycloak_runner_s3`** adds `ReadOnlyTheKeycloakDeploymentObjects`. It grants
`s3:GetObject` on exactly the one object under `<account-id>-ansible/applications/keycloak/` the
playbook reads: the Keycloak administrator password.

**`nwarila-platform_keycloak_reaper_rds`** and **`nwarila-platform_keycloak_reaper_elb`** are the
destroy-only halves: describe, plus tag-scoped delete and deregister. The reaper keeps no KMS or
Secrets Manager grant. Its destroy runs with `-refresh=false`, and deleting the instance deletes
the managed secret.

**`nwarila-platform_keycloak_admin_secretsmanager`** is the admin role's only new grant: the read
of this database's master secret.

**`nwarila-platform_keycloak_admin`** converges a held bed by hand and never builds the stack. It
therefore carries the baseline runner policies, `admin_s3` and `admin_secretsmanager`, but neither
`runner_elb` nor `runner_rds`. That puts it at the ten-policy quota.

## Applying

`scripts/apply-dependencies.sh` is the only apply path. A hand-typed `aws iam` apply once shipped an
unrendered `<region>` token into a live policy (recorded in secure-wazuh's `bootstrap-iam.sh`). Run
it with an administrator profile:

~~~bash
scripts/apply-dependencies.sh [--apply] [aws-profile]
~~~

Without `--apply` it plans and writes nothing. It exits 0 when live AWS is in sync, 2 when changes
are pending, and 1 on any failure, naming the command that failed. Each run does the following:
- renders every document from live values: the account, the GitHub owner and repository ids, and
  the region;
- refuses any document that still holds a token;
- validates every document with IAM Access Analyzer;
- reports every difference between this tree and live IAM and estate:
  - policy documents;
  - roles: trusts, session durations, attachments, and any undeclared inline policy or
    permissions boundary;
  - service-linked roles;
  - the subnet group;
  - security groups with their rules.
- refuses to adopt a same-named subnet group or security group that does not carry this tree's
  estate tags.

A failed or throttled read stops the run. It is never taken to mean an object is absent.

With `--apply` it writes those differences, detaching before attaching so a role at its quota can
converge. A write that fails stops the run where it failed. Every write is idempotent against the
next plan, so a re-run converges.

Once everything has been written, it re-plans and requires no difference. It then simulates each
role against requests its guards must allow and deny:
- the database shape, one condition at a time, and the instance size;
- creating without the deploy identity, and deleting unowned objects;
- the secret, both through RDS and directly, and both this database's and another's;
- the load balancer scheme, and tagging after creation;
- an escalation probe;
- the reaper's and the admin role's boundaries.

Finally it prints the security group ids that `terraform/aws.tfvars` consumes.

The subnet group needs systems in two availability zones. Until `terraform/aws.tfvars` has them,
the run reports that object as blocked and exits 1, but applies everything else first.

## External dependencies

This repository's hosts launch with the shared instance profile `nwarila-ec2-profile`, which carries
SSM alone: the controller fetches every artifact, so a host needs no read of the application
repository. That profile is registry-owned and declared by whichever repository owns the shared
estate. `terraform/aws.tfvars` selects it, and the runner holds `iam:PassRole` and
`iam:GetInstanceProfile` on it.

The release archive lives in the shared application repository bucket, under its
`<Publisher>/<Application>/<version>/` layout. The runner already reads that bucket by exact path.

The RDS master secret is not an artifact: RDS creates it with each database and deletes it with
each database, and the runner reads it by the ARN the framework outputs.

The service-linked roles are account-wide. Whichever repository's apply runs first creates them;
every later plan reports them present.

## Registry shim

`registry-values.yml` is the sacrificial local resolver. Delete that one file when the
organization registry exists; declarations retain their URIs. It contains only values genuinely
referenced by machine declarations, in both directions, each with evidence a reader can open in
this repository. Canonical AWS documents are already portable through the token vocabulary. They
therefore keep native AWS ARNs and names and have no resolver entries.

## Integrity

Every file below `dependencies/`, except `MANIFEST.sha256`, is covered by the manifest.
The SHA-256 of `MANIFEST.sha256` is the bundle digest naming the entire declaration set.
Regenerate it from the repository root with exactly:

~~~bash
(cd dependencies && LC_ALL=C find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z \
  | xargs -0 sha256sum > MANIFEST.sha256)
~~~

Verify it with exactly:

~~~bash
(cd dependencies && sha256sum -c MANIFEST.sha256)
~~~

The credential-free validator, `scripts/check-dependencies.py`, also checks:
- schemas, metadata, attachments and object closure;
- tokens, literals, canonical JSON and symlinks;
- that no policy or trust uses `NotAction`, `NotResource` or `NotPrincipal`;
- divergence references;
- that the estate is closed, names no subnet, VPC, security group id or address, declares no
  security group rule twice, and that its subnet group is the one `runner_rds` authorizes;
- that each role stays within the default managed-policy quota;
- that the playbook's installer pin equals the declared artifact, and that it reads every declared
  secret;
- that the runner's S3 policy authorizes every declared object, and that nothing in it reaches
  this repository's prefix beyond the declared objects.

The documents use `<account-id>`, `<owner-id>`, `<repository-id>` and `<region>`.

## Known gaps

- **Not yet proven live.** This is the first RDS and load balancer consumer in the organization.
  The following are correct per the AWS Service Authorization Reference and the provider's source,
  but no live run has exercised them yet:
  - `aws:CalledVia` on the RDS-created secret;
  - that RDS tags its secret `aws:rds:primaryDBInstanceArn`;
  - the provider's filtered `DescribeDBInstances` reads against a `db:*` grant;
  - RDS accepting `aws/secretsmanager` named explicitly as the secret's key;
  - the managed secret being deleted with the database.

  Each is a narrowing, so a wrong one fails closed as an AccessDenied naming the action. The fix
  is a reviewed edit here, never a wildcard.
- **Measured.** The first live apply (2026-10-01) found that IAM's policy simulator does not
  evaluate service-prefixed tag keys such as `secretsmanager:ResourceTag/<key>`, even for a plain
  tag, while it does evaluate the global `aws:ResourceTag/<key>`, including for the `aws:`-prefixed
  `aws:rds:primaryDBInstanceArn`. The secret-read statements therefore use the global key: it is
  the key AWS recommends, Secrets Manager supports it for `GetSecretValue`, and the apply's
  simulations can evidence it.
- **Keycloak uses the RDS master user.** The database exists only for Keycloak and only for one
  run, so a separate application role would protect nothing the run does not already destroy. A
  persistent deployment must create one.
- **Baseline grants this repository does not use.** `runner_s3` grants `s3:GetObject` on the
  domain-join secret and the VPN profile, and on all of `<account-id>-apprepo/*`. `runner_ssm`
  grants `SendCommand` with the PowerShell document. `runner_iam` reads and passes the apprepo
  profile and role, which these hosts no longer launch with. These remain in the fleet baseline
  pending a separately reviewed, fleet-wide hardening change.
- **Transitive reach is not declared.** The apprepo role, the profile, and `nwarila-apprepo-read`
  are excluded because reach is transitive through `PassRole`, not a configured dependency.

## Copy this pattern

The next consumer should:
- declare only the objects it owns;
- keep policy metadata and authoritative attachments in one manifest;
- preserve role sidecars where they carry real data;
- record external shared estate without redeclaring it;
- declare owned standing estate in `estate.yml` with reachability by membership, naming no
  subnet, VPC or address;
- close every URI, attachment, token, literal, checksum and divergence reference in its validator.
