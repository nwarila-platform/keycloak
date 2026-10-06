# `keycloak` role

Installs Keycloak at a pinned version on a CIS-hardened RHEL 8 host, builds it with its declared
build-time options, and runs it as a service in a cluster that shares one PostgreSQL database. In
one converge it:

1. installs the Java 21 runtime from RHEL AppStream;
2. creates the unprivileged `keycloak` system account and group;
3. unpacks the pinned distribution into `/opt/keycloak/<version>` from a copy verified against
   its SHA-256 on the guest, immediately before `tar` reads it;
4. trusts the version's libraries in fapolicyd;
5. runs `kc.sh build` as the account;
6. writes `keycloak.conf`, a root-only environment file carrying the database and first
   administrator passwords, and a hardened systemd unit, then links `/opt/keycloak/current` to
   the built version, restarting Keycloak when one of them changed;
7. starts the service;
8. waits for `/health/ready` on the management port, then reads the version back from Keycloak
   itself, through that link, and the service's state from the host.

The nodes find each other through the database: Keycloak 26.7's default cache stack, jdbc-ping,
registers every node there, and the nodes talk on TCP 7800 and 57800. The playbook owns the host
firewall and starts nodes one at a time, so the first creates the schema before the second joins.

## Composition and prerequisites

The play runs `credential_resolver`, `host_readiness` and `os_bootstrap` first; the inventory
names the Python 3.12 that bootstrap installs and pipelines every module. The controller reads
two things with its own credentials: the one object the installer key names in the application
repository (with no right to list the bucket), and the administrator password. Keycloak's
database role, and the schema it runs in, are provisioned beforehand by
[`keycloak_db_config`](../keycloak_db_config/README.md); this role receives only that role's name
and password, never the database's master credential. The role hands the guest no cloud
credentials, and its instance profile carries SSM alone.

## Inputs

The playbook supplies these, which have no safe default;
[`tasks/validate.yml`](tasks/validate.yml) enforces them on the controller.

- `installer.bucket`: the S3 bucket holding the distribution, the application repository.
- `installer.version`: the three-part Keycloak version the tarball delivers. It names the
  versioned install directory and is read back from `kc.sh`.
- `installer.sha256`: the lower-case 64-character digest of that object, verified on the guest
  before it is unpacked.
- `hostname`: the URL clients reach Keycloak by; every token and redirect is issued under it.
- `database.host`, `database.name`: the PostgreSQL every node shares, which is also the registry
  the nodes find each other by (jdbc-ping).
- `database.schema`: the schema Keycloak creates its tables in.
- `database.username`, `database.password`: the database role, passed to Keycloak through a
  root-only environment file, never logged.
- `administrator.password`: the first administrator's, created only while the master realm has
  none.

The role composes the object key from the version:
`Keycloak/Keycloak/<version>/Keycloak_Keycloak_<version>_noarch.tar.gz`.

## Configuration

[`defaults/main.yml`](defaults/main.yml) documents every other input with its safe default: the
Java runtime, the account, the install root, the build options, the listeners, the database port
and pool, the administrator's name, the readiness bounds and the fapolicyd trust file.

## Layout

| Path | Owner | Why |
|---|---|---|
| `/opt/keycloak` | `root:keycloak`, 0750 | The account's home; shuts every other account out |
| `/opt/keycloak/<version>` | `root` | One unpacked, built version; a bump builds beside it |
| `/opt/keycloak/current` | link | The built version the service starts from |
| `/opt/keycloak/keycloak.env` | `root`, 0600 | The two passwords; systemd reads it before dropping to the account |
| `/etc/systemd/system/keycloak.service` | `root` | The hardened unit |
| `<version>/conf` | `root:keycloak`, `o=` | `keycloak.conf`; read by the account, written by root |
| `<version>/lib/quarkus` | `keycloak` | The only directory the build rewrites (INV-02) |
| `<version>/data`, `data/tmp` | `keycloak` | Run-time data, and the JVM's temporary directory |
| `<version>/.unpacked` | `root` | The archive digest, written only after an unpack completes |
| `<version>/.build-options` | `root` | What the tree was last built from and with |

A rebuild happens only when the version or the build options differ from `.build-options`. The
record is written after a build succeeds, so a converged host reports no change and a failed
build is retried by the next converge.

## CIS and STIG constraints

| Constraint | How the role meets it |
|---|---|
| fapolicyd | `lib/` joins the trust file `trust.d/keycloak`; the build waits until the reloaded database carries it (INV-08) |
| `noexec` `/tmp`, `/var/tmp`, `/home` | JVM temp is `data/tmp`; the home is the install root |
| FIPS mode | No opt-out: the build and version read run on the FIPS-mode JVM (INV-04) |
| SELinux | `restorecon -R -v` over the install root, which prints nothing on a converged host (INV-09) |

## State

| State | Does |
|---|---|
| `present` | Everything above |
| `absent` | Stops the service and removes its unit, the tree, the trust file, the account and group; proves none remains |

`absent` leaves the Java runtime installed: it is a shared system package this role cannot tell
it installed, and removing it would take any package that requires it along.

A version's tree is unpacked once: `.unpacked` records a complete unpack, so a changed
`installer.sha256` at an unchanged `installer.version` is not re-examined. A rebuilt distribution
takes a new version.

## Design invariants

1. [INV-01] fapolicyd types 130 of the distribution's 492 files `application/java-archive`, a
   `%languages` type that RHEL's default rules let a non-root process open only when trusted; the
   other jars type `application/zip`. Measured with `fapolicyd-cli --ftype` (fapolicyd 1.3.2,
   Rocky Linux 8, default rules, `integrity = none`) on 2026-10-01. Consequence: `lib/` is
   trusted before the build runs as the account.
2. [INV-02] `kc.sh build` rewrites exactly the four files under `lib/quarkus`, under the same
   names, and uses `java.io.tmpdir`; nothing else changes. The rewritten files type
   `application/zip`, `application/octet-stream` and `text/plain`, none of them a `%languages`
   type. Measured on UBI 8.10 with OpenJDK 21.0.12, and typed with fapolicyd 1.3.2, on
   2026-10-01. Consequence: the account owns `lib/quarkus` and `data/` only, and trust by path
   survives a rebuild.
3. [INV-03] In 26.7.5 the cache stack is a run-time option: `kc.sh build --help` lists no
   `--cache`, a build given one reports that it ignores `kc.cache`, and `kc.sh show-config` then
   persists only `db`, `health-enabled` and `metrics-enabled`. Measured on 2026-10-01.
   Consequence: `build_options` carries no cache option.
4. [INV-04] `kc.sh build` and `kc.sh --version` succeed on RHEL's OpenJDK 21 in FIPS mode
   (`SunPKCS11-NSS-FIPS` first, forced with `NSS_FIPS=1` under the FIPS crypto policy on UBI
   8.10, 2026-10-01). Kernel FIPS mode on the CIS host itself is not yet measured. Consequence:
   no FIPS opt-out is configured.
5. [INV-05] The distribution records its entries as owned by the vendor's build account
   (`runner`), read with `tar -tv` on 2026-10-01. Consequence: the unpack sets `root:root` rather
   than keeping the recorded owner.
6. [INV-06] With `JAVA_OPTS_APPEND` set, `kc.sh` prints `Appending additional Java properties to
   JAVA_OPTS` before `Keycloak <version>`. Measured on 2026-10-01. Consequence: END matches the
   version line, not the first line.
7. [INV-07] The 26.7.5 archive has no entries for `conf/`, `providers/` or `themes/`, only for
   files beneath them, so tar creates those three with the extracting process's umask. On the CIS
   host root's umask is 077, which made them 0700 and failed `kc.sh build` as the account with
   `ERROR: .../lib/../providers` (measured live on 2026-10-01). Consequence: the role sets
   `providers/` and `themes/` to 0755 after unpacking. `conf/` is already restricted to
   `root:keycloak` by its own task.
8. [INV-08] `fapolicyd-cli --update` returns before the daemon has reloaded its database: a build
   started at once was denied 84 ms after it (Rocky Linux 8, fapolicyd 1.3.2, default rules,
   2026-10-01). Consequence: after trusting `lib/`, the role reads the loaded database until it
   lists `lib/`, and fails naming fapolicyd if it never does.
9. [INV-09] On a fresh CIS RHEL 8 host the unpacked tree does not carry its policy labels:
   `restorecon -R -v` over the install root changed labels on both nodes in the first converge of
   AWS Deploy run 37061257295 (2026-10-02), and reported nothing in its second. Consequence: the
   role relabels the install root on every converge, which a converged host reports as no change.

## Verification

END is ungated: every converge waits until `/health/ready` answers 200, runs
`current/bin/kc.sh --version` as the account and requires the line `Keycloak <version>`, requires
`.build-options` to hold the declared version and options, and requires the service enabled and
active. Two steps wait, each bounded: until fapolicyd has loaded the trust, and until the service
reports ready.
