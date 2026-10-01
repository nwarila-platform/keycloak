# `keycloak` role

Installs Keycloak at a pinned version on a CIS-hardened RHEL 8 host and builds it with its
declared build-time options. In one converge it:

1. installs the Java 21 runtime from RHEL AppStream;
2. creates the unprivileged `keycloak` system account and group;
3. unpacks the pinned distribution into `/opt/keycloak/<version>` from a copy verified against
   its SHA-256 on the controller **and** on the guest, immediately before `tar` reads it;
4. trusts the version's libraries in fapolicyd;
5. runs `kc.sh build` as the account;
6. links `/opt/keycloak/current` to the built version;
7. reads the version back from Keycloak itself, through that link.

> **Scope:** install and build only. Nothing is started and nothing listens: the database
> Keycloak starts against arrives in a later stage, and with it the service, the listener and the
> firewall.

## Composition and prerequisites

The play runs `credential_resolver`, `host_readiness` and `os_bootstrap` first; the inventory
names the Python 3.12 that bootstrap installs and pipelines every module. The controller needs
read access to the one object the installer key names in the application repository, and no
right to list the bucket. The role hands the guest no cloud credentials, and its instance profile
carries SSM alone.

## Inputs

See [`meta/main.yml`](meta/main.yml) for the required inputs and
[`defaults/main.yml`](defaults/main.yml) for everything with a safe default. The playbook
supplies `installer.bucket`, `installer.version` and `installer.sha256`; the role composes the
object key from the version:
`Keycloak/Keycloak/<version>/Keycloak_Keycloak_<version>_noarch.tar.gz`.

## Layout

| Path | Owner | Why |
|---|---|---|
| `/opt/keycloak` | `root:keycloak`, 0750 | The account's home; shuts every other account out |
| `/opt/keycloak/<version>` | `root` | One unpacked, built version; a bump builds beside it |
| `/opt/keycloak/current` | link | The built version a service will start from |
| `<version>/conf` | `root:keycloak`, `o=` | Read by the account, written by root |
| `<version>/lib/quarkus` | `keycloak` | The only directory the build rewrites [INV-02] |
| `<version>/data`, `data/tmp` | `keycloak` | Run-time data, and the JVM's temporary directory |
| `<version>/.unpacked` | `root` | The archive digest, written only after an unpack completes |
| `<version>/.build-options` | `root` | What the tree was last built from and with |

A rebuild happens only when the version or the build options differ from `.build-options`. The
record is written after a build succeeds, so a converged host reports no change and a failed
build is retried by the next converge.

## CIS and STIG constraints

| Constraint | How the role meets it |
|---|---|
| fapolicyd | `lib/` joins the trust file `trust.d/keycloak`; the build waits until the reloaded database carries it [INV-01] |
| `noexec` `/tmp`, `/var/tmp`, `/home` | JVM temp is `data/tmp`; the home is the install root |
| FIPS mode | No opt-out: the build and version read run on the FIPS-mode JVM [INV-04] |
| SELinux | `restorecon -R -v` over the install root, which prints nothing on a converged host |

## State

| State | Does |
|---|---|
| `present` | Everything above |
| `absent` | Removes the tree, the trust file, the account and group; proves none remains |

`absent` leaves the Java runtime installed: it is a shared system package this role cannot tell
it installed, and removing it would take any package that requires it along.

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
   8.10, 2026-10-01). Consequence: no FIPS opt-out is configured. Kernel FIPS mode on the CIS
   host is the proof the first AWS run owes.
5. [INV-05] The distribution records its entries as owned by the vendor's build account
   (`runner`), read with `tar -tv` on 2026-10-01. Consequence: the unpack sets `root:root` rather
   than keeping the recorded owner.
6. [INV-06] With `JAVA_OPTS_APPEND` set, `kc.sh` prints `Appending additional Java properties to
   JAVA_OPTS` before `Keycloak <version>`. Measured on 2026-10-01. Consequence: END matches the
   version line, not the first line.
7. [INV-07] The 26.7.5 archive has no entries for `conf/`, `providers/` or `themes/`, only for
   files beneath them, so tar creates those three with the extracting process's umask. On the CIS
   host root's umask is 077, which made them 0700 and failed `kc.sh build` as the account with
   `ERROR: .../lib/../providers` (measured live on 2026-10-01). A lab with umask 022 had not shown
   it. Consequence: the role sets `providers/` and `themes/` to 0755 after unpacking. `conf/` is
   already restricted to `root:keycloak` by its own task.

## Verification

END is ungated: every converge runs `current/bin/kc.sh --version` as the account and requires
the line `Keycloak <version>`, and requires `.build-options` to hold the declared version and
options. No step waits on anything; the build and the version read are bounded by the workflow
step's budget.
