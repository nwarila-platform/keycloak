# `keycloak_db_config` role

Provisions the PostgreSQL role Keycloak runs as, and the schema it runs in, logged in as the
database's administrator. Keycloak then holds a credential with no administrative attribute and,
in Keycloak's database, nothing beyond its own schema; the administrator's credential never leaves
this role.

Keycloak creates and migrates its own tables at startup, so it owns everything it creates in the
schema -- including the jdbc-ping table the nodes find each other by -- and nothing else.

## Composition and prerequisites

The playbook runs this role on exactly one node, so the administrator's credential reaches one
host, and before any node starts Keycloak, because that first start creates Keycloak's tables as
this role. The caller resolves the credential; the node receives it only as parameters of the
community.postgresql modules, whose argument specs mask it in every log and result. It never
reaches the node's disk because the inventory pipelines every module, so parameters reach the
interpreter on stdin rather than as a staged file.

The modules run as the SSH user, not root: they only open a TLS connection to the database.
RHEL's default fapolicyd rules deny such a process an untrusted shared library, so after
installing the driver the role retries a connection check until the modules can load it (INV-02).

Requires `community.postgresql` >= 5.0.0, the first release tested on ansible-core 2.21.

## Inputs

[`defaults/main.yml`](defaults/main.yml) documents every input, with a safe default where one
exists; the server, the database, both credentials, the role and the schema have none, so the
playbook supplies them. Every name reaches SQL as an identifier, so
[`tasks/validate.yml`](tasks/validate.yml) holds each to `^[A-Za-z_][A-Za-z0-9_]*$` once, and the
tasks pass them to the modules as trusted input. The role must not be the administrator, the
schema must not be `public`, and the role's password must be printable ASCII.

## The role's shape

| Object | Shape | Why |
|---|---|---|
| The role | `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`, a connection limit | It cannot administer anything, and cannot exhaust the server's connections |
| The database | PUBLIC holds nothing; the role holds CONNECT | No other role connects by default |
| Schema `public` | PUBLIC holds nothing | Nothing uses it |
| The schema | Owned by the administrator; the role holds USAGE and CREATE | The role cannot drop it or grant on it |

## Known limits

- An existing role keeps the password and the connection limit it was created with, so the caller
  must supply the same `role.password` on every converge; END's login as the role fails if it
  does not (INV-03).
- PUBLIC keeps PostgreSQL's default CONNECT and TEMP on the `postgres` and `template1` databases,
  so the role can open them and create temporary tables there (PostgreSQL's default database ACL,
  measured on PostgreSQL 17 on 2026-10-02; inferred for RDS). This role does not revoke them.

## State

| State | Does |
|---|---|
| `present` | Everything above |
| `absent` | Drops the schema with **every realm, user, client and session Keycloak stored in it**, withdraws the role's CONNECT, drops the role, and proves neither remains |

`absent` must run only once Keycloak is stopped everywhere; the playbook runs it after removing
Keycloak from every node. It leaves PUBLIC's privileges revoked, because they harden the database
as a whole, and leaves the driver installed: a shared system package this role cannot tell nothing
else uses. A second `absent` run changes nothing.

## Design invariants

1. [INV-01] Keycloak 26.7.5 runs entirely inside a schema it does not own. Started with
   `db-schema=keycloak` against a role holding only CONNECT on the database and USAGE and CREATE in
   that schema, two nodes created all 346 relations there, owned by the role, formed one cluster,
   and created, changed and deleted a realm. `kc.sh build --help` does not list `db-schema`, so it
   is a run-time option. Measured on 2026-10-02 against PostgreSQL 17 with a non-superuser
   administrator standing in for the RDS master, then on RDS PostgreSQL 17 in AWS Deploy run
   37061257295 the same day: the master provisioned this shape, END passed as the role, and two
   nodes formed one cluster, carried a realm change between them and survived losing one. END
   proves the role's privileges on every deploy. Consequence: the schema stays the
   administrator's, and no SET ROLE to the role is needed.
2. [INV-02] fapolicyd's rpm plugin notifies the daemon of a new package (documented: RHEL 8's
   fapolicyd guide, "The plugin notifies the fapolicyd daemon"), and a notified daemon reloads
   its trust behind the notification: the keycloak role measured a deny 84 ms after
   `fapolicyd-cli --update` (Rocky 8, fapolicyd 1.3.2, 2026-10-01). That the plugin's
   notification reloads the same way is inferred. On RDS PostgreSQL 17 from CIS RHEL 8 v10 (AWS
   Deploy run 37765837623, 2026-10-08), the first ping imported the driver on both converges.
   Consequence: after installing the driver, the role retries a `postgresql_ping`, which imports
   the driver as the modules' user, until the import succeeds, and fails naming the driver
   import if it never does.
3. [INV-03] PostgreSQL keeps the text of `CREATE USER ... PASSWORD '<value>'` verbatim in
   `pg_stat_statements` and, under `log_statement = ddl`, in the server log; given a
   SCRAM-SHA-256 verifier instead, it stores the verifier byte-for-byte and authenticates the
   password it was computed from. Measured on PostgreSQL 17.11 on 2026-10-03 with
   `pg_stat_statements` preloaded and `log_statement=ddl`. RDS preloads pg_stat_statements in its
   default parameter group (AWS documentation), and CIS PostgreSQL 17 3.1.25 sets
   `log_statement=ddl`. community.postgresql 5.0.0's `postgresql_user` passes a verifier through
   but computes none, no shipped filter does (ansible-core's `password_hash` covers crypt schemes
   only; Jinja has no HMAC; psql's `\password` reads from a terminal), and where `pg_authid` is
   hidden, as on RDS, the module cannot compare passwords (its documented notes). Consequence:
   the role sends only a verifier, from its own filter, salted afresh each run, so
   `postgresql_user` runs with `no_password_changes`: an existing role keeps its password and
   connection limit, and END logs in as the role to prove the caller's password still opens the
   database.

## Verification

END is ungated: every converge logs in as the role -- which proves the password Keycloak holds
opens the database -- and requires every row of the shape above, reading a never-set ACL as the
default it stands for. One step waits, bounded: until the modules can load a newly installed
driver.
