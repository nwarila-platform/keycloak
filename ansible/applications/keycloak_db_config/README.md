# `keycloak_db_config` role

Provisions the PostgreSQL role Keycloak runs as, and the schema it runs in, logged in as the
database's administrator. Keycloak then holds a credential with no administrative attribute and,
in Keycloak's database, nothing beyond its own schema; the administrator's credential never leaves
this role. In one converge it:

1. installs the Python 3.12 PostgreSQL driver the modules need, and waits until fapolicyd has
   loaded it;
2. creates the login role with no administrative attribute, a bounded connection count, and a
   password sent as a SCRAM-SHA-256 verifier, so the password itself never reaches the server;
3. revokes PUBLIC's default privileges on the database and on schema `public`;
4. grants the role CONNECT on the database;
5. creates the schema, owned by the administrator, and grants the role USAGE and CREATE in it;
6. logs in as the role and reads its attributes and privileges back.

Keycloak creates and migrates its own tables at startup, so it owns everything it creates in the
schema -- including the jdbc-ping table the nodes find each other by -- and nothing else.

## Composition and prerequisites

The playbook runs this role on exactly one node, so the administrator's credential reaches one
host, and before any node starts Keycloak, because that first start creates Keycloak's tables as
this role. The controller reads the credential from the secret RDS manages; the node receives it
only as parameters of the community.postgresql modules, whose argument specs mask it in every log
and result. It never reaches the node's disk because the inventory pipelines every module, so
parameters reach the interpreter on stdin rather than as a staged file.

The modules run as the SSH user, not root: they only open a TLS connection to the database. RHEL's
default fapolicyd rules deny such a process an untrusted shared library, so after installing the
driver the role waits until fapolicyd has loaded its trust [INV-02].

Requires `community.postgresql` >= 5.0.0, the first release tested on ansible-core 2.21.

## Inputs

See [`meta/main.yml`](meta/main.yml) for the required inputs and
[`defaults/main.yml`](defaults/main.yml) for everything with a safe default. Every name reaches SQL
as an identifier, so [`tasks/validate.yml`](tasks/validate.yml) holds each to
`^[A-Za-z_][A-Za-z0-9_]*$` once, and the tasks pass them to the modules as trusted input. The role
must not be the administrator.

## The role's shape

| Object | Shape | Why |
|---|---|---|
| The role | `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`, a connection limit | It cannot administer anything, and cannot exhaust the server's connections |
| The database | PUBLIC holds nothing; the role holds CONNECT | No other role connects by default |
| Schema `public` | PUBLIC holds nothing | Nothing uses it |
| The schema | Owned by the administrator; the role holds USAGE and CREATE | The role cannot drop it or grant on it |

## Known limits

- `postgresql_user` runs with `no_password_changes`. The verifier is salted afresh each run and RDS
  hides `pg_authid`, so without it every run would rewrite the password and report a change. A role
  that already exists therefore keeps its password and its connection limit; in the ephemeral
  pipeline the database is new every run, and END reads both back.
- PUBLIC keeps PostgreSQL's default CONNECT and TEMP on the `postgres` and `template1` databases,
  so the role can open them and create temporary tables there (PostgreSQL's default database ACL,
  measured on PostgreSQL 17; inferred for RDS). Revoking them is later work.
- The role's password exists only in the controller file
  `~/.ansible/keycloak/<sha256 of the master secret's ARN>.password`, which the first converge
  writes. A converge from any other controller -- an operator's, during the workflow's hold --
  generates a different one: END's login as the role then fails before Keycloak is touched, but a
  run whose `--limit` leaves out the node this role runs on skips END and writes the new password
  to the nodes it does reach. To converge a living stack from another controller, first write that
  file with `KCRAW_DB_PASSWORD` from a node's root-only `/opt/keycloak/keycloak.env`; the value is
  letters and digits, so it needs no unescaping.

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
   administrator standing in for the RDS master; on RDS, END proves the role's privileges on every
   deploy. Consequence: the schema stays the administrator's, and no SET ROLE to the role is
   needed.
2. [INV-02] fapolicyd's rpm plugin notifies the daemon of a new package (documented: RHEL 8's
   fapolicyd guide, "The plugin notifies the fapolicyd daemon"), and a notified daemon reloads its
   trust behind the notification: the keycloak role measured a deny 84 ms after
   `fapolicyd-cli --update` (Rocky 8, fapolicyd 1.3.2, 2026-10-01). That the plugin's notification
   reloads the same way is inferred. Consequence: after installing the driver, the role reads the
   loaded database until it lists the driver's directory, and fails naming fapolicyd if it never
   does.

## Verification

END is ungated: every converge logs in as the role -- which proves the password Keycloak holds
opens the database -- and requires every row of the shape above, reading a never-set ACL as the
default it stands for. One step waits, bounded: until fapolicyd has loaded a newly installed
driver.
