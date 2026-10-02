# `keycloak_db_config` role

Provisions the PostgreSQL role Keycloak runs as, and the schema it runs in, logged in as the
database's administrator. Keycloak then holds a credential that can do nothing but run Keycloak:
the administrator's never leaves this role. In one converge it:

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

The playbook runs this role on exactly one node, before any node starts Keycloak, because that
first start creates Keycloak's tables as this role. The controller reads the administrator's
credential from the secret RDS manages; the node receives it only as parameters of the
community.postgresql modules, whose argument specs mask it in every log and result, and never on
disk. The modules run as the SSH user, not root: they only open a TLS connection to the database.

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
| The role | `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`, a connection limit | It cannot administer anything, and cannot exhaust the server |
| The database | PUBLIC holds nothing; the role holds CONNECT | No other role connects by default |
| Schema `public` | PUBLIC holds nothing | Nothing uses it |
| The schema | Owned by the administrator; the role holds USAGE and CREATE | The role cannot drop it or grant on it |

## State

| State | Does |
|---|---|
| `present` | Everything above |
| `absent` | Drops the schema with **every realm, user, client and session Keycloak stored in it**, withdraws the role's CONNECT, drops the role, and proves neither remains |

`absent` must run only once Keycloak is stopped everywhere; the playbook runs it after removing
Keycloak from every node. It leaves PUBLIC's privileges revoked, because they harden the database
as a whole, and leaves the driver installed: a shared system package this role cannot tell nothing
else uses. A second `absent` run changes nothing.

## Known limit

`postgresql_user` runs with `no_password_changes`: on RDS the administrator cannot read
`pg_authid`, so without it the module would send the password on every run and report a change it
did not make. A role that already exists therefore keeps its password and its connection limit. In
the ephemeral pipeline the database is new every run, so the two cannot diverge; a standing
database would need its own rotation.

## Design invariants

1. [INV-01] Keycloak 26.7.5 runs entirely inside a schema it does not own. Started with
   `db-schema=keycloak` against a role holding only CONNECT on the database and USAGE and CREATE in
   that schema, two nodes created all 346 relations there, owned by the role, formed one cluster,
   and created, changed and deleted a realm. `kc.sh build --help` does not list `db-schema`, so it
   is a run-time option. Measured on 2026-10-02 against PostgreSQL 17 with a non-superuser
   administrator standing in for the RDS master; on RDS, END proves the resulting shape on every
   deploy. Consequence: the schema stays the administrator's, and no SET ROLE to the role is
   needed.

## Verification

END is ungated: every converge logs in as the role -- which proves the password Keycloak holds
opens the database -- and requires every row of the shape above, reading a never-set ACL as the
default it stands for. One step waits, bounded: until fapolicyd has loaded a newly installed
driver.
