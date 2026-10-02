# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT
"""Turn a password into the SCRAM-SHA-256 verifier PostgreSQL stores for it.

WHY THIS EXISTS
    PostgreSQL stores a password it is given as a verifier, so the server can authenticate a login
    without ever holding the password. Sent as plaintext, `CREATE ROLE ... PASSWORD '...'` reaches
    the server as text: RDS preloads pg_stat_statements, which keeps that statement verbatim, and
    `log_statement = ddl` (CIS PostgreSQL 17, 3.1.25) writes it to the log. Given a verifier,
    PostgreSQL stores it as-is, and the plaintext never leaves the controller.

WHY HERE
    Nothing shipped computes one: community.postgresql has no such filter, Jinja has no HMAC, and
    psql's \\password reads from a terminal.

HOW
    RFC 5802 with SHA-256 (RFC 7677), in PostgreSQL's storage form:
    SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>, base64 throughout. 4096 iterations
    and a 16-byte salt are what PostgreSQL itself uses. A fresh salt every call means a fresh
    verifier every call; the role passes it only where a role is being created.

WHAT IT DELIBERATELY DOES NOT DO
    It does not apply SASLprep. libpq normalises a password with SASLprep before hashing it, which
    leaves printable ASCII unchanged and may change anything else, so a verifier built here from
    other characters would never match a login. Such a password is refused rather than hashed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

ITERATIONS = 4096
SALT_BYTES = 16


def scram_sha256_verifier(password):
    if not (isinstance(password, str) and password and all(' ' < c <= '~' for c in password)):
        raise ValueError('scram_sha256_verifier: the password must be non-empty printable ASCII '
                         'without spaces, which SASLprep leaves unchanged')

    salt = os.urandom(SALT_BYTES)
    salted = hashlib.pbkdf2_hmac('sha256', password.encode('ascii'), salt, ITERATIONS)
    stored_key = hashlib.sha256(hmac.new(salted, b'Client Key', 'sha256').digest()).digest()
    server_key = hmac.new(salted, b'Server Key', 'sha256').digest()

    def b64(raw):
        return base64.b64encode(raw).decode('ascii')

    return f'SCRAM-SHA-256${ITERATIONS}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}'


class FilterModule:

    def filters(self):
        return {'scram_sha256_verifier': scram_sha256_verifier}
