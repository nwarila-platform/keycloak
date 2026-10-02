# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT
"""Turn a password into the SCRAM-SHA-256 verifier PostgreSQL stores for it.

WHY THIS EXISTS
    PostgreSQL stores a password it is given as a verifier, so the server can authenticate a login
    without ever holding the password. Sent as plaintext, `CREATE ROLE ... PASSWORD '...'` reaches
    the server as text: RDS preloads pg_stat_statements, which keeps that statement verbatim, and
    `log_statement = ddl` (CIS PostgreSQL 17, 3.1.25) writes it to the log. Given a verifier,
    PostgreSQL stores it as-is, and the plaintext never reaches the server.

WHY HERE
    Nothing shipped computes one: community.postgresql has no such filter, Jinja has no HMAC, and
    psql's \\password reads from a terminal.

HOW
    RFC 5802 with SHA-256 (RFC 7677), in PostgreSQL's storage form:
    SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>, base64 throughout. 4096 iterations
    and a 16-byte salt are what PostgreSQL itself uses. A fresh salt every call means a fresh
    verifier every call; the module applies it only when it creates the role. SASLprep is not
    applied: it leaves printable ASCII unchanged, which is all the playbook generates.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

ITERATIONS = 4096
SALT_BYTES = 16


def scram_sha256_verifier(password):
    salt = os.urandom(SALT_BYTES)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    stored_key = hashlib.sha256(hmac.new(salted, b"Client Key", "sha256").digest()).digest()
    server_key = hmac.new(salted, b"Server Key", "sha256").digest()

    def b64(raw):
        return base64.b64encode(raw).decode("ascii")

    return f"SCRAM-SHA-256${ITERATIONS}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


class FilterModule:

    def filters(self):
        return {"scram_sha256_verifier": scram_sha256_verifier}
