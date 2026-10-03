# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT
"""The scram_sha256_verifier filter: a password as the SCRAM-SHA-256 verifier PostgreSQL stores.

RFC 5802 with SHA-256 (RFC 7677), in PostgreSQL's storage form
SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>, base64 throughout, with PostgreSQL's
own 4096 iterations and 16-byte salt. A fresh salt every call means a fresh verifier every call.
SASLprep is not applied: tasks/validate.yml admits only printable ASCII, which it leaves
unchanged.
Why a verifier rather than the password, and why a filter: [INV-03] in this role's README.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from collections.abc import Callable

ITERATIONS = 4096
SALT_BYTES = 16


def scram_sha256_verifier(password: str) -> str:
    salt = os.urandom(SALT_BYTES)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    stored_key = hashlib.sha256(hmac.new(salted, b"Client Key", "sha256").digest()).digest()
    server_key = hmac.new(salted, b"Server Key", "sha256").digest()

    def b64(raw: bytes) -> str:
        return base64.b64encode(raw).decode("ascii")

    return f"SCRAM-SHA-256${ITERATIONS}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


class FilterModule:

    def filters(self) -> dict[str, Callable[[str], str]]:
        return {"scram_sha256_verifier": scram_sha256_verifier}
