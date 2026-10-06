# SPDX-FileCopyrightText: 2026 Nicholas Warila
# SPDX-License-Identifier: MIT
"""Known-answer tests for the scram_sha256_verifier filter.

The verifier is checked the way a server uses it, against the exchange RFC 7677 section 3
publishes for user "user" and password "pencil": the client's proof must verify against StoredKey,
and ServerKey must sign the exchange exactly as the RFC's server did.
"""

import base64
import hashlib
import hmac
import importlib.util
import unittest
from pathlib import Path
from unittest import mock

PLUGIN_PATH = Path(__file__).resolve().parents[1] / "filter_plugins" / "scram.py"
PLUGIN_SPEC = importlib.util.spec_from_file_location("scram", PLUGIN_PATH)
scram = importlib.util.module_from_spec(PLUGIN_SPEC)
PLUGIN_SPEC.loader.exec_module(scram)

# RFC 7677, section 3.
SALT = base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ==")
CLIENT_FIRST_BARE = "n=user,r=rOprNGfwEbeRWgbNEkqO"
SERVER_FIRST = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
CLIENT_FINAL_WITHOUT_PROOF = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
CLIENT_PROOF = base64.b64decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
SERVER_SIGNATURE = base64.b64decode("6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
AUTH_MESSAGE = f"{CLIENT_FIRST_BARE},{SERVER_FIRST},{CLIENT_FINAL_WITHOUT_PROOF}".encode("ascii")


def parse(verifier):
    mechanism, rest = verifier.split("$", 1)
    iterations_and_salt, keys = rest.split("$")
    iterations, salt = iterations_and_salt.split(":")
    stored_key, server_key = keys.split(":")
    return (mechanism, int(iterations), base64.b64decode(salt),
            base64.b64decode(stored_key), base64.b64decode(server_key))


class ScramVerifierTest(unittest.TestCase):

    def setUp(self):
        with mock.patch.object(scram.os, "urandom", return_value=SALT):
            self.verifier = scram.scram_sha256_verifier("pencil")

    def test_storage_form(self):
        mechanism, iterations, salt, _, _ = parse(self.verifier)
        self.assertEqual(mechanism, "SCRAM-SHA-256")
        self.assertEqual(iterations, 4096)
        self.assertEqual(salt, SALT)

    def test_the_rfc_client_proof_verifies_against_stored_key(self):
        _, _, _, stored_key, _ = parse(self.verifier)
        client_signature = hmac.new(stored_key, AUTH_MESSAGE, "sha256").digest()
        client_key = bytes(p ^ s for p, s in zip(CLIENT_PROOF, client_signature))
        self.assertEqual(hashlib.sha256(client_key).digest(), stored_key)

    def test_server_key_signs_the_exchange_as_the_rfc_server_did(self):
        _, _, _, _, server_key = parse(self.verifier)
        self.assertEqual(hmac.new(server_key, AUTH_MESSAGE, "sha256").digest(), SERVER_SIGNATURE)

    def test_every_call_draws_a_fresh_salt(self):
        first, second = (parse(scram.scram_sha256_verifier("pencil"))[2] for _ in range(2))
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
