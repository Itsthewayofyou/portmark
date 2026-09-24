"""OAuth for HTTP MCP servers, phase 1: the configuration block and the token store.

Nothing here touches the network. What is being pinned down is the two things that decide whether the rest
can be safe at all: that an `oauth` block is names and paths rather than secrets, and that a refresh token --
a credential that outlives the process -- is stored in a way that refuses to be shared, and is refused when
the authorization server that issued it is no longer the one being talked to.
"""

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from portmark.security import canonical_json
from portmark.mcp_config import McpConfigError, McpOAuthConfig, McpServerConfig, config_from_bytes, server_digest
from portmark.mcp_token_store import (
    SCHEMA,
    STORE_VERSION,
    StoredTokens,
    TokenStoreError,
    binding_error,
    clear_tokens,
    read_tokens,
    write_tokens,
)

HTTP_SERVER = {
    "url": "https://mcp.example.com/mcp",
    "tools": {"read_file": {"pin": "sha256:" + "a" * 64, "read_only": True}},
}
OAUTH = {"client_id_env": "EXAMPLE_CLIENT_ID", "token_store": "/var/lib/portmark/example.json"}  # nosec B105 - a file PATH, not a token


class OauthConfigTests(unittest.TestCase):
    def load(self, oauth=None, **server_changes):
        server = dict(HTTP_SERVER, **server_changes)
        if oauth is not None:
            server["oauth"] = oauth
        document = {"schema": "portmark.mcp.config.v1", "servers": {"example": server}}
        return config_from_bytes(json.dumps(document).encode())

    def refusal(self, oauth=None, **server_changes):
        with self.assertRaises(McpConfigError) as caught:
            self.load(oauth, **server_changes)
        return str(caught.exception)

    def test_an_oauth_block_carries_names_and_a_path_and_never_a_secret(self):
        config = self.load(dict(OAUTH, client_secret_env="EXAMPLE_SECRET", scopes=["files:read"]))  # nosec B106 - an environment variable NAME, which is the whole point of the test
        oauth = config.servers["example"].oauth
        self.assertEqual(
            (oauth.client_id_env, oauth.client_secret_env, oauth.token_store, oauth.scopes),
            ("EXAMPLE_CLIENT_ID", "EXAMPLE_SECRET", "/var/lib/portmark/example.json", ("files:read",)),
        )

    def test_a_credential_shaped_like_a_credential_is_refused(self):
        # The whole point of naming a variable is that the config file never holds the credential. Real
        # client ids look like `Iv1.a1b2c3d4` or `1234.apps.googleusercontent.com`, and the dots cannot
        # appear in an environment variable name, so pasting one in is caught.
        #
        # Be clear about the limit: this is a SHAPE check, not a secret detector. A credential made only of
        # letters, digits and underscores is indistinguishable from a variable name and passes here. What
        # actually protects the operator is that nothing in Portmark ever reads a credential VALUE from the
        # config -- the value is looked up in the environment, so a pasted secret simply names a variable
        # that does not exist and the server fails to authorize.
        for pasted in ("Iv1.a1b2c3d4", "1234.apps.googleusercontent.com", "client-id-with-dashes", "a" * 65):
            with self.subTest(pasted=pasted):
                self.assertIn("client_id_env", self.refusal(dict(OAUTH, client_id_env=pasted)))
                self.assertIn("client_secret_env", self.refusal(dict(OAUTH, client_secret_env=pasted)))

    def test_oauth_and_bearer_env_together_are_refused(self):
        # Two answers to one question: which credential travelled would be decided by reading the code.
        self.assertIn("one way, not two", self.refusal(OAUTH, bearer_env="EXAMPLE_TOKEN"))

    def test_oauth_over_plain_http_is_refused_even_when_private_is_allowed(self):
        # Unlike the MCP endpoint, the specification DOES mandate https for the OAuth endpoints, and an
        # authorization code or refresh token on a plaintext hop is a durable credential in clear.
        message = self.refusal(OAUTH, url="http://127.0.0.1:8931/mcp", allow_private=True)
        self.assertIn("must be https", message)

    def test_oauth_on_a_stdio_server_is_refused(self):
        # The specification says stdio clients SHOULD NOT use this; credentials come from the environment.
        document = {
            "schema": "portmark.mcp.config.v1",
            "servers": {"example": {"command": sys.executable, "oauth": OAUTH, "tools": HTTP_SERVER["tools"]}},
        }
        with self.assertRaises(McpConfigError) as caught:
            config_from_bytes(json.dumps(document).encode())
        self.assertIn("cannot set `oauth`", str(caught.exception))

    def test_a_relative_token_store_is_refused(self):
        # The host, the CLI and the worker each resolve a relative path from a different directory, so it
        # would name a different file in each and the one that mattered would be whoever wrote last.
        self.assertIn("absolute path", self.refusal(dict(OAUTH, token_store="tokens/example.json")))  # nosec B106 - a file PATH, not a token

    def test_a_scope_that_would_split_into_two_is_refused(self):
        # Scopes travel space-separated. A scope containing a space silently becomes two different scopes.
        self.assertIn("usable OAuth scope", self.refusal(dict(OAUTH, scopes=["files:read files:write"])))
        self.assertIn("usable OAuth scope", self.refusal(dict(OAUTH, scopes=['files:"read"'])))

    def test_an_unknown_key_in_the_oauth_block_is_refused(self):
        # A misspelled key that is ignored reads as a setting that is in force.
        self.assertIn("unknown keys", self.refusal(dict(OAUTH, client_secret="literal")))  # nosec B106 - a misspelled KEY name being refused, not a credential


class OauthDigestTests(unittest.TestCase):
    """`server_digest` decides whether an approved pin still describes this server."""

    def server(self, oauth=None):
        return McpServerConfig("example", url="https://mcp.example.com/mcp", tools={}, oauth=oauth)

    def test_a_server_without_oauth_digests_exactly_as_it_did_before_oauth_existed(self):
        """The hard constraint: adding the feature must not re-digest servers that do not use it, or every
        pin approved before today reads as drift on the next start-up.

        The expected value is DERIVED here from the documented body -- the five keys an HTTP server digested
        before `oauth` existed -- rather than copied from what the code now prints. A constant captured from
        the implementation would agree with the implementation whatever it did, including growing a sixth
        key; rebuilding the body is what forces the code to match the contract instead of the reverse."""
        import hashlib

        server = self.server()
        body = {
            "transport": "http",
            "url": server.url,
            "bearer_env": server.bearer_env,
            "allow_private": server.allow_private,
            "timeout_seconds": server.timeout_seconds,
        }
        self.assertEqual(server_digest(server), "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest())

    def test_every_change_to_how_the_server_is_authorized_changes_the_digest(self):
        # One test, not two, because "turning oauth on" and "repointing oauth somewhere else" are the same
        # question -- does the pin still describe this server -- and a mutation that breaks the first always
        # breaks the second. Splitting them would give two tests that no single mutant can tell apart.
        base = McpOAuthConfig("CID", "/t.json")
        for label, changed in (
            ("turned on", base),
            ("a different client id variable", McpOAuthConfig("OTHER_CID", "/t.json")),
            ("a different token store", McpOAuthConfig("CID", "/elsewhere.json")),
            ("a client secret added", McpOAuthConfig("CID", "/t.json", client_secret_env="SECRET")),  # nosec B106 - an environment variable NAME
            ("different scopes", McpOAuthConfig("CID", "/t.json", scopes=("files:read",))),
        ):
            with self.subTest(label):
                self.assertNotEqual(server_digest(self.server()), server_digest(self.server(changed)))
                if changed is not base:
                    self.assertNotEqual(server_digest(self.server(base)), server_digest(self.server(changed)))


class TokenStoreTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = str(Path(self._dir.name) / "tokens.json")
        self.tokens = StoredTokens("https://as.example", "cid", "ACCESS-SECRET", 4_000_000_000, "REFRESH-SECRET", ("files:read",))

    def tearDown(self):
        self._dir.cleanup()

    def test_nothing_stored_reads_as_nothing_not_as_an_error(self):
        self.assertIsNone(read_tokens(self.path))

    def test_the_round_trip_is_exact(self):
        write_tokens(self.path, self.tokens)
        self.assertEqual(read_tokens(self.path), self.tokens)

    def test_the_repr_never_prints_a_token(self):
        # This object travels through exceptions and log records, where the repr is what gets written.
        text = repr(self.tokens)
        self.assertNotIn("ACCESS-SECRET", text)
        self.assertNotIn("REFRESH-SECRET", text)
        self.assertIn("https://as.example", text)

    @unittest.skipUnless(os.name == "posix", "file modes are not permissions on Windows")
    def test_the_store_is_written_owner_only_even_over_a_world_readable_file(self):
        Path(self.path).write_text("{}", encoding="utf-8")
        os.chmod(self.path, 0o644)
        write_tokens(self.path, self.tokens)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "file modes are not permissions on Windows")
    def test_a_store_other_users_can_read_is_refused_rather_than_used(self):
        # A refresh token readable by group or other is already shared; using it would be pretending it is not.
        write_tokens(self.path, self.tokens)
        os.chmod(self.path, 0o640)
        with self.assertRaises(TokenStoreError) as caught:
            read_tokens(self.path)
        self.assertIn("accessible to other users", str(caught.exception))

    def test_tokens_from_a_different_authorization_server_or_client_are_refused(self):
        # The specification's MUST: credentials are keyed by issuer, and a server that starts naming a
        # different authorization server is either being reconfigured or attacked. Both look the same here.
        self.assertIsNone(binding_error(self.tokens, "https://as.example", "cid"))
        self.assertIn("different authorization server", binding_error(self.tokens, "https://evil.example", "cid") or "")
        self.assertIn("log in again", binding_error(self.tokens, "https://as.example", "other") or "")

    def test_a_token_that_expires_during_the_call_it_authorizes_is_not_fresh(self):
        self.assertTrue(self.tokens.fresh(now=3_999_999_000))
        self.assertFalse(self.tokens.fresh(now=3_999_999_990))  # inside the refresh margin
        self.assertFalse(self.tokens.fresh(now=4_000_000_001))

    def test_a_store_written_by_another_version_is_refused_not_guessed_at(self):
        # A credential read under the wrong rules is a credential used under the wrong rules.
        for document in ({"schema": SCHEMA, "version": STORE_VERSION + 1}, {"schema": "something.else", "version": STORE_VERSION}):
            with self.subTest(document=document):
                Path(self.path).write_text(json.dumps(document), encoding="utf-8")
                os.chmod(self.path, 0o600)
                with self.assertRaises(TokenStoreError) as caught:
                    read_tokens(self.path)
                self.assertIn("different version", str(caught.exception))

    def test_clearing_removes_the_file_rather_than_emptying_it(self):
        # A file of empty strings still says a login happened here.
        write_tokens(self.path, self.tokens)
        self.assertTrue(clear_tokens(self.path))
        self.assertFalse(os.path.exists(self.path))
        self.assertFalse(clear_tokens(self.path))

    def test_a_renewal_keeps_the_binding_and_keeps_a_refresh_token_the_server_did_not_reissue(self):
        renewed = self.tokens.renewed("NEW-ACCESS", 4_000_009_999)
        self.assertEqual((renewed.issuer, renewed.client_id), (self.tokens.issuer, self.tokens.client_id))
        self.assertEqual(renewed.refresh_token, "REFRESH-SECRET")
        self.assertEqual(renewed.renewed("N", 1, "ROTATED").refresh_token, "ROTATED")


if __name__ == "__main__":
    unittest.main()
