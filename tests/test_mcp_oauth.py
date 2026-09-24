"""OAuth for HTTP MCP servers, phase 1: the configuration block and the token store.

Nothing here touches the network. What is being pinned down is the two things that decide whether the rest
can be safe at all: that an `oauth` block is names and paths rather than secrets, and that a refresh token --
a credential that outlives the process -- is stored in a way that refuses to be shared, and is refused when
the authorization server that issued it is no longer the one being talked to.
"""

import argparse
import contextlib
import io
import json
import logging
import os
import re
import socket as socket_module
import stat
import subprocess  # nosec B404 - runs THIS interpreter to prove what the worker imports
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, quote, urlsplit

import mcp_http_server
from oauth_server import ACCESS_TOKEN, AUTHORIZATION_CODE, REFRESH_TOKEN, FakeAuthorizationServer, _trust_anchor

from portmark.mcp_oauth import (
    McpOAuthError,
    McpOAuthRefused,
    authorize,
    current_access_token,
    refresh,
    refuse_sync_use,
    sdk_available,
)
from portmark.security import canonical_json
from portmark import mcp_worker
from portmark.cli import _finite_seconds, _install_mcp_tools, _run_mcp
from portmark.mcp import (
    MIN_REFRESH_SLEEP_SECONDS,
    REFRESH_AHEAD_SECONDS,
    REFRESH_RETRY_SECONDS,
    McpStartupError,
    TokenRefresher,
    probe_server,
    refresh_oauth_tokens,
)
from portmark.mcp_http import HttpTransport, resolve_endpoint_address
from portmark.mcp_login import DEFAULT_REDIRECT, _Loopback, login, logout, result_from_redirect
from portmark.mcp_client import McpError
from portmark.mcp_config import (
    McpConfigError,
    McpOAuthConfig,
    McpServerConfig,
    config_from_bytes,
    definition_digest,
    load_config,
    server_digest,
)
from portmark.mcp_http import checked_fetch
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
# `token_store` must be absolute, and what "absolute" MEANS is platform-native. Python 3.13 changed
# `ntpath.isabs` so a single leading slash is no longer absolute on Windows, which is why a POSIX path here
# passed the Windows 3.11 and 3.12 lanes and failed 3.13 and 3.14. The fixture follows the platform rather
# than the config rule following the fixture.
ABSOLUTE_STORE = "C:\\portmark\\example.json" if os.name == "nt" else "/var/lib/portmark/example.json"
OAUTH = {"client_id_env": "EXAMPLE_CLIENT_ID", "token_store": ABSOLUTE_STORE}  # nosec B105 - a file PATH, not a token


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
            ("EXAMPLE_CLIENT_ID", "EXAMPLE_SECRET", ABSOLUTE_STORE, ("files:read",)),
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


class OauthBearerDeliveryTests(unittest.TestCase):
    """A token read from the STORE has no environment-variable name, and the transport is keyed on one."""

    def test_a_token_from_the_store_and_one_from_the_environment_together_are_refused(self):
        # The config refuses `oauth` beside `bearer_env`, but the transport is reachable on its own and
        # would otherwise pick one silently. Which one it picked would decide who the request authenticates
        # as, so there is no safe default.
        with self.assertRaises(McpError) as caught:
            HttpTransport("https://mcp.example.com/mcp", 5.0, 5.0, "MCP_TOKEN", "env-token",
                          bearer_token="store-token")  # nosec B106
        self.assertIn("not from both", str(caught.exception))

    def test_an_unusable_stored_token_is_refused_without_printing_it(self):
        # `http.client` would reject it too, and its own message prints the offending value; the worker
        # forwards error text to the host, which writes it to the audit chain.
        with self.assertRaises(McpError) as caught:
            HttpTransport("https://mcp.example.com/mcp", 5.0, 5.0, bearer_token="tok with space")  # nosec B106
        self.assertIn("not usable", str(caught.exception))
        self.assertNotIn("tok with space", str(caught.exception))


class OauthWorkerTests(unittest.TestCase):
    """The isolated worker's half: read a string from the store, and never renew one.

    Renewal drives the SDK, whose 28 packages include a web-server framework. Keeping those out of the
    sandboxed worker is the entire reason the token logic lives in the host, so the test that the worker
    does not import the SDK is the test that this design is still the design.
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = str(self.root / "tokens.json")
        certificate, key = _trust_anchor(self.root)
        address = resolve_endpoint_address("localhost", 0, allow_private=True)
        self.server, port = mcp_http_server.start("modern", str(certificate), str(key), host=address)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.certificate = str(certificate)
        self.pin = definition_digest(mcp_http_server.TOOLS["read_file"])
        self.config_path = self.root / "mcp.json"
        self.config_path.write_text(json.dumps({
            "schema": "portmark.mcp.config.v1",
            "servers": {"files": {
                "url": f"https://localhost:{port}/mcp", "allow_private": True, "timeout_seconds": 20,
                "oauth": {"client_id_env": "EXAMPLE_CLIENT_ID", "token_store": self.store},
                "tools": {"read_file": {"pin": self.pin, "read_only": True}},
            }},
        }), encoding="utf-8")

    def stored(self, **changes):
        fields = {"issuer": "https://issuer.example", "client_id": "cid", "access_token": "store-tok",  # nosec B105 - a fixture, not a credential
                  "expires_at": int(time.time()) + 3600, "refresh_token": "r"}  # nosec B105 - as above
        fields.update(changes)
        write_tokens(self.store, StoredTokens(**fields))

    def environment(self):
        server = load_config(str(self.config_path)).servers["files"]
        return {
            "SSL_CERT_FILE": self.certificate,
            "EXAMPLE_CLIENT_ID": "cid",
            "PORTMARK_MCP_CONFIG": str(self.config_path), "PORTMARK_MCP_SERVER": "files",
            "PORTMARK_MCP_TOOL": "read_file", "PORTMARK_MCP_PIN": self.pin,
            "PORTMARK_MCP_LAUNCH": server_digest(server),
        }

    def test_the_worker_sends_the_access_token_it_read_from_the_store(self):
        """The whole path, and the proof of the fail-open the transport change exists to close.

        `checked_bearer` is reached only when `bearer_env` names a variable, so a token from the store
        handed in as the value alone would be DROPPED and this request sent with no `Authorization` header
        at all -- to a server the operator configured precisely because it needs one. A unit test of that
        could not be told apart from this one: any mutation that drops the token is visible to both. This
        test owns it, because it exercises the real path rather than a constructed transport.
        """
        self.stored()
        with patch.dict(os.environ, self.environment()):
            value = mcp_worker.call({"path": "a.txt"})
        self.assertEqual(value["content"][0]["text"], 'read_file:{"path": "a.txt"}')
        headers = {name.lower(): item for name, item in self.server.seen[-1][0].items()}
        self.assertEqual(headers["authorization"], "Bearer store-tok")

    def test_the_worker_does_not_import_the_sdk(self):
        """Run the real call in its own interpreter and ask it what it loaded.

        Checking `sys.modules` in THIS process would prove nothing: the test suite imports the SDK for the
        driver tests, so the name is already there. A separate interpreter is the only honest reading.
        """
        self.stored()
        driver = (
            "import json, os, sys;"
            "sys.path[:0] = ['src', 'tests'];"
            "from portmark import mcp_worker;"
            "mcp_worker.call({'path': 'a.txt'});"
            "print(json.dumps(sorted(n for n in sys.modules if n == 'mcp' or n.startswith('mcp.'))))"
        )
        answer = subprocess.run(  # nosec B603 - this interpreter, a literal program, no shell
            [sys.executable, "-c", driver],
            cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, text=True,
            env={**os.environ, **self.environment(), "PYTHONDONTWRITEBYTECODE": "1"}, timeout=120,
        )
        self.assertEqual(answer.returncode, 0, answer.stderr[-2000:])
        self.assertEqual(json.loads(answer.stdout.strip().splitlines()[-1]), [])

    def test_an_expired_stored_token_is_refused_rather_than_sent(self):
        """Both ways in, because the refusal is one function and `probe_server` is exported.

        The worker cannot renew, so the honest answer is to refuse. Sending it would authenticate as nobody
        and be logged by the resource server as a failed call the operator never made. `probe_server` is
        checked here rather than in a test of its own: it reaches the same `_stored_access_token`, so a
        separate test would rest on the same line and neither mutant would prove its own thing. What is
        asserted for both is that the server saw NOTHING.
        """
        self.stored(expires_at=int(time.time()) - 1)
        with patch.dict(os.environ, self.environment()):
            with self.assertRaises(McpError) as caught:
                mcp_worker.call({"path": "a.txt"})
            self.assertIn("expired", str(caught.exception))
            self.assertEqual(self.server.seen, [])
            with self.assertRaises(McpStartupError) as probed:
                probe_server(str(self.config_path), "files", timeout=60)
        self.assertIn("expired", str(probed.exception))
        self.assertEqual(self.server.seen, [])

    def test_no_stored_authorization_says_how_to_create_one(self):
        with patch.dict(os.environ, self.environment()):
            with self.assertRaises(McpError) as caught:
                mcp_worker.call({"path": "a.txt"})
        self.assertIn("portmark mcp login files", str(caught.exception))
        self.assertEqual(self.server.seen, [])

    def test_a_token_issued_to_a_different_client_is_refused(self):
        # Re-pointing `client_id_env` at another application leaves the old application's tokens in the
        # store. Sending them would act on the OLD client's granted authority under the new one's name.
        self.stored(client_id="a-different-application")
        with patch.dict(os.environ, self.environment()):
            with self.assertRaises(McpError) as caught:
                mcp_worker.call({"path": "a.txt"})
        self.assertIn("client", str(caught.exception))
        self.assertEqual(self.server.seen, [])


class OauthHostRefreshTests(unittest.TestCase):
    """The host's half: make the store current before anything reads it, and say plainly when it cannot."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.path = self.root / "mcp.json"
        self.path.write_text(json.dumps({
            "schema": "portmark.mcp.config.v1",
            "servers": {"example": dict(HTTP_SERVER, oauth=OAUTH)},
        }), encoding="utf-8")

    def test_a_server_with_no_oauth_block_is_left_alone(self):
        plain = self.root / "plain.json"
        plain.write_text(json.dumps({
            "schema": "portmark.mcp.config.v1", "servers": {"example": dict(HTTP_SERVER)},
        }), encoding="utf-8")
        self.assertEqual(refresh_oauth_tokens(load_config(str(plain))), ())

    def test_the_missing_optional_extra_is_named_rather_than_raised_as_an_import_error(self):
        with patch("portmark.mcp_oauth.sdk_available", return_value=False):
            with self.assertRaises(McpConfigError) as caught:
                refresh_oauth_tokens(load_config(str(self.path)))
        self.assertIn("portmark[mcp-oauth]", str(caught.exception))

    def test_an_unset_client_id_variable_is_named(self):
        with patch("portmark.mcp_oauth.sdk_available", return_value=True):
            with patch.dict(os.environ, {"EXAMPLE_CLIENT_ID": ""}):
                with self.assertRaises(McpConfigError) as caught:
                    refresh_oauth_tokens(load_config(str(self.path)))
        self.assertIn("EXAMPLE_CLIENT_ID", str(caught.exception))

    def test_start_up_refreshes_the_store_before_it_probes_anything(self):
        """A probe of an OAuth server carries the stored access token, so the order is load, renew, probe.

        Both steps are recorded rather than made to fail. An earlier version stopped the run by removing the
        SDK, which meant this test and the one about the missing extra both rested on the same check and
        neither mutant proved its own thing. What is asserted here is the ORDER and nothing else.
        """
        order = []

        def renew(config):
            order.append("renew")
            return ()

        def probe(*_, **__):
            order.append("probe")
            return MagicMock()

        with patch("portmark.mcp.refresh_oauth_tokens", side_effect=renew):
            with patch("portmark.mcp.probe_server", side_effect=probe):
                with contextlib.redirect_stderr(io.StringIO()):
                    with contextlib.suppress(SystemExit):
                        _install_mcp_tools(argparse.ArgumentParser(), str(self.path), None)
        self.assertEqual(order[:2], ["renew", "probe"])

    def test_the_worker_is_given_the_client_id_and_never_the_client_secret(self):
        """The worker compares the stored client against the configured one, so it needs the id.

        It never speaks to the authorization server, so a client SECRET there would be a credential with
        no use in that process and one more place for it to leak from.
        """
        from portmark.mcp import _worker_environment

        document = {
            "schema": "portmark.mcp.config.v1",
            "servers": {"example": dict(HTTP_SERVER, oauth=dict(
                OAUTH, client_secret_env="EXAMPLE_CLIENT_SECRET"))},  # nosec B106 - a variable NAME
        }
        path = self.root / "secret.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        config = config_from_bytes(path.read_bytes(), str(path))
        server = config.servers["example"]
        secrets = {"EXAMPLE_CLIENT_ID": "cid", "EXAMPLE_CLIENT_SECRET": "shh"}  # nosec B105 - a fixture
        with patch.dict(os.environ, secrets):
            environment = _worker_environment(str(path), server, server.tools["read_file"], "")
        self.assertEqual(environment.get("EXAMPLE_CLIENT_ID"), "cid")
        self.assertNotIn("EXAMPLE_CLIENT_SECRET", environment)


class OauthTransportTests(unittest.TestCase):
    """The rules `checked_fetch` holds an OAuth endpoint to. No SDK needed: this is Portmark's own transport."""

    def test_an_oauth_endpoint_over_plain_http_is_refused_even_when_private_is_allowed(self):
        """`allow_private` says which ADDRESSES may be reached. It is not permission to drop TLS.

        Conflating the two is how a discovered private token endpoint ends up receiving a client secret, an
        authorization code or a refresh token in clear. The specification mandates https for the OAuth
        endpoints, and there is deliberately no flag that opens it -- the tests reach a loopback
        authorization server over real TLS with a throwaway trust anchor instead."""
        for url in ("http://127.0.0.1:1/token", "http://10.0.0.1/.well-known/oauth-authorization-server"):
            with self.subTest(url=url):
                for allow_private in (True, False):
                    with self.assertRaises(McpError) as caught:
                        checked_fetch("GET", url, total_seconds=5, request_timeout=1,
                                      allow_private=allow_private)
                    self.assertIn("must be https", str(caught.exception))


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


class OauthDriverTests(unittest.TestCase):
    """Phase 2: Portmark drives the SDK's flow, and performs every request itself.

    Skipped without the optional extra. The CI lane that owns this file installs it and treats a SKIP as a
    failure, because a lane that can skip its way to green is not a gate.

    Three tests here are DEPENDENCY-CONTRACT tests, not tests of Portmark's own code: the PKCE and `resource`
    parameters, the refusal of metadata claiming an issuer it was not served from, and the handling of a
    refused token exchange are all performed by the SDK. No mutation of Portmark can make them fail, so they
    are calibrated by a different thing entirely -- raising the SDK pin. They are worth keeping precisely
    because of that: they are what notices if an SDK upgrade quietly stops meeting a specification MUST."""

    def setUp(self):
        if not sdk_available():
            self.skipTest("requires portmark[mcp-oauth]")
        self.opened = {}

    def open_authorization(self):
        async def handler(url: str) -> None:
            self.opened["url"] = url
        return handler

    def read_callback(self, server, code=AUTHORIZATION_CODE, issuer=None):
        async def handler():
            from mcp.shared.auth import AuthorizationCodeResult

            query = parse_qs(urlsplit(self.opened["url"]).query)
            return AuthorizationCodeResult(code=code, state=query.get("state", [""])[0],
                                           iss=server.origin if issuer is None else issuer)
        return handler

    def authorize(self, server, **changes):
        settings = dict(
            server_url=server.url,
            client_id="portmark-test-client",
            client_secret="portmark-test-secret",  # nosec B106 - a fixture for a loopback server
            scopes=("files:read",),
            redirect_uri="http://127.0.0.1:0/callback",
            open_authorization=self.open_authorization(),
            read_callback=self.read_callback(server),
            allow_private=True,
            total_seconds=30,
            context=server.context,
        )
        settings.update(changes)
        return authorize(**settings)

    def test_a_whole_flow_runs_over_portmarks_transport_and_never_sends_the_retry(self):
        # The flow ends by yielding the ORIGINAL request again, now carrying the token. Performing it would
        # invoke whatever that request was -- during `login`, a tool call nobody asked for.
        #
        # This invariant is one line in `_drive`, and THREE tests rest on it: this one and the two refresh
        # tests, which assert that renewing a token calls the MCP server not at all. A mutant that removes
        # it therefore fails all three. That overlap is deliberate and stated rather than engineered away:
        # it is the shape of a single guard protecting more than one path, not a sign the tests overlap.
        with FakeAuthorizationServer() as server:
            result = self.authorize(server)
            self.assertEqual(result.access_token, ACCESS_TOKEN)
            self.assertEqual(result.refresh_token, REFRESH_TOKEN)
            self.assertEqual(result.issuer, server.origin)
            self.assertEqual(result.scopes, ("files:read",))
            self.assertEqual(len(server.mcp_requests), 1)  # the unauthorized probe, and nothing after it

    def test_pkce_and_the_resource_parameter_are_on_both_requests(self):
        # Two specification MUSTs that are invisible when they work: `resource` (RFC 8707) must be on the
        # authorization AND the token request, and the code must be bound by PKCE.
        with FakeAuthorizationServer() as server:
            self.authorize(server)
            authorization = parse_qs(urlsplit(self.opened["url"]).query)
            self.assertEqual(authorization["code_challenge_method"], ["S256"])
            self.assertEqual(authorization["resource"], [server.url])
            token = server.token_requests[0]
            self.assertEqual(token["resource"], [server.url])
            self.assertIn("code_verifier", token)

    def test_the_access_token_never_appears_in_the_repr(self):
        with FakeAuthorizationServer() as server:
            text = repr(self.authorize(server))
        self.assertNotIn(ACCESS_TOKEN, text)
        self.assertNotIn(REFRESH_TOKEN, text)

    def test_a_redirecting_oauth_endpoint_is_refused_rather_than_followed(self):
        # The SDK's own flow WOULD follow this. The destination has been checked by nobody, and the next
        # request would carry the client's credentials to it.
        with FakeAuthorizationServer("redirecting_metadata") as server:
            with self.assertRaises(McpOAuthError) as caught:
                self.authorize(server)
        self.assertIn("redirect", str(caught.exception))
        self.assertNotIn("169.254.169.254", str(caught.exception).split("answered")[0])

    def test_metadata_claiming_an_issuer_it_was_not_served_from_is_refused(self):
        # The specification's own worked example: a document from one origin claiming to be another.
        # DEPENDENCY-CONTRACT: what is asserted is that the SDK still refuses, not how the refusal is
        # typed. Pinning the type here would make it rest on Portmark's translation as well, and then one
        # mutation would fail this and the refused-exchange test and prove neither.
        with FakeAuthorizationServer("wrong_issuer") as server:
            with self.assertRaises(Exception) as caught:
                self.authorize(server)
        self.assertNotIsInstance(caught.exception, AssertionError)

    def test_an_oauth_endpoint_on_a_private_address_is_refused_without_allow_private(self):
        # The address checks that protect the MCP endpoint protect these server-chosen urls too. Nothing in
        # the specification asks for this; it is Portmark's rule.
        with FakeAuthorizationServer() as server:
            with self.assertRaises(McpOAuthError) as caught:
                self.authorize(server, allow_private=False)
        self.assertIn("not usable", str(caught.exception))

    def test_a_refused_token_exchange_is_reported_as_this_module_s_own_error(self):
        """An authorization server that refuses is an ordinary outcome, not a Portmark fault.

        The SDK raises `OAuthTokenError` for it. Letting that out would put a traceback in front of an
        operator and would force every caller to import the SDK's exception types to catch a refusal --
        the coupling this module exists to prevent.
        """
        with FakeAuthorizationServer("token_refused") as server:
            with self.assertRaises(McpOAuthError) as caught:
                self.authorize(server)
        self.assertIn("did not complete the flow", str(caught.exception))

    def logged_at(self, level, mode="token_refused"):
        """What a terminal configured at `level` would actually show while a flow is refused."""
        captured = io.StringIO()
        handler = logging.StreamHandler(captured)
        handler.setLevel(level)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(level)
        try:
            with FakeAuthorizationServer(mode) as server:
                with self.assertRaises(McpOAuthError):
                    self.authorize(server)
        finally:
            root.removeHandler(handler)
            root.setLevel(previous)
        return captured.getvalue()

    def test_an_expected_refusal_does_not_put_a_traceback_in_front_of_the_operator(self):
        """The SDK calls `logger.exception(...)` BEFORE re-raising, from inside the flow.

        So the traceback -- and the failed token response body with it -- reach the terminal before Portmark
        holds the exception at all: neither the translation nor its truncation can reach them, and nor can a
        `try`. What an operator should read is the one sentence Portmark raises.
        """
        shown = self.logged_at(logging.WARNING)
        self.assertNotIn("Traceback", shown)
        self.assertNotIn("invalid_grant", shown)

    def test_the_sdk_s_own_report_is_filed_rather_than_hidden(self):
        """Lowered to DEBUG, not discarded. Anyone who turns DEBUG on gets all of it back.

        Keeping this honest is the point: an earlier version also cleared `exc_info`, which put the
        traceback beyond reach at ANY level while the docstring said it was still available.
        """
        shown = self.logged_at(logging.DEBUG)
        self.assertIn("Traceback", shown)
        self.assertIn("invalid_grant", shown)

    def test_the_quietening_lasts_only_as_long_as_the_flow(self):
        """A filter left attached would quieten the SDK's logger for the rest of the process.

        That is the difference between filing the report of ONE expected refusal and switching a
        dependency's error reporting off altogether -- including for the failures nobody expected. Found by
        mutating the `finally` away and seeing that nothing failed.
        """
        from mcp.client.auth import oauth2

        from portmark.mcp_oauth import _OwnReportIsEnough

        before = len(oauth2.logger.filters)
        with FakeAuthorizationServer("token_refused") as server:
            with self.assertRaises(McpOAuthError):
                self.authorize(server)
        self.assertEqual([f for f in oauth2.logger.filters if isinstance(f, _OwnReportIsEnough)], [])
        self.assertEqual(len(oauth2.logger.filters), before)

    def test_the_sdk_still_keeps_its_logger_where_portmark_quietens_it(self):
        """DEPENDENCY-CONTRACT, like the three above: no mutation of Portmark can fail it.

        A filter set on a parent logger is NOT applied to records made on a child, so Portmark attaches to
        the SDK's own logger object rather than to a name written here. If the SDK moved or renamed it, a
        name would attach to a logger nobody uses, the tracebacks would come back, and nothing would fail.
        """
        from mcp.client.auth import oauth2

        self.assertIsInstance(oauth2.logger, logging.Logger)

    def test_a_server_that_issues_no_refresh_token_still_authorizes(self):
        with FakeAuthorizationServer("no_refresh_token") as server:
            result = self.authorize(server)
        self.assertEqual(result.access_token, ACCESS_TOKEN)
        self.assertEqual(result.refresh_token, "")

    def test_the_sdk_still_has_no_synchronous_auth_path(self):
        """The single most dangerous property of this dependency, asserted rather than assumed.

        The SDK overrides only `async_auth_flow`. `httpx2`'s base `auth_flow` yields the request unchanged,
        so a SYNCHRONOUS client with this provider attached sends an UNAUTHENTICATED request and raises
        nothing -- authorization silently becomes a no-op. Portmark never builds an httpx2 client, but a
        future SDK that grows a `sync_auth_flow` changes what this module reasons about, and that has to be
        noticed on purpose instead of inherited."""
        import httpx2
        from mcp.client.auth.oauth2 import OAuthClientProvider

        self.assertIs(OAuthClientProvider.sync_auth_flow, httpx2.Auth.sync_auth_flow)
        refuse_sync_use(OAuthClientProvider)

        # A guard whose refusal path never runs is decoration. Feed it the shape it exists to catch -- a
        # future SDK that grows its own synchronous path -- and it must refuse.
        class WithASyncPath(OAuthClientProvider):
            def sync_auth_flow(self, request):  # pragma: no cover - never called, only inspected
                raise NotImplementedError

        with self.assertRaises(McpOAuthError) as caught:
            refuse_sync_use(WithASyncPath)
        self.assertIn("sync_auth_flow", str(caught.exception))

    def test_without_the_extra_the_error_says_how_to_install_it(self):
        with patch.dict(sys.modules, {"mcp.client.auth.oauth2": None}):
            with self.assertRaises(McpOAuthError) as caught:
                authorize(server_url="https://example.com/mcp", client_id="c")
        self.assertIn("portmark[mcp-oauth]", str(caught.exception))


class OauthRefreshTests(unittest.TestCase):
    """Phase 3: using a stored authorization, and renewing it without a browser."""

    def setUp(self):
        if not sdk_available():
            self.skipTest("requires portmark[mcp-oauth]")
        self._dir = tempfile.TemporaryDirectory()
        self.store = str(Path(self._dir.name) / "tokens.json")

    def tearDown(self):
        self._dir.cleanup()

    def settings(self, server, **changes):
        base = dict(
            server_url=server.url, token_store=self.store, client_id="portmark-test-client",
            client_secret="portmark-test-secret", allow_private=True,  # nosec B106 - a loopback fixture
            context=server.context,
        )
        base.update(changes)
        return base

    def stored(self, server, **changes):
        base = dict(issuer=server.origin, client_id="portmark-test-client", access_token="STORED-ACCESS",  # nosec B106 - a loopback fixture, not a credential
                    expires_at=4_000_000_000, token_endpoint=f"{server.origin}/token")
        base.update(changes)
        return StoredTokens(**base)

    def test_a_still_valid_token_is_used_without_touching_the_network(self):
        # A tool call must not pay for two discovery round trips to learn what the store already says.
        with FakeAuthorizationServer() as server:
            write_tokens(self.store, self.stored(server))
            self.assertEqual(current_access_token(**self.settings(server)), "STORED-ACCESS")
            self.assertEqual(server.token_requests, [])

    def test_an_expired_token_is_refreshed_and_the_store_is_updated(self):
        with FakeAuthorizationServer() as server:
            write_tokens(self.store, self.stored(server, expires_at=1, refresh_token="a-refresh-token"))  # nosec B106 - a loopback fixture, not a credential
            token = current_access_token(**self.settings(server))
            self.assertEqual(token, ACCESS_TOKEN)
            self.assertEqual(server.token_requests[-1]["grant_type"], ["refresh_token"])
            self.assertEqual(read_tokens(self.store).access_token, token)
            # Renewing a token must not call the MCP server at all. Asserted here as well as in the
            # authorize test because both rest on the same one line in `_drive`.
            self.assertEqual(server.mcp_requests, [])

    def test_the_refresh_goes_to_the_pinned_endpoint_not_one_derived_from_the_server_url(self):
        """The refresh token must reach the authorization server that issued it, and nothing else.

        With no discovered metadata the SDK builds the token url as `{MCP server origin}/token`. For any real
        service the resource server and the authorization server are different hosts, so that fallback posts
        a durable credential to the wrong party. The endpoints discovered and validated at login are pinned
        in the store for exactly this reason, and this test is what proves they are honoured."""
        with FakeAuthorizationServer() as server:
            write_tokens(self.store, self.stored(
                server, expires_at=1, refresh_token="a-refresh-token",  # nosec B106 - a loopback fixture, not a credential
                token_endpoint=f"{server.origin}/elsewhere/token",
            ))
            current_access_token(**self.settings(server))
            self.assertEqual(server.token_paths, ["/elsewhere/token"])
            self.assertEqual(server.mcp_requests, [])

    def test_a_refresh_is_refused_when_the_server_now_names_a_different_authorization_server(self):
        """The specification's binding MUST, checked against what the resource says NOW.

        This is the test that was missing. Comparing the stored issuer with itself -- which is what an
        unqualified binding check does on the cached path -- cannot fail, so it proved nothing. Here the
        resource is made to advertise a different authorization server, and the refresh must refuse rather
        than renew credentials at a server they do not belong to."""
        with FakeAuthorizationServer("moved_issuer") as server:
            write_tokens(self.store, self.stored(server, expires_at=1, refresh_token="a-refresh-token"))  # nosec B106 - a loopback fixture
            with self.assertRaises(McpOAuthError) as caught:
                current_access_token(**self.settings(server))
        self.assertIn("different authorization server", str(caught.exception))
        self.assertIn("somewhere-else.example", str(caught.exception))
        # Nothing was renewed: the refresh token never left.
        self.assertEqual(server.token_requests, [])
        # And the check was made by ASKING, not by comparing the store with itself. Asserted in this test
        # rather than a separate one because the two cannot be told apart by a mutant: skipping the fetch
        # and neutering the comparison both show up here and nowhere else.
        self.assertTrue(server.prm_requests, "the protected-resource metadata was never fetched")

    def test_a_refresh_without_a_pinned_endpoint_is_refused_rather_than_guessed_at(self):
        with FakeAuthorizationServer() as server:
            with self.assertRaises(McpOAuthError) as caught:
                refresh(server_url=server.url, stored=self.stored(server, token_endpoint="", refresh_token="r"),  # nosec B106 - a loopback fixture, not a credential
                        client_id="portmark-test-client", allow_private=True)
        self.assertIn("token endpoint", str(caught.exception))

    def test_an_expired_token_with_nothing_to_renew_it_says_what_to_do(self):
        with FakeAuthorizationServer() as server:
            write_tokens(self.store, self.stored(server, expires_at=1))
            with self.assertRaises(McpOAuthError) as caught:
                current_access_token(**self.settings(server))
        self.assertIn("no refresh token", str(caught.exception))
        self.assertIn("mcp login", str(caught.exception))

    def test_credentials_belonging_to_another_client_are_refused_before_they_are_used(self):
        with FakeAuthorizationServer() as server:
            write_tokens(self.store, self.stored(server, client_id="a-different-client"))
            with self.assertRaises(McpOAuthError) as caught:
                current_access_token(**self.settings(server))
        self.assertIn("log in again", str(caught.exception))

    def test_no_stored_authorization_says_to_log_in_rather_than_proceeding_unauthenticated(self):
        with FakeAuthorizationServer() as server:
            with self.assertRaises(McpOAuthError) as caught:
                current_access_token(**self.settings(server))
        self.assertIn("mcp login", str(caught.exception))

    def test_logging_in_records_the_endpoints_it_discovered(self):
        # Without this, the refresh above would have nothing to pin to.
        opened = {}

        async def open_authorization(url):
            opened["url"] = url

        async def read_callback():
            from mcp.shared.auth import AuthorizationCodeResult

            query = parse_qs(urlsplit(opened["url"]).query)
            return AuthorizationCodeResult(code=AUTHORIZATION_CODE, state=query.get("state", [""])[0],
                                           iss=self.origin)

        with FakeAuthorizationServer() as server:
            self.origin = server.origin
            result = authorize(
                server_url=server.url, client_id="portmark-test-client",
                client_secret="portmark-test-secret",  # nosec B106 - a loopback fixture
                redirect_uri="http://127.0.0.1:0/callback",
                open_authorization=open_authorization, read_callback=read_callback,
                allow_private=True, total_seconds=30, context=server.context,
            )
        self.assertEqual(result.token_endpoint, f"{server.origin}/token")
        self.assertEqual(result.authorization_endpoint, f"{server.origin}/authorize")
        self.assertEqual(result.stored().token_endpoint, result.token_endpoint)


class SdkContractTests(unittest.TestCase):
    """What the SDK must keep doing, asserted so that raising its pin cannot quietly drop a MUST.

    These are not tests of Portmark's code and no mutation of Portmark can fail them. They exist because the
    alternative -- reimplementing the checks Portmark deliberately delegated -- is how two implementations of
    one rule start to disagree."""

    def setUp(self):
        if not sdk_available():
            self.skipTest("requires portmark[mcp-oauth]")

    def metadata(self, issuer):
        from mcp.shared.auth import OAuthMetadata

        return OAuthMetadata(issuer=issuer, authorization_endpoint=f"{issuer}/authorize",
                             token_endpoint=f"{issuer}/token", response_types_supported=["code"],
                             authorization_response_iss_parameter_supported=True)

    def test_the_iss_comparison_does_not_normalise_the_url(self):
        # The specification is explicit: no case folding, no default-port elision, no trailing-slash and no
        # percent-encoding normalisation before comparing. A trailing slash is a MISMATCH, not a match.
        from mcp.client.auth.utils import validate_authorization_response_iss

        metadata = self.metadata("https://as.example")
        validate_authorization_response_iss("https://as.example", metadata)
        for nearly in ("https://as.example/", "https://AS.example", "https://as.example:443"):
            with self.subTest(nearly=nearly):
                with self.assertRaises(Exception):
                    validate_authorization_response_iss(nearly, metadata)

    def test_an_absent_iss_is_refused_only_when_the_server_advertised_it(self):
        from mcp.client.auth.utils import validate_authorization_response_iss

        with self.assertRaises(Exception):
            validate_authorization_response_iss(None, self.metadata("https://as.example"))
        quiet = self.metadata("https://as.example")
        quiet.authorization_response_iss_parameter_supported = False
        validate_authorization_response_iss(None, quiet)  # proceeds, per the specification's table

    def test_metadata_is_refused_when_its_issuer_is_not_the_one_it_was_fetched_for(self):
        from mcp.client.auth.utils import validate_metadata_issuer

        validate_metadata_issuer(self.metadata("https://as.example"), "https://as.example")
        with self.assertRaises(Exception):
            validate_metadata_issuer(self.metadata("https://honest.example"), "https://attacker.example")


if __name__ == "__main__":
    unittest.main()


def _free_loopback_port() -> int:
    """A port nothing is listening on right now. The listener under test binds it a moment later."""
    probe = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class RedirectParsingTests(unittest.TestCase):
    """What comes back from the authorization server is handed on as received, or refused."""

    def setUp(self):
        if not sdk_available():
            self.skipTest("requires portmark[mcp-oauth]")

    def test_the_issuer_is_carried_through(self):
        """RFC 9207. Portmark does not read `iss`; the SDK compares it with the discovered issuer.

        A parser that quietly dropped it would turn that comparison into a no-op -- and every test that
        only looked at the resulting token would still pass, which is exactly why this one looks at `iss`.
        """
        # SHARED INVARIANT, stated here and in `test_a_manual_login_...`: a login cannot complete without
        # this, because the authorization server advertises `authorization_response_iss_parameter_supported`
        # and the SDK then requires the parameter. One mutation therefore fails both, and rather than weaken
        # either test both say why.
        result = result_from_redirect(
            "http://127.0.0.1:3000/callback?code=abc&state=xyz&iss=https%3A%2F%2Fissuer.example"
        )
        self.assertEqual(result.code, "abc")
        self.assertEqual(result.state, "xyz")
        self.assertEqual(result.iss, "https://issuer.example")

    def test_a_refusal_from_the_authorization_server_is_reported_as_one(self):
        with self.assertRaises(McpOAuthError) as caught:
            result_from_redirect("http://127.0.0.1:3000/callback?error=access_denied&error_description=nope")
        self.assertIn("access_denied", str(caught.exception))
        self.assertIn("nope", str(caught.exception))

    def test_a_url_with_no_code_says_to_paste_the_whole_thing(self):
        # The commonest operator mistake is pasting the address bar before the redirect completes.
        with self.assertRaises(McpOAuthError) as caught:
            result_from_redirect("http://127.0.0.1:3000/callback")
        self.assertIn("whole url", str(caught.exception))


class LoopbackListenerTests(unittest.TestCase):
    """The convenience path: collect the redirect without the operator copying anything."""

    def setUp(self):
        if not sdk_available():
            self.skipTest("requires portmark[mcp-oauth]")

    def test_a_redirect_uri_that_is_not_loopback_is_refused(self):
        """An authorization CODE arrives in that url's query string.

        Binding a routable interface would publish it to anyone else who can reach the port, and the code
        is exchangeable for the operator's tokens until it is used.
        """
        with self.assertRaises(McpConfigError) as caught:
            _Loopback("http://10.0.0.5:3000/callback", io.StringIO(), 5.0)
        self.assertIn("loopback", str(caught.exception))

    def test_https_is_refused_because_the_listener_speaks_plain_http(self):
        with self.assertRaises(McpConfigError):
            _Loopback("https://127.0.0.1:3000/callback", io.StringIO(), 5.0)

    def test_the_listener_collects_a_real_redirect(self):
        import asyncio
        import threading
        import urllib.request

        redirect = f"http://127.0.0.1:{_free_loopback_port()}/callback"
        collector = _Loopback(redirect, io.StringIO(), 10.0)
        with collector:
            def visit():
                for _ in range(50):
                    try:
                        urllib.request.urlopen(  # nosec B310 - a literal http loopback url built here
                            f"{redirect}?code=the-code&state=the-state&iss=https%3A%2F%2Fissuer.example"
                        ).read()
                        return
                    except OSError:
                        time.sleep(0.05)

            caller = threading.Thread(target=visit, daemon=True)
            caller.start()
            result = asyncio.run(collector.collect())
            caller.join(timeout=5)
        self.assertEqual(result.code, "the-code")
        self.assertEqual(result.state, "the-state")

    def test_a_login_nobody_completes_gives_the_terminal_back(self):
        """The flow's budget is spent by REQUESTS, and waiting for a human performs none of them.

        Without its own deadline the listener holds the terminal for ever. The test therefore bounds
        ITSELF rather than trusting the code under test to stop: a test that hangs when the deadline is
        missing cannot be used to prove the deadline is there -- it just stops the run.
        """
        import asyncio
        import threading

        collector = _Loopback(f"http://127.0.0.1:{_free_loopback_port()}/callback", io.StringIO(), 0.0)
        outcome = []

        def wait():
            try:
                asyncio.run(collector.collect())
            except BaseException as stopped:  # noqa: BLE001 - what it raised matters less than THAT it did
                outcome.append(stopped)

        with collector:
            waiter = threading.Thread(target=wait, daemon=True)
            waiter.start()
            waiter.join(timeout=15)
        self.assertFalse(waiter.is_alive(), "the listener never gave up, so it has no deadline of its own")
        self.assertIsInstance(outcome[0], McpOAuthError)
        self.assertIn("--manual", str(outcome[0]))


class LoginCommandTests(unittest.TestCase):
    """`portmark mcp login --manual` against a real authorization server over real TLS."""

    def setUp(self):
        if not sdk_available():
            self.skipTest("requires portmark[mcp-oauth]")
        self.root = Path(tempfile.mkdtemp())
        self.store = str(self.root / "tokens.json")

    def config(self, server, **oauth_changes):
        oauth = {"client_id_env": "EXAMPLE_CLIENT_ID", "client_secret_env": "EXAMPLE_CLIENT_SECRET",  # nosec B105 - a variable NAME
                 "token_store": self.store, "scopes": ["files:read"]}
        oauth.update(oauth_changes)
        path = self.root / "mcp.json"
        path.write_text(json.dumps({
            "schema": "portmark.mcp.config.v1",
            "servers": {"files": {
                "url": server.url, "allow_private": True, "oauth": oauth,
                "tools": {"read_file": {"pin": "sha256:" + "a" * 64, "read_only": True}},
            }},
        }), encoding="utf-8")
        return str(path)

    def paste_from(self, transcript, redirect, issuer):
        """Answer the way an operator does: read the url that was printed, and hand back where it sent you.

        The `state` cannot be invented -- the SDK generates it and compares it with `compare_digest` -- so
        the only way to answer is to read what was shown, which is what a person does."""

        class _Stdin:
            def readline(self, limit=-1):
                shown = re.search(r"(https://\S+/authorize\?\S+)", transcript.getvalue())
                assert shown is not None, transcript.getvalue()  # nosec B101 - a test helper
                query = parse_qs(urlsplit(shown.group(1)).query)
                return (f"{redirect}?code={AUTHORIZATION_CODE}&state={query['state'][0]}"
                        f"&iss={quote(issuer, safe='')}\n")

        return _Stdin()

    def test_a_manual_login_stores_what_was_granted_and_prints_no_token(self):
        # SHARED INVARIANT with `test_the_issuer_is_carried_through`: this flow completes only because the
        # RFC 9207 `iss` reaches the SDK, since the fake authorization server advertises support for it.
        with FakeAuthorizationServer() as server:
            path = self.config(server)
            transcript = io.StringIO()
            environment = {"EXAMPLE_CLIENT_ID": "portmark-test-client",
                           "EXAMPLE_CLIENT_SECRET": "portmark-test-secret",  # nosec B105 - a loopback fixture
                           "SSL_CERT_FILE": server.certificate}
            with patch.dict(os.environ, environment):
                with patch("sys.stdin", self.paste_from(transcript, DEFAULT_REDIRECT, server.origin)):
                    granted = login(path, "files", manual=True, total_seconds=30, out=transcript)
        self.assertEqual(granted["issuer"], server.origin)
        self.assertEqual(granted["client_id"], "portmark-test-client")
        self.assertTrue(granted["refreshable"])
        # What is printed ends up in a scrollback buffer and often in a terminal recording.
        printed = json.dumps(granted)
        self.assertNotIn(ACCESS_TOKEN, printed)
        self.assertNotIn(REFRESH_TOKEN, printed)
        stored = read_tokens(self.store)
        self.assertEqual(stored.access_token, ACCESS_TOKEN)
        self.assertEqual(stored.refresh_token, REFRESH_TOKEN)
        self.assertTrue(stored.token_endpoint, "the endpoint must be pinned, or a refresh has to guess")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(self.store).st_mode), 0o600)

    def test_logging_out_removes_the_stored_authorization_and_saying_so_twice_is_not_a_failure(self):
        with FakeAuthorizationServer() as server:
            path = self.config(server)
            write_tokens(self.store, StoredTokens("https://issuer.example", "cid", "a", 1, "r"))
            self.assertTrue(logout(path, "files")["removed"])
            self.assertFalse(logout(path, "files")["removed"])

    def test_logging_in_to_a_server_that_does_not_use_oauth_is_refused(self):
        path = self.root / "plain.json"
        path.write_text(json.dumps({
            "schema": "portmark.mcp.config.v1", "servers": {"files": dict(HTTP_SERVER)},
        }), encoding="utf-8")
        with self.assertRaises(McpConfigError) as caught:
            login(str(path), "files")
        self.assertIn("no `oauth` block", str(caught.exception))

    def test_an_unset_client_id_variable_is_named_rather_than_sent_as_an_empty_client(self):
        with FakeAuthorizationServer() as server:
            path = self.config(server)
            with patch.dict(os.environ, {"EXAMPLE_CLIENT_ID": ""}):
                with self.assertRaises(McpConfigError) as caught:
                    login(path, "files")
        self.assertIn("EXAMPLE_CLIENT_ID", str(caught.exception))


class LoginTimeoutTests(unittest.TestCase):
    """`--timeout` sets a deadline, so a value that cannot BE a deadline has to be refused at the edge."""

    def test_a_timeout_that_is_not_a_finite_number_is_refused(self):
        """`nan` and `inf` both switch the deadline off rather than set it.

        `now >= nan` is false for ever and `now >= inf` never becomes true, so a login given either would
        wait for a redirect that never comes, with nothing left to stop it.
        """
        for value in ("nan", "inf", "-inf", "NaN", "Infinity"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    _finite_seconds(value)
        # And through the REAL parser, because a check nothing calls is decorative. argparse refuses while
        # parsing, so nothing is loaded and no network is touched.
        from portmark import cli

        with patch.object(sys, "argv", ["portmark", "mcp", "login", "files", "--timeout", "nan"]):
            with contextlib.redirect_stderr(io.StringIO()) as complaint:
                with self.assertRaises(SystemExit):
                    cli.main()
        self.assertIn("finite positive", complaint.getvalue())

    def test_a_timeout_that_is_zero_or_negative_is_refused(self):
        # A deadline already in the past gives up before the operator has seen the url.
        for value in ("0", "-1", "-0.5"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    _finite_seconds(value)

    def test_an_ordinary_timeout_is_accepted(self):
        self.assertEqual(_finite_seconds("90"), 90.0)


class PinRenewalScopeTests(unittest.TestCase):
    """`mcp pin --server X` talks to one server, so it must not be stopped by a different one."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.path = self.root / "mcp.json"
        self.path.write_text(json.dumps({
            "schema": "portmark.mcp.config.v1",
            "servers": {
                "plain": dict(HTTP_SERVER, bearer_env="MCP_TOKEN"),
                "delegated": dict(HTTP_SERVER, url="https://other.example.com/mcp", oauth=OAUTH),
            },
        }), encoding="utf-8")

    def test_renewing_can_be_limited_to_one_server(self):
        """The unrelated OAuth server here would fail: its client id variable is unset.

        Without the limit, pinning `plain` -- which needs no authorization at all -- would stop on it.
        """
        with patch.dict(os.environ, {"EXAMPLE_CLIENT_ID": ""}):
            self.assertEqual(refresh_oauth_tokens(load_config(str(self.path)), only="plain"), ())

    def test_pinning_one_server_renews_only_that_one(self):
        # The wiring, not the helper: `_run_mcp` has to pass the selection on.
        seen = {}

        def renew(config, only=None):
            seen["only"] = only
            return ()

        arguments = argparse.Namespace(mcp_command="pin", server="plain")
        settings = SimpleNamespace(mcp_config_path=str(self.path))
        with patch("portmark.mcp.refresh_oauth_tokens", side_effect=renew):
            with patch("portmark.mcp.pin_report", return_value={}):
                with contextlib.redirect_stdout(io.StringIO()):
                    _run_mcp(argparse.ArgumentParser(), arguments, settings)
        self.assertEqual(seen["only"], "plain")


class McpCommandErrorTests(unittest.TestCase):
    """A store that cannot be written is an operator's problem to fix, not a traceback to decipher."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.path = self.root / "mcp.json"
        self.path.write_text(json.dumps({
            "schema": "portmark.mcp.config.v1",
            "servers": {"files": dict(HTTP_SERVER, oauth=OAUTH)},
        }), encoding="utf-8")

    def test_a_token_store_failure_is_reported_as_an_error_and_not_a_traceback(self):
        if not sdk_available():
            self.skipTest("requires portmark[mcp-oauth]")
        arguments = argparse.Namespace(mcp_command="logout", server="files")
        settings = SimpleNamespace(mcp_config_path=str(self.path))
        broken = TokenStoreError("the token store is a directory")
        with patch("portmark.mcp_login.clear_tokens", side_effect=broken):
            with contextlib.redirect_stderr(io.StringIO()) as complaint:
                with self.assertRaises(SystemExit):
                    _run_mcp(argparse.ArgumentParser(), arguments, settings)
        self.assertIn("the token store is a directory", complaint.getvalue())

    def test_a_token_store_failure_at_start_up_is_reported_as_an_error_too(self):
        """The same gap on the other entry point: start-up renews, and renewing reads the store."""
        broken = TokenStoreError("the token store is group readable")
        with patch("portmark.mcp_oauth.sdk_available", return_value=True):
            with patch("portmark.mcp_oauth.read_tokens", side_effect=broken):
                with patch.dict(os.environ, {"EXAMPLE_CLIENT_ID": "cid"}):
                    with contextlib.redirect_stderr(io.StringIO()) as complaint:
                        with self.assertRaises(SystemExit):
                            _install_mcp_tools(argparse.ArgumentParser(), str(self.path), None)
        self.assertIn("group readable", complaint.getvalue())


class TokenRefresherTests(unittest.TestCase):
    """Renewing on a timer, in the host. The clock is passed in, so each decision is tested at an instant.

    A test that started the thread and slept would be measuring the scheduler, not the rule.
    """

    NOW = 1_800_000_000

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = str(self.root / "tokens.json")
        self.path = self.root / "mcp.json"
        self.write_config(dict(HTTP_SERVER, oauth=dict(OAUTH, token_store=self.store)))

    def write_config(self, server):
        self.path.write_text(json.dumps({
            "schema": "portmark.mcp.config.v1", "servers": {"files": server},
        }), encoding="utf-8")

    def refresher(self):
        return TokenRefresher(load_config(str(self.path)))

    def store_expiring_in(self, seconds):
        write_tokens(self.store, StoredTokens(
            "https://issuer.example", "cid", "tok", self.NOW + seconds, "a-refresh-token"))

    def test_a_config_with_no_oauth_server_has_nothing_to_renew(self):
        self.write_config(dict(HTTP_SERVER, bearer_env="MCP_TOKEN"))
        refresher = self.refresher()
        self.assertFalse(refresher.wanted)
        refresher.start()
        self.addCleanup(refresher.stop)
        self.assertEqual(refresher.live(), ())
        # And no thread at all: a timer that can never have anything to do is pure cost.
        self.assertIsNone(refresher._thread)

    def test_a_token_with_plenty_of_life_left_is_not_renewed(self):
        self.store_expiring_in(3600)
        refresher = self.refresher()
        with patch("portmark.mcp_oauth.current_access_token") as renew:
            slept = refresher.tick(self.NOW)
        renew.assert_not_called()
        self.assertGreater(slept, MIN_REFRESH_SLEEP_SECONDS)

    def test_a_token_is_renewed_while_the_worker_would_still_accept_it(self):
        """The load-bearing one: the refresher has to run AHEAD of the refuser, not beside it.

        This token has 120 seconds left. The worker's own margin is 60, so it would still send this token
        happily -- nothing is failing yet. That is exactly when the renewal has to happen. If the refresher
        used the worker's margin instead of its own wider one, renewal and refusal would begin at the same
        instant and there would be a window in which calls fail and nothing has renewed.
        """
        self.assertLess(120, REFRESH_AHEAD_SECONDS, "the fixture must sit inside the refresher's margin")
        self.store_expiring_in(120)
        refresher = self.refresher()
        with patch("portmark.mcp_oauth.current_access_token") as renew:
            refresher.tick(self.NOW)
        renew.assert_called_once()
        self.assertEqual(renew.call_args.kwargs["margin"], REFRESH_AHEAD_SECONDS)

    def test_a_refusal_from_the_authorization_server_stops_that_server_being_asked_again(self):
        """Many authorization servers rotate the refresh token on use.

        So repeating a refused refresh spends a credential that is already dead and hammers the server with
        it. Only a person can fix this, and the worker's own refusal is what tells them to.
        """
        self.store_expiring_in(0)
        refresher = self.refresher()
        with patch("portmark.mcp_oauth.current_access_token", side_effect=McpOAuthRefused("no")) as renew:
            refresher.tick(self.NOW)
            self.assertEqual(refresher.live(), ())
            refresher.tick(self.NOW)
        renew.assert_called_once()

    def test_a_failure_that_might_pass_is_retried(self):
        # A network blip is not an answer from the authorization server, so it is worth asking again.
        self.store_expiring_in(0)
        refresher = self.refresher()
        with patch("portmark.mcp_oauth.current_access_token", side_effect=McpOAuthError("blip")):
            slept = refresher.tick(self.NOW)
        self.assertEqual(refresher.live(), ("files",))
        self.assertEqual(slept, REFRESH_RETRY_SECONDS)

    def test_an_unexpected_failure_does_not_bring_the_host_down(self):
        """`tick` runs on a background thread. An exception escaping it would end the renewals silently."""
        self.store_expiring_in(0)
        refresher = self.refresher()
        with patch("portmark.mcp_oauth.current_access_token", side_effect=RuntimeError("boom")):
            slept = refresher.tick(self.NOW)
        self.assertEqual(slept, REFRESH_RETRY_SECONDS)
        self.assertEqual(refresher.live(), ("files",))

    def test_an_unreadable_store_is_retried_rather_than_treated_as_an_answer(self):
        refresher = self.refresher()
        with patch("portmark.mcp.read_tokens", side_effect=TokenStoreError("group readable")):
            with patch("portmark.mcp_oauth.current_access_token") as renew:
                slept = refresher.tick(self.NOW)
        renew.assert_not_called()
        self.assertEqual(slept, REFRESH_RETRY_SECONDS)

    def test_a_server_never_logged_in_to_is_left_for_the_worker_to_report(self):
        """There is nothing to renew from, and nothing to say that the worker will not say better.

        The worker names the server and the exact command, at the moment a call actually needs the token.
        """
        refresher = self.refresher()
        with patch("portmark.mcp_oauth.current_access_token") as renew:
            refresher.tick(self.NOW)
        renew.assert_not_called()

    def test_the_wait_never_becomes_a_spin(self):
        # An expiry already long past makes every gap negative; without a floor the loop would busy-wait.
        self.store_expiring_in(-100_000)
        refresher = self.refresher()
        with patch("portmark.mcp_oauth.current_access_token", side_effect=McpOAuthError("blip")):
            with patch.object(TokenRefresher, "_renew", return_value=0.0):
                slept = refresher.tick(self.NOW)
        self.assertEqual(slept, MIN_REFRESH_SLEEP_SECONDS)

    def test_the_thread_starts_and_stops(self):
        self.store_expiring_in(3600)
        refresher = self.refresher()
        refresher.start()
        self.addCleanup(refresher.stop)
        self.assertTrue(refresher._thread is not None and refresher._thread.is_alive())
        refresher.stop()
        self.assertIsNone(refresher._thread)
