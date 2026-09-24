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
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from oauth_server import ACCESS_TOKEN, AUTHORIZATION_CODE, REFRESH_TOKEN, FakeAuthorizationServer

from portmark.mcp_oauth import (
    McpOAuthError,
    authorize,
    current_access_token,
    refresh,
    refuse_sync_use,
    sdk_available,
)
from portmark.security import canonical_json
from portmark.cli import _install_mcp_tools
from portmark.mcp import pin_report, probe_server, register_mcp_tools
from portmark.mcp_client import McpError
from portmark.mcp_config import McpConfigError, McpOAuthConfig, McpServerConfig, config_from_bytes, server_digest
from portmark.mcp_http import checked_fetch
from portmark.tools import ToolRegistry
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


class OauthNotYetWiredTests(unittest.TestCase):
    """Until the call path reads `oauth`, a server that sets it must not start -- or be CONTACTED.

    Refusing late is not refusing. The start-up sequence probes every server before it registers anything,
    so a guard that sat only at registration would let the refusal message claim something already untrue:
    the server would have received unauthenticated requests before the host decided not to start.
    """

    def setUp(self):
        document = {
            "schema": "portmark.mcp.config.v1",
            "servers": {"example": dict(HTTP_SERVER, oauth=OAUTH)},
        }
        self.path = Path(tempfile.mkdtemp()) / "mcp.json"
        self.path.write_text(json.dumps(document), encoding="utf-8")

    def test_the_host_refuses_to_register_a_server_whose_oauth_would_be_ignored(self):
        # Accepting a setting that is not in force is the failure this whole codebase refuses elsewhere:
        # the operator would read the config, believe the server is authorized, and it would be contacted
        # with no token at all. Failing at start-up is the honest answer until the wiring lands.
        config = config_from_bytes(self.path.read_bytes(), str(self.path))
        with self.assertRaises(McpConfigError) as caught:
            register_mcp_tools(ToolRegistry(), config)
        self.assertIn("not built yet", str(caught.exception))
        self.assertIn("unauthenticated", str(caught.exception))

    def test_start_up_refuses_before_any_server_has_been_probed(self):
        """The real start-up sequence, not the registration step alone.

        `_install_mcp_tools` runs `check_pins` FIRST, and a probe starts the server and talks to it. The
        observable that matters is therefore not the refusal -- it is that the probe was never attempted.
        `probe_server` is patched so that only a check placed ahead of the loop can keep the count at zero.
        """
        with patch("portmark.mcp.probe_server") as probe:
            with contextlib.redirect_stderr(io.StringIO()) as complaint:
                # argparse turns the refusal into its own exit; the message still has to be the real one.
                with self.assertRaises(SystemExit):
                    _install_mcp_tools(argparse.ArgumentParser(), str(self.path), None)
        self.assertEqual(probe.call_count, 0)
        self.assertIn("unauthenticated", complaint.getvalue())

    def test_probing_a_server_that_sets_oauth_is_refused_by_the_probe_itself(self):
        """`probe_server` is exported and called directly, so the guard has to live in it.

        Nothing is patched here. If this raises, no process was launched and no request was sent, which is
        the property the refusal message asserts.
        """
        with self.assertRaises(McpConfigError) as caught:
            probe_server(str(self.path), "example", timeout=1)
        self.assertIn("unauthenticated", str(caught.exception))

    def test_mcp_pin_refuses_the_same_configuration_without_probing(self):
        """`portmark mcp pin` probes too, and pinning is not a reason to contact a server unauthenticated.

        The way out is in the message rather than in a flag: pin with the `oauth` block removed.
        """
        with patch("portmark.mcp.probe_server") as probe:
            with self.assertRaises(McpConfigError) as caught:
                pin_report(str(self.path), "example", timeout=1)
        self.assertEqual(probe.call_count, 0)
        self.assertIn("Remove the `oauth` block", str(caught.exception))


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

    def test_a_refused_token_exchange_is_reported_and_stores_nothing(self):
        with FakeAuthorizationServer("token_refused") as server:
            with self.assertRaises(Exception):
                self.authorize(server)

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
