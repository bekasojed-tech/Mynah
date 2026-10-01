"""Tests for Discord's legacy local-RPC OAuth flow.

The filename is retained so downstream test selectors keep working. Discord's
RPC AUTHORIZE command does not support browser/Social-SDK PKCE arguments.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from mynah.rpc import DiscordRPC, REDIRECT_URI, RpcError
import mynah.rpc as rpc_mod


def _rpc() -> DiscordRPC:
    return DiscordRPC("123456789012345678", "client-secret")


def _ok_token_response() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "access_token": "at",
        "refresh_token": "rt",
        "expires_in": 3600,
    }
    resp.raise_for_status.return_value = None
    return resp


class TestConstructor:
    def test_requires_id_and_secret(self):
        rpc = _rpc()
        assert rpc.client_id == "123456789012345678"
        assert rpc.client_secret == "client-secret"
        assert rpc.auth_mode == rpc_mod.AUTH_MODE_OWN_APP
        with pytest.raises(RpcError, match="client_id and client_secret"):
            DiscordRPC("", "")

    def test_streamkit_factory_needs_no_credentials(self):
        rpc = DiscordRPC.for_streamkit()
        assert rpc.auth_mode == rpc_mod.AUTH_MODE_STREAMKIT
        assert rpc.client_id == rpc_mod.STREAMKIT_CLIENT_ID
        assert rpc.client_secret == ""
        assert rpc.scopes == rpc_mod.STREAMKIT_SCOPES

    def test_unknown_mode_rejected(self):
        with pytest.raises(RpcError, match="Unknown Discord auth mode"):
            DiscordRPC("id", "secret", auth_mode="bogus")


class TestAuthorize:
    def _run_authorize(self, monkeypatch):
        rpc = _rpc()
        captured: dict = {}

        def fake_cmd(cmd, args, timeout=None):
            captured["cmd"] = cmd
            captured["args"] = args
            captured["timeout"] = timeout
            return {"code": "the-code"}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured["url"] = url
            captured["form"] = data
            return _ok_token_response()

        monkeypatch.setattr(rpc, "_cmd", fake_cmd)
        monkeypatch.setattr(rpc_mod.requests, "post", fake_post)
        token = rpc._authorize()
        return captured, token

    def test_authorize_uses_only_documented_rpc_args(self, monkeypatch):
        captured, _ = self._run_authorize(monkeypatch)
        assert rpc_mod.SCOPES == ["rpc", "identify"]
        assert captured["cmd"] == "AUTHORIZE"
        assert captured["args"] == {
            "client_id": "123456789012345678",
            "scopes": rpc_mod.SCOPES,
        }
        assert captured["timeout"] == 120.0

    def test_exchange_uses_secret_and_registered_redirect(self, monkeypatch):
        captured, token = self._run_authorize(monkeypatch)
        assert captured["form"] == {
            "client_id": "123456789012345678",
            "client_secret": "client-secret",
            "grant_type": "authorization_code",
            "code": "the-code",
            "redirect_uri": REDIRECT_URI,
        }
        assert token["access_token"] == "at"

    def test_no_code_raises(self, monkeypatch):
        rpc = _rpc()
        monkeypatch.setattr(rpc, "_cmd", lambda *a, **k: {})
        with pytest.raises(RpcError, match="no code"):
            rpc._authorize()

    def test_invalid_scope_explains_discord_rpc_approval(self, monkeypatch):
        rpc = _rpc()

        def denied(*_args, **_kwargs):
            raise RpcError(
                "OAuth2 Error: invalid_scope: The requested scope is invalid"
            )

        monkeypatch.setattr(rpc, "_cmd", denied)
        with pytest.raises(RpcError, match="Discord must approve RPC access"):
            rpc._authorize()


class TestStreamKitAuthorize:
    """The StreamKit identity: AUTHORIZE under Discord's own overlay app id,
    code exchanged at streamkit.discord.com, no secret anywhere."""

    def _run(self, monkeypatch, *, status=200, body=None, cmd_result=None):
        rpc = DiscordRPC.for_streamkit()
        captured: dict = {}

        def fake_cmd(cmd, args, timeout=None):
            captured["cmd"] = cmd
            captured["args"] = args
            return cmd_result if cmd_result is not None else {"code": "sk-code"}

        def fake_post(url, data=None, json=None, headers=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            captured["form"] = data
            resp = MagicMock()
            resp.status_code = status
            resp.json.return_value = body if body is not None else {"access_token": "sk-at"}
            return resp

        monkeypatch.setattr(rpc, "_cmd", fake_cmd)
        monkeypatch.setattr(rpc_mod.requests, "post", fake_post)
        return rpc, captured

    def test_authorize_uses_streamkit_identity_and_scopes(self, monkeypatch):
        rpc, captured = self._run(monkeypatch)
        token = rpc._authorize()
        assert captured["cmd"] == "AUTHORIZE"
        assert captured["args"] == {
            "client_id": rpc_mod.STREAMKIT_CLIENT_ID,
            "scopes": rpc_mod.STREAMKIT_SCOPES,
        }
        assert "rpc" in rpc_mod.STREAMKIT_SCOPES
        # Partner-only scope must never be requested; Discord rejects it.
        assert "rpc.voice.read" not in rpc_mod.STREAMKIT_SCOPES
        assert token["access_token"] == "sk-at"

    def test_code_exchanged_at_streamkit_as_json_without_secret(self, monkeypatch):
        rpc, captured = self._run(monkeypatch)
        rpc._authorize()
        assert captured["url"] == rpc_mod.STREAMKIT_TOKEN_URL
        assert captured["json"] == {"code": "sk-code"}
        assert captured["form"] is None
        assert "secret" not in str(captured).lower()

    def test_token_has_no_refresh_and_provisional_expiry(self, monkeypatch):
        rpc, _ = self._run(monkeypatch)
        before = time.time()
        token = rpc._authorize()
        assert token["refresh_token"] == ""
        assert token["expires_at"] >= before + rpc_mod._STREAMKIT_TOKEN_LIFETIME_SEC - 5

    def test_http_error_from_streamkit_is_explained(self, monkeypatch):
        rpc, _ = self._run(monkeypatch, status=400)
        with pytest.raises(RpcError, match="StreamKit token service rejected"):
            rpc._authorize()

    def test_missing_access_token_raises(self, monkeypatch):
        rpc, _ = self._run(monkeypatch, body={"nope": 1})
        with pytest.raises(RpcError, match="missing access_token"):
            rpc._authorize()

    def test_invalid_scope_message_points_at_streamkit(self, monkeypatch):
        rpc = DiscordRPC.for_streamkit()

        def denied(*_a, **_k):
            raise RpcError("OAuth2 Error: invalid_scope: bad")

        monkeypatch.setattr(rpc, "_cmd", denied)
        with pytest.raises(RpcError, match="StreamKit identity"):
            rpc._authorize()

    def test_refresh_is_refused(self):
        rpc = DiscordRPC.for_streamkit()
        with pytest.raises(RpcError, match="cannot be refreshed"):
            rpc._refresh_token("anything")


class TestAuthenticateExpiry:
    def test_parse_rpc_expiry_accepts_iso_and_z(self):
        ts = rpc_mod._parse_rpc_expiry("2026-10-09T12:00:00+00:00")
        assert ts is not None
        assert rpc_mod._parse_rpc_expiry("2026-10-09T12:00:00Z") == ts
        assert rpc_mod._parse_rpc_expiry("2026-10-09T12:00:00") == ts
        assert rpc_mod._parse_rpc_expiry("") is None
        assert rpc_mod._parse_rpc_expiry("not a date") is None
        assert rpc_mod._parse_rpc_expiry(None) is None

    def test_authenticate_records_expiry(self, monkeypatch):
        rpc = DiscordRPC.for_streamkit()
        monkeypatch.setattr(
            rpc,
            "_cmd",
            lambda *_a, **_k: {
                "user": {"id": "1", "username": "u"},
                "expires": "2026-10-09T12:00:00+00:00",
            },
        )
        rpc._authenticate("tok")
        assert rpc.authenticated
        assert rpc.token_expires_at == rpc_mod._parse_rpc_expiry("2026-10-09T12:00:00+00:00")

    def test_connect_adopts_authenticate_expiry_for_streamkit_token(self, monkeypatch):
        """connect(): a token without refresh_token takes its expiry from
        AUTHENTICATE so the next launch re-prompts exactly when Discord
        says the token lapses."""
        rpc = DiscordRPC.for_streamkit()
        monkeypatch.setattr(rpc, "_open_pipe", lambda: True)
        monkeypatch.setattr(rpc, "_write", lambda *_a, **_k: None)
        monkeypatch.setattr(
            rpc, "_handshake_read", lambda: (rpc.FRAME, {"evt": "READY"})
        )
        monkeypatch.setattr(
            rpc,
            "_authorize",
            lambda: {"access_token": "at", "refresh_token": "", "expires_at": 1.0},
        )

        def fake_auth(_tok):
            rpc.token_expires_at = 4102444800.0
            rpc.authenticated = True

        monkeypatch.setattr(rpc, "_authenticate", fake_auth)
        monkeypatch.setattr(rpc, "_start_reader", lambda: None)
        token = rpc.connect(existing_token=None)
        assert token["expires_at"] == 4102444800.0


class TestRefresh:
    def test_refresh_posts_client_credentials(self, monkeypatch):
        rpc = _rpc()
        captured: dict = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured["form"] = data
            return _ok_token_response()

        monkeypatch.setattr(rpc_mod.requests, "post", fake_post)
        token = rpc._refresh_token("rt-old")
        assert captured["form"] == {
            "client_id": rpc.client_id,
            "client_secret": rpc.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": "rt-old",
        }
        assert token["access_token"] == "at"


class TestInvalidClientGuidance:
    def test_invalid_client_points_to_credentials(self, monkeypatch):
        rpc = _rpc()
        resp = MagicMock()
        resp.status_code = 401
        resp.json.return_value = {"error": "invalid_client"}
        monkeypatch.setattr(rpc_mod.requests, "post", lambda *a, **k: resp)
        with pytest.raises(RpcError, match="Client ID and Client Secret"):
            rpc._refresh_token("rt")

    def test_other_http_errors_still_raise(self, monkeypatch):
        rpc = _rpc()
        resp = MagicMock()
        resp.status_code = 500
        resp.raise_for_status.side_effect = RuntimeError("boom")
        monkeypatch.setattr(rpc_mod.requests, "post", lambda *a, **k: resp)
        with pytest.raises(RuntimeError, match="boom"):
            rpc._refresh_token("rt")
