"""Tests for the Discord identity selector (StreamKit vs own application)."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock

import pytest

from mynah import secrets_store
from mynah.uicore import _AUTH_MODE_LABELS, apply_settings_atomically


@pytest.fixture
def config_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator:
    if "mynah.config" in sys.modules:
        del sys.modules["mynah.config"]
    import mynah.config as cfg_mod
    monkeypatch.setattr(cfg_mod, "APP_ROOT", tmp_path)
    monkeypatch.setattr(cfg_mod, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(cfg_mod, "DEFAULT_RECORDINGS_DIR", tmp_path / "Recordings")
    # Keep the credential store out of the picture.
    monkeypatch.setattr(secrets_store, "get_secret", lambda *_a, **_k: None)
    monkeypatch.setattr(secrets_store, "set_secret", lambda *_a, **_k: False)
    monkeypatch.setattr(secrets_store, "delete_secret", lambda *_a, **_k: None)
    yield cfg_mod
    if "mynah.config" in sys.modules:
        del sys.modules["mynah.config"]


class TestConfigAuthMode:
    def test_fresh_config_defaults_to_streamkit(self, config_module) -> None:
        cfg = config_module.Config.load()
        assert cfg.discord_auth_mode == config_module.AUTH_MODE_STREAMKIT
        assert cfg.uses_streamkit
        assert cfg.discord_is_configured()

    def test_existing_config_with_client_id_stays_on_own_app(
        self, config_module, tmp_path: Path
    ) -> None:
        (tmp_path / "config.json").write_text(
            json.dumps({"discord_client_id": "123"}), encoding="utf-8"
        )
        cfg = config_module.Config.load()
        assert cfg.discord_auth_mode == config_module.AUTH_MODE_OWN_APP
        # Own app without a secret is not connectable.
        assert not cfg.discord_is_configured()

    def test_existing_config_without_client_id_gets_streamkit(
        self, config_module, tmp_path: Path
    ) -> None:
        (tmp_path / "config.json").write_text(
            json.dumps({"whisper_model": "base"}), encoding="utf-8"
        )
        cfg = config_module.Config.load()
        assert cfg.discord_auth_mode == config_module.AUTH_MODE_STREAMKIT

    def test_explicit_mode_round_trips(self, config_module, tmp_path: Path) -> None:
        cfg = config_module.Config.create(
            discord_client_id="123", discord_auth_mode=config_module.AUTH_MODE_STREAMKIT
        )
        cfg.save()
        on_disk = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
        assert on_disk["discord_auth_mode"] == "streamkit"
        assert config_module.Config.load().discord_auth_mode == "streamkit"

    def test_invalid_mode_falls_back_to_default(self, config_module) -> None:
        cfg = config_module.Config(discord_auth_mode="bogus")
        assert cfg.discord_auth_mode == config_module._DEFAULT_AUTH_MODE

    def test_own_app_requires_both_credentials(self, config_module) -> None:
        cfg = config_module.Config.create(
            discord_client_id="123",
            discord_client_secret="s",
            discord_auth_mode=config_module.AUTH_MODE_OWN_APP,
        )
        assert cfg.discord_is_configured()
        cfg.discord_client_secret = ""
        assert not cfg.discord_is_configured()


class TestApplySettingsAuthMode:
    def _cfg(self):
        c = MagicMock()
        c.discord_client_id = "id"
        c.discord_client_secret = "secret"
        c.discord_auth_mode = "own_app"
        c.hf_token = ""
        c.token = object()
        return c

    def _values(self, mode):
        return {
            "discord_auth_mode": mode,
            "discord_client_id": "id",
            "discord_client_secret": "secret",
            "hf_token": "",
            "whisper_model": "base",
            "audio_source": "mixed",
            "recordings_dir": "x",
        }

    def test_switching_mode_clears_cached_token(self) -> None:
        c = self._cfg()
        assert apply_settings_atomically(c, self._values("streamkit")) is None
        assert c.token is None
        assert c.discord_auth_mode == "streamkit"

    def test_same_mode_keeps_token(self) -> None:
        c = self._cfg()
        sentinel = c.token
        assert apply_settings_atomically(c, self._values("own_app")) is None
        assert c.token is sentinel

    def test_missing_mode_key_is_treated_as_unchanged(self) -> None:
        c = self._cfg()
        values = self._values("own_app")
        del values["discord_auth_mode"]
        sentinel = c.token
        assert apply_settings_atomically(c, values) is None
        assert c.token is sentinel
        assert c.discord_auth_mode == "own_app"


def test_labels_cover_every_mode() -> None:
    from mynah import config as cfg_mod

    assert set(_AUTH_MODE_LABELS) == cfg_mod._VALID_AUTH_MODES
    assert next(iter(_AUTH_MODE_LABELS)) == cfg_mod.AUTH_MODE_STREAMKIT
