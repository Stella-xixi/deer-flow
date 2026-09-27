"""Tests for AuthConfig typed configuration."""

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

import app.gateway.auth.config as cfg


def test_auth_config_defaults():
    config = cfg.AuthConfig(jwt_secret="test-secret-key-123")
    assert config.token_expiry_days == 7


def test_auth_config_token_expiry_range():
    cfg.AuthConfig(jwt_secret="s", token_expiry_days=1)
    cfg.AuthConfig(jwt_secret="s", token_expiry_days=30)
    with pytest.raises(Exception):
        cfg.AuthConfig(jwt_secret="s", token_expiry_days=0)
    with pytest.raises(Exception):
        cfg.AuthConfig(jwt_secret="s", token_expiry_days=31)


def test_auth_config_from_env():
    env = {"AUTH_JWT_SECRET": "test-jwt-secret-from-env"}
    with patch.dict(os.environ, env, clear=False):
        old = cfg._auth_config
        cfg._auth_config = None
        try:
            config = cfg.get_auth_config()
            assert config.jwt_secret == "test-jwt-secret-from-env"
        finally:
            cfg._auth_config = old


def test_auth_config_missing_secret_generates_and_persists(tmp_path, caplog):
    import logging

    from deerflow.config.paths import Paths

    old = cfg._auth_config
    cfg._auth_config = None
    secret_file = tmp_path / ".jwt_secret"
    try:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AUTH_JWT_SECRET", None)
            with patch("deerflow.config.paths.get_paths", return_value=Paths(base_dir=tmp_path)), caplog.at_level(logging.WARNING):
                config = cfg.get_auth_config()
            assert config.jwt_secret
            assert any("AUTH_JWT_SECRET" in msg for msg in caplog.messages)
            assert secret_file.exists()
            assert secret_file.read_text().strip() == config.jwt_secret
    finally:
        cfg._auth_config = old


def test_auth_config_reuses_persisted_secret(tmp_path):
    from deerflow.config.paths import Paths

    old = cfg._auth_config
    cfg._auth_config = None
    persisted = "persisted-secret-from-file-min-32-chars!!"
    (tmp_path / ".jwt_secret").write_text(persisted, encoding="utf-8")
    try:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AUTH_JWT_SECRET", None)
            with patch("deerflow.config.paths.get_paths", return_value=Paths(base_dir=tmp_path)):
                config = cfg.get_auth_config()
            assert config.jwt_secret == persisted
    finally:
        cfg._auth_config = old


def test_auth_config_empty_secret_file_fails_without_overwriting(tmp_path):
    from deerflow.config.paths import Paths

    old = cfg._auth_config
    cfg._auth_config = None
    (tmp_path / ".jwt_secret").write_text("", encoding="utf-8")
    try:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AUTH_JWT_SECRET", None)
            with (
                patch("deerflow.config.paths.get_paths", return_value=Paths(base_dir=tmp_path)),
                pytest.raises(RuntimeError, match="exists but is empty"),
            ):
                cfg.get_auth_config()
            assert (tmp_path / ".jwt_secret").read_text() == ""
    finally:
        cfg._auth_config = old


def test_load_or_create_secret_reuses_concurrent_winner(tmp_path, monkeypatch):
    """A worker that loses atomic creation must use the winning worker's secret."""
    from deerflow.config.paths import Paths

    secret_file = tmp_path / ".jwt_secret"
    winning_secret = "w" * 43

    def lose_publish_race(source, destination):
        assert destination == secret_file
        secret_file.write_text(f"{winning_secret}\n", encoding="utf-8")
        raise FileExistsError

    monkeypatch.setattr("deerflow.config.paths.get_paths", lambda: Paths(base_dir=tmp_path))
    monkeypatch.setattr(cfg.os, "link", lose_publish_race)

    assert cfg._load_or_create_secret() == winning_secret
    assert not list(tmp_path.glob(".*.tmp"))


def test_concurrent_secret_creation_returns_one_persisted_value(tmp_path, monkeypatch):
    """Concurrent starters must agree with the atomically published value."""
    from deerflow.config.paths import Paths

    barrier = threading.Barrier(2)
    candidates = iter(("a" * 43, "b" * 43))
    candidate_lock = threading.Lock()

    def generate_candidate(_bytes):
        with candidate_lock:
            candidate = next(candidates)
        barrier.wait(timeout=5)
        return candidate

    monkeypatch.setattr("deerflow.config.paths.get_paths", lambda: Paths(base_dir=tmp_path))
    monkeypatch.setattr(cfg.secrets, "token_urlsafe", generate_candidate)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: cfg._load_or_create_secret(), range(2)))

    persisted = (tmp_path / ".jwt_secret").read_text(encoding="utf-8").strip()
    assert results == [persisted, persisted]
    assert persisted in {"a" * 43, "b" * 43}
    assert not list(tmp_path.glob(".*.tmp"))
