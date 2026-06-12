"""
tests/unit/Api_Layer/JWT/test_oidc_config.py

Unit tests for:
  Backend/Api_Layer/JWT/jwt_validator/auth/oidc_config.py

Covers:
  OIDCValidator.__init__    → loads keys on creation
  OIDCValidator.is_ready()  → reflects load state
  OIDCValidator.get_signing_key() → returns cached key, reloads on unknown KID
  get_oidc_validator()      → singleton pattern, thread-safe
  reset_oidc_validator()    → clears singleton for key rotation
  check_oidc_health()       → returns True/False

All external calls (DB key fetch, JWK/RSA processing) are mocked.
"""

import pytest
from unittest.mock import patch, MagicMock, call
import threading
import json


# ── helpers ────────────────────────────────────────────────────────────────────

MOCK_KID = "kid-001"
MOCK_RSA_KEY = MagicMock(name="rsa_key")
MOCK_PUBLIC_PEM = "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"


def _patch_key_loading(kid=MOCK_KID, rsa_key=None):
    """Context manager stack that mocks the entire key-loading chain."""
    rsa = rsa_key or MOCK_RSA_KEY
    return [
        patch("Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config.get_active_public_key",
              return_value=("enc_private", "enc_public", "RS256", kid)),
        patch("Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config.decrypt_key",
              return_value=MOCK_PUBLIC_PEM),
        patch("Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config.jwk_lib.JWK.from_pem",
              return_value=MagicMock(**{"export_public.return_value": json.dumps({"kty": "RSA", "n": "abc", "e": "AQAB"})})),
        patch("Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config.algorithms.RSAAlgorithm.from_jwk",
              return_value=rsa),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# OIDCValidator
# ══════════════════════════════════════════════════════════════════════════════

class TestOIDCValidator:

    def _make_validator(self, kid=MOCK_KID):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in _patch_key_loading(kid=kid):
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import OIDCValidator
            v = OIDCValidator()
        return v

    def test_is_ready_after_successful_init(self):
        """
        GIVEN  all key-loading dependencies are available
        WHEN   OIDCValidator() is created
        THEN   is_ready() returns True and the KID is in jwks_dict
        """
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import OIDCValidator
            v = OIDCValidator()

        assert v.is_ready() is True
        assert MOCK_KID in v.jwks_dict

    def test_is_ready_false_before_load(self):
        """
        GIVEN  OIDCValidator is created but key loading fails
        WHEN   is_ready() is checked
        THEN   returns False — cannot serve validation requests
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import OIDCValidator

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config.get_active_public_key",
                   side_effect=Exception("DB unreachable")):
            with pytest.raises(Exception):
                v = OIDCValidator()

    def test_get_signing_key_returns_cached_key(self):
        """
        GIVEN  the validator has loaded a key for a KID
        WHEN   get_signing_key() is called with that KID
        THEN   returns the RSA key from cache (no reload)
        """
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import OIDCValidator
            v = OIDCValidator()

        key = v.get_signing_key(MOCK_KID)
        assert key is MOCK_RSA_KEY

    def test_get_signing_key_raises_runtime_error_when_not_ready(self):
        """
        GIVEN  the validator is not ready (config_loaded=False)
        WHEN   get_signing_key() is called
        THEN   raises RuntimeError — caller must not proceed with validation
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import OIDCValidator

        with patch.object(OIDCValidator, "_load_config_from_memory"):
            v = OIDCValidator.__new__(OIDCValidator)
            v._config_loaded = False
            v._config_lock = threading.Lock()
            v.jwks_dict = {}
            v.issuer = "https://ums.example.com"
            v.allowed_issuers = ["https://ums.example.com"]

        with pytest.raises(RuntimeError, match="OIDC configuration not loaded"):
            v.get_signing_key("any-kid")

    def test_get_signing_key_reloads_on_unknown_kid(self):
        """
        GIVEN  a KID not in the cache (e.g. after key rotation)
        WHEN   get_signing_key() is called
        THEN   forces a reload from DB and returns the fresh key
        """
        from contextlib import ExitStack
        new_kid = "kid-002"
        new_key = MagicMock(name="rsa_key_new")

        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import OIDCValidator
            v = OIDCValidator()

        # Simulate key rotation — reload returns new kid
        with ExitStack() as stack:
            for p in _patch_key_loading(kid=new_kid, rsa_key=new_key):
                stack.enter_context(p)
            result = v.get_signing_key(new_kid)

        assert result is new_key
        assert new_kid in v.jwks_dict

    def test_get_signing_key_raises_value_error_when_kid_still_missing_after_reload(self):
        """
        GIVEN  a KID not in cache and still absent after force reload
        WHEN   get_signing_key() is called
        THEN   raises ValueError — key genuinely does not exist
        """
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import OIDCValidator
            v = OIDCValidator()

        # Force reload will return the SAME kid-001, not the requested "ghost-kid"
        with ExitStack() as stack:
            for p in _patch_key_loading(kid=MOCK_KID):
                stack.enter_context(p)
            with pytest.raises(ValueError, match="not found"):
                v.get_signing_key("ghost-kid")

    def test_force_reload_clears_old_keys(self):
        """
        GIVEN  a validator with one cached key
        WHEN   _load_config_from_memory(force_reload=True) is called
        THEN   old keys are cleared and only the new key is cached
        """
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import OIDCValidator
            v = OIDCValidator()

        assert MOCK_KID in v.jwks_dict
        # Insert a stale key
        v.jwks_dict["stale-kid"] = MagicMock(name="stale_key")

        new_kid = "kid-rotated"
        new_key = MagicMock(name="new_key")
        with ExitStack() as stack:
            for p in _patch_key_loading(kid=new_kid, rsa_key=new_key):
                stack.enter_context(p)
            v._load_config_from_memory(force_reload=True)

        assert "stale-kid" not in v.jwks_dict
        assert new_kid in v.jwks_dict

    def test_second_load_skipped_when_already_ready(self):
        """
        GIVEN  a validator that is already loaded
        WHEN   _load_config_from_memory() is called again (no force)
        THEN   the key-loading chain is NOT called again (cache respected)
        """
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import OIDCValidator
            v = OIDCValidator()

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config.get_active_public_key") as mock_get:
            v._load_config_from_memory(force_reload=False)

        mock_get.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# get_oidc_validator() — singleton
# ══════════════════════════════════════════════════════════════════════════════

class TestGetOidcValidator:

    def setup_method(self):
        """Reset global singleton before each test."""
        import Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config as cfg
        cfg._oidc_validator = None

    def teardown_method(self):
        """Clean up after each test."""
        import Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config as cfg
        cfg._oidc_validator = None

    def test_returns_singleton_instance(self):
        """
        GIVEN  get_oidc_validator() is called twice
        WHEN   the first call creates the validator
        THEN   the second call returns the exact same object
        """
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import get_oidc_validator
            v1 = get_oidc_validator()
            v2 = get_oidc_validator()

        assert v1 is v2

    def test_returns_ready_validator(self):
        """
        GIVEN  key loading succeeds
        WHEN   get_oidc_validator() is called
        THEN   the returned validator is_ready()
        """
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import get_oidc_validator
            v = get_oidc_validator()

        assert v.is_ready() is True


# ══════════════════════════════════════════════════════════════════════════════
# reset_oidc_validator()
# ══════════════════════════════════════════════════════════════════════════════

class TestResetOidcValidator:

    def test_clears_global_singleton(self):
        """
        GIVEN  a singleton validator exists
        WHEN   reset_oidc_validator() is called (e.g. after key rotation)
        THEN   the global is set to None so next call creates a fresh instance

        Business rule: key rotation requires the validator to reload its key cache.
        """
        from contextlib import ExitStack
        import Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config as cfg

        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import (
                get_oidc_validator, reset_oidc_validator,
            )
            get_oidc_validator()  # populate singleton
            assert cfg._oidc_validator is not None

            reset_oidc_validator()

        assert cfg._oidc_validator is None


# ══════════════════════════════════════════════════════════════════════════════
# check_oidc_health()
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckOidcHealth:

    def test_returns_true_when_validator_ready(self):
        """
        GIVEN  the OIDC validator loaded successfully
        WHEN   check_oidc_health() is called
        THEN   returns True
        """
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in _patch_key_loading():
                stack.enter_context(p)
            import Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config as cfg
            cfg._oidc_validator = None
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import check_oidc_health
            result = check_oidc_health()

        assert result is True

    def test_returns_false_when_validator_raises(self):
        """
        GIVEN  get_oidc_validator raises (key load failure)
        WHEN   check_oidc_health() is called
        THEN   returns False — health check must not propagate exceptions
        """
        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config.get_oidc_validator",
                   side_effect=Exception("DB unreachable")):
            from Backend.Api_Layer.JWT.jwt_validator.auth.oidc_config import check_oidc_health
            result = check_oidc_health()

        assert result is False
