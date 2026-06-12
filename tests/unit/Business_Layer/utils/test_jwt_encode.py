"""
tests/unit/Business_Layer/utils/test_jwt_encode.py

Unit tests for:  Business_Layer/utils/jwt_encode.py
Function tested: token_create()

DB and jwt.encode are mocked — we test our logic, not the library.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException


# ─────────────────────────────────────────────────────────────────────────────
# Shared test data
# ─────────────────────────────────────────────────────────────────────────────

VALID_TOKEN_DATA = {
    "sub":         "1",
    "user_id":     1,
    "name":        "John Doe",
    "email":       "john@example.com",
    "employee_id": "EMP001",
    "user_uuid":   "550e8400-e29b-41d4-a716-446655440000",
    "roles":       ["admin"],
    "permissions": ["read", "write"],
}


class TestTokenCreate:

    # ── Happy path ─────────────────────────────────────────────────────────

    def test_token_create_with_issuer_returns_string(self):
        """
        GIVEN  valid token_data and an explicit issuer
        WHEN   token_create() is called
        THEN   a non-empty string (JWT) is returned
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._private_key", "fake-key"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._algorithm",   "RS256"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._kid",         "kid-001"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.jwt.encode",
                   return_value="mocked.jwt.token"):

            # Act
            result = token_create(VALID_TOKEN_DATA, issuer="https://myapp.com")

        # Assert
        assert isinstance(result, str)
        assert result == "mocked.jwt.token"

    def test_token_create_issuer_always_uses_env_var(self):
        """
        GIVEN  a request object is passed to token_create()
        WHEN   token is created
        THEN   the issuer in the JWT payload is ALWAYS the env-configured ISSUER,
               not derived from the request — this is documented behavior (ALLOWED_ISSUERS env var)

        WHY REWRITTEN:
          The previous test patched a function 'get_issuer_from_request' that was removed
          from the implementation. The system now always uses ISSUER from the ALLOWED_ISSUERS
          env var (Technical Design Document §10.2). Dynamic issuer extraction from request
          is intentionally commented out to prevent issuer spoofing.
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create
        import Backend.Api_Layer.JWT.token_creation.token_create as tc_module

        mock_request = MagicMock()
        captured_payload = {}

        def capture_encode(payload, *args, **kwargs):
            captured_payload.update(payload)
            return "env.issuer.token"

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._private_key", "fake-key"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._algorithm",   "RS256"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._kid",         "kid-001"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.jwt.encode",
                   side_effect=capture_encode):

            result = token_create(VALID_TOKEN_DATA, request=mock_request)

        # Assert — token created, and issuer matches the module-level ISSUER constant
        assert isinstance(result, str)
        assert captured_payload["iss"] == tc_module.ISSUER

    def test_token_create_payload_contains_required_fields(self):
        """
        GIVEN  valid token_data
        WHEN   token_create() builds the JWT payload
        THEN   payload must contain: user_id, email, name, roles, permissions, iss, exp, jti
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create

        captured_payload = {}

        def capture_encode(payload, *args, **kwargs):
            captured_payload.update(payload)
            return "tok"

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._private_key", "fake-key"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._algorithm",   "RS256"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._kid",         "kid-001"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.jwt.encode",
                   side_effect=capture_encode):

            token_create(VALID_TOKEN_DATA, issuer="https://myapp.com")

        # Assert — all required JWT claims must be present
        assert "user_id"      in captured_payload
        assert "email"        in captured_payload
        assert "name"         in captured_payload
        assert "employee_id"  in captured_payload   # added: supports cross-module integration
        assert "obs_user_uuid" in captured_payload  # added: stable UUID for external consumers
        assert "roles"        in captured_payload
        assert "permissions"  in captured_payload
        assert "iss"          in captured_payload
        assert "exp"          in captured_payload
        assert "jti"          in captured_payload

    # ── Failure cases ──────────────────────────────────────────────────────

    def test_token_create_no_explicit_issuer_still_succeeds(self):
        """
        GIVEN  neither 'request' nor 'issuer' is provided to token_create()
        WHEN   token_create() is called
        THEN   token is STILL created successfully using the env-configured ISSUER constant

        WHY REWRITTEN:
          The previous test expected a ValueError when no issuer/request was provided.
          That guard was intentionally removed — the issuer is now unconditionally set
          to the module-level ISSUER constant (from ALLOWED_ISSUERS env var).
          This prevents runtime failures when callers omit the issuer parameter while
          still guaranteeing a valid, known issuer in every token (Technical Design §10.2).
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._private_key", "fake-key"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._algorithm",   "RS256"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._kid",         "kid-001"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.jwt.encode",
                   return_value="no-issuer-param.token"):

            # Act — no request, no explicit issuer
            result = token_create(VALID_TOKEN_DATA)

        # Assert — must succeed (issuer comes from env, not from caller)
        assert result == "no-issuer-param.token"

    def test_token_create_calls_load_keys(self):
        """
        GIVEN  any valid call to token_create
        WHEN   token is being created
        THEN   _load_keys must be called to ensure keys are loaded from DB
        """
        from Backend.Api_Layer.JWT.token_creation.token_create import token_create

        with patch("Backend.Api_Layer.JWT.token_creation.token_create._load_keys") as mock_load, \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._private_key", "key"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._algorithm",   "RS256"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create._kid",         "kid"), \
             patch("Backend.Api_Layer.JWT.token_creation.token_create.jwt.encode",
                   return_value="tok"):

            token_create(VALID_TOKEN_DATA, issuer="https://app.com")

        # Assert — keys must always be loaded (they may rotate)
        mock_load.assert_called_once()
