"""
tests/unit/Api_Layer/JWT/test_jwt_validator.py

Unit tests for:
  Backend/Api_Layer/JWT/jwt_validator/auth/jwt_validator.py  → validate_jwt_token()
  Backend/Api_Layer/JWT/jwt_validator/auth/jwt_utils.py      → decode_access_token(), decode_any_token()

All OIDC / JWT library calls are mocked — no real keys, no network, no DB.

Business rules validated:
  - Expired tokens → 401
  - Invalid signature / malformed token → 401
  - Blacklisted JTI → 401 (revoked)
  - Unknown / rotated KID → 401 from get_signing_key ValueError
  - OIDC internal error → 500 from get_signing_key RuntimeError
  - Blacklist check failure (Redis down) → ignored, token still accepted
  - Token without JTI → no blacklist lookup, still valid
  - decode_any_token skips expiry check (used for blacklisting expired tokens)
"""

import pytest
import jwt as pyjwt
from unittest.mock import patch, MagicMock
from fastapi import HTTPException


# ── shared mock helpers ────────────────────────────────────────────────────────

def _make_validator(key="fake-rsa-key", allowed_issuers=None):
    v = MagicMock()
    v.allowed_issuers = allowed_issuers or ["https://ums.example.com"]
    v.get_signing_key.return_value = key
    return v


DECODED_PAYLOAD = {
    "jti": "jti-abc-123",
    "user_id": 1,
    "email": "user@example.com",
    "roles": ["General"],
    "permissions": ["VIEW_USER_PUBLIC"],
    "iss": "https://ums.example.com",
}


# ══════════════════════════════════════════════════════════════════════════════
# validate_jwt_token()
# ══════════════════════════════════════════════════════════════════════════════

class TestValidateJwtToken:

    # ── happy path ─────────────────────────────────────────────────────────────

    def test_valid_token_returns_decoded_payload(self):
        """
        GIVEN  a valid, non-expired, non-blacklisted token
        WHEN   validate_jwt_token() is called
        THEN   returns the decoded payload dict
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token

        validator = _make_validator()

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.get_unverified_header",
                   return_value={"kid": "kid-001"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.decode",
                   return_value=DECODED_PAYLOAD), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.is_token_blacklisted",
                   return_value=False):

            result = validate_jwt_token("valid.jwt.token")

        assert result == DECODED_PAYLOAD

    def test_valid_token_without_jti_skips_blacklist_check(self):
        """
        GIVEN  a valid token that has no jti claim
        WHEN   validate_jwt_token() is called
        THEN   blacklist check is skipped and payload is returned

        Tokens without JTI cannot be individually revoked — that's acceptable
        for short-lived access tokens that predate the JTI scheme.
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token

        payload_no_jti = {k: v for k, v in DECODED_PAYLOAD.items() if k != "jti"}
        validator = _make_validator()

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.get_unverified_header",
                   return_value={"kid": "kid-001"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.decode",
                   return_value=payload_no_jti), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.is_token_blacklisted") as mock_bl:

            result = validate_jwt_token("no.jti.token")

        assert result == payload_no_jti
        mock_bl.assert_not_called()

    def test_blacklist_check_error_is_ignored_and_token_accepted(self):
        """
        GIVEN  a valid token but the blacklist check (Redis) raises an unexpected error
        WHEN   validate_jwt_token() is called
        THEN   the error is swallowed and the decoded payload is still returned

        Business rule: Redis outage must NOT block authenticated requests.
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token

        validator = _make_validator()

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.get_unverified_header",
                   return_value={"kid": "kid-001"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.decode",
                   return_value=DECODED_PAYLOAD), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.is_token_blacklisted",
                   side_effect=Exception("Redis timeout")):

            result = validate_jwt_token("valid.despite.redis.down")

        assert result["user_id"] == 1

    # ── failure paths ──────────────────────────────────────────────────────────

    def test_expired_token_raises_401(self):
        """
        GIVEN  an expired JWT
        WHEN   validate_jwt_token() is called
        THEN   HTTPException 401 with 'Token has expired' detail

        Security rule: expired tokens must be rejected immediately.
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token

        validator = _make_validator()

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.get_unverified_header",
                   return_value={"kid": "kid-001"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.decode",
                   side_effect=pyjwt.ExpiredSignatureError("Signature expired")):

            with pytest.raises(HTTPException) as exc_info:
                validate_jwt_token("expired.token")

        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_invalid_token_raises_401(self):
        """
        GIVEN  a malformed or tampered JWT
        WHEN   validate_jwt_token() is called
        THEN   HTTPException 401 with 'Invalid token' detail
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token

        validator = _make_validator()

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.get_unverified_header",
                   return_value={"kid": "kid-001"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.decode",
                   side_effect=pyjwt.InvalidTokenError("Bad signature")):

            with pytest.raises(HTTPException) as exc_info:
                validate_jwt_token("tampered.token")

        assert exc_info.value.status_code == 401
        assert "invalid token" in exc_info.value.detail.lower()

    def test_blacklisted_token_raises_401(self):
        """
        GIVEN  a structurally valid token whose JTI appears in the blacklist
        WHEN   validate_jwt_token() is called
        THEN   HTTPException 401 with 'Token has been revoked'

        Business rule: logout / session invalidation must be immediate via JTI blacklist.
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token

        validator = _make_validator()

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.get_unverified_header",
                   return_value={"kid": "kid-001"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.decode",
                   return_value=DECODED_PAYLOAD), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.is_token_blacklisted",
                   return_value=True):

            with pytest.raises(HTTPException) as exc_info:
                validate_jwt_token("blacklisted.token")

        assert exc_info.value.status_code == 401
        assert "revoked" in exc_info.value.detail.lower()

    def test_unknown_kid_raises_401_via_value_error(self):
        """
        GIVEN  a token signed with a KID not in the validator's cache (e.g. old rotated key)
        WHEN   validate_jwt_token() is called
        THEN   get_signing_key raises ValueError → HTTPException 401

        Security rule: tokens signed with unrecognised keys are rejected.
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token

        validator = _make_validator()
        validator.get_signing_key.side_effect = ValueError("Key ID 'old-kid' not found")

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.get_unverified_header",
                   return_value={"kid": "old-kid"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.decode",
                   return_value={"iss": "https://ums.example.com"}):

            with pytest.raises(HTTPException) as exc_info:
                validate_jwt_token("unknown.kid.token")

        assert exc_info.value.status_code == 401
        assert "not found" in exc_info.value.detail.lower()

    def test_oidc_runtime_error_raises_500(self):
        """
        GIVEN  the OIDC validator raises RuntimeError (e.g. config not loaded)
        WHEN   validate_jwt_token() is called
        THEN   HTTPException 500 — infrastructure error, not an auth failure
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token

        validator = _make_validator()
        validator.get_signing_key.side_effect = RuntimeError("OIDC configuration not loaded")

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.get_unverified_header",
                   return_value={"kid": "kid-001"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.jwt.decode",
                   return_value={"iss": "https://ums.example.com"}):

            with pytest.raises(HTTPException) as exc_info:
                validate_jwt_token("any.token")

        assert exc_info.value.status_code == 500

    def test_unexpected_exception_raises_401(self):
        """
        GIVEN  an unexpected exception during validation (not jwt.* or HTTPException)
        WHEN   validate_jwt_token() is called
        THEN   HTTPException 401 with 'JWT validation failed' — never leaks stack traces
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.get_oidc_validator",
                   side_effect=Exception("Database connection lost")):

            with pytest.raises(HTTPException) as exc_info:
                validate_jwt_token("any.token")

        assert exc_info.value.status_code == 401
        assert "JWT validation failed" in exc_info.value.detail


# ══════════════════════════════════════════════════════════════════════════════
# decode_access_token() — thin wrapper around validate_jwt_token
# ══════════════════════════════════════════════════════════════════════════════

class TestDecodeAccessToken:

    def test_delegates_to_validate_jwt_token(self):
        """
        GIVEN  a valid token
        WHEN   decode_access_token() is called
        THEN   it calls validate_jwt_token and returns the same result

        Note: validate_jwt_token is imported inside the function body
        (lazy import), so we patch it at the source module level.
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils import decode_access_token

        # Patch at the source — the local `from .jwt_validator import validate_jwt_token`
        # re-imports from this path each call, so patching here intercepts it.
        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.validate_jwt_token",
                   return_value=DECODED_PAYLOAD) as mock_validate:

            result = decode_access_token("a.valid.token")

        assert result == DECODED_PAYLOAD
        mock_validate.assert_called_once_with("a.valid.token")

    def test_propagates_http_exception_from_validate(self):
        """
        GIVEN  validate_jwt_token raises HTTPException
        WHEN   decode_access_token() is called
        THEN   the same exception propagates unmodified
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils import decode_access_token

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_validator.validate_jwt_token",
                   side_effect=HTTPException(401, "Token has expired")):

            with pytest.raises(HTTPException) as exc_info:
                decode_access_token("expired.token")

        assert exc_info.value.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# decode_any_token() — no expiry check, used for blacklisting
# ══════════════════════════════════════════════════════════════════════════════

class TestDecodeAnyToken:

    def test_decodes_token_without_expiry_check(self):
        """
        GIVEN  a structurally valid token (even if expired)
        WHEN   decode_any_token() is called
        THEN   returns the decoded payload regardless of expiry

        Business rule: blacklisting must work for already-expired tokens
        (e.g. user logs out after token naturally expired).
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils import decode_any_token

        validator = _make_validator()

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils.jwt.get_unverified_header",
                   return_value={"kid": "kid-001"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils.jwt.decode",
                   return_value=DECODED_PAYLOAD) as mock_decode:

            result = decode_any_token("any.jwt.token")

        # Assert verify_exp is False — the critical requirement
        call_kwargs = mock_decode.call_args[1]
        assert call_kwargs["options"]["verify_exp"] is False
        assert result == DECODED_PAYLOAD

    def test_uses_oidc_validator_signing_key(self):
        """
        GIVEN  a token with a known kid
        WHEN   decode_any_token() is called
        THEN   the signing key is fetched from the OIDC validator by kid
        """
        from Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils import decode_any_token

        validator = _make_validator()

        with patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils.get_oidc_validator",
                   return_value=validator), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils.jwt.get_unverified_header",
                   return_value={"kid": "kid-xyz"}), \
             patch("Backend.Api_Layer.JWT.jwt_validator.auth.jwt_utils.jwt.decode",
                   return_value=DECODED_PAYLOAD):

            decode_any_token("any.jwt.token")

        validator.get_signing_key.assert_called_once_with("kid-xyz")
