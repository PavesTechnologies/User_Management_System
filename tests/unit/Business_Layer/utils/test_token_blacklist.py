"""
tests/unit/Business_Layer/utils/test_token_blacklist.py

Unit tests for: Business_Layer/utils/token_blacklist.py
Functions:       blacklist_token(), is_token_blacklisted()

Business rules validated (Functional Spec §4.7 / Technical Design §3.4):
  - User deactivation / logout MUST invalidate active sessions
  - Token revocation is via JTI blacklist (not key rotation)
  - Dual-layer cache: local in-memory (instant) + Redis (persistent, best-effort)
  - Redis failure MUST NOT prevent blacklisting — local cache is the safety net
  - Expired tokens (TTL <= 0) are not added to blacklist (they expire anyway)
  - is_token_blacklisted() checks local cache first, Redis only on cache miss

What is NOT tested here (mocked away):
  - Real JWT decoding     → tested in test_jwt_encode.py
  - Real Redis connection → redis_client is mocked
"""

import time
import pytest
from unittest.mock import patch, MagicMock
import Backend.Business_Layer.utils.token_blacklist as bl_module


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _clear_local_blacklist():
    """Clear module-level local cache between tests to avoid state leakage."""
    bl_module._local_blacklist.clear()


def _make_payload(jti: str = "test-jti-001", exp_offset: int = 3600) -> dict:
    """Returns a decoded JWT payload dict with exp in the future."""
    return {"jti": jti, "exp": time.time() + exp_offset}


# ─────────────────────────────────────────────────────────────────────────────
# blacklist_token()
# ─────────────────────────────────────────────────────────────────────────────

class TestBlacklistToken:

    def setup_method(self):
        _clear_local_blacklist()

    def test_valid_token_is_added_to_local_cache(self):
        """
        GIVEN  a valid JWT with jti and future exp
        WHEN   blacklist_token() is called
        THEN   jti is added to in-memory cache immediately (zero-latency revocation)
        """
        jti = "jti-cache-001"
        payload = _make_payload(jti=jti)

        with patch("Backend.Business_Layer.utils.token_blacklist.decode_any_token",
                   return_value=payload), \
             patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=None):

            result = bl_module.blacklist_token("some.jwt.token")

        assert result is True
        assert jti in bl_module._local_blacklist

    def test_valid_token_also_written_to_redis_when_available(self):
        """
        GIVEN  a valid JWT and Redis is available
        WHEN   blacklist_token() is called
        THEN   jti is persisted to Redis with correct TTL (for cross-instance revocation)
        """
        jti = "jti-redis-001"
        payload = _make_payload(jti=jti)
        mock_redis = MagicMock()

        with patch("Backend.Business_Layer.utils.token_blacklist.decode_any_token",
                   return_value=payload), \
             patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=mock_redis):

            result = bl_module.blacklist_token("some.jwt.token")

        assert result is True
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args[0]
        assert call_args[0] == f"blacklist:{jti}"
        assert call_args[2] == "1"

    def test_redis_failure_does_not_prevent_local_blacklisting(self):
        """
        GIVEN  a valid JWT but Redis raises an exception
        WHEN   blacklist_token() is called
        THEN   token is STILL added to local cache (Redis failure is best-effort)

        Business rule: logout must work even when Redis is down.
        """
        jti = "jti-redis-fail-001"
        payload = _make_payload(jti=jti)
        mock_redis = MagicMock()
        mock_redis.setex.side_effect = Exception("Redis connection refused")

        with patch("Backend.Business_Layer.utils.token_blacklist.decode_any_token",
                   return_value=payload), \
             patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=mock_redis):

            result = bl_module.blacklist_token("some.jwt.token")

        # Local cache must still work even when Redis fails
        assert result is True
        assert jti in bl_module._local_blacklist

    def test_expired_token_is_not_added_to_blacklist(self):
        """
        GIVEN  a JWT whose exp is in the past (TTL <= 0)
        WHEN   blacklist_token() is called
        THEN   returns False and nothing is added to cache (expired tokens auto-expire)

        Business rule: already-expired tokens need no explicit revocation.
        """
        jti = "jti-expired-001"
        payload = _make_payload(jti=jti, exp_offset=-100)  # already expired

        with patch("Backend.Business_Layer.utils.token_blacklist.decode_any_token",
                   return_value=payload), \
             patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=None):

            result = bl_module.blacklist_token("expired.jwt.token")

        assert result is False
        assert jti not in bl_module._local_blacklist

    def test_token_without_jti_is_not_blacklisted(self):
        """
        GIVEN  a JWT that has no jti claim
        WHEN   blacklist_token() is called
        THEN   returns False — cannot blacklist without a unique token ID
        """
        payload = {"exp": time.time() + 3600}  # no jti

        with patch("Backend.Business_Layer.utils.token_blacklist.decode_any_token",
                   return_value=payload), \
             patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=None):

            result = bl_module.blacklist_token("no.jti.token")

        assert result is False

    def test_invalid_token_decode_failure_returns_false(self):
        """
        GIVEN  a malformed or invalid JWT string
        WHEN   blacklist_token() is called
        THEN   exception is swallowed gracefully, returns False — no crash
        """
        with patch("Backend.Business_Layer.utils.token_blacklist.decode_any_token",
                   side_effect=Exception("Invalid token")), \
             patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=None):

            result = bl_module.blacklist_token("garbage.token")

        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# is_token_blacklisted()
# ─────────────────────────────────────────────────────────────────────────────

class TestIsTokenBlacklisted:

    def setup_method(self):
        _clear_local_blacklist()

    def test_returns_true_when_jti_in_local_cache(self):
        """
        GIVEN  a jti that was blacklisted (present in local cache with future expiry)
        WHEN   is_token_blacklisted() is called
        THEN   returns True immediately (no Redis call needed)

        Performance rule: local cache = zero-latency check.
        """
        jti = "jti-local-001"
        bl_module._local_blacklist[jti] = time.time() + 3600  # future expiry

        with patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=None) as mock_redis_fn:

            result = bl_module.is_token_blacklisted(jti)

        assert result is True
        mock_redis_fn.assert_not_called()  # Redis must NOT be hit when local cache has it

    def test_returns_false_and_removes_expired_jti_from_local_cache(self):
        """
        GIVEN  a jti that is in local cache but has expired
        WHEN   is_token_blacklisted() is called
        THEN   returns False and removes the stale entry from local cache
        """
        jti = "jti-expired-local-001"
        bl_module._local_blacklist[jti] = time.time() - 1  # already expired

        with patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=None):

            result = bl_module.is_token_blacklisted(jti)

        assert result is False
        assert jti not in bl_module._local_blacklist

    def test_returns_true_when_jti_found_in_redis(self):
        """
        GIVEN  a jti not in local cache but present in Redis
        WHEN   is_token_blacklisted() is called
        THEN   returns True and populates local cache for subsequent fast lookups
        """
        jti = "jti-redis-only-001"
        mock_redis = MagicMock()
        mock_redis.exists.return_value = 1
        mock_redis.ttl.return_value = 1800

        with patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=mock_redis):

            result = bl_module.is_token_blacklisted(jti)

        assert result is True
        # Should now be in local cache too
        assert jti in bl_module._local_blacklist

    def test_returns_false_when_jti_not_in_any_store(self):
        """
        GIVEN  a jti that has not been blacklisted
        WHEN   is_token_blacklisted() is called
        THEN   returns False — valid token should pass through
        """
        jti = "jti-valid-token-001"
        mock_redis = MagicMock()
        mock_redis.exists.return_value = 0

        with patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=mock_redis):

            result = bl_module.is_token_blacklisted(jti)

        assert result is False

    def test_redis_unavailable_does_not_raise(self):
        """
        GIVEN  Redis is unavailable (get_redis_client returns None)
        WHEN   is_token_blacklisted() is called for an unknown jti
        THEN   returns False gracefully — system stays available

        Business rule: Redis outage must not block all authenticated requests.
        """
        jti = "jti-no-redis-001"

        with patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=None):

            result = bl_module.is_token_blacklisted(jti)

        assert result is False

    def test_redis_exception_returns_false(self):
        """
        GIVEN  Redis raises an exception during lookup
        WHEN   is_token_blacklisted() is called
        THEN   exception is swallowed, returns False — fail open for availability
        """
        jti = "jti-redis-error-001"
        mock_redis = MagicMock()
        mock_redis.exists.side_effect = Exception("Redis timeout")

        with patch("Backend.Business_Layer.utils.token_blacklist.get_redis_client",
                   return_value=mock_redis):

            result = bl_module.is_token_blacklisted(jti)

        assert result is False
