"""
tests/unit/Business_Layer/utils/test_password_utils.py

Unit tests for:  Business_Layer/utils/password_utils.py
Functions tested:
  - verify_password()
  - hash_password()   (if exposed)

No DB, no HTTP — pure crypto logic.
"""

import pytest
from fastapi import HTTPException
from Backend.Business_Layer.utils.password_utils import verify_password


class TestVerifyPassword:

    # ── Helper ─────────────────────────────────────────────────────────────

    def _make_hash(self, plain: str) -> str:
        """Hash a plain password for use in tests."""
        from Backend.Business_Layer.utils.password_utils import hash_password
        return hash_password(plain)

    # ── Happy path ─────────────────────────────────────────────────────────

    def test_correct_password_does_not_raise(self):
        """
        GIVEN  a password and its correct bcrypt hash
        WHEN   verify_password() is called
        THEN   no exception is raised
        """
        hashed = self._make_hash("Secret123")
        verify_password("Secret123", hashed)   # must not raise

    def test_correct_password_with_special_chars_does_not_raise(self):
        """Passwords with special characters must also verify correctly."""
        hashed = self._make_hash("P@ssw0rd!#$")
        verify_password("P@ssw0rd!#$", hashed)

    # ── Failure cases ──────────────────────────────────────────────────────

    def test_wrong_password_raises_401(self):
        """
        GIVEN  a correct hash but wrong plain password
        WHEN   verify_password() is called
        THEN   HTTPException with status_code=401 must be raised
        """
        hashed = self._make_hash("Secret123")

        with pytest.raises(HTTPException) as exc_info:
            verify_password("WrongPassword", hashed)

        assert exc_info.value.status_code == 401

    def test_empty_password_raises_exception(self):
        """Empty string as password must fail verification."""
        hashed = self._make_hash("Secret123")

        with pytest.raises((HTTPException, ValueError)):
            verify_password("", hashed)

    def test_case_sensitive_password_raises_401(self):
        """
        GIVEN  'secret123' (lowercase) when hash was made from 'Secret123'
        WHEN   verify_password() is called
        THEN   must raise 401 — passwords are case-sensitive
        """
        hashed = self._make_hash("Secret123")

        with pytest.raises(HTTPException) as exc_info:
            verify_password("secret123", hashed)

        assert exc_info.value.status_code == 401

    def test_similar_password_raises_401(self):
        """A password with an extra space or character must not match."""
        hashed = self._make_hash("Secret123")

        with pytest.raises(HTTPException):
            verify_password("Secret123 ", hashed)   # trailing space


class TestHashPassword:
    def test_hash_password_returns_string(self):
        from Backend.Business_Layer.utils.password_utils import hash_password
        result = hash_password("MyPassword123")
        assert isinstance(result, str)
        assert result.startswith("$2b$")

    def test_hash_password_different_hashes_same_input(self):
        """bcrypt produces unique hashes (salt) for the same input."""
        from Backend.Business_Layer.utils.password_utils import hash_password
        h1 = hash_password("MyPassword")
        h2 = hash_password("MyPassword")
        assert h1 != h2


class TestCheckPasswordMatch:
    def test_returns_true_for_correct_password(self):
        from Backend.Business_Layer.utils.password_utils import hash_password, check_password_match
        hashed = hash_password("Correct123")
        assert check_password_match("Correct123", hashed) is True

    def test_returns_false_for_wrong_password(self):
        from Backend.Business_Layer.utils.password_utils import hash_password, check_password_match
        hashed = hash_password("Correct123")
        assert check_password_match("Wrong123", hashed) is False
