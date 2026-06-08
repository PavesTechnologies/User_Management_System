"""
tests/unit/Business_Layer/utils/test_input_validators.py

Unit tests for:  Business_Layer/utils/input_validators.py
Function tested: validate_email_format()

No mocking needed — pure logic function.
"""

import pytest
from fastapi import HTTPException


# ─────────────────────────────────────────────────────────────────────────────
# Import the function under test
# ─────────────────────────────────────────────────────────────────────────────

from Backend.Business_Layer.utils.input_validators import (
    validate_email_format,
    validate_contact_number,
    validate_name,
    validate_password_strength,
)


class TestValidateEmailFormat:

    # ── Happy path ─────────────────────────────────────────────────────────

    def test_valid_email_does_not_raise(self):
        """
        GIVEN  a properly formatted email
        WHEN   validate_email_format() is called
        THEN   no exception is raised
        """
        validate_email_format("user@example.com")   # must not raise

    def test_valid_email_with_subdomain_does_not_raise(self):
        """Subdomains like user@mail.example.com must be valid."""
        validate_email_format("user@mail.example.com")

    def test_valid_email_with_plus_tag_does_not_raise(self):
        """Plus-tagged emails like user+tag@example.com must be valid."""
        validate_email_format("user+tag@example.com")

    # ── Failure cases ──────────────────────────────────────────────────────

    def test_missing_at_symbol_raises_422(self):
        """
        GIVEN  an email missing the @ symbol
        WHEN   validate_email_format() is called
        THEN   HTTPException 422 must be raised
        """
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("userexample.com")
        assert exc_info.value.status_code == 422

    def test_missing_domain_raises_422(self):
        """Email with no domain part (user@) must fail."""
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("user@")
        assert exc_info.value.status_code == 422

    def test_missing_local_part_raises_422(self):
        """Email with no local part (@example.com) must fail."""
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("@example.com")
        assert exc_info.value.status_code == 422

    def test_empty_string_raises_422(self):
        """Empty string must not pass email validation."""
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("")
        assert exc_info.value.status_code == 422

    def test_whitespace_only_raises_422(self):
        """Whitespace-only string must fail."""
        with pytest.raises(HTTPException):
            validate_email_format("   ")

    def test_none_raises_exception(self):
        """None must raise an exception (TypeError or HTTPException)."""
        with pytest.raises((HTTPException, TypeError, AttributeError)):
            validate_email_format(None)

    def test_plain_text_no_at_raises_422(self):
        """Plain text without any email structure must fail."""
        with pytest.raises(HTTPException) as exc_info:
            validate_email_format("notanemail")
        assert exc_info.value.status_code == 422


class TestValidateContactNumber:

    def test_valid_number_does_not_raise(self):
        validate_contact_number("9876543210")

    def test_valid_number_with_plus_prefix(self):
        validate_contact_number("+919876543210")

    def test_too_short_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            validate_contact_number("12345")
        assert exc.value.status_code == 400

    def test_non_digits_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            validate_contact_number("987-654-3210")
        assert exc.value.status_code == 400


class TestValidateName:

    def test_valid_name_does_not_raise(self):
        validate_name("John Doe")

    def test_name_with_hyphen_does_not_raise(self):
        validate_name("Mary-Jane")

    def test_name_with_apostrophe_does_not_raise(self):
        validate_name("O'Brien")

    def test_name_with_digit_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            validate_name("John2")
        assert exc.value.status_code == 400

    def test_name_with_special_char_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            validate_name("John@Doe")
        assert exc.value.status_code == 400


class TestValidatePasswordStrength:

    def test_valid_password_does_not_raise(self):
        validate_password_strength("Secure@123")

    def test_too_short_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            validate_password_strength("Ab@1")
        assert exc.value.status_code == 400

    def test_no_uppercase_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            validate_password_strength("secure@123")
        assert exc.value.status_code == 400

    def test_no_lowercase_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            validate_password_strength("SECURE@123")
        assert exc.value.status_code == 400

    def test_no_digit_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            validate_password_strength("Secure@abc")
        assert exc.value.status_code == 400

    def test_no_special_char_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            validate_password_strength("SecurePass123")
        assert exc.value.status_code == 400
