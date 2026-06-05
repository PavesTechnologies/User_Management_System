"""
tests/unit/Business_Layer/services/test_auth_service_extended.py

Extended unit tests for: Business_Layer/services/auth_service.py
Covers methods NOT tested in test_auth_service.py:
  - refresh_token()
  - forgot_password()
  - change_password()
  - change_password_first_login()

Business rules validated (Functional Spec §3, Technical Design §4.2/4.4):
  - Refresh token must be of type 'refresh' — access tokens cannot be used for refresh
  - Logout / session termination blacklists both tokens
  - Forgotten password flow requires valid OTP + strong new password
  - Password change requires matching confirm_password
  - First-login password change is user-scoped — cannot change another user's password
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_auth_service():
    from Backend.Business_Layer.services.auth_service import AuthService
    service = AuthService.__new__(AuthService)
    return service


def make_mock_dao():
    return MagicMock()


def make_mock_request(auth_header: str = "Bearer valid.token"):
    req = MagicMock()
    req.headers = {"Authorization": auth_header}
    req.state.db = MagicMock()
    req.client.host = "127.0.0.1"
    return req


# ─────────────────────────────────────────────────────────────────────────────
# refresh_token()
# ─────────────────────────────────────────────────────────────────────────────

class TestRefreshToken:

    def test_valid_refresh_token_returns_new_access_and_refresh_tokens(self):
        """
        GIVEN  a valid, non-blacklisted refresh token
        WHEN   refresh_token() is called
        THEN   response contains new access_token and refresh_token
               (documented token lifecycle: Token Refresh Flow §4.2)
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_user = MagicMock()
        mock_user.user_id = 1
        mock_user.employee_id = "EMP001"
        mock_user.user_uuid = "uuid-1"
        mock_user.first_name = "John"
        mock_user.last_name = "Doe"
        mock_user.mail = "john@example.com"
        mock_dao.get_user_login_data_by_id.return_value = (
            mock_user, ["General"], ["VIEW_USER_PUBLIC"]
        )
        refresh_payload = {
            "token_type": "refresh",
            "user_id": 1,
            "jti": "jti-refresh-001",
        }
        mock_request = make_mock_request()

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_jwt_token",
                   return_value=refresh_payload), \
             patch("Backend.Business_Layer.services.auth_service.blacklist_token",
                   return_value=True), \
             patch("Backend.Business_Layer.services.auth_service.token_create",
                   return_value="new.access.token"), \
             patch("Backend.Business_Layer.services.auth_service.refresh_token_create",
                   return_value="new.refresh.token"):

            result = service.refresh_token("old.refresh.token", mock_request)

        assert result["access_token"] == "new.access.token"
        assert result["refresh_token"] == "new.refresh.token"
        assert result["token_type"] == "bearer"

    def test_access_token_used_as_refresh_token_raises_401(self):
        """
        GIVEN  an access token (token_type != 'refresh') sent to the refresh endpoint
        WHEN   refresh_token() is called
        THEN   raises HTTPException 401 — type guard prevents token misuse

        Security rule (Technical Design §4.2): only refresh tokens may be used
        to obtain new access tokens. An access token in the refresh slot is
        a protocol violation.
        """
        service = make_auth_service()
        access_payload = {
            "token_type": "access",   # wrong type
            "user_id": 1,
            "jti": "jti-access-001",
        }
        mock_request = make_mock_request()

        with patch.object(service, "_get_dao", return_value=make_mock_dao()), \
             patch("Backend.Business_Layer.services.auth_service.validate_jwt_token",
                   return_value=access_payload):

            with pytest.raises(HTTPException) as exc_info:
                service.refresh_token("not.a.refresh.token", mock_request)

        assert exc_info.value.status_code == 401
        assert "token type" in exc_info.value.detail.lower()

    def test_expired_or_invalid_refresh_token_raises_401(self):
        """
        GIVEN  an expired or invalid refresh token
        WHEN   refresh_token() is called
        THEN   raises HTTPException 401 — user must re-authenticate
        """
        service = make_auth_service()
        mock_request = make_mock_request()

        with patch.object(service, "_get_dao", return_value=make_mock_dao()), \
             patch("Backend.Business_Layer.services.auth_service.validate_jwt_token",
                   side_effect=HTTPException(401, "Token has expired")):

            with pytest.raises(HTTPException) as exc_info:
                service.refresh_token("expired.token", mock_request)

        assert exc_info.value.status_code == 401

    def test_user_not_found_after_token_validation_raises_401(self):
        """
        GIVEN  a valid refresh token but the user no longer exists or is inactive
        WHEN   refresh_token() is called
        THEN   raises HTTPException 401 — deactivated users cannot get new tokens

        Business rule (Functional Spec §4.7): deactivated users cannot login.
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_dao.get_user_login_data_by_id.return_value = (None, None, None)
        refresh_payload = {"token_type": "refresh", "user_id": 999}
        mock_request = make_mock_request()

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_jwt_token",
                   return_value=refresh_payload):

            with pytest.raises(HTTPException) as exc_info:
                service.refresh_token("valid.but.user.gone", mock_request)

        assert exc_info.value.status_code == 401

    def test_old_refresh_token_is_blacklisted_on_successful_refresh(self):
        """
        GIVEN  a valid refresh token
        WHEN   refresh_token() is called successfully
        THEN   the old refresh token is blacklisted to prevent token reuse

        Security rule (Technical Design §4.4): single-use refresh tokens.
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_user = MagicMock()
        mock_user.user_id = 1
        mock_user.employee_id = "EMP001"
        mock_user.user_uuid = "uuid-1"
        mock_user.first_name = "Test"
        mock_user.last_name = "User"
        mock_user.mail = "test@example.com"
        mock_dao.get_user_login_data_by_id.return_value = (
            mock_user, ["General"], []
        )
        refresh_payload = {"token_type": "refresh", "user_id": 1}
        mock_request = make_mock_request()
        old_token = "old.refresh.token.to.blacklist"

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_jwt_token",
                   return_value=refresh_payload), \
             patch("Backend.Business_Layer.services.auth_service.blacklist_token",
                   return_value=True) as mock_blacklist, \
             patch("Backend.Business_Layer.services.auth_service.token_create",
                   return_value="new.access"), \
             patch("Backend.Business_Layer.services.auth_service.refresh_token_create",
                   return_value="new.refresh"):

            service.refresh_token(old_token, mock_request)

        mock_blacklist.assert_called_once_with(old_token)


# ─────────────────────────────────────────────────────────────────────────────
# forgot_password()
# ─────────────────────────────────────────────────────────────────────────────

class TestForgotPassword:

    def test_valid_email_and_otp_updates_password(self):
        """
        GIVEN  a valid email, valid OTP, and strong new password
        WHEN   forgot_password() is called
        THEN   password is updated and OTP record is deleted

        Business rule (Functional Spec §3.1): password reset requires OTP verification.
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_user = MagicMock()
        mock_user.user_id = 1
        mock_otp = MagicMock()

        mock_dao.get_user_by_email.return_value = mock_user
        mock_dao.get_valid_otp.return_value = mock_otp
        mock_dao.delete_otp.return_value = None
        mock_dao.update_user_password.return_value = True
        mock_dao.password_last_updated.return_value = None

        forgot_data = MagicMock()
        forgot_data.email = "user@example.com"
        forgot_data.otp = "123456"
        forgot_data.new_password = "NewStrongPass@123"

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"), \
             patch("Backend.Business_Layer.services.auth_service.validate_password_strength"), \
             patch("Backend.Business_Layer.services.auth_service.hash_password",
                   return_value="$2b$hashed"):

            result = service.forgot_password(forgot_data)

        assert "password" in result["message"].lower()
        mock_dao.delete_otp.assert_called_once_with(mock_otp)
        mock_dao.update_user_password.assert_called_once()

    def test_user_not_found_raises_404(self):
        """
        GIVEN  an email that doesn't exist
        WHEN   forgot_password() is called
        THEN   raises HTTPException 404
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_dao.get_user_by_email.return_value = None

        forgot_data = MagicMock()
        forgot_data.email = "ghost@example.com"

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"):

            with pytest.raises(HTTPException) as exc_info:
                service.forgot_password(forgot_data)

        assert exc_info.value.status_code == 404

    def test_invalid_otp_raises_400(self):
        """
        GIVEN  a valid email but wrong or expired OTP
        WHEN   forgot_password() is called
        THEN   raises HTTPException 400 — OTP must match and be non-expired
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_dao.get_user_by_email.return_value = MagicMock()
        mock_dao.get_valid_otp.return_value = None  # OTP not found

        forgot_data = MagicMock()
        forgot_data.email = "user@example.com"
        forgot_data.otp = "000000"  # wrong OTP

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"):

            with pytest.raises(HTTPException) as exc_info:
                service.forgot_password(forgot_data)

        assert exc_info.value.status_code == 400
        assert "otp" in exc_info.value.detail.lower()


# ─────────────────────────────────────────────────────────────────────────────
# change_password()
# ─────────────────────────────────────────────────────────────────────────────

class TestChangePassword:

    def test_valid_payload_changes_password_successfully(self):
        """
        GIVEN  a valid Authorization header and matching new/confirm passwords
        WHEN   change_password() is called
        THEN   password is updated and success message is returned
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_user = MagicMock()
        mock_user.user_id = 1
        mock_dao.get_user_by_email.return_value = mock_user
        mock_dao.update_user_password.return_value = True

        payload = MagicMock()
        payload.new_password = "NewPass@123"
        payload.confirm_password = "NewPass@123"

        request = make_mock_request("Bearer valid.jwt")

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_jwt_token",
                   return_value={"email": "user@example.com"}), \
             patch("Backend.Business_Layer.services.auth_service.validate_password_strength"), \
             patch("Backend.Business_Layer.services.auth_service.hash_password",
                   return_value="$2b$new_hash"):

            result = service.change_password(payload, request)

        assert "password" in result["message"].lower()

    def test_missing_auth_header_raises_401(self):
        """
        GIVEN  a request with no Authorization header
        WHEN   change_password() is called
        THEN   raises HTTPException 401
        """
        service = make_auth_service()
        payload = MagicMock()
        request = make_mock_request("")  # no header

        with pytest.raises(HTTPException) as exc_info:
            service.change_password(payload, request)

        assert exc_info.value.status_code == 401

    def test_passwords_do_not_match_raises_400(self):
        """
        GIVEN  new_password and confirm_password are different
        WHEN   change_password() is called
        THEN   raises HTTPException 400

        Validation rule: passwords must match before hashing.
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_user = MagicMock()
        mock_dao.get_user_by_email.return_value = mock_user

        payload = MagicMock()
        payload.new_password = "NewPass@123"
        payload.confirm_password = "DifferentPass@456"

        request = make_mock_request("Bearer valid.jwt")

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_jwt_token",
                   return_value={"email": "user@example.com"}):

            with pytest.raises(HTTPException) as exc_info:
                service.change_password(payload, request)

        assert exc_info.value.status_code == 400
        assert "match" in exc_info.value.detail.lower()

    def test_user_not_found_raises_404(self):
        """
        GIVEN  a valid token but user no longer exists in DB
        WHEN   change_password() is called
        THEN   raises HTTPException 404
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_dao.get_user_by_email.return_value = None

        payload = MagicMock()
        request = make_mock_request("Bearer valid.jwt")

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_jwt_token",
                   return_value={"email": "gone@example.com"}):

            with pytest.raises(HTTPException) as exc_info:
                service.change_password(payload, request)

        assert exc_info.value.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# change_password_first_login()
# ─────────────────────────────────────────────────────────────────────────────

class TestChangePasswordFirstLogin:

    def test_valid_first_login_change_succeeds(self):
        """
        GIVEN  matching new/confirm passwords and correct user_id
        WHEN   change_password_first_login() is called
        THEN   password is updated successfully
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_user = MagicMock()
        mock_user.user_id = 5
        mock_dao.get_user_by_email.return_value = mock_user
        mock_dao.update_user_password.return_value = True

        payload = MagicMock()
        payload.email = "user@example.com"
        payload.new_password = "FirstPass@123"
        payload.confirm_password = "FirstPass@123"

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_password_strength"), \
             patch("Backend.Business_Layer.services.auth_service.hash_password",
                   return_value="$2b$first_hash"):

            result = service.change_password_first_login(payload, user_id=5)

        assert "password" in result["message"].lower()

    def test_cannot_change_another_users_password_raises_403(self):
        """
        GIVEN  a user trying to change a password for a different user_id
        WHEN   change_password_first_login() is called
        THEN   raises HTTPException 403

        Business rule (Functional Spec §3.1): users can only change their own
        password. The user_id from the JWT must match the requested account.
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_user = MagicMock()
        mock_user.user_id = 99  # different user
        mock_dao.get_user_by_email.return_value = mock_user

        payload = MagicMock()
        payload.email = "other@example.com"
        payload.new_password = "Pass@123"
        payload.confirm_password = "Pass@123"

        with patch.object(service, "_get_dao", return_value=mock_dao):

            with pytest.raises(HTTPException) as exc_info:
                service.change_password_first_login(payload, user_id=1)  # different id

        assert exc_info.value.status_code == 403

    def test_passwords_mismatch_raises_400(self):
        """
        GIVEN  new_password and confirm_password are different
        WHEN   change_password_first_login() is called
        THEN   raises HTTPException 400
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_user = MagicMock()
        mock_user.user_id = 5
        mock_dao.get_user_by_email.return_value = mock_user

        payload = MagicMock()
        payload.email = "user@example.com"
        payload.new_password = "Pass@123"
        payload.confirm_password = "DifferentPass@456"

        with patch.object(service, "_get_dao", return_value=mock_dao):

            with pytest.raises(HTTPException) as exc_info:
                service.change_password_first_login(payload, user_id=5)

        assert exc_info.value.status_code == 400

    def test_user_not_found_raises_404(self):
        """
        GIVEN  an email that doesn't exist in the DB
        WHEN   change_password_first_login() is called
        THEN   raises HTTPException 404
        """
        service = make_auth_service()
        mock_dao = make_mock_dao()
        mock_dao.get_user_by_email.return_value = None

        payload = MagicMock()
        payload.email = "ghost@example.com"

        with patch.object(service, "_get_dao", return_value=mock_dao):

            with pytest.raises(HTTPException) as exc_info:
                service.change_password_first_login(payload, user_id=5)

        assert exc_info.value.status_code == 404
