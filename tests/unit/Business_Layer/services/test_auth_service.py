"""
tests/unit/Business_Layer/services/test_auth_service.py

Unit tests for:  Business_Layer/services/auth_service.py
Mirrors:         auth_service.login_user()

What is tested here:
  - login_user() orchestration logic
  - Correct redirect based on first-login status
  - Correct response shape
  - User not found raises 404
  - Wrong password raises 401
  - Invalid email format raises 422

What is NOT tested here (mocked away):
  - Real DB queries           → tested in integration tests
  - Real password hashing     → tested in test_password_utils.py
  - Real JWT encoding         → tested in test_jwt_encode.py
  - Real email validation     → tested in test_input_validators.py
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException


# ─────────────────────────────────────────────────────────────────────────────
# Helper — build an AuthService instance without triggering __init__ DB setup
# ─────────────────────────────────────────────────────────────────────────────

def make_auth_service():
    """
    Creates AuthService bypassing __init__ so no real DB connection is made.
    We inject a fully mocked DAO instead.
    """
    # Import here so missing modules don't break collection
    from Backend.Business_Layer.services.auth_service import AuthService
    service = AuthService.__new__(AuthService)
    return service


def make_mock_dao(user_row, roles=None, permissions=None, is_first_login=False):
    """
    Builds a mocked DAO pre-configured with given return values.
    Keeps individual tests clean — they just declare what the DB 'returns'.
    """
    dao = MagicMock()
    dao.get_user_login_data.return_value = (
        user_row,
        roles or ["viewer"],
        permissions or ["read"]
    )
    dao.check_user_first_login.return_value = is_first_login
    dao.update_last_login.return_value = None
    return dao


# ─────────────────────────────────────────────────────────────────────────────
# Happy path tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginUserHappyPath:

    def test_login_user_valid_credentials_returns_access_token(
        self, mock_user_row, login_credentials, mock_request
    ):
        """
        GIVEN  valid email and correct password
        WHEN   login_user() is called
        THEN   response must contain access_token and refresh_token as non-empty strings
               (login now issues both tokens per documented token lifecycle)
        """
        # Arrange
        service = make_auth_service()
        mock_dao = make_mock_dao(mock_user_row)

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"), \
             patch("Backend.Business_Layer.services.auth_service.verify_password"), \
             patch("Backend.Business_Layer.services.auth_service.token_create",
                   return_value="mocked.jwt.token"), \
             patch("Backend.Business_Layer.services.auth_service.refresh_token_create",
                   return_value="mocked.refresh.token"):

            # Act
            result = service.login_user(login_credentials, "127.0.0.1", mock_request)

        # Assert
        assert "access_token" in result
        assert result["access_token"] == "mocked.jwt.token"
        assert "refresh_token" in result
        assert result["refresh_token"] == "mocked.refresh.token"

    def test_login_user_valid_credentials_returns_bearer_token_type(
        self, mock_user_row, login_credentials, mock_request
    ):
        """
        GIVEN  valid credentials
        WHEN   login_user() is called
        THEN   token_type in response must always be 'bearer'
        """
        # Arrange
        service = make_auth_service()
        mock_dao = make_mock_dao(mock_user_row)

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"), \
             patch("Backend.Business_Layer.services.auth_service.verify_password"), \
             patch("Backend.Business_Layer.services.auth_service.token_create",
                   return_value="tok"), \
             patch("Backend.Business_Layer.services.auth_service.refresh_token_create",
                   return_value="refresh.tok"):

            # Act
            result = service.login_user(login_credentials, "127.0.0.1", mock_request)

        # Assert
        assert result["token_type"] == "bearer"

    def test_login_user_returning_user_redirects_to_dashboard(
        self, mock_user_row, login_credentials, mock_request
    ):
        """
        GIVEN  a user who has logged in before (last_login_at is set)
        WHEN   login_user() is called
        THEN   redirect must be '/dashboard'
        """
        # Arrange
        service  = make_auth_service()
        mock_dao = make_mock_dao(mock_user_row, is_first_login=False)

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"), \
             patch("Backend.Business_Layer.services.auth_service.verify_password"), \
             patch("Backend.Business_Layer.services.auth_service.token_create",
                   return_value="tok"), \
             patch("Backend.Business_Layer.services.auth_service.refresh_token_create",
                   return_value="refresh.tok"):

            # Act
            result = service.login_user(login_credentials, "127.0.0.1", mock_request)

        # Assert
        assert result["redirect"] == "/dashboard"

    def test_login_user_first_time_login_redirects_to_change_password(
        self, mock_first_login_user_row, mock_request
    ):
        """
        GIVEN  a user logging in for the first time (last_login_at is None)
        WHEN   login_user() is called
        THEN   redirect must be '/change-password' so user sets a new password
        """
        # Arrange
        service  = make_auth_service()
        creds    = MagicMock()
        creds.email    = mock_first_login_user_row.mail
        creds.password = "Secret123"

        mock_dao = make_mock_dao(mock_first_login_user_row, is_first_login=True)

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"), \
             patch("Backend.Business_Layer.services.auth_service.verify_password"), \
             patch("Backend.Business_Layer.services.auth_service.token_create",
                   return_value="tok"), \
             patch("Backend.Business_Layer.services.auth_service.refresh_token_create",
                   return_value="refresh.tok"):

            # Act
            result = service.login_user(creds, "127.0.0.1", mock_request)

        # Assert
        assert result["redirect"] == "/change-password"

    def test_login_user_calls_update_last_login_with_correct_ip(
        self, mock_user_row, login_credentials, mock_request
    ):
        """
        GIVEN  a successful login from IP 192.168.1.1
        WHEN   login_user() completes
        THEN   update_last_login must be called with that exact user_id and IP
        """
        # Arrange
        service  = make_auth_service()
        mock_dao = make_mock_dao(mock_user_row)
        client_ip = "192.168.1.1"

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"), \
             patch("Backend.Business_Layer.services.auth_service.verify_password"), \
             patch("Backend.Business_Layer.services.auth_service.token_create",
                   return_value="tok"), \
             patch("Backend.Business_Layer.services.auth_service.refresh_token_create",
                   return_value="refresh.tok"):

            # Act
            service.login_user(login_credentials, client_ip, mock_request)

        # Assert — verify the DAO was called with correct args
        mock_dao.update_last_login.assert_called_once_with(
            mock_user_row.user_id, client_ip
        )

    def test_login_user_token_contains_correct_user_data(
        self, mock_user_row, login_credentials, mock_request
    ):
        """
        GIVEN  a valid login
        WHEN   token_create is called inside login_user
        THEN   token payload must include user_id, email, name, roles, permissions
        """
        # Arrange
        service  = make_auth_service()
        mock_dao = make_mock_dao(
            mock_user_row,
            roles=["admin"],
            permissions=["read", "write"]
        )
        captured_token_data = {}

        def capture_token_create(token_data, **kwargs):
            captured_token_data.update(token_data)
            return "tok"

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"), \
             patch("Backend.Business_Layer.services.auth_service.verify_password"), \
             patch("Backend.Business_Layer.services.auth_service.token_create",
                   side_effect=capture_token_create), \
             patch("Backend.Business_Layer.services.auth_service.refresh_token_create",
                   return_value="refresh.tok"):

            # Act
            service.login_user(login_credentials, "127.0.0.1", mock_request)

        # Assert — token payload must carry the right fields
        assert captured_token_data["user_id"]     == mock_user_row.user_id
        assert captured_token_data["email"]       == mock_user_row.mail
        assert "admin" in captured_token_data["roles"]
        assert "read"  in captured_token_data["permissions"]


# ─────────────────────────────────────────────────────────────────────────────
# Failure / error path tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginUserFailurePaths:

    def test_login_user_not_found_raises_404(
        self, login_credentials, mock_request
    ):
        """
        GIVEN  an email that does not exist in the DB (or user is inactive)
        WHEN   login_user() is called
        THEN   HTTPException with status_code=404 must be raised
        """
        # Arrange
        service  = make_auth_service()
        mock_dao = MagicMock()
        mock_dao.get_user_login_data.return_value = (None, [], [])  # no user

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"):

            # Act + Assert
            with pytest.raises(HTTPException) as exc_info:
                service.login_user(login_credentials, "127.0.0.1", mock_request)

        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail.lower()

    def test_login_user_wrong_password_raises_401(
        self, mock_user_row, login_credentials_wrong_password, mock_request
    ):
        """
        GIVEN  a valid email but wrong password
        WHEN   login_user() is called
        THEN   HTTPException with status_code=401 must be raised
               verify_password raises 401 — login_user must let it bubble up
        """
        # Arrange
        service  = make_auth_service()
        mock_dao = make_mock_dao(mock_user_row)

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"), \
             patch("Backend.Business_Layer.services.auth_service.verify_password",
                   side_effect=HTTPException(
                       status_code=401, detail="Incorrect password"
                   )):

            # Act + Assert
            with pytest.raises(HTTPException) as exc_info:
                service.login_user(
                    login_credentials_wrong_password, "127.0.0.1", mock_request
                )

        assert exc_info.value.status_code == 401

    def test_login_user_invalid_email_format_raises_422(
        self, login_credentials_bad_email, mock_request
    ):
        """
        GIVEN  an email in invalid format (e.g. 'not-an-email')
        WHEN   login_user() is called
        THEN   HTTPException with status_code=422 must be raised
               validate_email_format raises 422 — login_user must not swallow it
        """
        # Arrange
        service  = make_auth_service()
        mock_dao = MagicMock()

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format",
                   side_effect=HTTPException(
                       status_code=422, detail="Invalid email format"
                   )):

            # Act + Assert
            with pytest.raises(HTTPException) as exc_info:
                service.login_user(
                    login_credentials_bad_email, "127.0.0.1", mock_request
                )

        assert exc_info.value.status_code == 422

    def test_login_user_user_not_found_does_not_call_verify_password(
        self, login_credentials, mock_request
    ):
        """
        GIVEN  a user that does not exist
        WHEN   login_user() raises 404
        THEN   verify_password must NOT be called
               (we must not try to verify a password for a non-existent user)
        """
        # Arrange
        service  = make_auth_service()
        mock_dao = MagicMock()
        mock_dao.get_user_login_data.return_value = (None, [], [])

        with patch.object(service, "_get_dao", return_value=mock_dao), \
             patch("Backend.Business_Layer.services.auth_service.validate_email_format"), \
             patch("Backend.Business_Layer.services.auth_service.verify_password") as mock_verify:

            with pytest.raises(HTTPException):
                service.login_user(login_credentials, "127.0.0.1", mock_request)

        # Assert — verify_password must never be reached
        mock_verify.assert_not_called()
