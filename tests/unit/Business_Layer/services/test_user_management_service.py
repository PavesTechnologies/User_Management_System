"""
tests/unit/Business_Layer/services/test_user_management_service.py

Unit tests for:  Business_Layer/services/user_management_service.py
Methods tested:
  - create_user()
  - list_users()
  - get_user(), get_user_uuid()
  - get_users_with_roles(), get_users_with_roles_id()
  - update_user(), update_user_uuid()
  - deactivate_user(), deactivate_user_uuid()
  - activate_user_uuid()
  - update_user_roles(), update_user_roles_uuid()

What is tested here:
  - Business logic orchestration
  - Validation integration with utils
  - Proper error handling
  - Audit decorator integration

What is NOT tested (mocked away):
  - Real DB queries           → tested in DAO tests
  - Real password hashing     → tested separately
  - Real email sending        → mocked
  - Real UUID generation      → mocked
"""

import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, UTC
from fastapi import HTTPException
import pandas as pd


# ─────────────────────────────────────────────────────────────────────────────
# Helper — build UserService with fake DAO
# ─────────────────────────────────────────────────────────────────────────────

def make_user_service(mock_dao=None):
    """
    Creates UserService with a mocked DAO injected.
    Bypasses __init__ so no real DB connection is attempted.
    """
    from Backend.Business_Layer.services.user_management_service import UserService
    service = UserService.__new__(UserService)
    service.db = MagicMock()
    service.dao = mock_dao or MagicMock()
    return service


def make_mock_user_model(user_id=1, first_name="John", last_name="Doe",
                         email="john@example.com", mail=None, is_active=True,
                         user_uuid=None, **kwargs):
    """Helper to create mock user model objects."""

    email = email if mail is None else mail
    email = kwargs.get("mail", email)

    user = MagicMock()
    user.user_id = user_id
    user.user_uuid = user_uuid or f"uuid-{user_id}"
    user.first_name = first_name
    user.last_name = last_name
    user.mail = email
    user.contact = "9876543210"
    user.password = "$2b$12$hashedpassword"
    user.is_active = is_active
    user.created_at = datetime.now(UTC)
    user.updated_at = datetime.now(UTC)
    user.gender = None

    # ⭐ simulate SQLAlchemy table metadata for audit decorator
    col1 = MagicMock()
    col1.name = "user_id"

    col2 = MagicMock()
    col2.name = "user_uuid"

    table = MagicMock()
    table.columns = [col1, col2]

    user.__table__ = table

    return user


def make_mock_user_schema(first_name="John", last_name="Doe",
                          email="john@example.com", contact="9876543210",
                          password="SecurePass123!", is_active=True):
    """Helper to create mock Pydantic schema objects."""
    schema = MagicMock()
    schema.first_name = first_name
    schema.last_name = last_name
    schema.mail = email
    schema.contact = contact
    schema.password = password
    schema.is_active = is_active
    return schema


def make_mock_request(user_id=1, roles=None, ip="127.0.0.1"):
    """Helper to create mock FastAPI request objects."""
    request = MagicMock()
    request.client.host = ip
    request.state.user = {
        "user_id": user_id,
        "roles": roles or ["User"]
    }
    request.state.db = MagicMock()
    return request


# ─────────────────────────────────────────────────────────────────────────────
# COUNT OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class TestCountUsers:
    """Tests for count_users() and count_active_users()"""

    def test_count_users_returns_total_count(self):
        """
        GIVEN  a service accessing database
        WHEN   count_users() is called
        THEN   returns the total user count
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.count_users.return_value = 42
        service = make_user_service(mock_dao)

        # Act
        result = service.count_users()

        # Assert
        assert result == 42
        mock_dao.count_users.assert_called_once()

    def test_count_active_users_returns_active_count(self):
        """
        GIVEN  a service with both active and inactive users
        WHEN   count_active_users() is called
        THEN   returns only active user count
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.count_active_users.return_value = 35
        service = make_user_service(mock_dao)

        # Act
        result = service.count_active_users()

        # Assert
        assert result == 35


# ─────────────────────────────────────────────────────────────────────────────
# LIST/GET OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class TestListUsers:
    """Tests for list_users()"""

    def test_list_users_returns_paginated_result(self):
        """
        GIVEN  a request for paginated users
        WHEN   list_users(page=1, limit=10) is called
        THEN   returns dict with 'total' and 'users' list
        """
        # Arrange
        mock_dao = MagicMock()
        mock_users = [make_mock_user_model(user_id=i) for i in range(1, 4)]
        mock_dao.get_paginated_users.return_value = {
            "total": 3,
            "users": mock_users
        }
        service = make_user_service(mock_dao)

        # Act
        result = service.list_users(page=1, limit=10)

        # Assert
        assert result["total"] == 3
        assert len(result["users"]) == 3
        mock_dao.get_paginated_users.assert_called_once_with(1, 10, None)

    def test_list_users_with_search_filter(self):
        """
        GIVEN  a search term
        WHEN   list_users() is called with search parameter
        THEN   search is passed to DAO
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.get_paginated_users.return_value = {"total": 1, "users": []}
        service = make_user_service(mock_dao)

        # Act
        service.list_users(page=1, limit=10, search="John")

        # Assert
        mock_dao.get_paginated_users.assert_called_once_with(1, 10, "John")

    def test_list_users_returns_empty_when_no_users(self):
        """
        GIVEN  a database with no users
        WHEN   list_users() is called
        THEN   returns total=0 and empty users list
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.get_paginated_users.return_value = {"total": 0, "users": []}
        service = make_user_service(mock_dao)

        # Act
        result = service.list_users(page=1, limit=10)

        # Assert
        assert result["total"] == 0
        assert len(result["users"]) == 0


class TestGetUser:
    """Tests for get_user() and get_user_uuid()"""

    def test_get_user_by_id_returns_user_when_exists(self):
        """
        GIVEN  a user_id that exists
        WHEN   get_user() is called
        THEN   returns the User object
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=42)
        mock_dao.get_user_by_id.return_value = mock_user
        service = make_user_service(mock_dao)

        # Act
        result = service.get_user(42)

        # Assert
        assert result == mock_user

    def test_get_user_by_id_returns_none_when_not_found(self):
        """
        GIVEN  a user_id that doesn't exist
        WHEN   get_user() is called
        THEN   returns None
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.get_user_by_id.return_value = None
        service = make_user_service(mock_dao)

        # Act
        result = service.get_user(99999)

        # Assert
        assert result is None

    def test_get_user_by_uuid_returns_user_when_exists(self):
        """
        GIVEN  a user_uuid that exists
        WHEN   get_user_uuid() is called
        THEN   returns the User object
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=5)
        mock_dao.get_user_by_uuid.return_value = mock_user
        service = make_user_service(mock_dao)
        request = make_mock_request(roles=["Admin"])

        # Act
        result = service.get_user_uuid(request.state.user, "uuid-5")

        # Assert
        assert result == mock_user

    def test_get_user_uuid_restricts_super_admin_access(self):
        """
        GIVEN  a non-Super-Admin user trying to access a Super_Admin account
        WHEN   get_user_uuid() is called
        THEN   raises HTTPException 403

        Business rule (Functional Spec §4.3):
          Super_Admin cannot be accessed/edited by non-Super_Admin users.
          Role name is 'Super_Admin' (underscore) — matches role table role_name column.
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=5)
        mock_dao.get_user_by_uuid.return_value = mock_user
        mock_dao.get_user_roles_by_uuid.return_value = ["Super_Admin"]
        service = make_user_service(mock_dao)
        current_user = {"user_id": 1, "roles": ["Admin"]}

        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            service.get_user_uuid(current_user, "uuid-5")

        assert exc_info.value.status_code == 403


class TestGetUsersWithRoles:
    """Tests for get_users_with_roles() and get_users_with_roles_id()"""

    def test_get_users_with_roles_returns_paginated_with_roles(self):
        """
        GIVEN  a request for users with role names
        WHEN   get_users_with_roles() is called
        THEN   returns paginated result with role names aggregated
        """
        # Arrange
        mock_dao = MagicMock()
        mock_result = {
            "total": 2,
            "users": [
                {"user_uuid": "uuid-1", "name": "John Doe", "roles": ["Admin"], "mail": "john@example.com"},
                {"user_uuid": "uuid-2", "name": "Jane Smith", "roles": ["User"], "mail": "jane@example.com"},
            ]
        }
        mock_dao.get_users_with_roles.return_value = mock_result
        service = make_user_service(mock_dao)

        # Act
        result = service.get_users_with_roles(page=1, limit=10)

        # Assert
        assert result["total"] == 2
        assert len(result["users"]) == 2
        assert result["users"][0]["roles"] == ["Admin"]

    def test_get_users_with_roles_id_returns_users_with_id(self):
        """
        GIVEN  a request for users with ID and roles
        WHEN   get_users_with_roles_id() is called
        THEN   returns list of users with user_id and aggregated roles
        """
        # Arrange
        mock_dao = MagicMock()
        mock_users = [
            {"user_id": 1, "name": "John Doe", "roles": ["Admin"], "mail": "john@example.com"},
            {"user_id": 2, "name": "Jane Smith", "roles": ["User"], "mail": "jane@example.com"},
        ]
        mock_dao.get_users_with_roles_id.return_value = mock_users
        service = make_user_service(mock_dao)

        # Act
        result = service.get_users_with_roles_id()

        # Assert
        assert len(result) == 2
        assert result[0]["user_id"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# CREATE USER OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class TestCreateUser:
    """Tests for create_user()"""

    @patch("Backend.Business_Layer.services.user_management_service.validate_email_format")
    @patch("Backend.Business_Layer.services.user_management_service.validate_name")
    @patch("Backend.Business_Layer.services.user_management_service.validate_contact_number")
    @patch("Backend.Business_Layer.services.user_management_service.validate_password_strength")
    @patch("Backend.Business_Layer.services.user_management_service.hash_password")
    @patch("Backend.Business_Layer.services.user_management_service.send_welcome_email")
    @patch("Backend.Business_Layer.services.user_management_service.generate_uuid7")
    @patch("Backend.Business_Layer.services.user_management_service.models")
    def test_create_user_successfully(
        self, mock_models, mock_uuid, mock_send_email, mock_hash_pwd,
        mock_val_pwd, mock_val_contact, mock_val_name, mock_val_email
    ):
        """
        GIVEN  a valid UserBaseIn schema
        WHEN   create_user() is called
        THEN   user is created, General role is assigned, welcome email is sent
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=1)
        mock_general_role = MagicMock()
        mock_general_role.role_id = 10
        
        mock_dao.get_user_by_email.return_value = None
        mock_dao.create_user.return_value = mock_user
        mock_dao.get_role_by_name.return_value = mock_general_role
        mock_dao.map_user_role.return_value = None
        
        mock_hash_pwd.return_value = "hashed_password"
        mock_uuid.return_value = "new-uuid-123"
        mock_models.User = MagicMock()
        mock_models.User.return_value = mock_user
        
        service = make_user_service(mock_dao)
        schema = make_mock_user_schema()
        request = make_mock_request()

        # Act
        result = service.create_user(schema, created_by_user_id=1, current_user=request.state.user, request=request)

        # Assert
        assert result == mock_user
        mock_val_email.assert_called_once()
        mock_val_name.assert_called()
        mock_send_email.assert_called_once()
        mock_dao.create_user.assert_called_once()
        mock_dao.map_user_role.assert_called_once()

    @patch("Backend.Business_Layer.services.user_management_service.validate_email_format")
    def test_create_user_raises_error_when_email_exists(self, mock_val_email):
        """
        GIVEN  an email that already exists in database
        WHEN   create_user() is called
        THEN   raises ValueError
        """
        # Arrange
        mock_dao = MagicMock()
        existing_user = make_mock_user_model(user_id=1)
        mock_dao.get_user_by_email.return_value = existing_user
        
        service = make_user_service(mock_dao)
        schema = make_mock_user_schema()
        request = make_mock_request()

        # Act & Assert
        with pytest.raises(ValueError, match="User already exists"):
            service.create_user(schema, created_by_user_id=1, current_user=request.state.user, request=request)

    @patch("Backend.Business_Layer.services.user_management_service.validate_email_format")
    def test_create_user_validates_email_format(self, mock_val_email):
        """
        GIVEN  an invalid email format
        WHEN   create_user() is called
        THEN   validation error is raised
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.get_user_by_email.return_value = None
        mock_val_email.side_effect = ValueError("Invalid email")
        
        service = make_user_service(mock_dao)
        schema = make_mock_user_schema(email="not-an-email")
        request = make_mock_request()

        # Act & Assert
        with pytest.raises(ValueError):
            service.create_user(schema, created_by_user_id=1, current_user=request.state.user, request=request)


class TestCreateBulkUsers:
    """Tests for create_bulk_user()"""

    @patch("Backend.Business_Layer.services.user_management_service.validate_email_format")
    @patch("Backend.Business_Layer.services.user_management_service.validate_name")
    @patch("Backend.Business_Layer.services.user_management_service.validate_contact_number")
    @patch("Backend.Business_Layer.services.user_management_service.validate_password_strength")
    @patch("Backend.Business_Layer.services.user_management_service.hash_password")
    @patch("Backend.Business_Layer.services.user_management_service.send_welcome_email")
    @patch("Backend.Business_Layer.services.user_management_service.generate_uuid7")
    @patch("Backend.Business_Layer.services.user_management_service.models")
    def test_create_bulk_users_with_valid_data(
        self, mock_models, mock_uuid, mock_send_email, mock_hash_pwd,
        mock_val_pwd, mock_val_contact, mock_val_name, mock_val_email
    ):
        """
        GIVEN  a valid Excel DataFrame with user data
        WHEN   create_bulk_user() is called
        THEN   successfully creates all users and returns success list
        """
        # Arrange
        mock_dao = MagicMock()
        mock_general_role = MagicMock()
        mock_general_role.role_id = 10
        mock_users = [make_mock_user_model(user_id=i) for i in range(1, 3)]
        
        mock_dao.get_users_by_emails.return_value = []
        mock_dao.get_role_by_name.return_value = mock_general_role
        mock_dao.create_users_batch.return_value = mock_users
        mock_dao.map_user_roles_batch.return_value = None
        mock_dao.create_audit_logs_batch.return_value = None
        
        mock_hash_pwd.return_value = "hashed_password"
        mock_uuid.return_value = "new-uuid"
        mock_models.User = MagicMock(side_effect=lambda **kwargs: make_mock_user_model(**kwargs))
        mock_models.AuditTrail = MagicMock()
        
        service = make_user_service(mock_dao)
        request = make_mock_request()
        
        # Create sample DataFrame
        df = pd.DataFrame({
            "first_name": ["John", "Jane"],
            "last_name": ["Doe", "Smith"],
            "mail": ["john@example.com", "jane@example.com"],
            "contact": ["9876543210", "9123456789"],
            "is_active": [True, True]
        })

        # Act
        result = service.create_bulk_user(df, created_by_user_id=1, request=request)

        # Assert
        assert "success" in result
        assert "failed" in result
        assert len(result["success"]) == 2
        assert len(result["failed"]) == 0

    @patch("Backend.Business_Layer.services.user_management_service.validate_email_format")
    def test_create_bulk_users_skips_invalid_rows(self, mock_val_email):
        """
        GIVEN  Excel data with some invalid rows
        WHEN   create_bulk_user() is called
        THEN   skips invalid rows and creates only valid ones
        """
        # Arrange
        mock_dao = MagicMock()
        mock_general_role = MagicMock()
        mock_general_role.role_id = 10
        
        mock_dao.get_users_by_emails.return_value = []
        mock_dao.get_role_by_name.return_value = mock_general_role
        mock_dao.create_users_batch.return_value = []
        mock_dao.map_user_roles_batch.return_value = None
        
        # Simulate validation error
        mock_val_email.side_effect = ValueError("Invalid email")
        
        service = make_user_service(mock_dao)
        request = make_mock_request()
        
        df = pd.DataFrame({
            "first_name": ["John", "Jane"],
            "last_name": ["Doe", "Smith"],
            "mail": ["not-email", "jane@example.com"],
            "contact": ["9876543210", "9123456789"],
            "is_active": [True, True]
        })

        # Act
        result = service.create_bulk_user(df, created_by_user_id=1, request=request)

        # Assert
        assert "failed" in result
        assert len(result["failed"]) >= 1  # At least one failed

    def test_create_bulk_users_returns_all_failed_when_no_valid_rows(self):
        """
        GIVEN  Excel data where all rows are invalid
        WHEN   create_bulk_user() is called
        THEN   returns failed message and empty success list
        """
        # Arrange
        mock_dao = MagicMock()
        service = make_user_service(mock_dao)
        request = make_mock_request()
        
        df = pd.DataFrame({
            "first_name": ["", ""],
            "last_name": ["", ""],
            "mail": ["not-email", "also-invalid"],
            "contact": ["123", "456"],  # Invalid contact numbers
            "is_active": [True, True]
        })

        # Act
        with patch("Backend.Business_Layer.services.user_management_service.validate_contact_number") as mock_val:
            mock_val.side_effect = ValueError("Invalid contact")
            result = service.create_bulk_user(df, created_by_user_id=1, request=request)

        # Assert
        assert "All rows failed validation" in result["message"] or result["message"] == "No valid new users to create."


# ─────────────────────────────────────────────────────────────────────────────
# UPDATE USER OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class TestUpdateUser:
    """Tests for update_user() and update_user_uuid()"""

    @patch("Backend.Business_Layer.services.user_management_service.validate_email_format")
    @patch("Backend.Business_Layer.services.user_management_service.validate_name")
    @patch("Backend.Business_Layer.services.user_management_service.validate_contact_number")
    def test_update_user_by_id_successfully(
        self, mock_val_contact, mock_val_name, mock_val_email
    ):
        """
        GIVEN  a valid user_id and update data
        WHEN   update_user() is called
        THEN   user is updated successfully
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=1)
        mock_dao.get_user_by_id.return_value = mock_user
        mock_dao.update_user.return_value = True
        
        service = make_user_service(mock_dao)
        schema = make_mock_user_schema(first_name="Jane")
        request = make_mock_request()

        # Act
        result = service.update_user(1, schema, current_user=request.state.user, request=request)

        # Assert
        assert result == mock_user
        mock_dao.update_user.assert_called_once()

    @patch("Backend.Business_Layer.services.user_management_service.validate_email_format")
    def test_update_user_raises_error_when_not_found(self, mock_val_email):
        """
        GIVEN  a user_id that doesn't exist
        WHEN   update_user() is called
        THEN   raises ValueError
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.get_user_by_id.return_value = None
        
        service = make_user_service(mock_dao)
        schema = make_mock_user_schema()
        request = make_mock_request()

        # Act & Assert
        with pytest.raises(ValueError):
            service.update_user(99999, schema, current_user=request.state.user, request=request)

    @patch("Backend.Business_Layer.services.user_management_service.validate_email_format")
    def test_update_user_with_duplicate_email_raises_error(self, mock_val_email):

        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=1, email="john@example.com")
        other_user = make_mock_user_model(user_id=2, email="jane@example.com")

        mock_dao.get_user_by_id.return_value = mock_user
        mock_dao.get_user_by_email.return_value = other_user

        service = make_user_service(mock_dao)
        schema = make_mock_user_schema(email="jane@example.com")
        request = make_mock_request()

        with pytest.raises(ValueError, match="already"):
            service.update_user(1, schema, current_user=request.state.user, request=request)


# ─────────────────────────────────────────────────────────────────────────────
# DEACTIVATE / ACTIVATE OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class TestDeactivateUser:
    """Tests for deactivate_user() and deactivate_user_uuid()"""

    def test_deactivate_user_by_id_successfully(self):
        """
        GIVEN  a valid user_id
        WHEN   deactivate_user() is called
        THEN   user is deactivated
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=1, is_active=True)
        mock_dao.get_user_by_id.return_value = mock_user
        mock_dao.deactivate_user.return_value = None
        
        service = make_user_service(mock_dao)
        request = make_mock_request()

        # Act
        service.deactivate_user(1, current_user=request.state.user, request=request)

        # Assert
        mock_dao.deactivate_user.assert_called_once_with(mock_user)

    def test_deactivate_user_raises_error_when_not_found(self):
        """
        GIVEN  a user_id that doesn't exist
        WHEN   deactivate_user() is called
        THEN   raises ValueError
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.get_user_by_id.return_value = None
        
        service = make_user_service(mock_dao)
        request = make_mock_request()

        # Act & Assert
        with pytest.raises(ValueError):
            service.deactivate_user(99999, current_user=request.state.user, request=request)

    def test_deactivate_super_admin_restricted_for_non_super_admin(self):
        """
        GIVEN  a non-Super-Admin user trying to deactivate a Super_Admin account
        WHEN   deactivate_user_uuid() is called
        THEN   raises HTTPException 403

        Business rule (Functional Spec §4.3):
          Super_Admin cannot be deactivated by non-Super_Admin users.
          Role name is 'Super_Admin' (underscore) — matches role table role_name column.
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=2)
        mock_dao.get_user_by_uuid.return_value = mock_user
        mock_dao.get_user_roles_by_uuid.return_value = ["Super_Admin"]

        service = make_user_service(mock_dao)
        current_user = {"user_id": 1, "roles": ["Admin"]}

        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            service.deactivate_user_uuid("uuid-2", current_user=current_user, request=MagicMock())

        assert exc_info.value.status_code == 403


class TestActivateUser:
    """Tests for activate_user_uuid()"""

    def test_activate_user_successfully(self):
        """
        GIVEN  an inactive user
        WHEN   activate_user_uuid() is called
        THEN   user is activated
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=1, is_active=False)
        mock_dao.get_user_by_uuid.return_value = mock_user
        mock_dao.get_user_roles_by_uuid.return_value = ["User"]
        mock_dao.activate_user.return_value = None
        
        service = make_user_service(mock_dao)
        current_user = {"user_id": 1, "roles": ["Admin"]}

        # Act
        service.activate_user_uuid("uuid-1", current_user=current_user, request=MagicMock())

        # Assert
        mock_dao.activate_user.assert_called_once_with(mock_user)

    def test_activate_user_raises_error_when_not_found(self):
        """
        GIVEN  a user_uuid that doesn't exist
        WHEN   activate_user_uuid() is called
        THEN   raises ValueError
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.get_user_by_uuid.return_value = None
        
        service = make_user_service(mock_dao)
        current_user = {"user_id": 1, "roles": ["Admin"]}

        # Act & Assert
        with pytest.raises(ValueError):
            service.activate_user_uuid("nonexistent-uuid", current_user=current_user, request=MagicMock())


# ─────────────────────────────────────────────────────────────────────────────
# UPDATE ROLES OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class TestUpdateUserRoles:
    """Tests for update_user_roles() and update_user_roles_uuid()"""

    def test_update_user_roles_by_id_successfully(self):
        """
        GIVEN  a user_id and list of role_ids
        WHEN   update_user_roles() is called
        THEN   user roles are updated
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=1, is_active=True)
        mock_dao.get_user_by_id.return_value = mock_user
        mock_dao.clear_roles.return_value = None
        mock_dao.assign_role.return_value = None
        
        service = make_user_service(mock_dao)
        current_user = {"user_id": 1, "roles": ["Admin"]}

        # Act
        result = service.update_user_roles(1, [2, 3], 1, current_user=current_user, request=MagicMock())

        # Assert
        assert "successfully" in result.lower()
        mock_dao.clear_roles.assert_called_once()

    def test_update_user_roles_raises_error_when_user_not_found(self):
        """
        GIVEN  a user_id that doesn't exist
        WHEN   update_user_roles() is called
        THEN   raises ValueError
        """
        # Arrange
        mock_dao = MagicMock()
        mock_dao.get_user_by_id.return_value = None
        
        service = make_user_service(mock_dao)
        current_user = {"user_id": 1, "roles": ["Admin"]}

        # Act & Assert
        with pytest.raises(ValueError):
            service.update_user_roles(99999, [2], 1, current_user=current_user, request=MagicMock())

    def test_update_user_roles_raises_error_when_user_inactive(self):
        """
        GIVEN  an inactive user
        WHEN   update_user_roles() is called
        THEN   raises ValueError
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=1, is_active=False)
        mock_dao.get_user_by_id.return_value = mock_user
        
        service = make_user_service(mock_dao)
        current_user = {"user_id": 1, "roles": ["Admin"]}

        # Act & Assert
        with pytest.raises(ValueError):
            service.update_user_roles(1, [2], 1, current_user=current_user, request=MagicMock())

    def test_update_user_roles_by_uuid_successfully(self):
        """
        GIVEN  a user_uuid and list of role_uuids
        WHEN   update_user_roles_uuid() is called
        THEN   user roles are updated
        """
        # Arrange
        mock_dao = MagicMock()
        mock_user = make_mock_user_model(user_id=1, is_active=True)
        mock_dao.get_user_by_uuid.return_value = mock_user
        mock_dao.get_user_roles.return_value = ["User"]
        mock_dao.get_user_roles_uuids.return_value = ["uuid-user"]
        mock_dao.remove_role_by_uuid.return_value = None
        mock_dao.assign_role_uuid.return_value = None
        
        service = make_user_service(mock_dao)
        current_user = {"user_id": 1, "roles": ["Admin"]}

        # Act
        result = service.update_user_roles_uuid("uuid-1", ["uuid-admin"], 1, current_user=current_user, request=MagicMock())

        # Assert
        assert "successfully" in result.lower()
