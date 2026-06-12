"""
tests/unit/Business_Layer/services/test_permission_service.py

Business rules (Functional Spec §3.3):
  - Permission codes must match ^[A-Z]+(_[A-Z]+)*$ (uppercase, underscores only)
  - Empty code or description → 400
  - Duplicate permission code → 400
  - When no group_uuid given, assign to default group
  - Explicit group_uuid must exist → 404 if not
  - reassign_group: permission must exist, group must exist
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException


MOCK_REQUEST = MagicMock()
MOCK_USER = {"user_id": 1, "roles": ["Admin"]}


class TestPermissionServiceInit:
    def test_init_sets_all_daos(self):
        """Service __init__ should wire up DAO, group_dao, and access_point_dao."""
        from Backend.Business_Layer.services.permission_service import PermissionService
        db = MagicMock()
        svc = PermissionService(db)
        assert svc.dao is not None
        assert svc.group_dao is not None
        assert svc.access_point_dao is not None


def make_service(permission_dao=None, group_dao=None):
    from Backend.Business_Layer.services.permission_service import PermissionService
    svc = PermissionService.__new__(PermissionService)
    svc.db = MagicMock()
    svc.dao = permission_dao or MagicMock()
    svc.group_dao = group_dao or MagicMock()
    svc.access_point_dao = MagicMock()
    return svc


def make_permission(permission_id=1, permission_uuid="perm-uuid-1",
                    permission_code="VIEW_USERS", description="View users"):
    p = MagicMock()
    p.permission_id = permission_id
    p.permission_uuid = permission_uuid
    p.permission_code = permission_code
    p.description = description
    return p


def make_group(group_id=5, group_uuid="uuid-g1", group_name="Admin Group"):
    g = MagicMock()
    g.group_id = group_id
    g.group_uuid = group_uuid
    g.group_name = group_name
    return g


DEFAULT_GROUP = make_group(group_id=1, group_uuid="default-uuid",
                           group_name="newly_created_permissions_group")


# ══════════════════════════════════════════════════════════════════════════════
# create_permission_minimal — validation
# ══════════════════════════════════════════════════════════════════════════════

class TestCreatePermissionValidation:

    def test_empty_code_raises_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal("", "Description",
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400
        assert "empty" in exc.value.detail.lower()

    def test_whitespace_code_raises_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal("   ", "Description",
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_empty_description_raises_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal("VIEW_USERS", "",
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_invalid_format_lowercase_raises_400(self):
        """Permission code must be uppercase — lowercase is rejected."""
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal("view_users", "Description",
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400
        assert "uppercase" in exc.value.detail.lower() or "invalid" in exc.value.detail.lower()

    def test_invalid_format_with_digit_raises_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal("VIEW_USER2", "Description",
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_invalid_format_with_spaces_raises_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal("VIEW USERS", "Description",
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_duplicate_code_raises_400(self):
        dao = MagicMock()
        dao.get_by_code.return_value = make_permission()
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal("VIEW_USERS", "Description",
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400
        assert "already exists" in exc.value.detail.lower()


# ══════════════════════════════════════════════════════════════════════════════
# create_permission_minimal — group assignment
# ══════════════════════════════════════════════════════════════════════════════

class TestCreatePermissionGroupAssignment:

    def _setup_happy_path(self, group_uuid=None):
        dao = MagicMock()
        group_dao = MagicMock()
        dao.get_by_code.return_value = None
        perm = make_permission()
        dao.create.return_value = perm
        dao.map_to_group.return_value = None
        group_dao.get_group_by_name.return_value = DEFAULT_GROUP
        group_dao.get_group_by_uuid.return_value = make_group() if group_uuid else None
        return dao, group_dao, perm

    def test_no_group_uuid_assigns_to_default_group(self):
        dao, group_dao, perm = self._setup_happy_path()
        svc = make_service(permission_dao=dao, group_dao=group_dao)

        with patch("Backend.Business_Layer.services.permission_service.generate_uuid7",
                   return_value="new-perm-uuid"):
            result = svc.create_permission_minimal(
                "VIEW_USERS", "View all users",
                current_user=MOCK_USER, request=MOCK_REQUEST
            )

        assert result["group_uuid"] == DEFAULT_GROUP.group_uuid
        dao.map_to_group.assert_called_once_with(perm.permission_id, DEFAULT_GROUP.group_id)

    def test_explicit_group_uuid_assigns_to_that_group(self):
        dao = MagicMock()
        group_dao = MagicMock()
        dao.get_by_code.return_value = None
        perm = make_permission()
        dao.create.return_value = perm
        dao.map_to_group.return_value = None
        my_group = make_group(group_id=99, group_uuid="my-group-uuid")
        group_dao.get_group_by_uuid.return_value = my_group
        svc = make_service(permission_dao=dao, group_dao=group_dao)

        with patch("Backend.Business_Layer.services.permission_service.generate_uuid7",
                   return_value="new-perm-uuid"):
            result = svc.create_permission_minimal(
                "VIEW_USERS", "View all users",
                group_uuid="my-group-uuid",
                current_user=MOCK_USER, request=MOCK_REQUEST
            )

        assert result["group_uuid"] == "my-group-uuid"
        dao.map_to_group.assert_called_once_with(perm.permission_id, 99)

    def test_map_to_group_value_error_raises_400(self):
        """map_to_group raising ValueError (duplicate mapping) → 400."""
        dao = MagicMock()
        group_dao = MagicMock()
        dao.get_by_code.return_value = None
        dao.create.return_value = make_permission()
        dao.map_to_group.side_effect = ValueError("Duplicate mapping")
        group_dao.get_group_by_name.return_value = DEFAULT_GROUP
        svc = make_service(permission_dao=dao, group_dao=group_dao)

        with patch("Backend.Business_Layer.services.permission_service.generate_uuid7",
                   return_value="uuid"), \
             pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal(
                "VIEW_USERS", "View all users",
                current_user=MOCK_USER, request=MOCK_REQUEST
            )
        assert exc.value.status_code == 400

    def test_explicit_group_uuid_not_found_raises_404(self):
        dao = MagicMock()
        group_dao = MagicMock()
        dao.get_by_code.return_value = None
        perm = make_permission()
        dao.create.return_value = perm
        group_dao.get_group_by_uuid.return_value = None  # group not found
        svc = make_service(permission_dao=dao, group_dao=group_dao)

        with patch("Backend.Business_Layer.services.permission_service.generate_uuid7",
                   return_value="new-uuid"), \
             pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal(
                "VIEW_USERS", "View all users",
                group_uuid="nonexistent-group",
                current_user=MOCK_USER, request=MOCK_REQUEST
            )
        assert exc.value.status_code == 404

    def test_default_group_missing_raises_500(self):
        dao = MagicMock()
        group_dao = MagicMock()
        dao.get_by_code.return_value = None
        dao.create.return_value = make_permission()
        group_dao.get_group_by_name.return_value = None  # default group missing
        svc = make_service(permission_dao=dao, group_dao=group_dao)

        with patch("Backend.Business_Layer.services.permission_service.generate_uuid7",
                   return_value="uuid"), \
             pytest.raises(HTTPException) as exc:
            svc.create_permission_minimal(
                "VIEW_USERS", "View all users",
                current_user=MOCK_USER, request=MOCK_REQUEST
            )
        assert exc.value.status_code == 500

    def test_valid_permission_code_single_word(self):
        """'VIEWUSERS' (no underscore) is valid."""
        dao = MagicMock()
        group_dao = MagicMock()
        dao.get_by_code.return_value = None
        dao.create.return_value = make_permission(permission_code="VIEWUSERS")
        group_dao.get_group_by_name.return_value = DEFAULT_GROUP
        svc = make_service(permission_dao=dao, group_dao=group_dao)

        with patch("Backend.Business_Layer.services.permission_service.generate_uuid7",
                   return_value="uuid"):
            result = svc.create_permission_minimal(
                "VIEWUSERS", "View all users",
                current_user=MOCK_USER, request=MOCK_REQUEST
            )
        assert "permission_uuid" in result


# ══════════════════════════════════════════════════════════════════════════════
# reassign_group
# ══════════════════════════════════════════════════════════════════════════════

class TestReassignGroup:

    def test_permission_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_by_uuid.return_value = None
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.reassign_group("ghost-perm-uuid", "group-uuid")
        assert exc.value.status_code == 404

    def test_group_not_found_raises_404(self):
        dao = MagicMock()
        group_dao = MagicMock()
        dao.get_by_uuid.return_value = make_permission()
        group_dao.get_group_by_uuid.return_value = None
        svc = make_service(permission_dao=dao, group_dao=group_dao)
        with pytest.raises(HTTPException) as exc:
            svc.reassign_group("perm-uuid-1", "ghost-group-uuid")
        assert exc.value.status_code == 404

    def test_reassign_group_happy_path(self):
        dao = MagicMock()
        group_dao = MagicMock()
        perm = make_permission()
        group = make_group()
        dao.get_by_uuid.return_value = perm
        group_dao.get_group_by_uuid.return_value = group
        dao.update_group_mapping.return_value = None
        svc = make_service(permission_dao=dao, group_dao=group_dao)

        svc.reassign_group("perm-uuid-1", "uuid-g1")
        dao.update_group_mapping.assert_called_once_with(perm.permission_id, group.group_id)


# ══════════════════════════════════════════════════════════════════════════════
# update_permission
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdatePermission:

    def test_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_by_uuid.return_value = None
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.update_permission("ghost-uuid", "NEW_CODE", "desc",
                                  current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_empty_code_raises_400(self):
        dao = MagicMock()
        dao.get_by_uuid.return_value = make_permission()
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.update_permission("perm-uuid-1", "", "desc",
                                  current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_invalid_code_format_raises_400(self):
        dao = MagicMock()
        dao.get_by_uuid.return_value = make_permission()
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.update_permission("perm-uuid-1", "invalid_code", "desc",
                                  current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_duplicate_code_raises_400(self):
        dao = MagicMock()
        perm = make_permission(permission_code="OLD_CODE")
        dao.get_by_uuid.return_value = perm
        dao.get_by_code.return_value = make_permission(permission_code="NEW_CODE")
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.update_permission("perm-uuid-1", "NEW_CODE", "desc",
                                  current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_happy_path(self):
        dao = MagicMock()
        perm = make_permission(permission_code="OLD_CODE")
        updated = make_permission(permission_code="NEW_CODE")
        dao.get_by_uuid.return_value = perm
        dao.get_by_code.return_value = None  # code not taken
        dao.update.return_value = updated
        svc = make_service(permission_dao=dao)

        result = svc.update_permission("perm-uuid-1", "NEW_CODE", "Updated desc",
                                       current_user=MOCK_USER, request=MOCK_REQUEST)
        assert result is updated


# ══════════════════════════════════════════════════════════════════════════════
# delete_permission
# ══════════════════════════════════════════════════════════════════════════════

class TestDeletePermission:

    def test_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_by_uuid.return_value = None
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.delete_permission("ghost-uuid",
                                  current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_happy_path_returns_message(self):
        dao = MagicMock()
        perm = make_permission()
        perm.access_mappings = MagicMock()
        perm.permission_groups = MagicMock()
        dao.get_by_uuid.return_value = perm
        dao.delete.return_value = None
        svc = make_service(permission_dao=dao)

        result = svc.delete_permission("perm-uuid-1",
                                       current_user=MOCK_USER, request=MOCK_REQUEST)
        assert "deleted" in result["message"].lower()


# ══════════════════════════════════════════════════════════════════════════════
# delete_permissions (bulk)
# ══════════════════════════════════════════════════════════════════════════════

class TestDeletePermissions:

    def test_empty_list_raises_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc.delete_permissions([], current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_not_found_uuids_skipped_then_raises_400(self):
        dao = MagicMock()
        dao.get_by_uuid.return_value = None
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.delete_permissions(["ghost-uuid"],
                                   current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_bulk_delete_success(self):
        dao = MagicMock()
        perm = make_permission()
        perm.access_mappings = MagicMock()
        perm.permission_groups = MagicMock()
        dao.get_by_uuid.return_value = perm
        dao.delete.return_value = None
        svc = make_service(permission_dao=dao)

        result = svc.delete_permissions(["perm-uuid-1"],
                                        current_user=MOCK_USER, request=MOCK_REQUEST)
        assert "deleted" in result["message"].lower()


# ══════════════════════════════════════════════════════════════════════════════
# list_permissions / get_permission
# ══════════════════════════════════════════════════════════════════════════════

class TestListAndGetPermission:

    def test_list_permissions_delegates_to_dao(self):
        dao = MagicMock()
        perms = [make_permission(), make_permission(permission_id=2, permission_code="EDIT_USERS")]
        dao.get_all.return_value = perms
        svc = make_service(permission_dao=dao)
        result = svc.list_permissions()
        assert result == perms

    def test_get_permission_found(self):
        dao = MagicMock()
        perm = make_permission()
        dao.get_by_uuid.return_value = perm
        svc = make_service(permission_dao=dao)
        result = svc.get_permission("perm-uuid-1")
        assert result is perm

    def test_get_permission_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_by_uuid.return_value = None
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.get_permission("ghost-uuid")
        assert exc.value.status_code == 404

    def test_list_unmapped_permissions(self):
        dao = MagicMock()
        dao.get_unmapped.return_value = [make_permission()]
        svc = make_service(permission_dao=dao)
        result = svc.list_unmapped_permissions()
        dao.get_unmapped.assert_called_once()

    def test_delete_permission_cascade_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_by_uuid.return_value = None
        svc = make_service(permission_dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.delete_permission_cascade("ghost-uuid")
        assert exc.value.status_code == 404

    def test_delete_permission_cascade_happy_path(self):
        dao = MagicMock()
        perm = make_permission()
        dao.get_by_uuid.return_value = perm
        dao.delete_cascade.return_value = None
        svc = make_service(permission_dao=dao)
        svc.delete_permission_cascade("perm-uuid-1")
        dao.delete_cascade.assert_called_once_with(perm.permission_id)
