"""
tests/unit/Business_Layer/services/test_role_service.py

Business rules validated (Functional Spec §3.2 / §4.3):
  - System roles (Admin, Super_Admin, HR, General, System) cannot be renamed or deleted
  - Duplicate role names (case/space insensitive) are rejected
  - Role name allows only letters, spaces, hyphens, underscores
  - Deleting a role reassigns affected users to General
  - get_role_by_uuid raises 404 when not found
  - Bulk delete skips mandatory and not-found roles; fails 400 when nothing deleted
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException


# ── helpers ────────────────────────────────────────────────────────────────────

def make_service():
    from Backend.Business_Layer.services.role_service import RoleService
    svc = RoleService.__new__(RoleService)
    svc.db = MagicMock()
    return svc


def make_mock_role(role_id=10, role_uuid="uuid-r1", role_name="Tester"):
    r = MagicMock()
    r.role_id = role_id
    r.role_uuid = role_uuid
    r.role_name = role_name
    # audit decorator serializes the result via entity.__table__.columns
    col = MagicMock()
    col.name = "role_id"
    tbl = MagicMock()
    tbl.columns = [col]
    r.__table__ = tbl
    return r


MOCK_REQUEST = MagicMock()
MOCK_USER = {"user_id": 1, "roles": ["Admin"]}


class TestRoleServiceInit:
    def test_init_sets_db(self):
        from Backend.Business_Layer.services.role_service import RoleService
        db = MagicMock()
        svc = RoleService(db)
        assert svc.db is db


# ══════════════════════════════════════════════════════════════════════════════
# list_roles / get_role_by_uuid
# ══════════════════════════════════════════════════════════════════════════════

class TestListAndGet:

    def test_list_roles_delegates_to_dao(self):
        svc = make_service()
        roles = [make_mock_role(), make_mock_role(2, "uuid-r2", "Dev")]
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_all_roles",
                   return_value=roles):
            result = svc.list_roles()
        assert result == roles

    def test_get_role_by_uuid_returns_role_when_found(self):
        svc = make_service()
        role = make_mock_role()
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role):
            result = svc.get_role_by_uuid("uuid-r1")
        assert result is role

    def test_get_role_by_uuid_raises_404_when_not_found(self):
        svc = make_service()
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=None):
            with pytest.raises(HTTPException) as exc:
                svc.get_role_by_uuid("uuid-ghost")
        assert exc.value.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# _normalize_role_name
# ══════════════════════════════════════════════════════════════════════════════

class TestNormalizeRoleName:

    def test_valid_name_returns_lowercase(self):
        svc = make_service()
        assert svc._normalize_role_name("Hr Manager") == "hr manager"

    def test_leading_trailing_spaces_stripped(self):
        svc = make_service()
        assert svc._normalize_role_name("  Dev  ") == "dev"

    def test_multiple_spaces_collapsed(self):
        svc = make_service()
        assert svc._normalize_role_name("Senior  Dev") == "senior dev"

    def test_hyphens_and_underscores_allowed(self):
        svc = make_service()
        result = svc._normalize_role_name("Tech-Lead_Senior")
        assert result == "tech-lead_senior"

    def test_digits_raise_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc._normalize_role_name("Role123")
        assert exc.value.status_code == 400

    def test_special_chars_raise_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc._normalize_role_name("Role@Admin")
        assert exc.value.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# _check_duplicate_role
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckDuplicateRole:

    def test_duplicate_name_raises_400(self):
        svc = make_service()
        existing = make_mock_role(role_id=5, role_name="Tester")
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_all_roles",
                   return_value=[existing]):
            with pytest.raises(HTTPException) as exc:
                svc._check_duplicate_role("tester")
        assert exc.value.status_code == 400

    def test_case_insensitive_duplicate_detected(self):
        svc = make_service()
        existing = make_mock_role(role_id=5, role_name="TESTER")
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_all_roles",
                   return_value=[existing]):
            with pytest.raises(HTTPException):
                svc._check_duplicate_role("tester")

    def test_exclude_role_id_allows_self_update(self):
        """Updating a role to the same name should not raise (exclude own ID)."""
        svc = make_service()
        existing = make_mock_role(role_id=5, role_name="Tester")
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_all_roles",
                   return_value=[existing]):
            # Should not raise — we exclude role_id=5 (the role being updated)
            svc._check_duplicate_role("Tester", exclude_role_id=5)

    def test_no_duplicate_passes_silently(self):
        svc = make_service()
        existing = make_mock_role(role_id=5, role_name="Dev")
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_all_roles",
                   return_value=[existing]):
            svc._check_duplicate_role("QA")  # no raise


# ══════════════════════════════════════════════════════════════════════════════
# create_role
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateRole:

    def test_create_role_happy_path(self):
        svc = make_service()
        role_data = MagicMock()
        role_data.role_name = "Tester"
        new_role = make_mock_role()

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_all_roles",
                   return_value=[]), \
             patch("Backend.Business_Layer.services.role_service.role_dao.create_role",
                   return_value=new_role), \
             patch("Backend.Business_Layer.services.role_service.generate_uuid7",
                   return_value="new-uuid"):
            result = svc.create_role(role_data, current_user=MOCK_USER, request=MOCK_REQUEST)

        assert result is new_role

    def test_create_role_duplicate_name_raises_400(self):
        svc = make_service()
        role_data = MagicMock()
        role_data.role_name = "Tester"
        existing = make_mock_role(role_id=5, role_name="Tester")

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_all_roles",
                   return_value=[existing]):
            with pytest.raises(HTTPException) as exc:
                svc.create_role(role_data, current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# update_role_by_uuid
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdateRoleByUuid:

    @pytest.mark.parametrize("mandatory", ["Admin", "Super_Admin", "HR", "General", "System"])
    def test_mandatory_role_cannot_be_renamed(self, mandatory):
        """Business rule: system roles are immutable."""
        svc = make_service()
        role = make_mock_role(role_name=mandatory)
        role_data = MagicMock()
        role_data.role_name = "NewName"

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role):
            with pytest.raises(HTTPException) as exc:
                svc.update_role_by_uuid("uuid-r1", role_data,
                                        current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_update_role_not_found_raises_404(self):
        svc = make_service()
        role_data = MagicMock()
        role_data.role_name = "NewName"

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=None):
            with pytest.raises(HTTPException) as exc:
                svc.update_role_by_uuid("ghost-uuid", role_data,
                                        current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_update_role_happy_path(self):
        svc = make_service()
        role = make_mock_role(role_name="Tester")
        role_data = MagicMock()
        role_data.role_name = "QA"
        updated = make_mock_role(role_name="QA")

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_all_roles",
                   return_value=[]), \
             patch("Backend.Business_Layer.services.role_service.role_dao.update_role_by_uuid",
                   return_value=updated):
            result = svc.update_role_by_uuid("uuid-r1", role_data,
                                             current_user=MOCK_USER, request=MOCK_REQUEST)
        assert result is updated


# ══════════════════════════════════════════════════════════════════════════════
# delete_role_by_uuid
# ══════════════════════════════════════════════════════════════════════════════

class TestDeleteRoleByUuid:

    def test_delete_not_found_raises_404(self):
        svc = make_service()
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=None):
            with pytest.raises(HTTPException) as exc:
                svc.delete_role_by_uuid("ghost-uuid", current_user=MOCK_USER,
                                        request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    @pytest.mark.parametrize("mandatory", ["Admin", "Super_Admin", "HR", "General"])
    def test_mandatory_role_cannot_be_deleted(self, mandatory):
        """Business rule: system roles are protected from deletion."""
        svc = make_service()
        role = make_mock_role(role_name=mandatory)
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role):
            with pytest.raises(HTTPException) as exc:
                svc.delete_role_by_uuid("uuid-r1", current_user=MOCK_USER,
                                        request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_delete_role_reassigns_users_to_general(self):
        """
        Business rule: users who lose their last role are reassigned to General.
        """
        svc = make_service()
        role = make_mock_role(role_name="Tester")
        general_role = make_mock_role(role_id=4, role_name="General")

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_users_by_role",
                   return_value=[101, 102]), \
             patch("Backend.Business_Layer.services.role_service.role_dao.delete_user_roles_by_role"), \
             patch("Backend.Business_Layer.services.role_service.role_dao.delete_role_permission_groups"), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_name",
                   return_value=general_role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_user_roles",
                   return_value=[]), \
             patch("Backend.Business_Layer.services.role_service.role_dao.assign_role") as mock_assign, \
             patch("Backend.Business_Layer.services.role_service.role_dao.delete_role",
                   return_value={"message": "Role deleted successfully"}):
            result = svc.delete_role_by_uuid("uuid-r1", current_user=MOCK_USER,
                                             request=MOCK_REQUEST)

        # Both users had no remaining roles → both reassigned to General
        assert mock_assign.call_count == 2

    def test_delete_role_does_not_reassign_users_with_remaining_roles(self):
        svc = make_service()
        role = make_mock_role(role_name="Tester")
        general_role = make_mock_role(role_id=4, role_name="General")

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_users_by_role",
                   return_value=[101]), \
             patch("Backend.Business_Layer.services.role_service.role_dao.delete_user_roles_by_role"), \
             patch("Backend.Business_Layer.services.role_service.role_dao.delete_role_permission_groups"), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_name",
                   return_value=general_role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_user_roles",
                   return_value=[2, 3]), \
             patch("Backend.Business_Layer.services.role_service.role_dao.assign_role") as mock_assign, \
             patch("Backend.Business_Layer.services.role_service.role_dao.delete_role",
                   return_value={"message": "done"}):
            svc.delete_role_by_uuid("uuid-r1", current_user=MOCK_USER, request=MOCK_REQUEST)

        mock_assign.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# delete_roles_by_uuid (bulk)
# ══════════════════════════════════════════════════════════════════════════════

class TestDeleteRolesByUuid:

    def test_empty_list_raises_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc.delete_roles_by_uuid([], current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_general_role_missing_raises_500(self):
        svc = make_service()
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_name",
                   return_value=None):
            with pytest.raises(HTTPException) as exc:
                svc.delete_roles_by_uuid(["uuid-r1"], current_user=MOCK_USER,
                                         request=MOCK_REQUEST)
        assert exc.value.status_code == 500

    def test_mandatory_roles_are_skipped(self):
        """Mandatory roles appear in failed_roles, none deleted → 400."""
        svc = make_service()
        admin_role = make_mock_role(role_name="Admin")
        general_role = make_mock_role(role_id=4, role_name="General")

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_name",
                   return_value=general_role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=admin_role):
            with pytest.raises(HTTPException) as exc:
                svc.delete_roles_by_uuid(["uuid-admin"], current_user=MOCK_USER,
                                         request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_not_found_roles_are_skipped(self):
        """Not-found roles appear in failed_roles, nothing deleted → 400."""
        svc = make_service()
        general_role = make_mock_role(role_id=4, role_name="General")

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_name",
                   return_value=general_role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=None):
            with pytest.raises(HTTPException) as exc:
                svc.delete_roles_by_uuid(["ghost-uuid"], current_user=MOCK_USER,
                                         request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_bulk_delete_success_returns_summary(self):
        svc = make_service()
        role = make_mock_role(role_name="Tester")
        general_role = make_mock_role(role_id=4, role_name="General")

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_name",
                   return_value=general_role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_users_by_role",
                   return_value=[]), \
             patch("Backend.Business_Layer.services.role_service.role_dao.delete_user_roles_by_role"), \
             patch("Backend.Business_Layer.services.role_service.role_dao.delete_role_permission_groups"), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_user_roles",
                   return_value=[1]), \
             patch("Backend.Business_Layer.services.role_service.role_dao.delete_role"):
            result = svc.delete_roles_by_uuid(["uuid-r1"], current_user=MOCK_USER,
                                              request=MOCK_REQUEST)

        assert result["deleted_count"] == 1
        assert "deleted_roles" in result


# ══════════════════════════════════════════════════════════════════════════════
# Permission-group management on roles
# ══════════════════════════════════════════════════════════════════════════════

class TestPermissionGroupsOnRoles:

    def test_get_permissions_by_role_uuid(self):
        svc = make_service()
        role = make_mock_role()
        perms = [{"code": "VIEW_USERS", "description": "View users"}]

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_permissions_by_role",
                   return_value=perms):
            result = svc.get_permissions_by_role_uuid("uuid-r1")
        assert result == perms

    def test_update_permission_groups_for_role(self):
        svc = make_service()
        payload = MagicMock()
        payload.group_ids = [1, 2]

        with patch("Backend.Business_Layer.services.role_service.role_dao.update_role_groups",
                   return_value={"message": "done"}) as mock_update:
            result = svc.update_role_permission_groups(5, payload)

        mock_update.assert_called_once_with(svc.db, 5, [1, 2])

    def test_get_users_by_role_uuid_or_name(self):
        svc = make_service()
        users = [{"user_id": 1}, {"user_id": 2}]

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_users_by_role_uuid_or_name",
                   return_value=users):
            result = svc.get_users_by_role_uuid_or_name(
                role_name="Tester", role_uuid=None
            )
        assert result == users

    def test_get_permission_groups_by_role_uuid(self):
        svc = make_service()
        groups = [MagicMock(), MagicMock()]
        role = make_mock_role()

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_permission_groups_by_role",
                   return_value=groups):
            result = svc.get_permission_groups_by_role_uuid("uuid-r1")
        assert result == groups


# ══════════════════════════════════════════════════════════════════════════════
# add_permission_groups_to_role
# ══════════════════════════════════════════════════════════════════════════════

class TestAddPermissionGroupsToRole:

    def test_happy_path_returns_result(self):
        svc = make_service()
        group = MagicMock()
        group.group_name = "Admin Group"

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=make_mock_role()), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_permission_group_by_uuid",
                   return_value=group), \
             patch("Backend.Business_Layer.services.role_service.role_dao.add_permission_groups_to_role",
                   return_value={"message": "Permission groups added successfully"}):
            result = svc.add_permission_groups_to_role(
                "uuid-r1", ["g-uuid-1"], assigned_by=1,
                current_user=MOCK_USER, request=MOCK_REQUEST
            )
        assert "added" in result["message"].lower()

    def test_dao_failure_raises_500(self):
        svc = make_service()
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=make_mock_role()), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_permission_group_by_uuid",
                   return_value=None), \
             patch("Backend.Business_Layer.services.role_service.role_dao.add_permission_groups_to_role",
                   side_effect=Exception("DB error")):
            with pytest.raises(HTTPException) as exc:
                svc.add_permission_groups_to_role(
                    "uuid-r1", ["g-uuid-1"], assigned_by=1,
                    current_user=MOCK_USER, request=MOCK_REQUEST
                )
        assert exc.value.status_code == 500


# ══════════════════════════════════════════════════════════════════════════════
# remove_permission_group_from_role
# ══════════════════════════════════════════════════════════════════════════════

class TestRemovePermissionGroupFromRole:

    def test_happy_path(self):
        svc = make_service()
        group = MagicMock()
        group.group_name = "Admin Group"

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=make_mock_role()), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_permission_group_by_uuid",
                   return_value=group), \
             patch("Backend.Business_Layer.services.role_service.role_dao.remove_permission_group_from_role",
                   return_value={"message": "removed"}):
            result = svc.remove_permission_group_from_role(
                "uuid-r1", "g-uuid-1",
                current_user=MOCK_USER, request=MOCK_REQUEST
            )
        assert result is not None

    def test_dao_exception_raises_500(self):
        svc = make_service()
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=make_mock_role()), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_permission_group_by_uuid",
                   return_value=None), \
             patch("Backend.Business_Layer.services.role_service.role_dao.remove_permission_group_from_role",
                   side_effect=Exception("DB error")):
            with pytest.raises(HTTPException) as exc:
                svc.remove_permission_group_from_role(
                    "uuid-r1", "g-uuid-1",
                    current_user=MOCK_USER, request=MOCK_REQUEST
                )
        assert exc.value.status_code == 500


# ══════════════════════════════════════════════════════════════════════════════
# remove_permission_groups_to_role (bulk)
# ══════════════════════════════════════════════════════════════════════════════

class TestRemovePermissionGroupsToRole:

    def test_happy_path(self):
        svc = make_service()
        group = MagicMock()
        group.group_name = "Admin Group"

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=make_mock_role()), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_permission_group_by_uuid",
                   return_value=group), \
             patch("Backend.Business_Layer.services.role_service.role_dao.remove_permission_groups_from_role",
                   return_value={"message": "removed"}):
            result = svc.remove_permission_groups_to_role(
                "uuid-r1", ["g-uuid-1"],
                current_user=MOCK_USER, request=MOCK_REQUEST
            )
        assert result is not None

    def test_dao_exception_raises_500(self):
        svc = make_service()
        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=make_mock_role()), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_permission_group_by_uuid",
                   return_value=None), \
             patch("Backend.Business_Layer.services.role_service.role_dao.remove_permission_groups_from_role",
                   side_effect=Exception("DB error")):
            with pytest.raises(HTTPException) as exc:
                svc.remove_permission_groups_to_role(
                    "uuid-r1", ["g-uuid-1"],
                    current_user=MOCK_USER, request=MOCK_REQUEST
                )
        assert exc.value.status_code == 500


# ══════════════════════════════════════════════════════════════════════════════
# update_permission_groups_for_role_uuid
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdatePermissionGroupsForRoleUuid:

    def test_resolves_role_and_delegates(self):
        svc = make_service()
        role = make_mock_role()

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.update_permission_groups_for_role",
                   return_value={"message": "done"}) as mock_update:
            svc.update_permission_groups_for_role_uuid("uuid-r1", ["g-uuid-1", "g-uuid-2"])

        mock_update.assert_called_once_with(svc.db, role.role_id, ["g-uuid-1", "g-uuid-2"])

    def test_get_unassigned_permission_groups_for_role(self):
        svc = make_service()
        role = make_mock_role()
        groups = [MagicMock(), MagicMock()]

        with patch("Backend.Business_Layer.services.role_service.role_dao.get_role_by_uuid",
                   return_value=role), \
             patch("Backend.Business_Layer.services.role_service.role_dao.get_unassigned_permission_groups",
                   return_value=groups):
            result = svc.get_unassigned_permission_groups("uuid-r1")
        assert result == groups
