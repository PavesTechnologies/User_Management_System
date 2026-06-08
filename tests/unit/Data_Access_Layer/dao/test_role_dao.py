"""
tests/unit/Data_Access_Layer/dao/test_role_dao.py

Unit tests for Backend/Data_Access_Layer/dao/role_dao.py

All SQLAlchemy session calls are mocked — no real DB connection.
Tests verify the query chains and business logic in each DAO function.
"""

import pytest
from unittest.mock import MagicMock, patch, call
from fastapi import HTTPException


# ── helpers ────────────────────────────────────────────────────────────────────

def make_db():
    return MagicMock()


def make_role(role_id=10, role_uuid="uuid-r1", role_name="Tester"):
    r = MagicMock()
    r.role_id = role_id
    r.role_uuid = role_uuid
    r.role_name = role_name
    return r


# ══════════════════════════════════════════════════════════════════════════════
# get_all_roles
# ══════════════════════════════════════════════════════════════════════════════

class TestGetAllRoles:

    def test_returns_rows_from_execute(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        rows = [MagicMock(), MagicMock()]
        db.execute.return_value.all.return_value = rows
        result = role_dao.get_all_roles(db)
        assert result == rows

    def test_empty_table_returns_empty_list(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.execute.return_value.all.return_value = []
        result = role_dao.get_all_roles(db)
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# get_role / get_role_by_uuid / get_role_by_name
# ══════════════════════════════════════════════════════════════════════════════

class TestGetRole:

    def test_get_role_by_id_found(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role = make_role()
        db.query.return_value.filter.return_value.first.return_value = role
        result = role_dao.get_role(db, 10)
        assert result is role

    def test_get_role_by_id_not_found(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        result = role_dao.get_role(db, 99)
        assert result is None

    def test_get_role_by_uuid_found(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role = make_role()
        db.query.return_value.filter.return_value.first.return_value = role
        result = role_dao.get_role_by_uuid(db, "uuid-r1")
        assert result is role

    def test_get_role_by_uuid_not_found(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        result = role_dao.get_role_by_uuid(db, "ghost-uuid")
        assert result is None

    def test_get_role_by_name_found(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role = make_role(role_name="General")
        db.query.return_value.filter.return_value.first.return_value = role
        result = role_dao.get_role_by_name(db, "General")
        assert result is role

    def test_get_role_by_name_not_found(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        result = role_dao.get_role_by_name(db, "Ghost")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# create_role
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateRole:

    def test_create_role_commits_and_returns(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role_data = MagicMock()
        role_data.role_name = "Tester"

        result = role_dao.create_role(db, "new-uuid", role_data)

        db.add.assert_called_once()
        db.commit.assert_called_once()
        db.refresh.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# update_role / update_role_by_uuid
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdateRole:

    def test_update_role_not_found_raises(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        role_data = MagicMock()
        role_data.role_name = "New"
        with pytest.raises(Exception, match="Role not found"):
            role_dao.update_role(db, 99, role_data)

    def test_update_role_happy_path(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        existing = make_role()
        db.query.return_value.filter.return_value.first.return_value = existing
        role_data = MagicMock()
        role_data.role_name = "NewName"
        result = role_dao.update_role(db, 10, role_data)
        assert existing.role_name == "NewName"
        db.commit.assert_called_once()

    def test_update_role_by_uuid_happy_path(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        existing = make_role()
        db.query.return_value.filter.return_value.first.return_value = existing
        role_data = MagicMock()
        role_data.role_name = "Updated"
        role_dao.update_role_by_uuid(db, "uuid-r1", role_data)
        assert existing.role_name == "Updated"
        db.commit.assert_called_once()

    def test_update_role_by_uuid_not_found_raises(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        role_data = MagicMock()
        role_data.role_name = "New"
        with pytest.raises(Exception, match="Role not found"):
            role_dao.update_role_by_uuid(db, "ghost-uuid", role_data)


# ══════════════════════════════════════════════════════════════════════════════
# delete_role
# ══════════════════════════════════════════════════════════════════════════════

class TestDeleteRole:

    def test_delete_role_not_found_raises(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        with pytest.raises(Exception, match="Role not found"):
            role_dao.delete_role(db, 99)

    def test_delete_role_happy_path(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role = make_role()
        db.query.return_value.filter.return_value.first.return_value = role
        result = role_dao.delete_role(db, 10)
        db.delete.assert_called_once_with(role)
        db.commit.assert_called_once()
        assert "deleted" in result["message"].lower()


# ══════════════════════════════════════════════════════════════════════════════
# get_users_by_role / get_user_roles / assign_role
# ══════════════════════════════════════════════════════════════════════════════

class TestUserRoleMappings:

    def test_get_users_by_role_returns_ids(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter_by.return_value.all.return_value = [(1,), (2,)]
        result = role_dao.get_users_by_role(db, 10)
        assert result == [1, 2]

    def test_get_users_by_role_empty(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter_by.return_value.all.return_value = []
        result = role_dao.get_users_by_role(db, 10)
        assert result == []

    def test_get_user_roles_returns_role_ids(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter_by.return_value.all.return_value = [(3,), (4,)]
        result = role_dao.get_user_roles(db, 100)
        assert result == [3, 4]

    def test_assign_role_adds_and_commits(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role_dao.assign_role(db, user_id=100, role_id=5)
        db.add.assert_called_once()
        db.commit.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# delete_user_roles_by_role / delete_role_permission_groups
# ══════════════════════════════════════════════════════════════════════════════

class TestCleanupMappings:

    def test_delete_user_roles_by_role_success(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role = make_role()
        db.query.return_value.filter.return_value.first.return_value = role
        db.query.return_value.filter_by.return_value.delete.return_value = 2
        role_dao.delete_user_roles_by_role(db, 10)
        db.commit.assert_called()

    def test_delete_user_roles_role_not_found_raises(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        with pytest.raises(Exception, match="Role not found"):
            role_dao.delete_user_roles_by_role(db, 99)

    def test_delete_role_permission_groups_success(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role = make_role()
        db.query.return_value.filter.return_value.first.return_value = role
        db.query.return_value.filter_by.return_value.delete.return_value = 1
        role_dao.delete_role_permission_groups(db, 10)
        db.commit.assert_called()

    def test_delete_role_permission_groups_role_not_found_raises(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        with pytest.raises(Exception, match="Role not found"):
            role_dao.delete_role_permission_groups(db, 99)


# ══════════════════════════════════════════════════════════════════════════════
# get_permissions_by_role
# ══════════════════════════════════════════════════════════════════════════════

class TestGetPermissionsByRole:

    def test_role_not_found_raises(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.scalar.return_value = False  # exists → False
        with pytest.raises(Exception, match="Role not found"):
            role_dao.get_permissions_by_role(db, 99)

    def test_no_groups_returns_empty_list(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        # exists returns True
        db.query.return_value.scalar.return_value = True
        # group_ids query returns empty
        db.query.return_value.filter_by.return_value.all.return_value = []
        result = role_dao.get_permissions_by_role(db, 10)
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# add_permission_groups_to_role
# ══════════════════════════════════════════════════════════════════════════════

class TestAddPermissionGroupsToRole:

    def test_role_not_found_raises_400(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        with pytest.raises(HTTPException) as exc:
            role_dao.add_permission_groups_to_role(db, "ghost-uuid", ["g-uuid-1"], 1)
        assert exc.value.status_code == 400

    def test_group_not_found_raises_400(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role = make_role()
        # First call (get_role_by_uuid) returns role; second call (get_permission_group_by_uuid) returns None
        db.query.return_value.filter.return_value.first.side_effect = [role, None]
        with pytest.raises(HTTPException) as exc:
            role_dao.add_permission_groups_to_role(db, "uuid-r1", ["ghost-g-uuid"], 1)
        assert exc.value.status_code == 400

    def test_happy_path_returns_success_message(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        role = make_role()
        group = MagicMock()
        group.group_id = 5

        # Mock: get_role_by_uuid → role, get_permission_group_by_uuid → group
        db.query.return_value.filter.return_value.first.side_effect = [role, group]
        # get_all group_ids (existing_group_ids query)
        db.query.return_value.all.return_value = [(5,)]
        # exists() scalar → False (not already assigned)
        db.query.return_value.scalar.return_value = False

        result = role_dao.add_permission_groups_to_role(db, "uuid-r1", ["g-uuid-1"], 1)
        assert "added" in result["message"].lower()


# ══════════════════════════════════════════════════════════════════════════════
# update_role_groups
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdateRoleGroups:

    def test_update_role_groups_clears_and_rebuilds(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter_by.return_value.delete.return_value = 2
        result = role_dao.update_role_groups(db, role_id=10, group_ids=[1, 2, 3])
        db.bulk_save_objects.assert_called_once()
        db.commit.assert_called_once()
        assert "updated" in result["message"].lower()


# ══════════════════════════════════════════════════════════════════════════════
# get_permission_group_by_uuid
# ══════════════════════════════════════════════════════════════════════════════

class TestGetPermissionGroupByUuid:

    def test_returns_group_when_found(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        group = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = group
        result = role_dao.get_permission_group_by_uuid(db, "g-uuid-1")
        assert result is group

    def test_returns_none_when_not_found(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.filter.return_value.first.return_value = None
        result = role_dao.get_permission_group_by_uuid(db, "ghost-uuid")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# get_permission_groups_by_role
# ══════════════════════════════════════════════════════════════════════════════

class TestGetUnassignedPermissionGroups:

    def test_returns_unassigned_groups(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        groups = [MagicMock(), MagicMock()]
        subq = MagicMock()
        db.query.return_value.filter_by.return_value.subquery.return_value = subq
        db.query.return_value.filter.return_value.all.return_value = groups
        result = role_dao.get_unassigned_permission_groups(db, 10)
        assert result == groups


class TestGetPermissionGroupsByRole:

    def test_returns_groups_for_role(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        groups = [MagicMock(), MagicMock()]
        db.query.return_value.join.return_value.filter.return_value.all.return_value = groups
        result = role_dao.get_permission_groups_by_role(db, 10)
        assert result == groups

    def test_returns_empty_when_no_groups(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        db.query.return_value.join.return_value.filter.return_value.all.return_value = []
        result = role_dao.get_permission_groups_by_role(db, 10)
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# remove_permission_group_from_role
# ══════════════════════════════════════════════════════════════════════════════

class TestRemovePermissionGroupFromRole:

    def test_group_not_found_raises_400(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        # exists() → False (group UUID doesn't exist)
        db.query.return_value.scalar.return_value = False
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            role_dao.remove_permission_group_from_role(db, "uuid-r1", "ghost-g-uuid")
        assert exc.value.status_code == 400

    def test_role_not_found_raises_400(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        # exists() → True (group exists), but get_role_by_uuid → None
        db.query.return_value.scalar.return_value = True
        db.query.return_value.filter.return_value.first.return_value = None
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            role_dao.remove_permission_group_from_role(db, "ghost-role-uuid", "g-uuid-1")
        assert exc.value.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# get_users_by_role_uuid_or_name
# ══════════════════════════════════════════════════════════════════════════════

class TestGetUsersByRoleUuidOrName:

    def test_raises_400_when_neither_uuid_nor_name_provided(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            role_dao.get_users_by_role_uuid_or_name(db, role_uuid=None, role_name=None)
        assert exc.value.status_code == 400

    def test_filters_by_role_name_returns_list_with_filter_chain(self):
        """Test with role_uuid provided (goes through both filter branches)."""
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        Row = MagicMock()
        # .join().join().filter().filter().all() — both uuid and name filters applied
        db.query.return_value.join.return_value.join.return_value.filter.return_value.filter.return_value.all.return_value = [Row]
        result = role_dao.get_users_by_role_uuid_or_name(
            db, role_uuid="uuid-r1", role_name="Tester"
        )
        assert isinstance(result, list)

    def test_filters_by_role_name_returns_list(self):
        from Backend.Data_Access_Layer.dao import role_dao
        db = make_db()
        Row = MagicMock()
        Row.user_id = 1
        Row.employee_id = "EMP001"
        Row.role_name = "Tester"
        # The query chain: .join().join().filter().all()
        db.query.return_value.join.return_value.join.return_value.filter.return_value.all.return_value = [Row]
        result = role_dao.get_users_by_role_uuid_or_name(db, role_name="Tester")
        assert isinstance(result, list)
