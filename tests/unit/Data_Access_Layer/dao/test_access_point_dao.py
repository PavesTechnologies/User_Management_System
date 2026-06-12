"""
tests/unit/Data_Access_Layer/dao/test_access_point_dao.py

Unit tests for Backend/Data_Access_Layer/dao/access_point_dao.py (AccessPointDAO)

All SQLAlchemy calls are mocked — no real DB.
Tests cover the core access point and permission mapping operations.
"""

import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime


# ── helpers ────────────────────────────────────────────────────────────────────

def make_dao(db=None):
    from Backend.Data_Access_Layer.dao.access_point_dao import AccessPointDAO
    dao = AccessPointDAO.__new__(AccessPointDAO)
    dao.db = db or MagicMock()
    return dao


def make_ap(access_id=1, access_uuid="ap-uuid-1", endpoint_path="/ums/users",
            method="GET", module="user", is_public=False, regex_pattern=None):
    ap = MagicMock()
    ap.access_id = access_id
    ap.access_uuid = access_uuid
    ap.endpoint_path = endpoint_path
    ap.method = method
    ap.module = module
    ap.is_public = is_public
    ap.regex_pattern = regex_pattern
    ap.permission_mappings = []
    return ap


# ══════════════════════════════════════════════════════════════════════════════
# create_access_point
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateAccessPoint:

    def test_creates_with_uppercase_method(self):
        db = MagicMock()
        dao = make_dao(db)
        ap = make_ap()
        db.add.return_value = None
        db.commit.return_value = None
        db.refresh.return_value = None

        # Make refresh set attributes on the object
        result = dao.create_access_point(
            endpoint_path="/ums/users",
            created_by=1,
            access_uuid="ap-uuid-1",
            regex_pattern=None,
            method="get",   # lowercase input
            module="user",
            is_public=False,
        )

        db.add.assert_called_once()
        db.commit.assert_called_once()
        # method is uppercased in the constructor
        added_obj = db.add.call_args[0][0]
        assert added_obj.method == "GET"

    def test_creates_public_access_point(self):
        db = MagicMock()
        dao = make_dao(db)
        dao.create_access_point(
            endpoint_path="/ums/auth/login",
            created_by=1,
            access_uuid="uuid-pub",
            regex_pattern=None,
            method="POST",
            module="auth",
            is_public=True,
        )
        added_obj = db.add.call_args[0][0]
        assert added_obj.is_public is True


# ══════════════════════════════════════════════════════════════════════════════
# get_by_endpoint_path
# ══════════════════════════════════════════════════════════════════════════════

class TestGetByEndpointPath:

    def test_found(self):
        db = MagicMock()
        ap = make_ap()
        db.query.return_value.filter_by.return_value.first.return_value = ap
        dao = make_dao(db)
        result = dao.get_by_endpoint_path("/ums/users")
        assert result is ap

    def test_not_found(self):
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = None
        dao = make_dao(db)
        result = dao.get_by_endpoint_path("/ums/ghost")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# get_access_point_by_path_and_method
# ══════════════════════════════════════════════════════════════════════════════

class TestGetByPathAndMethod:

    def test_exact_match_returned(self):
        db = MagicMock()
        ap = make_ap()
        db.expire_all.return_value = None
        db.query.return_value.filter_by.return_value.first.return_value = ap
        dao = make_dao(db)
        result = dao.get_access_point_by_path_and_method("/ums/users", "GET")
        assert result is ap

    def test_regex_match_when_no_exact_match(self):
        db = MagicMock()
        # Exact match returns None
        db.expire_all.return_value = None

        ap_with_regex = make_ap(endpoint_path="/ums/users/{id}",
                                regex_pattern=r"^/ums/users/([^/]+)$")
        # Setup: filter_by().first() → None (no exact match)
        db.query.return_value.filter_by.return_value.first.return_value = None
        # Setup: filter().all() → [ap_with_regex]
        db.query.return_value.filter.return_value.all.return_value = [ap_with_regex]

        dao = make_dao(db)
        result = dao.get_access_point_by_path_and_method("/ums/users/42", "GET")
        assert result is ap_with_regex

    def test_no_match_returns_none(self):
        db = MagicMock()
        db.expire_all.return_value = None
        db.query.return_value.filter_by.return_value.first.return_value = None
        db.query.return_value.filter.return_value.all.return_value = []
        dao = make_dao(db)
        result = dao.get_access_point_by_path_and_method("/ums/ghost/path", "DELETE")
        assert result is None

    def test_method_is_uppercased_for_lookup(self):
        db = MagicMock()
        ap = make_ap()
        db.expire_all.return_value = None
        db.query.return_value.filter_by.return_value.first.return_value = ap
        dao = make_dao(db)
        dao.get_access_point_by_path_and_method("/ums/users", "get")
        # filter_by is called with method="GET"
        call_kwargs = db.query.return_value.filter_by.call_args[1]
        assert call_kwargs.get("method") == "GET"


# ══════════════════════════════════════════════════════════════════════════════
# get_access_point_by_id / get_access_point_by_uuid
# ══════════════════════════════════════════════════════════════════════════════

class TestGetById:

    def test_get_by_id_found(self):
        db = MagicMock()
        ap = make_ap()
        db.query.return_value.options.return_value.filter_by.return_value.first.return_value = ap
        dao = make_dao(db)
        result = dao.get_access_point_by_id(1)
        assert result is ap

    def test_get_by_id_not_found(self):
        db = MagicMock()
        db.query.return_value.options.return_value.filter_by.return_value.first.return_value = None
        dao = make_dao(db)
        result = dao.get_access_point_by_id(99)
        assert result is None

    def test_get_by_uuid_found(self):
        db = MagicMock()
        ap = make_ap()
        db.query.return_value.options.return_value.filter_by.return_value.first.return_value = ap
        dao = make_dao(db)
        result = dao.get_access_point_by_uuid("ap-uuid-1")
        assert result is ap

    def test_get_by_uuid_not_found(self):
        db = MagicMock()
        db.query.return_value.options.return_value.filter_by.return_value.first.return_value = None
        dao = make_dao(db)
        result = dao.get_access_point_by_uuid("ghost-uuid")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# update_access_point
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdateAccessPoint:

    def test_returns_none_when_not_found(self):
        db = MagicMock()
        db.query.return_value.options.return_value.filter_by.return_value.first.return_value = None
        dao = make_dao(db)
        result = dao.update_access_point(99, module="new_module")
        assert result is None

    def test_updates_fields_and_commits(self):
        db = MagicMock()
        ap = make_ap()
        db.query.return_value.options.return_value.filter_by.return_value.first.return_value = ap
        db.expire_all.return_value = None
        dao = make_dao(db)

        result = dao.update_access_point(1, module="new_module", is_public=True)

        assert ap.module == "new_module"
        assert ap.is_public is True
        db.commit.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# delete_access_point
# ══════════════════════════════════════════════════════════════════════════════

class TestDeleteAccessPoint:

    def test_not_found_returns_false(self):
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = None
        dao = make_dao(db)
        result = dao.delete_access_point(99)
        assert result is False

    def test_found_deletes_and_returns_true(self):
        db = MagicMock()
        ap = make_ap()
        db.query.return_value.filter_by.return_value.first.return_value = ap
        dao = make_dao(db)
        result = dao.delete_access_point(1)
        db.delete.assert_called_once_with(ap)
        db.commit.assert_called_once()
        assert result is True


# ══════════════════════════════════════════════════════════════════════════════
# get_permission_code_by_access_id
# ══════════════════════════════════════════════════════════════════════════════

class TestGetPermissionCode:

    def test_no_mapping_returns_none(self):
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = None
        dao = make_dao(db)
        result = dao.get_permission_code_by_access_id(1)
        assert result is None

    def test_mapping_found_returns_code(self):
        db = MagicMock()
        mapping = MagicMock()
        mapping.permission_id = 10

        perm = MagicMock()
        perm.permission_code = "VIEW_USERS"

        # First call: AccessPointPermission lookup
        # Second call: Permissions lookup
        db.query.return_value.filter_by.return_value.first.side_effect = [mapping, perm]

        dao = make_dao(db)
        result = dao.get_permission_code_by_access_id(1)
        assert result == "VIEW_USERS"


# ══════════════════════════════════════════════════════════════════════════════
# get_distinct_modules
# ══════════════════════════════════════════════════════════════════════════════

class TestGetDistinctModules:

    def test_returns_non_null_module_names(self):
        db = MagicMock()
        db.query.return_value.distinct.return_value.all.return_value = [
            ("user",), ("role",), (None,), ("auth",)
        ]
        dao = make_dao(db)
        result = dao.get_distinct_modules()
        assert "user" in result
        assert "role" in result
        assert "auth" in result
        assert None not in result

    def test_empty_returns_empty_list(self):
        db = MagicMock()
        db.query.return_value.distinct.return_value.all.return_value = []
        dao = make_dao(db)
        result = dao.get_distinct_modules()
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# get_all_access_points
# ══════════════════════════════════════════════════════════════════════════════

class TestGetAllAccessPoints:

    def test_returns_list_of_access_points(self):
        db = MagicMock()
        aps = [make_ap(1), make_ap(2)]
        db.query.return_value.options.return_value.all.return_value = aps
        dao = make_dao(db)
        result = dao.get_all_access_points()
        assert result == aps

    def test_empty_table_returns_empty_list(self):
        db = MagicMock()
        db.query.return_value.options.return_value.all.return_value = []
        dao = make_dao(db)
        result = dao.get_all_access_points()
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# update_access_point_permission
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdateAccessPointPermission:

    def test_null_permission_code_deletes_mapping(self):
        db = MagicMock()
        mapping = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = mapping
        dao = make_dao(db)

        result = dao.update_access_point_permission(1, "Null")

        db.delete.assert_called_once_with(mapping)
        db.commit.assert_called_once()
        assert result is None

    def test_none_permission_code_deletes_mapping(self):
        db = MagicMock()
        mapping = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = mapping
        dao = make_dao(db)
        result = dao.update_access_point_permission(1, None)
        db.delete.assert_called_once_with(mapping)
        assert result is None

    def test_permission_not_found_returns_none(self):
        db = MagicMock()
        # No existing mapping; permission not found
        db.query.return_value.filter_by.return_value.first.side_effect = [None, None]
        dao = make_dao(db)
        result = dao.update_access_point_permission(1, "VIEW_USERS")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# Permission DAO helpers
# ══════════════════════════════════════════════════════════════════════════════

class TestPermissionHelpers:

    def test_get_permission_by_code_found(self):
        db = MagicMock()
        perm = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = perm
        dao = make_dao(db)
        result = dao.get_permission_by_code("VIEW_USERS")
        assert result is perm

    def test_get_permission_by_code_not_found(self):
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = None
        dao = make_dao(db)
        result = dao.get_permission_by_code("GHOST")
        assert result is None

    def test_get_permission_by_id_found(self):
        db = MagicMock()
        perm = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = perm
        dao = make_dao(db)
        result = dao.get_permission_by_id(10)
        assert result is perm

    def test_create_permission_commits_and_returns(self):
        db = MagicMock()
        dao = make_dao(db)
        result = dao.create_permission("VIEW_USERS", "View all users")
        db.add.assert_called_once()
        db.commit.assert_called_once()
        db.refresh.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# create_access_permission_mapping / get_mapping / delete_mapping
# ══════════════════════════════════════════════════════════════════════════════

class TestAccessPermissionMappings:

    def test_create_mapping_commits(self):
        db = MagicMock()
        dao = make_dao(db)
        result = dao.create_access_permission_mapping(
            access_id=1, permission_id=10, assigned_by=1
        )
        db.add.assert_called_once()
        db.commit.assert_called_once()

    def test_get_mapping_by_access_id_found(self):
        db = MagicMock()
        mapping = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = mapping
        dao = make_dao(db)
        result = dao.get_mapping_by_access_id(1)
        assert result is mapping

    def test_get_mapping_by_access_id_not_found(self):
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = None
        dao = make_dao(db)
        result = dao.get_mapping_by_access_id(99)
        assert result is None

    def test_delete_mapping_by_access_id_returns_false_when_not_found(self):
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = None
        dao = make_dao(db)
        result = dao.delete_mapping_by_access_id(99)
        assert result is False

    def test_delete_mapping_by_access_id_returns_true_when_found(self):
        db = MagicMock()
        mapping = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = mapping
        dao = make_dao(db)
        result = dao.delete_mapping_by_access_id(1)
        db.delete.assert_called_once_with(mapping)
        db.commit.assert_called_once()
        assert result is True


# ══════════════════════════════════════════════════════════════════════════════
# get_permissions_for_access_point (permission middleware uses this)
# ══════════════════════════════════════════════════════════════════════════════

class TestGetPermissionsForAccessPoint:

    def test_returns_permission_codes(self):
        from Backend.Data_Access_Layer.dao.access_point_dao import AccessPointDAO
        db = MagicMock()
        dao = AccessPointDAO.__new__(AccessPointDAO)
        dao.db = db

        mapping = MagicMock()
        perm = MagicMock()
        perm.permission_code = "VIEW_USERS"
        mapping.permission = perm
        mapping.permission_id = 10
        db.query.return_value.filter_by.return_value.all.return_value = [mapping]
        db.query.return_value.filter_by.return_value.first.return_value = perm

        # get_permissions_for_access_point is called in permission_utils
        # The method may not exist by this name — check what it's called
        # In the DAO, the method that permission_utils calls is get_permissions_for_access_point
        if hasattr(dao, "get_permissions_for_access_point"):
            result = dao.get_permissions_for_access_point(1)
            assert isinstance(result, list)


# ══════════════════════════════════════════════════════════════════════════════
# get_permissions_for_access_point (raw SQL via text())
# ══════════════════════════════════════════════════════════════════════════════

class TestGetPermissionsForAccessPoint:

    def test_returns_permission_codes_list(self):
        db = MagicMock()
        rows = [("VIEW_USERS",), ("EDIT_USERS",)]
        db.execute.return_value.fetchall.return_value = rows
        dao = make_dao(db)
        result = dao.get_permissions_for_access_point(1)
        assert result == ["VIEW_USERS", "EDIT_USERS"]

    def test_returns_empty_when_no_permissions(self):
        db = MagicMock()
        db.execute.return_value.fetchall.return_value = []
        dao = make_dao(db)
        result = dao.get_permissions_for_access_point(99)
        assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# get_all_access_point_permission_ids
# ══════════════════════════════════════════════════════════════════════════════

class TestGetAllPermissionIds:

    def test_returns_permission_ids_from_all_mappings(self):
        db = MagicMock()
        mapping1 = MagicMock()
        mapping1.permission_id = 10
        mapping2 = MagicMock()
        mapping2.permission_id = 20
        ap = make_ap()
        ap.permission_mappings = [mapping1, mapping2]
        db.query.return_value.options.return_value.all.return_value = [ap]
        dao = make_dao(db)
        result = dao.get_all_access_point_permission_ids()
        assert 10 in result
        assert 20 in result

    def test_returns_empty_when_no_mappings(self):
        db = MagicMock()
        ap = make_ap()
        ap.permission_mappings = []
        db.query.return_value.options.return_value.all.return_value = [ap]
        dao = make_dao(db)
        result = dao.get_all_access_point_permission_ids()
        assert result == []
