"""
tests/unit/Business_Layer/services/test_permission_group_service.py

Business rules (Functional Spec §3.4):
  - Default group ('newly_created_permissions_group') cannot be updated or deleted
  - Duplicate group names are rejected (409 on update, ValueError on create)
  - Bulk delete fails 400 when nothing is deleted
  - Permission UUID must exist when adding/removing permissions from a group
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException


MOCK_REQUEST = MagicMock()
MOCK_USER = {"user_id": 1, "roles": ["Admin"]}


class TestPermissionGroupServiceInit:
    def test_init_wires_dao(self):
        from Backend.Business_Layer.services.permission_group_service import PermissionGroupService
        db = MagicMock()
        svc = PermissionGroupService(db)
        assert svc.dao is not None


def make_service(dao=None):
    from Backend.Business_Layer.services.permission_group_service import PermissionGroupService
    svc = PermissionGroupService.__new__(PermissionGroupService)
    svc.db = MagicMock()
    svc.dao = dao or MagicMock()
    return svc


def make_group(group_id=5, group_uuid="uuid-g1", group_name="My Group", created_by=1,
               created_at="2024-01-01"):
    g = MagicMock()
    g.group_id = group_id
    g.group_uuid = group_uuid
    g.group_name = group_name
    g.created_by = created_by
    g.created_at = created_at
    # audit decorator serializes result via entity.__table__.columns
    col = MagicMock()
    col.name = "group_id"
    tbl = MagicMock()
    tbl.columns = [col]
    g.__table__ = tbl
    return g


DEFAULT_GROUP = make_group(group_id=1, group_uuid="default-uuid",
                           group_name="newly_created_permissions_group")


# ══════════════════════════════════════════════════════════════════════════════
# list / get
# ══════════════════════════════════════════════════════════════════════════════

class TestListAndGet:

    def test_list_groups_delegates_to_dao(self):
        dao = MagicMock()
        dao.get_all_groups.return_value = [make_group()]
        svc = make_service(dao)
        result = svc.list_groups()
        assert len(result) == 1

    def test_get_group_delegates_to_dao(self):
        dao = MagicMock()
        grp = make_group()
        dao.get_group_by_uuid.return_value = grp
        svc = make_service(dao)
        result = svc.get_group("uuid-g1")
        assert result is grp


# ══════════════════════════════════════════════════════════════════════════════
# create_group
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateGroup:

    def test_create_group_happy_path(self):
        dao = MagicMock()
        new_grp = make_group()
        dao.get_group_by_name.return_value = None
        dao.create_group.return_value = new_grp
        svc = make_service(dao)

        with patch("Backend.Business_Layer.services.permission_group_service.generate_uuid7",
                   return_value="new-uuid"):
            result = svc.create_group("My Group", created_by=1,
                                      current_user=MOCK_USER, request=MOCK_REQUEST)
        assert result is new_grp

    def test_create_group_duplicate_name_raises_value_error(self):
        dao = MagicMock()
        dao.get_group_by_name.return_value = make_group()
        svc = make_service(dao)
        with pytest.raises(ValueError, match="already exists"):
            svc.create_group("My Group", created_by=1,
                             current_user=MOCK_USER, request=MOCK_REQUEST)

    def test_create_group_dao_failure_raises_500(self):
        dao = MagicMock()
        dao.get_group_by_name.return_value = None
        dao.create_group.return_value = None  # DAO returns None → failure
        svc = make_service(dao)
        with patch("Backend.Business_Layer.services.permission_group_service.generate_uuid7",
                   return_value="uuid"):
            with pytest.raises(HTTPException) as exc:
                svc.create_group("New Group", created_by=1,
                                 current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 500


# ══════════════════════════════════════════════════════════════════════════════
# update_group
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdateGroup:

    def test_update_group_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_group_by_uuid.return_value = None
        svc = make_service(dao)
        with pytest.raises(HTTPException) as exc:
            svc.update_group("ghost-uuid", "New Name",
                             current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_update_default_group_raises_400(self):
        """Business rule: the default group cannot be modified."""
        dao = MagicMock()
        grp = make_group(group_uuid="default-uuid")
        dao.get_group_by_uuid.return_value = grp
        dao.get_group_by_name.return_value = DEFAULT_GROUP
        svc = make_service(dao)

        with pytest.raises(HTTPException) as exc:
            svc.update_group("default-uuid", "Something Else",
                             current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_update_group_name_conflict_raises_409(self):
        dao = MagicMock()
        current = make_group(group_uuid="uuid-g1", group_name="OldName")
        dao.get_group_by_uuid.return_value = current
        dao.get_group_by_name.side_effect = lambda name: (
            DEFAULT_GROUP if name == "newly_created_permissions_group"
            else make_group(group_name=name)  # name exists in DB
        )
        svc = make_service(dao)
        with pytest.raises(HTTPException) as exc:
            svc.update_group("uuid-g1", "Taken Name",
                             current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 409

    def test_update_group_happy_path(self):
        dao = MagicMock()
        current = make_group(group_uuid="uuid-g1", group_name="OldName")
        updated = make_group(group_uuid="uuid-g1", group_name="NewName")
        dao.get_group_by_uuid.return_value = current
        dao.get_group_by_name.side_effect = lambda name: (
            DEFAULT_GROUP if name == "newly_created_permissions_group" else None
        )
        dao.update_group.return_value = updated
        svc = make_service(dao)

        result = svc.update_group("uuid-g1", "NewName",
                                  current_user=MOCK_USER, request=MOCK_REQUEST)
        assert result is updated


# ══════════════════════════════════════════════════════════════════════════════
# delete_group
# ══════════════════════════════════════════════════════════════════════════════

class TestDeleteGroup:

    def test_delete_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_group_by_uuid.return_value = None
        svc = make_service(dao)
        with pytest.raises(HTTPException) as exc:
            svc.delete_group("ghost-uuid", current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_delete_default_group_raises_400(self):
        """Business rule: the default permission group cannot be deleted."""
        dao = MagicMock()
        grp = make_group(group_uuid="default-uuid")
        dao.get_group_by_uuid.return_value = grp
        dao.get_group_by_name.return_value = DEFAULT_GROUP
        svc = make_service(dao)
        with pytest.raises(HTTPException) as exc:
            svc.delete_group("default-uuid", current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_delete_group_happy_path(self):
        dao = MagicMock()
        grp = make_group(group_uuid="uuid-g1")
        dao.get_group_by_uuid.return_value = grp
        dao.get_group_by_name.return_value = DEFAULT_GROUP
        dao.clear_group_permissions.return_value = None
        dao.clear_group_roles.return_value = None
        dao.delete_group.return_value = True
        svc = make_service(dao)

        result = svc.delete_group("uuid-g1", current_user=MOCK_USER, request=MOCK_REQUEST)
        assert "deleted" in result["message"].lower()


# ══════════════════════════════════════════════════════════════════════════════
# delete_groups_bulk
# ══════════════════════════════════════════════════════════════════════════════

class TestDeleteGroupsBulk:

    def test_empty_list_raises_400(self):
        svc = make_service()
        with pytest.raises(HTTPException) as exc:
            svc.delete_groups_bulk([], current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_default_group_is_skipped(self):
        """Default group appears in failed_groups; if nothing else deleted → 400."""
        dao = MagicMock()
        dao.get_group_by_name.return_value = DEFAULT_GROUP
        dao.get_group_by_uuid.return_value = DEFAULT_GROUP
        svc = make_service(dao)
        with pytest.raises(HTTPException) as exc:
            svc.delete_groups_bulk(["default-uuid"], current_user=MOCK_USER,
                                   request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_not_found_group_is_skipped(self):
        dao = MagicMock()
        dao.get_group_by_name.return_value = DEFAULT_GROUP
        dao.get_group_by_uuid.return_value = None
        svc = make_service(dao)
        with pytest.raises(HTTPException) as exc:
            svc.delete_groups_bulk(["ghost-uuid"], current_user=MOCK_USER,
                                   request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_bulk_delete_success(self):
        dao = MagicMock()
        grp = make_group(group_uuid="uuid-g1")
        dao.get_group_by_name.return_value = DEFAULT_GROUP
        dao.get_group_by_uuid.return_value = grp
        dao.clear_group_permissions.return_value = None
        dao.clear_group_roles.return_value = None
        dao.delete_group.return_value = True
        svc = make_service(dao)

        result = svc.delete_groups_bulk(["uuid-g1"], current_user=MOCK_USER,
                                        request=MOCK_REQUEST)
        assert result["deleted_count"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# add_permissions_to_group / remove_permissions_from_group
# ══════════════════════════════════════════════════════════════════════════════

class TestPermissionMappings:

    def test_add_permissions_group_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_group_by_uuid.return_value = None
        svc = make_service(dao)
        with pytest.raises(HTTPException) as exc:
            svc.add_permissions_to_group("ghost-uuid", ["puid-1"], assigned_by=1,
                                         current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_add_permissions_invalid_permission_uuid_raises_value_error(self):
        dao = MagicMock()
        grp = make_group()
        dao.get_group_by_uuid.return_value = grp
        dao.get_permission_by_uuid.return_value = None
        svc = make_service(dao)
        with pytest.raises(ValueError, match="not found"):
            svc.add_permissions_to_group("uuid-g1", ["bad-puid"], assigned_by=1,
                                         current_user=MOCK_USER, request=MOCK_REQUEST)

    def test_add_permissions_happy_path(self):
        dao = MagicMock()
        grp = make_group()
        perm = MagicMock()
        perm.permission_id = 10
        perm.permission_code = "VIEW_USERS"
        perm.description = "View all users"
        perm.permission_uuid = "perm-uuid-1"
        mapping = MagicMock()
        mapping.permission_id = 10
        default_grp = DEFAULT_GROUP
        default_grp.group_uuid = "default-uuid"

        dao.get_group_by_uuid.return_value = grp
        dao.get_permission_by_uuid.return_value = perm
        dao.add_permissions_to_group.return_value = [mapping]
        dao.get_group_by_name.return_value = default_grp
        dao.list_permissions_in_group = MagicMock(return_value=[])
        dao.get_permissions_by_ids.return_value = [perm]
        svc = make_service(dao)

        with patch.object(svc, "list_permissions_in_group", return_value=[]):
            result = svc.add_permissions_to_group("uuid-g1", ["perm-uuid-1"],
                                                  assigned_by=1,
                                                  current_user=MOCK_USER,
                                                  request=MOCK_REQUEST)
        assert result is not None

    def test_remove_permissions_group_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_group_by_uuid.return_value = None
        svc = make_service(dao)
        with pytest.raises(HTTPException) as exc:
            svc.remove_permissions_from_group("ghost-uuid", ["puid-1"],
                                              current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_remove_permissions_not_found_uuid_raises_value_error(self):
        dao = MagicMock()
        dao.get_group_by_uuid.return_value = make_group()
        dao.get_permission_by_uuid.return_value = None
        svc = make_service(dao)
        with pytest.raises(ValueError, match="not found"):
            svc.remove_permissions_from_group("uuid-g1", ["bad-puid"],
                                              current_user=MOCK_USER, request=MOCK_REQUEST)

    def test_remove_permissions_no_match_raises_404(self):
        dao = MagicMock()
        grp = make_group()
        perm = MagicMock()
        perm.permission_id = 10
        perm.permission_code = "VIEW_USERS"
        perm.description = "View"
        dao.get_group_by_uuid.return_value = grp
        dao.get_permission_by_uuid.return_value = perm
        dao.remove_permissions_from_group.return_value = 0  # nothing deleted
        svc = make_service(dao)
        with pytest.raises(HTTPException) as exc:
            svc.remove_permissions_from_group("uuid-g1", ["perm-uuid-1"],
                                              current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_remove_permissions_happy_path(self):
        dao = MagicMock()
        grp = make_group()
        perm = MagicMock()
        perm.permission_id = 10
        perm.permission_code = "VIEW_USERS"
        perm.description = "View"
        dao.get_group_by_uuid.return_value = grp
        dao.get_permission_by_uuid.return_value = perm
        dao.remove_permissions_from_group.return_value = 1
        svc = make_service(dao)

        result = svc.remove_permissions_from_group("uuid-g1", ["perm-uuid-1"],
                                                   current_user=MOCK_USER,
                                                   request=MOCK_REQUEST)
        assert "removed" in result["message"].lower()


# ══════════════════════════════════════════════════════════════════════════════
# pass-through delegators
# ══════════════════════════════════════════════════════════════════════════════

class TestDelegators:

    def test_search_groups(self):
        dao = MagicMock()
        dao.search_groups.return_value = [make_group()]
        svc = make_service(dao)
        result = svc.search_groups("My")
        dao.search_groups.assert_called_once_with("My")

    def test_list_unmapped_groups(self):
        dao = MagicMock()
        dao.get_unmapped_groups.return_value = []
        svc = make_service(dao)
        svc.list_unmapped_groups()
        dao.get_unmapped_groups.assert_called_once()

    def test_list_permissions_in_group(self):
        dao = MagicMock()
        dao.list_permissions_in_group.return_value = [{"permission_code": "VIEW_USERS"}]
        svc = make_service(dao)
        result = svc.list_permissions_in_group("uuid-g1")
        dao.list_permissions_in_group.assert_called_once_with("uuid-g1")
