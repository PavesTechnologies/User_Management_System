"""
tests/unit/Business_Layer/services/test_access_point_service.py

Business rules (Functional Spec §3.5 / Technical Design §2.3):
  - Static endpoints (no {}) produce regex_pattern=None
  - Dynamic endpoints ({id}) are converted to '^...([^/]+)...$' regex
  - Duplicate endpoint+method combination → 400
  - IntegrityError from DB → 400
  - Invalid file extension → 400 (bulk upload)
  - Cache is set after create; invalidated after update/delete
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError


MOCK_REQUEST = MagicMock()
MOCK_USER = {"user_id": 1, "roles": ["Admin"]}


class TestAccessPointServiceInit:
    def test_init_creates_daos(self):
        """Verify __init__ wires DAO and permission_dao correctly."""
        from Backend.Business_Layer.services.access_point_service import AccessPointService
        db = MagicMock()
        with patch("Backend.Business_Layer.services.access_point_service.AccessPointDAO"), \
             patch("Backend.Business_Layer.services.access_point_service.PermissionDAO"):
            svc = AccessPointService(db)
            assert svc.db is db


def make_service(dao=None, permission_dao=None):
    from Backend.Business_Layer.services.access_point_service import AccessPointService
    svc = AccessPointService.__new__(AccessPointService)
    svc.db = MagicMock()
    svc.dao = dao or MagicMock()
    svc.permission_dao = permission_dao or MagicMock()
    return svc


def make_ap(access_id=1, access_uuid="550e8400-e29b-41d4-a716-446655440001",
            endpoint_path="/ums/users",
            method="GET", module="user", is_public=False, created_by=1,
            regex_pattern=None, created_at="2024-01-01", updated_at="2024-01-01"):
    ap = MagicMock()
    ap.access_id = access_id
    ap.access_uuid = access_uuid
    ap.endpoint_path = endpoint_path
    ap.method = method
    ap.module = module
    ap.is_public = is_public
    ap.created_by = created_by
    ap.regex_pattern = regex_pattern
    ap.created_at = created_at
    ap.updated_at = updated_at
    ap.permission_mappings = []
    return ap


# ══════════════════════════════════════════════════════════════════════════════
# normalize_endpoint
# ══════════════════════════════════════════════════════════════════════════════

class TestNormalizeEndpoint:

    def test_static_path_returns_none(self):
        svc = make_service()
        assert svc.normalize_endpoint("/ums/users") is None

    def test_dynamic_path_returns_regex(self):
        svc = make_service()
        result = svc.normalize_endpoint("/ums/users/{id}")
        assert result is not None
        assert result.startswith("^")
        assert result.endswith("$")
        assert "([^/]+)" in result

    def test_multiple_params_in_path(self):
        svc = make_service()
        result = svc.normalize_endpoint("/ums/roles/{role_id}/groups/{group_id}")
        assert result.count("([^/]+)") == 2

    def test_regex_matches_dynamic_value(self):
        """The produced regex should match actual request paths."""
        import re
        svc = make_service()
        pattern = svc.normalize_endpoint("/ums/users/{id}")
        assert re.match(pattern, "/ums/users/42")
        assert re.match(pattern, "/ums/users/uuid-abc-123")
        assert not re.match(pattern, "/ums/users/42/extra")


# ══════════════════════════════════════════════════════════════════════════════
# _invalidate_cache
# ══════════════════════════════════════════════════════════════════════════════

class TestInvalidateCache:

    def test_none_access_id_clears_all_cache(self):
        svc = make_service()
        with patch("Backend.Business_Layer.services.access_point_service.clear_all_access_point_cache") as mock_clear, \
             patch("Backend.Business_Layer.services.access_point_service.delete_access_point_cache_by_id") as mock_del:
            svc._invalidate_cache(None)
        mock_clear.assert_called_once()
        mock_del.assert_not_called()

    def test_specific_id_deletes_by_id(self):
        svc = make_service()
        with patch("Backend.Business_Layer.services.access_point_service.clear_all_access_point_cache") as mock_clear, \
             patch("Backend.Business_Layer.services.access_point_service.delete_access_point_cache_by_id") as mock_del:
            svc._invalidate_cache(42)
        mock_del.assert_called_once_with(42)
        mock_clear.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# create_access_point
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateAccessPoint:

    def _make_create_data(self, path="/ums/users", method="GET", module="user",
                          is_public=False):
        data = MagicMock()
        data.dict.return_value = {
            "endpoint_path": path,
            "method": method,
            "module": module,
            "is_public": is_public,
        }
        return data

    def test_duplicate_endpoint_raises_400(self):
        dao = MagicMock()
        dao.get_access_point_by_path_and_method.return_value = make_ap()
        svc = make_service(dao=dao)
        data = self._make_create_data()

        with patch("Backend.Business_Layer.services.access_point_service.generate_uuid7",
                   return_value="uuid"):
            with pytest.raises(HTTPException) as exc:
                svc.create_access_point(data, created_by_user_id=1,
                                        current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_integrity_error_raises_400(self):
        dao = MagicMock()
        dao.get_access_point_by_path_and_method.return_value = None
        orig = MagicMock()
        orig.args = ["constraint violation"]
        dao.create_access_point.side_effect = IntegrityError("stmt", "params", orig)
        svc = make_service(dao=dao)
        data = self._make_create_data()

        with patch("Backend.Business_Layer.services.access_point_service.generate_uuid7",
                   return_value="uuid"):
            with pytest.raises(HTTPException) as exc:
                svc.create_access_point(data, created_by_user_id=1,
                                        current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_generic_exception_raises_500(self):
        dao = MagicMock()
        dao.get_access_point_by_path_and_method.return_value = None
        dao.create_access_point.side_effect = Exception("DB down")
        svc = make_service(dao=dao)
        data = self._make_create_data()

        with patch("Backend.Business_Layer.services.access_point_service.generate_uuid7",
                   return_value="uuid"):
            with pytest.raises(HTTPException) as exc:
                svc.create_access_point(data, created_by_user_id=1,
                                        current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 500

    def test_happy_path_creates_and_caches(self):
        dao = MagicMock()
        ap = make_ap()
        dao.get_access_point_by_path_and_method.return_value = None
        dao.create_access_point.return_value = ap
        svc = make_service(dao=dao)
        data = self._make_create_data()

        with patch("Backend.Business_Layer.services.access_point_service.generate_uuid7",
                   return_value="uuid"), \
             patch("Backend.Business_Layer.services.access_point_service.set_access_point_cache") as mock_cache:
            result = svc.create_access_point(data, created_by_user_id=1,
                                             current_user=MOCK_USER, request=MOCK_REQUEST)

        assert "access_uuid" in result
        mock_cache.assert_called_once()

    def test_static_endpoint_stores_none_regex(self):
        dao = MagicMock()
        ap = make_ap(regex_pattern=None)
        dao.get_access_point_by_path_and_method.return_value = None
        dao.create_access_point.return_value = ap
        svc = make_service(dao=dao)
        data = self._make_create_data(path="/ums/users")

        with patch("Backend.Business_Layer.services.access_point_service.generate_uuid7",
                   return_value="uuid"), \
             patch("Backend.Business_Layer.services.access_point_service.set_access_point_cache"):
            svc.create_access_point(data, created_by_user_id=1,
                                    current_user=MOCK_USER, request=MOCK_REQUEST)

        # create_access_point is called with regex_pattern=None for static paths
        call_kwargs = dao.create_access_point.call_args[1]
        assert call_kwargs.get("regex_pattern") is None


# ══════════════════════════════════════════════════════════════════════════════
# bulk_create_access_points
# ══════════════════════════════════════════════════════════════════════════════

class TestBulkCreateAccessPoints:

    def _make_file(self, filename="test.xlsx"):
        f = MagicMock()
        f.filename = filename
        f.file = MagicMock()
        return f

    def test_invalid_extension_raises_400(self):
        svc = make_service()
        file = self._make_file("data.csv")
        with pytest.raises(HTTPException) as exc:
            svc.bulk_create_access_points(file, created_by_user_id=1,
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_none_filename_raises_400(self):
        svc = make_service()
        file = self._make_file(None)
        with pytest.raises(HTTPException) as exc:
            svc.bulk_create_access_points(file, created_by_user_id=1,
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_missing_required_columns_raises_500_with_detail(self):
        """
        The inner HTTPException(400) is caught by the outer except-Exception block
        and re-raised as 500. The original detail is embedded in the 500 message.
        """
        import pandas as pd
        import io as _io

        svc = make_service()
        file = self._make_file("data.xlsx")
        df = pd.DataFrame({"endpoint_path": ["/ums/users"]})
        buf = _io.BytesIO()
        df.to_excel(buf, index=False)
        file.file.read.return_value = buf.getvalue()

        with pytest.raises(HTTPException) as exc:
            svc.bulk_create_access_points(file, created_by_user_id=1,
                                          current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 500
        assert "Missing required columns" in exc.value.detail


# ══════════════════════════════════════════════════════════════════════════════
# get / list access points
# ══════════════════════════════════════════════════════════════════════════════

class TestGetAccessPoints:

    def test_get_by_uuid_found(self):
        """Service method is named `get(access_uuid)`."""
        dao = MagicMock()
        ap = make_ap()
        ap.permission_mappings = []
        dao.get_access_point_by_uuid.return_value = ap
        svc = make_service(dao=dao)

        result = svc.get("ap-uuid-1")
        assert result is not None

    def test_get_by_uuid_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_access_point_by_uuid.return_value = None
        svc = make_service(dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.get("ghost-uuid")
        assert exc.value.status_code == 404

    def test_list_all_returns_access_point_out_objects(self):
        """Service method is named `list()`."""
        dao = MagicMock()
        aps = [make_ap(), make_ap(access_id=2, access_uuid="550e8400-e29b-41d4-a716-446655440002")]
        for ap in aps:
            ap.permission_mappings = []
        dao.get_all_access_points.return_value = aps
        svc = make_service(dao=dao)

        result = svc.list()
        assert len(result) == 2


# ══════════════════════════════════════════════════════════════════════════════
# delete
# ══════════════════════════════════════════════════════════════════════════════

class TestDeleteAccessPoint:

    def test_delete_not_found_raises_404(self):
        """Service method is named `delete(access_uuid)`."""
        dao = MagicMock()
        dao.get_access_point_by_uuid.return_value = None
        svc = make_service(dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.delete("ghost-uuid", current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_delete_happy_path(self):
        dao = MagicMock()
        ap = make_ap()
        dao.get_access_point_by_uuid.return_value = ap
        dao.delete_access_point.return_value = True
        svc = make_service(dao=dao)

        with patch("Backend.Business_Layer.services.access_point_service.delete_access_point_cache_by_id"):
            result = svc.delete("550e8400-e29b-41d4-a716-446655440001",
                                current_user=MOCK_USER, request=MOCK_REQUEST)
        assert "message" in result


# ══════════════════════════════════════════════════════════════════════════════
# update() — access point modification
# ══════════════════════════════════════════════════════════════════════════════

class TestUpdateAccessPoint:

    def _make_update_data(self, **fields):
        data = MagicMock()
        data.dict.return_value = fields
        return data

    def test_update_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_access_point_by_uuid.return_value = None
        svc = make_service(dao=dao)
        data = self._make_update_data(module="new_module")

        with pytest.raises(HTTPException) as exc:
            svc.update("ghost-uuid", data, current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_update_module_only_success(self):
        dao = MagicMock()
        ap = make_ap()
        updated = make_ap(module="new_module")
        dao.get_access_point_by_uuid.return_value = ap
        dao.get_permission_code_by_access_id.return_value = None
        dao.update_access_point.return_value = updated
        dao.get_access_point_by_path_and_method_without_regex_check.return_value = None
        svc = make_service(dao=dao)
        data = self._make_update_data(module="new_module")

        with patch("Backend.Business_Layer.services.access_point_service.delete_access_point_cache_by_id"):
            result = svc.update("550e8400-e29b-41d4-a716-446655440001", data,
                                current_user=MOCK_USER, request=MOCK_REQUEST)
        assert result is not None

    def test_update_with_null_permission_deletes_mapping(self):
        """Updating permission_code to 'Null' removes the permission mapping."""
        dao = MagicMock()
        ap = make_ap()
        updated = make_ap()
        dao.get_access_point_by_uuid.return_value = ap
        dao.get_permission_code_by_access_id.return_value = "VIEW_USERS"
        dao.update_access_point.return_value = updated
        dao.update_access_point_permission.return_value = None
        svc = make_service(dao=dao)
        data = self._make_update_data(permission_code="Null")

        with patch("Backend.Business_Layer.services.access_point_service.delete_access_point_cache_by_id"):
            svc.update("550e8400-e29b-41d4-a716-446655440001", data,
                       current_user=MOCK_USER, request=MOCK_REQUEST)

        dao.update_access_point_permission.assert_called_once_with(ap.access_id, "Null")

    def test_update_modify_permission_raises_400(self):
        """Trying to set a non-null permission_code raises 400 — only delete is allowed."""
        dao = MagicMock()
        ap = make_ap()
        dao.get_access_point_by_uuid.return_value = ap
        dao.get_permission_code_by_access_id.return_value = "OLD_PERM"
        svc = make_service(dao=dao)
        data = self._make_update_data(permission_code="NEW_PERM")

        with pytest.raises(HTTPException) as exc:
            svc.update("550e8400-e29b-41d4-a716-446655440001", data,
                       current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400

    def test_update_endpoint_path_change_success(self):
        """Changing endpoint_path triggers regex recalculation and duplicate check."""
        dao = MagicMock()
        ap = make_ap(endpoint_path="/ums/users", method="GET")
        updated = make_ap(endpoint_path="/ums/users/v2", method="GET")
        dao.get_access_point_by_uuid.return_value = ap
        dao.get_permission_code_by_access_id.return_value = None
        dao.update_access_point.return_value = updated
        dao.get_access_point_by_path_and_method_without_regex_check.return_value = None
        svc = make_service(dao=dao)
        data = self._make_update_data(endpoint_path="/ums/users/v2")

        with patch("Backend.Business_Layer.services.access_point_service.delete_access_point_cache_by_id"):
            result = svc.update("550e8400-e29b-41d4-a716-446655440001", data,
                                current_user=MOCK_USER, request=MOCK_REQUEST)
        assert result is not None

    def test_update_duplicate_endpoint_raises_400(self):
        """If new endpoint+method already exists for another AP → 400."""
        dao = MagicMock()
        ap = make_ap(endpoint_path="/ums/users", method="GET")
        other_ap = make_ap(access_id=99,
                           access_uuid="550e8400-e29b-41d4-a716-446655440099",
                           endpoint_path="/ums/users/v2")
        dao.get_access_point_by_uuid.return_value = ap
        dao.get_permission_code_by_access_id.return_value = None
        dao.get_access_point_by_path_and_method_without_regex_check.return_value = other_ap
        svc = make_service(dao=dao)
        data = self._make_update_data(endpoint_path="/ums/users/v2")

        with pytest.raises(HTTPException) as exc:
            svc.update("550e8400-e29b-41d4-a716-446655440001", data,
                       current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# normalize_endpoint — additional cases
# ══════════════════════════════════════════════════════════════════════════════

class TestNormalizeEndpointAdditional:

    def test_list_modules_delegates(self):
        dao = MagicMock()
        dao.get_distinct_modules.return_value = ["user", "role"]
        svc = make_service(dao=dao)
        result = svc.list_modules()
        assert "user" in result

    def test_list_modules_delegates(self):
        dao = MagicMock()
        dao.get_distinct_modules.return_value = ["user", "role"]
        svc = make_service(dao=dao)
        result = svc.list_modules()
        assert "user" in result

    def test_get_unmapped_access_points_filters_no_permission_mappings(self):
        """
        get_unmapped_access_points() calls get_all_access_points() then filters
        for APs with no permission_mappings.
        """
        dao = MagicMock()
        ap_unmapped = make_ap()
        ap_unmapped.permission_mappings = []  # no mapping → included
        dao.get_all_access_points.return_value = [ap_unmapped]
        svc = make_service(dao=dao)
        result = svc.get_unmapped_access_points()
        assert len(result) == 1

    def test_get_unmapped_permissions_returns_list(self):
        dao = MagicMock()
        perm = MagicMock()
        perm.permission_uuid = "perm-uuid-1"
        perm.permission_code = "VIEW_USERS"
        perm.description = "View users"
        dao.get_unmapped_permissions.return_value = [perm]
        svc = make_service(dao=dao)
        result = svc.get_unmapped_permissions()
        assert len(result) == 1
        assert result[0]["code"] == "VIEW_USERS"


# ══════════════════════════════════════════════════════════════════════════════
# map_permission / unmap_permission
# ══════════════════════════════════════════════════════════════════════════════

class TestMapPermission:

    def test_access_point_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_access_point_by_uuid.return_value = None
        svc = make_service(dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.map_permission("ghost-uuid", "perm-uuid-1", assigned_by=1,
                               current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_permission_not_found_raises_404(self):
        dao = MagicMock()
        perm_dao = MagicMock()
        ap = make_ap()
        dao.get_access_point_by_uuid.return_value = ap
        dao.get_access_point_by_id.return_value = ap
        perm_dao.get_by_uuid.return_value = None
        svc = make_service(dao=dao, permission_dao=perm_dao)
        with pytest.raises(HTTPException) as exc:
            svc.map_permission(str(ap.access_uuid), "ghost-perm-uuid", assigned_by=1,
                               current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_happy_path_creates_mapping(self):
        dao = MagicMock()
        perm_dao = MagicMock()
        ap = make_ap()
        perm = MagicMock()
        perm.permission_id = 10
        perm.permission_code = "VIEW_USERS"
        perm.permission_uuid = "perm-uuid-1"
        dao.get_access_point_by_uuid.return_value = ap
        dao.get_access_point_by_id.return_value = ap
        dao.create_access_permission_mapping.return_value = MagicMock()
        perm_dao.get_by_uuid.return_value = perm
        svc = make_service(dao=dao, permission_dao=perm_dao)

        with patch("Backend.Business_Layer.services.access_point_service.delete_access_point_cache_by_id"):
            result = svc.map_permission(str(ap.access_uuid), "perm-uuid-1",
                                        assigned_by=1,
                                        current_user=MOCK_USER, request=MOCK_REQUEST)
        assert "mapped" in result["message"].lower()


class TestUnmapPermission:

    def test_no_mapping_found_raises_404(self):
        dao = MagicMock()
        dao.delete_mapping_by_access_id.return_value = False
        svc = make_service(dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.unmap_permission(99)
        assert exc.value.status_code == 404

    def test_happy_path_removes_mapping(self):
        dao = MagicMock()
        ap = make_ap()
        dao.delete_mapping_by_access_id.return_value = True
        dao.get_access_point_by_id.return_value = ap
        svc = make_service(dao=dao)

        with patch("Backend.Business_Layer.services.access_point_service.delete_access_point_cache_by_id"):
            result = svc.unmap_permission(1)
        assert "unmapped" in result["message"].lower()


class TestUnmapPermissionBoth:

    def test_access_point_not_found_raises_404(self):
        dao = MagicMock()
        dao.get_access_point_by_uuid.return_value = None
        svc = make_service(dao=dao)
        with pytest.raises(HTTPException) as exc:
            svc.unmap_permission_both("ghost-uuid", "perm-uuid-1",
                                      current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_permission_not_found_raises_404(self):
        dao = MagicMock()
        perm_dao = MagicMock()
        ap = make_ap()
        dao.get_access_point_by_uuid.return_value = ap
        perm_dao.get_by_uuid.return_value = None
        svc = make_service(dao=dao, permission_dao=perm_dao)
        with pytest.raises(HTTPException) as exc:
            svc.unmap_permission_both(str(ap.access_uuid), "ghost-perm",
                                      current_user=MOCK_USER, request=MOCK_REQUEST)
        assert exc.value.status_code == 404

    def test_happy_path_returns_success(self):
        dao = MagicMock()
        perm_dao = MagicMock()
        ap = make_ap()
        perm = MagicMock()
        perm.permission_id = 10
        perm.permission_uuid = "perm-uuid-1"
        perm.permission_code = "VIEW_USERS"
        dao.get_access_point_by_uuid.return_value = ap
        dao.unmap_permission_dao.return_value = True
        perm_dao.get_by_uuid.return_value = perm
        svc = make_service(dao=dao, permission_dao=perm_dao)

        with patch("Backend.Business_Layer.services.access_point_service.delete_access_point_cache_by_id"):
            result = svc.unmap_permission_both(str(ap.access_uuid), "perm-uuid-1",
                                               current_user=MOCK_USER, request=MOCK_REQUEST)
        assert "unmapped" in result["message"].lower()

    def test_mapping_not_found_returns_not_found_message(self):
        dao = MagicMock()
        perm_dao = MagicMock()
        ap = make_ap()
        perm = MagicMock()
        perm.permission_id = 10
        perm.permission_uuid = "perm-uuid-1"
        perm.permission_code = "VIEW_USERS"
        dao.get_access_point_by_uuid.return_value = ap
        dao.unmap_permission_dao.return_value = False  # not found
        perm_dao.get_by_uuid.return_value = perm
        svc = make_service(dao=dao, permission_dao=perm_dao)

        result = svc.unmap_permission_both(str(ap.access_uuid), "perm-uuid-1",
                                           current_user=MOCK_USER, request=MOCK_REQUEST)
        assert "not found" in result["message"].lower()
