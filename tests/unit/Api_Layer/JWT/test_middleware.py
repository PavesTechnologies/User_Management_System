"""
tests/unit/Api_Layer/JWT/test_middleware.py

Unit tests for:
  jwt_middleware.py      → JWTMiddleware.dispatch()
  permission_middleware.py → OptimizedPermissionMiddleware.dispatch()
  permission_utils.py    → check_permission()

All external dependencies (JWT validation, DB, Redis) are mocked.
Middleware dispatch is tested by calling dispatch() directly with a mocked
Request and a mocked async call_next.

Coverage targets:
  jwt_middleware.py      21% → ~90%
  permission_middleware.py 23% → ~90%
  permission_utils.py    12% → ~85%
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi.responses import JSONResponse
from starlette.responses import Response


# ── shared async helpers ───────────────────────────────────────────────────────

async def _ok_next(request):
    return Response("OK", status_code=200)


def _make_request(path="/ums/users", method="GET", auth_header=None, user=None, db=None):
    """Build a mock Starlette Request with the fields our middleware accesses."""
    req = MagicMock()
    req.url.path = path
    req.method = method

    # headers must be a MagicMock so we can stub .get() — plain dicts are read-only
    headers = MagicMock()
    headers.get = MagicMock(
        side_effect=lambda k, d=None: auth_header if (k == "Authorization" and auth_header) else d
    )
    req.headers = headers

    req.state = MagicMock()
    req.state.user = user
    req.state.db = db
    return req


# ══════════════════════════════════════════════════════════════════════════════
# JWTMiddleware
# ══════════════════════════════════════════════════════════════════════════════

class TestJWTMiddleware:

    def _make_middleware(self):
        from Backend.Api_Layer.JWT.jwt_validator.middleware.jwt_middleware import JWTMiddleware
        app = MagicMock()
        return JWTMiddleware(app)

    # ── public / skipped paths ──────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_options_request_passes_through_without_validation(self):
        """
        GIVEN  an OPTIONS preflight request (CORS)
        WHEN   JWTMiddleware.dispatch() is called
        THEN   call_next is invoked without any JWT validation (no 401)
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/users", method="OPTIONS")
        call_next = AsyncMock(return_value=Response("OK", 200))

        response = await mw.dispatch(req, call_next)

        call_next.assert_called_once_with(req)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_docs_path_passes_through_without_validation(self):
        """
        GIVEN  a request to /ums/docs (Swagger UI — public path)
        WHEN   JWTMiddleware.dispatch() is called
        THEN   skips JWT check and forwards to call_next
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/docs", method="GET")
        call_next = AsyncMock(return_value=Response("OK", 200))

        response = await mw.dispatch(req, call_next)

        call_next.assert_called_once_with(req)

    @pytest.mark.asyncio
    async def test_auth_path_passes_through_without_validation(self):
        """
        GIVEN  a request to /ums/auth/login (public auth path)
        WHEN   JWTMiddleware.dispatch() is called
        THEN   skips JWT check — login does not require a token
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/auth/login", method="POST")
        call_next = AsyncMock(return_value=Response("OK", 200))

        response = await mw.dispatch(req, call_next)

        call_next.assert_called_once_with(req)

    @pytest.mark.asyncio
    async def test_first_login_change_password_requires_token(self):
        """
        GIVEN  a request to the excluded path (first-login/change-password)
        WHEN   no Authorization header is present
        THEN   returns 401 — this path is NOT public despite being under /ums/auth

        This is the sole excluded path: users must have a token to change
        their first-login password, because they're already logged in.
        """
        mw = self._make_middleware()
        req = _make_request(
            path="/ums/auth/first-login/change-password",
            method="POST",
            auth_header=None,
        )
        call_next = AsyncMock(return_value=Response("OK", 200))

        response = await mw.dispatch(req, call_next)

        assert response.status_code == 401

    # ── missing / malformed auth header ───────────────────────────────────────

    @pytest.mark.asyncio
    async def test_missing_auth_header_returns_401(self):
        """
        GIVEN  a protected path with no Authorization header
        WHEN   JWTMiddleware.dispatch() is called
        THEN   returns JSONResponse 401 'Missing or invalid token'
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/users", method="GET", auth_header=None)
        call_next = AsyncMock()

        response = await mw.dispatch(req, call_next)

        assert response.status_code == 401
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_bearer_auth_header_returns_401(self):
        """
        GIVEN  an Authorization header that does not start with 'Bearer '
        WHEN   JWTMiddleware.dispatch() is called
        THEN   returns 401 — only Bearer scheme is supported
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/users", method="GET", auth_header="Basic abc123")
        call_next = AsyncMock()

        response = await mw.dispatch(req, call_next)

        assert response.status_code == 401
        call_next.assert_not_called()

    # ── valid token ─────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_valid_token_sets_user_and_calls_next(self):
        """
        GIVEN  a valid Bearer token
        WHEN   JWTMiddleware.dispatch() is called
        THEN   request.state.user is set and call_next is invoked
        """
        decoded = {"user_id": 1, "email": "user@example.com", "roles": ["General"]}
        mw = self._make_middleware()
        req = _make_request(path="/ums/users", method="GET",
                            auth_header="Bearer valid.jwt.token")
        call_next = AsyncMock(return_value=Response("OK", 200))

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.jwt_middleware.validate_jwt_token",
                   return_value=decoded), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.jwt_middleware.get_access_point_from_cache",
                   return_value=None):

            response = await mw.dispatch(req, call_next)

        assert response.status_code == 200
        assert req.state.user == decoded
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_access_point_cache_populated_in_request_state(self):
        """
        GIVEN  a valid token and a cache hit for the access point
        WHEN   JWTMiddleware.dispatch() is called
        THEN   request.state.access_point_cache is set from cache
        """
        decoded = {"user_id": 1, "roles": ["Admin"]}
        cache_data = {"is_public": False, "required_permissions": ["VIEW_USERS"]}
        mw = self._make_middleware()
        req = _make_request(path="/ums/users", method="GET",
                            auth_header="Bearer valid.jwt.token")
        call_next = AsyncMock(return_value=Response("OK", 200))

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.jwt_middleware.validate_jwt_token",
                   return_value=decoded), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.jwt_middleware.get_access_point_from_cache",
                   return_value=cache_data):

            await mw.dispatch(req, call_next)

        assert req.state.access_point_cache == cache_data

    @pytest.mark.asyncio
    async def test_none_decoded_token_returns_401(self):
        """
        GIVEN  validate_jwt_token returns None (e.g. misconfigured validator)
        WHEN   JWTMiddleware.dispatch() is called
        THEN   returns 401 'Invalid token' — None is never a valid user
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/users", method="GET",
                            auth_header="Bearer valid.jwt.token")
        call_next = AsyncMock()

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.jwt_middleware.validate_jwt_token",
                   return_value=None), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.jwt_middleware.get_access_point_from_cache",
                   return_value=None):

            response = await mw.dispatch(req, call_next)

        assert response.status_code == 401
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_validation_exception_returns_401_json_response(self):
        """
        GIVEN  validate_jwt_token raises an exception (e.g. HTTPException 401)
        WHEN   JWTMiddleware.dispatch() is called
        THEN   returns JSONResponse 401 with the exception detail

        The middleware catches all exceptions to avoid leaking stack traces.
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/users", method="GET",
                            auth_header="Bearer bad.token")
        call_next = AsyncMock()

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.jwt_middleware.validate_jwt_token",
                   side_effect=Exception("Token has expired")):

            response = await mw.dispatch(req, call_next)

        assert response.status_code == 401
        call_next.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# OptimizedPermissionMiddleware
# ══════════════════════════════════════════════════════════════════════════════

class TestPermissionMiddleware:

    def _make_middleware(self):
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_middleware import (
            OptimizedPermissionMiddleware,
        )
        app = MagicMock()
        return OptimizedPermissionMiddleware(app)

    @pytest.mark.asyncio
    async def test_options_request_skips_permission_check(self):
        """
        GIVEN  an OPTIONS preflight request
        WHEN   OptimizedPermissionMiddleware.dispatch() is called
        THEN   call_next is invoked without permission check
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/users", method="OPTIONS")
        call_next = AsyncMock(return_value=Response("OK", 200))

        response = await mw.dispatch(req, call_next)

        call_next.assert_called_once_with(req)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_public_path_skips_permission_check(self):
        """
        GIVEN  a request to a public path (/ums/docs)
        WHEN   OptimizedPermissionMiddleware.dispatch() is called
        THEN   call_next is invoked without permission check
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/docs", method="GET")
        call_next = AsyncMock(return_value=Response("OK", 200))

        response = await mw.dispatch(req, call_next)

        call_next.assert_called_once_with(req)

    @pytest.mark.asyncio
    async def test_no_user_in_state_returns_401(self):
        """
        GIVEN  a protected path but request.state.user is None (JWT middleware not run)
        WHEN   OptimizedPermissionMiddleware.dispatch() is called
        THEN   returns 401 'Unauthorized'
        """
        mw = self._make_middleware()
        req = _make_request(path="/ums/users", method="GET", user=None)
        call_next = AsyncMock()

        response = await mw.dispatch(req, call_next)

        assert response.status_code == 401
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_allowed_request_calls_next(self):
        """
        GIVEN  check_permission returns None (permission granted)
        WHEN   OptimizedPermissionMiddleware.dispatch() is called
        THEN   call_next is invoked and the response is returned
        """
        mw = self._make_middleware()
        user = {"user_id": 1, "roles": ["Admin"], "permissions": ["VIEW_USERS"]}
        req = _make_request(path="/ums/users", method="GET", user=user)
        call_next = AsyncMock(return_value=Response("OK", 200))

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_middleware.check_permission",
                   return_value=None):

            response = await mw.dispatch(req, call_next)

        call_next.assert_called_once()
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_denied_request_returns_403_without_calling_next(self):
        """
        GIVEN  check_permission returns a 403 JSONResponse (permission denied)
        WHEN   OptimizedPermissionMiddleware.dispatch() is called
        THEN   the 403 is returned and call_next is NOT invoked
        """
        mw = self._make_middleware()
        user = {"user_id": 1, "roles": ["General"], "permissions": []}
        req = _make_request(path="/ums/users", method="DELETE", user=user)
        call_next = AsyncMock()
        denied_response = JSONResponse(
            status_code=403, content={"detail": "You don't have permission"}
        )

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_middleware.check_permission",
                   return_value=denied_response):

            response = await mw.dispatch(req, call_next)

        assert response.status_code == 403
        call_next.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# check_permission() — the core RBAC decision function
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckPermission:
    """
    Tests the pure permission logic in permission_utils.py.
    All DB and Redis calls are mocked.
    """

    # ── input validation ────────────────────────────────────────────────────────

    def test_missing_method_returns_400(self):
        """
        GIVEN  an empty HTTP method string
        WHEN   check_permission() is called
        THEN   returns JSONResponse 400 — invalid request
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        result = check_permission("/ums/users", "", {"roles": [], "permissions": []})

        assert isinstance(result, JSONResponse)
        assert result.status_code == 400

    # ── Redis cache hit ──────────────────────────────────────────────────────────

    def test_cache_hit_public_access_point_returns_none(self):
        """
        GIVEN  cache returns an access point marked is_public=True
        WHEN   check_permission() is called
        THEN   returns None (allowed) without hitting DB
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        cached = {
            "access_point": {"is_public": True, "access_id": 1},
            "required_permissions": [],
        }
        user = {"roles": ["General"], "permissions": []}

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_access_point_from_cache",
                   return_value=cached):

            result = check_permission("/ums/public/endpoint", "GET", user)

        assert result is None

    def test_cache_hit_super_admin_bypasses_permission_check(self):
        """
        GIVEN  cache returns a protected access point
        WHEN   the user is Super_Admin
        THEN   returns None (allowed) — Super_Admin bypasses all permission checks
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        cached = {
            "access_point": {"is_public": False, "access_id": 5},
            "required_permissions": ["DELETE_ROLE"],
        }
        user = {"roles": ["Super_Admin"], "permissions": []}

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_access_point_from_cache",
                   return_value=cached):

            result = check_permission("/ums/admin/roles", "DELETE", user)

        assert result is None

    def test_cache_hit_user_has_required_permission_returns_none(self):
        """
        GIVEN  cache returns a protected endpoint with a required permission
        WHEN   the user has that permission in their token
        THEN   returns None (allowed)
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        cached = {
            "access_point": {"is_public": False, "access_id": 10},
            "required_permissions": ["VIEW_USERS"],
        }
        user = {"roles": ["Admin"], "permissions": ["VIEW_USERS", "EDIT_USERS"]}

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_access_point_from_cache",
                   return_value=cached):

            result = check_permission("/ums/users", "GET", user)

        assert result is None

    def test_cache_hit_user_lacks_permission_returns_403(self):
        """
        GIVEN  cache returns a protected endpoint with a required permission
        WHEN   the user does NOT have that permission
        THEN   returns JSONResponse 403 'You don't have permission'
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        cached = {
            "access_point": {"is_public": False, "access_id": 10},
            "required_permissions": ["DELETE_ROLE"],
        }
        user = {"roles": ["General"], "permissions": ["VIEW_USER_PUBLIC"]}

        with patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_access_point_from_cache",
                   return_value=cached):

            result = check_permission("/ums/roles/123", "DELETE", user)

        assert isinstance(result, JSONResponse)
        assert result.status_code == 403

    # ── DB fallback (cache miss) ────────────────────────────────────────────────

    def _no_cache(self):
        return patch(
            "Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_access_point_from_cache",
            return_value=None,
        )

    def _mock_dao(self, access_point=None, permissions=None):
        dao = MagicMock()
        dao.get_access_point_by_path_and_method.return_value = access_point
        dao.get_permissions_for_access_point.return_value = permissions or []
        return dao

    def test_cache_miss_access_point_not_found_super_admin_allowed(self):
        """
        GIVEN  cache miss AND access point does not exist in DB
        WHEN   user is Super_Admin
        THEN   returns None — Super_Admin bypasses 'access point not found' block

        Business rule: Super_Admin always has access even to unmapped endpoints.
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        user = {"roles": ["Super_Admin"], "permissions": []}
        mock_dao = self._mock_dao(access_point=None)

        with self._no_cache(), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.AccessPointDAO",
                   return_value=mock_dao), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_db_session",
                   return_value=MagicMock()):

            result = check_permission("/ums/unknown-endpoint", "GET", user)

        assert result is None

    def test_cache_miss_access_point_not_found_regular_user_gets_403(self):
        """
        GIVEN  cache miss AND access point does not exist in DB
        WHEN   user is NOT Super_Admin
        THEN   returns JSONResponse 403 'Access point not found'

        Business rule: unmapped access points must return 403 for non-admins.
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        user = {"roles": ["General"], "permissions": ["VIEW_USER_PUBLIC"]}
        mock_dao = self._mock_dao(access_point=None)

        with self._no_cache(), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.AccessPointDAO",
                   return_value=mock_dao), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_db_session",
                   return_value=MagicMock()):

            result = check_permission("/ums/unmapped", "GET", user)

        assert isinstance(result, JSONResponse)
        assert result.status_code == 403

    def test_cache_miss_no_permissions_mapped_not_public_super_admin_allowed(self):
        """
        GIVEN  access point exists, no permissions mapped, is_public=False
        WHEN   user is Super_Admin
        THEN   returns None (allowed via Super_Admin bypass)
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        ap = MagicMock()
        ap.access_id = 7
        ap.is_public = False
        mock_dao = self._mock_dao(access_point=ap, permissions=[])
        user = {"roles": ["Super_Admin"], "permissions": []}

        with self._no_cache(), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.AccessPointDAO",
                   return_value=mock_dao), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_db_session",
                   return_value=MagicMock()), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.set_access_point_cache"):

            result = check_permission("/ums/admin/thing", "POST", user)

        assert result is None

    def test_cache_miss_no_permissions_mapped_not_public_regular_user_gets_403(self):
        """
        GIVEN  access point exists, no permissions mapped, is_public=False
        WHEN   user is NOT Super_Admin
        THEN   returns JSONResponse 403 'No permissions mapped'

        Business rule: protected endpoints without permission mappings must
        block regular users — failing safe is the secure default.
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        ap = MagicMock()
        ap.access_id = 7
        ap.is_public = False
        mock_dao = self._mock_dao(access_point=ap, permissions=[])
        user = {"roles": ["Admin"], "permissions": ["VIEW_USERS"]}

        with self._no_cache(), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.AccessPointDAO",
                   return_value=mock_dao), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_db_session",
                   return_value=MagicMock()):

            result = check_permission("/ums/protected-no-perm", "GET", user)

        assert isinstance(result, JSONResponse)
        assert result.status_code == 403
        assert "No permissions mapped" in result.body.decode()

    def test_cache_miss_public_access_point_returns_none(self):
        """
        GIVEN  access point found, no permissions, is_public=True
        WHEN   check_permission() is called for any user
        THEN   returns None — public endpoints require no permission

        Business rule: is_public flag on access_point overrides RBAC.
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        ap = MagicMock()
        ap.access_id = 99
        ap.is_public = True
        mock_dao = self._mock_dao(access_point=ap, permissions=[])
        user = {"roles": ["General"], "permissions": []}

        with self._no_cache(), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.AccessPointDAO",
                   return_value=mock_dao), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_db_session",
                   return_value=MagicMock()), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.set_access_point_cache"):

            result = check_permission("/ums/health", "GET", user)

        assert result is None

    def test_cache_miss_user_has_permission_returns_none(self):
        """
        GIVEN  access point found with required permission, user has it
        WHEN   check_permission() is called
        THEN   returns None (allowed) and cache is populated

        After a DB lookup, the result should be cached for future requests.
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        ap = MagicMock()
        ap.access_id = 3
        ap.is_public = False
        mock_dao = self._mock_dao(access_point=ap, permissions=["VIEW_USERS"])
        user = {"roles": ["Admin"], "permissions": ["VIEW_USERS"]}

        with self._no_cache(), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.AccessPointDAO",
                   return_value=mock_dao), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_db_session",
                   return_value=MagicMock()), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.set_access_point_cache") as mock_cache:

            result = check_permission("/ums/users", "GET", user)

        assert result is None
        mock_cache.assert_called_once()

    def test_cache_miss_user_lacks_permission_returns_403(self):
        """
        GIVEN  access point found with required permission, user does NOT have it
        WHEN   check_permission() is called
        THEN   returns JSONResponse 403 'You don't have permission'
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        ap = MagicMock()
        ap.access_id = 3
        ap.is_public = False
        mock_dao = self._mock_dao(access_point=ap, permissions=["DELETE_USERS"])
        user = {"roles": ["General"], "permissions": ["VIEW_USER_PUBLIC"]}

        with self._no_cache(), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.AccessPointDAO",
                   return_value=mock_dao), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_db_session",
                   return_value=MagicMock()), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.set_access_point_cache"):

            result = check_permission("/ums/users/1", "DELETE", user)

        assert isinstance(result, JSONResponse)
        assert result.status_code == 403

    def test_cache_miss_db_session_from_parameter(self):
        """
        GIVEN  a db_session is passed to check_permission (from request.state.db)
        WHEN   check_permission() is called
        THEN   the provided session is used, get_db_session() is NOT called
        """
        from Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils import check_permission

        ap = MagicMock()
        ap.access_id = 1
        ap.is_public = True
        mock_dao = self._mock_dao(access_point=ap, permissions=[])
        user = {"roles": ["General"], "permissions": []}
        provided_db = MagicMock()

        with self._no_cache(), \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.AccessPointDAO",
                   return_value=mock_dao) as mock_dao_cls, \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.get_db_session") as mock_get_db, \
             patch("Backend.Api_Layer.JWT.jwt_validator.middleware.permission_utils.set_access_point_cache"):

            check_permission("/ums/public", "GET", user, db_session=provided_db)

        # AccessPointDAO must be initialised with the provided session, not get_db_session()
        mock_dao_cls.assert_called_once_with(provided_db)
        mock_get_db.assert_not_called()
