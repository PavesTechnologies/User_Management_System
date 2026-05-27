# jwt_validator/middleware/optimized_permission_middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.responses import JSONResponse
from .permission_utils import check_permission
import time


class OptimizedPermissionMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        t_start = time.time()
        print("Permission Middleware - ENTERING")

        public_paths = [
            "/ums/docs",
            "/ums/redoc",
            "/ums/openapi.json",
            "/ums/favicon.ico",
            "/favicon.ico",
            "/ums/auth",
            "/ums/.well-known",
        ]

        path = request.url.path

        is_public = any(path.startswith(p) for p in public_paths)
        is_first_login = path == "/auth/first-login/change-password"

        # ✅ Explicit logic (NO ambiguity)
        if request.method == "OPTIONS" or (is_public and not is_first_login):
            print("Permission Middleware - Skipped (public route)")
            response = await call_next(request)

        else:
            user = getattr(request.state, "user", None)

            if user is None:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized"},
                )

            method = request.method
            db = getattr(request.state, "db", None)

            result = check_permission(path, method, user, db_session=db)

            if isinstance(result, JSONResponse):
                elapsed = (time.time() - t_start) * 1000
                print(f"⏱ Permission Middleware: {elapsed:.2f}ms (permission denied)")
                return result

            response = await call_next(request)

        elapsed = (time.time() - t_start) * 1000
        print(f"⏱ Permission Middleware: {elapsed:.2f}ms")
        return response
