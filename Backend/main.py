# main.py
from fastapi import FastAPI, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from .Api_Layer.JWT.jwt_validator.middleware.jwt_middleware import JWTMiddleware
from .Api_Layer.JWT.jwt_validator.middleware.permission_middleware import (
    OptimizedPermissionMiddleware,
)
from .Data_Access_Layer.utils.database import engine
from .Data_Access_Layer.models import models
from .Api_Layer.routes import (
    auth_routes,
    profile_routes,
    permission_group_route,
    role_management_routes,
    permission_routes,
    user_management_routes,
    access_point_routes,
    otp_routes,
)
from .Api_Layer.JWT.openid_config import openid_endpoint
from .Api_Layer.JWT.jwt_validator.middleware.db_session_middleware import (
    DBSessionMiddleware,
)

from .config.env_loader import get_env_var

import time
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="User Management System",
    docs_url="/ums/docs",
    redoc_url="/ums/redoc",
    openapi_url="/ums/openapi.json",
)

FRONTEND_URL = get_env_var("FRONTEND_URL")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[FRONTEND_URL, "http://localhost:5173"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


app.add_middleware(OptimizedPermissionMiddleware)
app.add_middleware(DBSessionMiddleware)
app.add_middleware(JWTMiddleware)

# 🔑 Add CORS last so it wraps *all* responses
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
    max_age=3600,
)


@app.middleware("http")
async def add_timing_middleware(request: Request, call_next):
    t_start = time.time()
    path = request.url.path
    method = request.method

    logger.info(f"🚀 REQUEST START: {method} {path}")

    response = await call_next(request)

    t_end = time.time()
    elapsed = (t_end - t_start) * 1000

    # Add header for debugging
    response.headers["X-Response-Time"] = f"{elapsed:.2f}ms"

    logger.info(
        f"🏁 REQUEST END: {method} {path} - {elapsed:.2f}ms - Status: {response.status_code}"
    )

    if elapsed > 1000:
        logger.error(f"🔴 VERY SLOW REQUEST: {method} {path} took {elapsed:.2f}ms")
    elif elapsed > 500:
        logger.warning(f"🟠 SLOW REQUEST: {method} {path} took {elapsed:.2f}ms")

    return response


# @app.on_event("startup")
# def generate_jwks_on_startup():
#     from Backend.Api_Layer.JWT.token_creation.jwks_generator import generate_jwks
#     try:
#         generate_jwks()
#         print("✅ JWKS file ensured at startup.")
#     except Exception as e:
#         print(f"⚠️ Failed to generate JWKS at startup: {e}")


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="User Management System",
        version="0.1.0",
        description="Secure API with JWT & RBAC",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method in ["get", "post", "put", "delete", "patch"]:
                openapi_schema["paths"][path][method]["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

api_router = APIRouter(prefix="/ums")

# Route imports
api_router.include_router(
    openid_endpoint.router,
    prefix="",
    tags=["Login Management"],
)

api_router.include_router(
    auth_routes.router,
    prefix="/auth",
    tags=["Login Management"],
)

api_router.include_router(
    otp_routes.router,
    prefix="/auth",
    tags=["OTP Management"],
)

api_router.include_router(
    profile_routes.router,
    prefix="/general_user",
    tags=["General User Management"],
)

api_router.include_router(
    user_management_routes.router,
    prefix="/admin/users",
    tags=["Admin - User Management"],
)

api_router.include_router(
    role_management_routes.router,
    prefix="/admin/roles",
    tags=["Admin - Role Management"],
)

api_router.include_router(
    permission_routes.router,
    prefix="/admin/permissions",
    tags=["Admin - Permission Management"],
)

api_router.include_router(
    permission_group_route.router,
    prefix="/admin/groups",
    tags=["Admin - Permission Group Management"],
)

api_router.include_router(
    access_point_routes.router,
    prefix="/admin/access-points",
    tags=["Admin - Access Point Management"],
)

# IMPORTANT
app.include_router(api_router)


@app.get("/")
def read_root():
    return {"status": "User Management System API is running"}
