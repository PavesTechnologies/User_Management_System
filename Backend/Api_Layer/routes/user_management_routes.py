from fastapi import APIRouter, UploadFile, File, HTTPException, Request, Query
from ..interfaces.user_management import (
    UserOut,
    UserRoleUpdate,
    UserBaseIn,
    UserOut_uuid,
    UserWithRoleNames_id,
    PaginatedUserResponse,
    PaginatedUserWithRolesResponse,
)
from ...Business_Layer.services.user_management_service import UserService
import pandas as pd
from io import BytesIO
from typing import Optional
import time
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Inject service from request middleware session
# ------------------------------------------------------------------------------
def get_user_service(request: Request) -> UserService:
    """Inject UserService with DB session from middleware"""
    return UserService(request.state.db)


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
@router.get("/home")
def admin_home():
    return {"message": "User Management Route"}


# ------------------------------------------------------------------------------
# Count APIs
# ------------------------------------------------------------------------------
@router.get("/count")
def count_users(request: Request):
    service = get_user_service(request)
    return {"user_count": service.count_users()}


@router.get("/active-count")
def count_active_users(request: Request):
    service = get_user_service(request)
    return {"active_user_count": service.count_active_users()}


# ------------------------------------------------------------------------------
# Paginated User List
# ------------------------------------------------------------------------------
@router.get("", response_model=PaginatedUserResponse)
@router.get("/", response_model=PaginatedUserResponse)
def list_users(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(50, le=500),
    search: Optional[str] = Query(None),
):
    start = time.perf_counter()
    logger.info(f"🔵 [list_users] page={page}, limit={limit}, search={search}")

    service = get_user_service(request)
    try:
        result = service.list_users(page, limit, search)
        elapsed = (time.perf_counter() - start) * 1000
        msg = f"✅ [list_users] completed in {elapsed:.2f}ms"
        (
            logger.warning(f"⚠️ SLOW ENDPOINT: {msg}")
            if elapsed > 500
            else logger.debug(msg)
        )
        return result
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        logger.error(f"❌ [list_users] failed in {elapsed:.2f}ms: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------------------
# Users + Roles APIs
# ------------------------------------------------------------------------------
@router.get("/roles", response_model=PaginatedUserWithRolesResponse)
def get_users_with_roles(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(10, le=100),
    search: Optional[str] = Query(None),
):
    return get_user_service(request).get_users_with_roles(page, limit, search)


@router.get("/id/roles", response_model=list[UserWithRoleNames_id])
def get_users_with_roles_id(request: Request):
    return get_user_service(request).get_users_with_roles_id()


# ------------------------------------------------------------------------------
# Get User by ID / UUID
# ------------------------------------------------------------------------------
@router.get("/{user_id}", response_model=UserOut)
def get_user(user_id: int, request: Request):
    service = get_user_service(request)
    user = service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/uuid/{user_uuid}", response_model=UserOut_uuid)
def get_user_uuid(user_uuid: str, request: Request):
    service = get_user_service(request)
    try:
        user = service.get_user_uuid(request.state.user, user_uuid)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return user


# ------------------------------------------------------------------------------
# Create / Bulk Create
# ------------------------------------------------------------------------------
@router.post("", response_model=UserOut)
@router.post("/", response_model=UserOut)
def create_user(user: UserBaseIn, request: Request):
    service = get_user_service(request)
    try:
        current_user = request.state.user
        return service.create_user(
            user,
            created_by_user_id=current_user["user_id"],
            current_user=current_user,
            request=request,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/multiple-users", response_model=dict)
async def bulk_create_users(request: Request, file: UploadFile = File(...)):
    service = get_user_service(request)
    try:
        content = await file.read()
        df = pd.read_excel(BytesIO(content))

        required_cols = {"user_uuid", "first_name", "last_name", "mail", "contact", "employee_id", "Designation", "Department", "Status"}
        if not required_cols.issubset(df.columns):
            raise HTTPException(
                status_code=400,
                detail=f"Missing required columns. Expected: {', '.join(required_cols)}",
            )

        return service.create_bulk_user(
            df, created_by_user_id=request.state.user["user_id"], request=request
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------------------
# Update User (by ID / UUID)
# ------------------------------------------------------------------------------
@router.put("/{user_id}", response_model=UserOut)
def update_user(user_id: int, user: UserBaseIn, request: Request):
    service = get_user_service(request)
    try:
        return service.update_user(
            user_id, user, current_user=request.state.user, request=request
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/uuid/{user_uuid}", response_model=UserOut_uuid)
def update_user_uuid(user_uuid: str, user: UserBaseIn, request: Request):
    service = get_user_service(request)
    try:
        return service.update_user_uuid(
            user_uuid, user, current_user=request.state.user, request=request
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ------------------------------------------------------------------------------
# Deactivate / Activate Users
# ------------------------------------------------------------------------------
@router.delete("/{user_id}")
def deactivate_user(user_id: int, request: Request):
    service = get_user_service(request)
    try:
        service.deactivate_user(
            user_id, current_user=request.state.user, request=request
        )
        return {"message": "User deactivated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/uuid/{user_uuid}")
def deactivate_user_uuid(user_uuid: str, request: Request):
    service = get_user_service(request)
    try:
        service.deactivate_user_uuid(
            user_uuid, current_user=request.state.user, request=request
        )
        return {"message": "User deactivated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.patch("/uuid/{user_uuid}/activate")
def activate_user_uuid(user_uuid: str, request: Request):
    service = get_user_service(request)
    try:
        service.activate_user_uuid(
            user_uuid, current_user=request.state.user, request=request
        )
        return {"message": "User activated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ------------------------------------------------------------------------------
# Update Roles (by ID / UUID)
# ------------------------------------------------------------------------------
@router.put("/{user_id}/role")
def update_user_roles(user_id: int, payload: UserRoleUpdate, request: Request):
    service = get_user_service(request)
    try:
        current_user = request.state.user
        message = service.update_user_roles(
            user_id,
            payload.role_ids,
            current_user["user_id"],
            current_user=current_user,
            request=request,
        )
        return {"message": message}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/uuid/{user_uuid}/role")
def update_user_roles_uuid(user_uuid: str, payload: UserRoleUpdate, request: Request):
    service = get_user_service(request)
    try:
        current_user = request.state.user
        message = service.update_user_roles_uuid(
            user_uuid,
            payload.role_ids,
            current_user["user_id"],
            current_user=current_user,
            request=request,
        )
        return {"message": message}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------------------
# Get Roles (by ID / UUID)
# ------------------------------------------------------------------------------
@router.get("/{user_id}/roles")
def get_user_roles(user_id: int, request: Request):
    service = get_user_service(request)
    try:
        user = service.get_user(user_id)
        if not user:
            raise ValueError("User not found")
        return {"roles": service.get_user_roles(user_id)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/uuid/{user_uuid}/roles")
def get_user_roles_uuid(user_uuid: str, request: Request):
    service = get_user_service(request)
    try:
        user = service.dao.get_user_by_uuid(user_uuid)
        if not user:
            raise ValueError("User not found")
        return {"roles": service.get_user_roles_by_uuid(user_uuid)}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
