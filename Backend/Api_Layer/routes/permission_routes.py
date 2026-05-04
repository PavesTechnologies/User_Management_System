from fastapi import APIRouter, Request, UploadFile, File
from typing import List
from ...Business_Layer.services.permission_service import PermissionService
from ..interfaces.permission_management import (
    PermissionOut,
    PermissionCreate,
    PermissionGroupUpdate,
    PermissionResponse,
    PermissionBaseCreation,
    BulkPermissionCreationResponse,
    BulkDeletePermissionsRequest
)

router = APIRouter()


# Inject service from request.state.db instead of Depends(get_db)
def get_permission_service(request: Request) -> PermissionService:
    return PermissionService(request.state.db)


# --- Permission Routes ---


@router.get("/", response_model=List[PermissionOut])
def list_permissions(request: Request):
    service = PermissionService(request.state.db)
    return service.list_permissions()


@router.get("/unmapped", response_model=List[PermissionOut])
def get_unmapped_permissions(request: Request):
    service = PermissionService(request.state.db)
    return service.list_unmapped_permissions()


@router.delete("/bulk-delete", status_code=200)
def bulk_delete_permissions(
    payload: BulkDeletePermissionsRequest,
    request: Request,
):
    service = PermissionService(request.state.db)

    return service.delete_permissions(
        payload.permission_uuids,
        current_user=request.state.user,
        request=request,
    )

@router.get("/{permission_uuid}", response_model=PermissionOut)
def get_permission(permission_uuid: str, request: Request):
    service = PermissionService(request.state.db)
    return service.get_permission(permission_uuid)


@router.post("/group", status_code=201)
def create_permission(payload: PermissionCreate, request: Request):
    service = PermissionService(request.state.db)
    return service.create_permission_minimal(
        payload.permission_code,
        payload.description,
        payload.group_uuid,
        current_user=request.state.user,
        request=request,
    )


@router.post("/", status_code=201)
def create_permission_basic(permission: PermissionBaseCreation, request: Request):
    service = PermissionService(request.state.db)
    return service.create_permission_minimal(
        permission.permission_code,
        permission.description,
        current_user=request.state.user,
        request=request,
    )


@router.post(
    "/bulk-permissions-creation", response_model=BulkPermissionCreationResponse
)
def create_bulk_permissions(request: Request, file: UploadFile = File(...)):
    service = PermissionService(request.state.db)
    return service.bulk_permissions_creation(
        file, current_user=request.state.user, request=request
    )


@router.put("/{permission_uuid}", response_model=dict)
def update_permission(
    permission_uuid: str, payload: PermissionBaseCreation, request: Request
):
    service = PermissionService(request.state.db)
    result = service.update_permission(
        permission_uuid,
        payload.permission_code,
        payload.description,
        current_user=request.state.user,
        request=request,
    )

    permission_data = (
        PermissionResponse.from_orm(result)
        if hasattr(PermissionResponse, "from_orm")
        else PermissionResponse.model_validate(result)
    )

    return {
        "message": "Permission updated successfully",
        "data": permission_data.dict(),
    }


@router.delete("/{permission_uuid}")
def delete_permission(permission_uuid: str, request: Request):
    service = PermissionService(request.state.db)
    service.delete_permission(
        permission_uuid, current_user=request.state.user, request=request
    )
    return {"message": "Permission deleted successfully"}


@router.delete("/cascading/{permission_uuid}")
def delete_permission_cascade(permission_uuid: str, request: Request):
    service = PermissionService(request.state.db)
    service.delete_permission_cascade(permission_uuid)
    return {"message": "Permission and all associations deleted successfully"}


@router.put("/{permission_uuid}/group")
def update_permission_group(
    permission_uuid: str, payload: PermissionGroupUpdate, request: Request
):
    service = PermissionService(request.state.db)
    service.reassign_group(permission_uuid, payload.group_uuid)
    return {"message": "Permission reassigned to new group successfully"}
