from fastapi import APIRouter, Depends, Request
from typing import List

from ..interfaces.role_mangement import RoleBase, RoleOut, RoleGroupRequest, Group , BulkDeleteRolesRequest
from ...Business_Layer.services.role_service import RoleService

router = APIRouter()


# Service injector using request.state.db
def get_role_service(request: Request) -> RoleService:
    return RoleService(request.state.db)


# --- Basic Role CRUD ---
@router.get("/")
def admin_home():
    return {"message": "Role Management Route"}


@router.get("", response_model=List[RoleOut])
def list_roles(service: RoleService = Depends(get_role_service)):
    return service.list_roles()


@router.delete("/bulk-delete", status_code=200)
def bulk_delete_roles(
    payload: BulkDeleteRolesRequest,
    request: Request,
    service: RoleService = Depends(get_role_service),
):
    return service.delete_roles_by_uuid(
        payload.role_uuids,
        current_user=request.state.user,
        request=request,
    )

@router.get("/uuid/{role_uuid}", response_model=RoleOut)
def get_role_by_uuid(role_uuid: str, service: RoleService = Depends(get_role_service)):
    return service.get_role_by_uuid(role_uuid)


@router.post("", response_model=RoleOut)
def create_role(
    role: RoleBase, request: Request, service: RoleService = Depends(get_role_service)
):
    return service.create_role(role, current_user=request.state.user, request=request)


@router.put("/uuid/{role_uuid}", response_model=RoleOut)
def update_role_by_uuid(
    role_uuid: str,
    role: RoleBase,
    request: Request,
    service: RoleService = Depends(get_role_service),
):
    return service.update_role_by_uuid(
        role_uuid, role, current_user=request.state.user, request=request
    )


@router.delete("/uuid/{role_uuid}")
def delete_role_by_uuid(
    role_uuid: str,
    request: Request,
    service: RoleService = Depends(get_role_service),
):
    return service.delete_role_by_uuid(
        role_uuid, current_user=request.state.user, request=request
    )


# --- Permission Group Management for Roles ---
@router.get("/uuid/{role_uuid}/permissions")
def get_permissions_by_role(
    role_uuid: str, service: RoleService = Depends(get_role_service)
):
    return service.get_permissions_by_role_uuid(role_uuid)


@router.get("/uuid/{role_uuid}/groups", response_model=List[Group])
def get_permission_groups_by_role(
    role_uuid: str, service: RoleService = Depends(get_role_service)
):
    return service.get_permission_groups_by_role_uuid(role_uuid)


@router.put("/{role_id}/groups")
def update_permission_groups_for_role(
    role_id: int,
    payload: RoleGroupRequest,
    service: RoleService = Depends(get_role_service),
):
    return service.update_permission_groups_for_role(role_id, payload.group_ids)


@router.put("/uuid/{role_uuid}/groups")
def update_permission_groups_for_role_uuid(
    role_uuid: str,
    payload: RoleGroupRequest,
    request: Request,
    service: RoleService = Depends(get_role_service),
):
    return service.update_permission_groups_for_role_uuid(
        role_uuid, payload.group_uuids, current_user=request.state.user, request=request
    )


@router.post("/uuid/{role_uuid}/groups")
def add_permission_groups_to_role(
    role_uuid: str,
    payload: RoleGroupRequest,
    request: Request,
    service: RoleService = Depends(get_role_service),
):
    current_user = request.state.user
    return service.add_permission_groups_to_role(
        role_uuid,
        payload.group_uuids,
        current_user["user_id"],
        request=request,
        current_user=current_user,
    )


@router.delete("/{role_uuid}/groups/{group_uuid}")
def remove_permission_group_from_role(
    role_uuid: str,
    group_uuid: str,
    request: Request,
    service: RoleService = Depends(get_role_service),
):
    return service.remove_permission_group_from_role(
        role_uuid, group_uuid, current_user=request.state.user, request=request
    )


@router.post("/uuid/{role_uuid}/groups/remove")
def remove_permission_groups_to_role(
    role_uuid: str,
    payload: RoleGroupRequest,
    request: Request,
    service: RoleService = Depends(get_role_service),
):
    return service.remove_permission_groups_to_role(
        role_uuid, payload.group_uuids, current_user=request.state.user, request=request
    )


@router.get("/{role_uuid}/available-groups", response_model=List[Group])
def get_unassigned_permission_groups_for_role(
    role_uuid: str, service: RoleService = Depends(get_role_service)
):
    return service.get_unassigned_permission_groups(role_uuid)
