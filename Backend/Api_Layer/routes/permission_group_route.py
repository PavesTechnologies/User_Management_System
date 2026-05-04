from fastapi import APIRouter, HTTPException, Query, Request
from typing import List

from ..interfaces.permissiongroup import (
    GroupOut,
    PermissionInGroupwithId,
    GroupIn,
    BulkDeletePermissionGroupsRequest,
)
from ...Business_Layer.services.permission_group_service import PermissionGroupService
from ..interfaces.permission_management import PermissionOut

router = APIRouter()


# ✅ Inject service using middleware DB session
def get_permission_group_service(request: Request) -> PermissionGroupService:
    return PermissionGroupService(request.state.db)


# -------------------------------------------------------
# Unmapped groups
# -------------------------------------------------------
@router.get("/permission-groups/unmapped", response_model=List[GroupOut])
def get_unmapped_groups(request: Request):
    service = PermissionGroupService(request.state.db)
    return service.list_unmapped_groups()


# -------------------------------------------------------
# Home
# -------------------------------------------------------
@router.get("/")
def admin_home():
    return {"message": "Group Management Route"}


# -------------------------------------------------------
# List groups
# -------------------------------------------------------
@router.get("", response_model=List[GroupOut])
def list_groups(
    request: Request, keyword: str = Query(default="", description="Search keyword")
):
    service = PermissionGroupService(request.state.db)

    if keyword:
        return service.search_groups(keyword)

    return service.list_groups()

# -------------------------------------------------------
# Bulk delete permission groups
# -------------------------------------------------------
@router.delete("/bulk-delete", status_code=200)
def bulk_delete_permission_groups(
    payload: BulkDeletePermissionGroupsRequest,
    request: Request,
):
    service = PermissionGroupService(request.state.db)

    return service.delete_groups_bulk(
        payload.group_uuids,
        request=request,
        current_user=request.state.user,
    )

# -------------------------------------------------------
# Get group by UUID
# -------------------------------------------------------
@router.get("/{group_uuid}", response_model=GroupOut)
def get_group(group_uuid: str, request: Request):
    service = PermissionGroupService(request.state.db)
    group = service.get_group(group_uuid)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


# -------------------------------------------------------
# Create group
# -------------------------------------------------------
@router.post("", response_model=GroupOut, status_code=201)
def create_group(group: GroupIn, request: Request):
    service = PermissionGroupService(request.state.db)
    current_user = request.state.user

    return service.create_group(
        group.group_name,
        current_user["user_id"],
        request=request,
        current_user=current_user,
    )


# -------------------------------------------------------
# Update group
# -------------------------------------------------------
@router.put("/{group_uuid}", response_model=GroupOut)
def update_group(group_uuid: str, group: GroupIn, request: Request):
    service = PermissionGroupService(request.state.db)

    updated = service.update_group(
        group_uuid, group.group_name, request=request, current_user=request.state.user
    )

    if not updated:
        raise HTTPException(status_code=404, detail="Group not found")

    return updated


# -------------------------------------------------------
# Delete group (with optional cascade)
# -------------------------------------------------------
@router.delete("/{group_uuid}", status_code=204)
def delete_group(
    group_uuid: str,
    request: Request,
    cascade: bool = Query(default=False, description="Delete group and its mappings"),
):
    service = PermissionGroupService(request.state.db)

    if cascade:
        deleted = service.delete_group_cascade(group_uuid)
    else:
        deleted = service.delete_group(
            group_uuid, request=request, current_user=request.state.user
        )

    if not deleted:
        raise HTTPException(status_code=404, detail="Group not found")
    



# -------------------------------------------------------
# Permissions inside group
# -------------------------------------------------------
@router.get("/{group_uuid}/permissions", response_model=List[PermissionInGroupwithId])
def get_permissions_in_group(group_uuid: str, request: Request):
    service = PermissionGroupService(request.state.db)

    group = service.get_group(group_uuid)
    if not group:
        raise HTTPException(status_code=404, detail="Permission group not found")

    return service.list_permissions_in_group(group_uuid)


# -------------------------------------------------------
# Add permissions to group
# -------------------------------------------------------
@router.post("/{group_uuid}/permissions", response_model=List[PermissionOut])
def add_permissions_to_group(
    group_uuid: str, permission_uuids: List[str], request: Request
):
    service = PermissionGroupService(request.state.db)
    current_user = request.state.user

    return service.add_permissions_to_group(
        group_uuid,
        permission_uuids,
        current_user["user_id"],
        request=request,
        current_user=current_user,
    )


# -------------------------------------------------------
# Remove permissions from group
# -------------------------------------------------------
@router.delete("/{group_uuid}/permissions", status_code=200)
def remove_permissions_from_group(
    group_uuid: str, permission_uuids: List[str], request: Request
):
    service = PermissionGroupService(request.state.db)

    removed = service.remove_permissions_from_group(
        group_uuid, permission_uuids, request=request, current_user=request.state.user
    )

    if not removed:
        raise HTTPException(
            status_code=404, detail="No matching permission mappings found."
        )

    return {"message": "Permissions removed successfully"}


# -------------------------------------------------------
# Unmapped permissions for a group
# -------------------------------------------------------
@router.get("/{group_uuid}/unmapped-permissions", response_model=List[PermissionOut])
def get_unmapped_permissions_for_group(group_uuid: str, request: Request):
    service = PermissionGroupService(request.state.db)

    group = service.get_group(group_uuid)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    return service.get_unmapped_permissions(group.group_id)
