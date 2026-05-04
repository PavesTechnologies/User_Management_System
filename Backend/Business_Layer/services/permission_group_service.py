from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.group_dao import PermissionGroupDAO
from fastapi import HTTPException, status
from ..utils.generate_uuid7 import generate_uuid7
from ..utils.audit_decorator import audit_action_with_request


class PermissionGroupService:
    def __init__(self, db: Session):
        self.db = db
        self.dao = PermissionGroupDAO(self.db)

    def list_groups(self):
        return self.dao.get_all_groups()

    def get_group(self, group_id: int):
        return self.dao.get_group_by_uuid(group_id)

    @audit_action_with_request(
        action_type="CREATE",
        entity_type="Permission_Group",
        capture_old_data=False,
        capture_new_data=True,
        description="Created new permission group",
    )
    def create_group(self, group_name: str, created_by: int, **kwargs):
        existing = self.dao.get_group_by_name(group_name)
        if existing:
            raise ValueError("Group name already exists")

        result = self.dao.create_group(group_name, generate_uuid7(), created_by)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create permission group",
            )

        return result

    @audit_action_with_request(
        action_type="UPDATE",
        entity_type="Permission_Group",
        capture_old_data=True,
        capture_new_data=True,
        description="Updated permission group",
    )
    def update_group(self, group_uuid: str, group_name: str, **kwargs):
        audit_data = kwargs.get("audit_data", {})
        # Get current group
        current = self.dao.get_group_by_uuid(group_uuid)
        if not current:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Group not found"
            )

        # Set entity_id for audit
        audit_data["entity_id"] = current.group_id
        audit_data["old_data"] = {
            "group_id": current.group_id,
            "group_name": current.group_name,
            "group_uuid": current.group_uuid,
            "created_by": current.created_by,
            "created_at": str(current.created_at),
        }
        # Check if it's the default group
        default_group = self.dao.get_group_by_name("newly_created_permissions_group")
        if current.group_uuid == default_group.group_uuid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot update the default permission group",
            )

        # If the name is changing, check if another group already has it
        if current.group_name != group_name:
            existing = self.dao.get_group_by_name(group_name)
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Group name already exists",
                )

        # Now safe to update
        updated_group = self.dao.update_group(group_uuid, group_name)
        return updated_group

    @audit_action_with_request(
        action_type="DELETE",
        entity_type="Permission_Group",
        capture_old_data=True,
        description="Deleted permission group",
    )
    def delete_group(self, group_uuid: str, **kwargs):
        audit_data = kwargs.get("audit_data", {})
        # Fetch group once
        group = self.dao.get_group_by_uuid(group_uuid)
        if not group:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission group not found",
            )

        # Set entity_id for audit
        audit_data["entity_id"] = group.group_id  # ← Manually set the ID

        # Check if it's the default group
        default_group = self.dao.get_group_by_name("newly_created_permissions_group")
        if group.group_uuid == default_group.group_uuid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the default permission group",
            )

        try:
            # Clear dependent relationships first
            self.dao.clear_group_permissions(group.group_id)
            self.dao.clear_group_roles(group.group_id)

            # Delete the group itself
            if not self.dao.delete_group(group.group_id):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to delete permission group",
                )
        except Exception as e:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete permission group: {str(e)}",
            )

        audit_data["old_data"] = {
            "group_id": group.group_id,
            "group_name": group.group_name,
            "group_uuid": group.group_uuid,
            "created_by": group.created_by,
            "created_at": str(group.created_at),
        }
        return {"message": "Permission group deleted successfully"}
    
    @audit_action_with_request(
    action_type="DELETE",
    entity_type="Permission_Group",
    capture_old_data=True,
    description="Deleted permission groups",
    )
    def delete_groups(self, group_uuids: list[str], **kwargs):
        audit_data = kwargs.get("audit_data", {})

        if not group_uuids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one permission group UUID is required",
            )

        # Remove duplicate UUIDs
        group_uuids = list(set(group_uuids))

        deleted_groups_old_data = []
        failed_groups = []

        default_group = self.dao.get_group_by_name("newly_created_permissions_group")

        try:
            for group_uuid in group_uuids:
                group = self.dao.get_group_by_uuid(group_uuid)

                if not group:
                    failed_groups.append({
                        "group_uuid": group_uuid,
                        "reason": "Permission group not found",
                    })
                    continue

                if default_group and group.group_uuid == default_group.group_uuid:
                    failed_groups.append({
                        "group_uuid": group_uuid,
                        "reason": "Cannot delete the default permission group",
                    })
                    continue

                # Store old data before delete for audit
                deleted_groups_old_data.append({
                    "group_id": group.group_id,
                    "group_name": group.group_name,
                    "group_uuid": group.group_uuid,
                    "created_by": group.created_by,
                    "created_at": str(group.created_at),
                })

                # Clear relationships first
                self.dao.clear_group_permissions(group.group_id)
                self.dao.clear_group_roles(group.group_id)

                # Delete group
                deleted = self.dao.delete_group(group.group_id)

                if not deleted:
                    failed_groups.append({
                        "group_uuid": group_uuid,
                        "reason": "Failed to delete permission group",
                    })

            if not deleted_groups_old_data:
                self.db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "message": "No permission groups were deleted",
                        "failed": failed_groups,
                    },
                )

            self.db.commit()

        except HTTPException:
            self.db.rollback()
            raise

        except Exception as e:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete permission groups: {str(e)}",
            )

        # Audit data for multiple deleted groups
        audit_data["entity_id"] = None
        audit_data["old_data"] = {
            "deleted_count": len(deleted_groups_old_data),
            "deleted_groups": deleted_groups_old_data,
            "failed_groups": failed_groups,
        }

        return {
            "message": "Permission groups deleted successfully",
            "deleted_count": len(deleted_groups_old_data),
            "deleted_groups": deleted_groups_old_data,
            "failed_groups": failed_groups,
        }

    def delete_group_cascade(self, group_uuid: str):
        return self.dao.delete_group_cascade(group_uuid)

    def search_groups(self, keyword: str):
        return self.dao.search_groups(keyword)

    def list_unmapped_groups(self):
        return self.dao.get_unmapped_groups()

    def list_permissions_in_group(self, group_uuid: str):
        return self.dao.list_permissions_in_group(group_uuid)

    # services/permission_group_service.py

    @audit_action_with_request(
        action_type="CREATE",
        entity_type="Permission_Group_Mapping",
        capture_new_data=False,  # We'll manually set the data
        description="Added permissions to group",
    )
    def add_permissions_to_group(
        self, group_uuid: str, permission_uuids: list[str], assigned_by: int, **kwargs
    ):
        audit_data = kwargs.get("audit_data", {})
        group = self.dao.get_group_by_uuid(group_uuid)
        if not group:
            raise HTTPException(status_code=404, detail="Permission group not found")
        group_id = group.group_id

        # Validate permission UUIDs and get their IDs
        permission_ids = []
        permission_codes = []  # For audit trail
        permissions_dict = {}
        for puid in permission_uuids:
            perm = self.dao.get_permission_by_uuid(puid)
            if not perm:
                raise ValueError(f"Permission with UUID {puid} not found")
            permission_ids.append(perm.permission_id)
            permission_codes.append(perm.permission_code)

            # Serialize the permission object to a dict
            permissions_dict[perm.permission_id] = {
                "permission_code": perm.permission_code,
                "description": perm.description,
                "permission_uuid": perm.permission_uuid,
            }

        # Add permissions to group
        new_mappings = self.dao.add_permissions_to_group(
            group_id, permission_ids, assigned_by
        )

        # Remove any permissions that are already in the default group
        default_group = self.dao.get_group_by_name("newly_created_permissions_group")
        default_group_uuid = default_group.group_uuid
        default_group_permissions = self.list_permissions_in_group(default_group_uuid)
        default_group_permissions_uuids = [
            permission["permission_uuid"] for permission in default_group_permissions
        ]
        current_permissions_uuids = [
            permission["permission_uuid"] for permission in permissions_dict.values()
        ]

        print("Default Group Permissions UUIDs:", default_group_permissions_uuids)
        print("Current Permissions UUIDs to Add:", current_permissions_uuids)

        redundant_permissions = []
        for puid in current_permissions_uuids:
            if puid in default_group_permissions_uuids:
                redundant_permissions.append(puid)

        print("Redundant Permissions to Remove:", redundant_permissions)
        if redundant_permissions:
            self.remove_permissions_from_group(
                default_group_uuid, redundant_permissions
            )

        # Set audit data
        audit_data["entity_id"] = group_id  # The group being modified
        audit_data["new_data"] = {
            "group_id": group_id,
            "group_name": group.group_name,
            "added_permissions": permissions_dict,  # Now JSON-serializable
            "permission_count": len(new_mappings),
            "assigned_by": assigned_by,
        }

        # Return full permission objects for response
        return self.dao.get_permissions_by_ids([m.permission_id for m in new_mappings])

    @audit_action_with_request(
        action_type="DELETE",
        entity_type="Permission_Group_Mapping",
        capture_old_data=False,  # We'll manually capture what's being removed
        description="Removed permissions from group",
    )
    def remove_permissions_from_group(
        self, group_uuid: str, permission_uuids: list[str], **kwargs
    ):
        audit_data = kwargs.get("audit_data", {})
        group = self.dao.get_group_by_uuid(group_uuid)
        if not group:
            raise HTTPException(status_code=404, detail="Permission group not found")
        group_id = group.group_id

        # Validate permission UUIDs and get their IDs
        permission_ids = []
        permissions_list = []
        for puid in permission_uuids:
            perm = self.dao.get_permission_by_uuid(puid)
            if not perm:
                raise ValueError(f"Permission with UUID {puid} not found")
            permission_ids.append(perm.permission_id)
            permissions_list.append(
                {
                    "permission_id": perm.permission_id,
                    "permission_code": perm.permission_code,
                    "description": perm.description,
                }
            )

        # Remove permissions from group
        result = self.dao.remove_permissions_from_group(group_id, permission_ids)

        if not result:
            raise HTTPException(
                status_code=404, detail="No matching permissions found in this group"
            )

        # Set audit data
        audit_data["entity_id"] = group_id
        audit_data["old_data"] = {
            "group_id": group_id,
            "group_name": group.group_name,
            "removed_permissions": permissions_list,
            "permission_count": len(permissions_list),
        }

        return {
            "message": f"Successfully removed {len(permissions_list)} permission(s) from group"
        }

    def get_permission_by_code(self, code: str):
        return self.dao.get_permission_by_code(code)

    def get_unmapped_permissions(self, group_id: int):
        return self.dao.get_unmapped_permissions(group_id)
