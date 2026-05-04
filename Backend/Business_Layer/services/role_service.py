from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao import role_dao
from ...Api_Layer.interfaces.role_mangement import (
    RoleBase,
    RolePermissionGroupUpdate,
)
from ..utils.generate_uuid7 import generate_uuid7
from ..utils.audit_decorator import audit_action_with_request


class RoleService:
    def __init__(self, db: Session):
        self.db = db

    def list_roles(self):
        return role_dao.get_all_roles(self.db)

    def get_role_by_uuid(self, role_uuid: str):
        role = role_dao.get_role_by_uuid(self.db, role_uuid)
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        return role

    def _normalize_role_name(self, role_name: str) -> str:
        """
        Validate and normalize role name for duplicate checking:
        - Allow only letters (A–Z, a–z), spaces, hyphens, and underscores
        - No digits or other special characters allowed
        - Remove leading/trailing spaces
        - Replace multiple spaces with a single space
        - Lowercase for comparison
        """
        import re

        # 1. Validation — ensure only allowed characters (added _)
        if not re.fullmatch(r"[A-Za-z\s\-_]+", role_name.strip()):
            raise HTTPException(
                status_code=400,
                detail="Role name can only contain letters, spaces, hyphens, and underscores",
            )

        # 2. Normalize spaces and lowercase for comparison
        cleaned = re.sub(r"\s+", " ", role_name.strip())
        return cleaned.lower()

    def _check_duplicate_role(self, role_name: str, exclude_role_id: int = None):
        normalized_new = self._normalize_role_name(role_name)
        roles = role_dao.get_all_roles(self.db)  # returns list of role objects

        for role in roles:
            normalized_existing = self._normalize_role_name(role.role_name)
            if normalized_existing == normalized_new:
                if exclude_role_id is None or role.role_id != exclude_role_id:
                    raise HTTPException(
                        status_code=400,
                        detail="Role name already exists (case-insensitive, space-insensitive)",
                    )

    @audit_action_with_request(
        action_type="CREATE",
        entity_type="Role",
        capture_new_data=True,
        description="Created new role: {role_data.role_name}",
    )
    def create_role(self, role_data: RoleBase, **kwargs):
        self._check_duplicate_role(role_data.role_name)
        return role_dao.create_role(self.db, generate_uuid7(), role_data)

    @audit_action_with_request(
        action_type="UPDATE",
        entity_type="Role",
        get_entity_id=lambda self, role_uuid, *args, **kwargs: (
            role_dao.get_role_by_uuid(self.db, role_uuid).role_id
            if role_dao.get_role_by_uuid(self.db, role_uuid)
            else None
        ),
        capture_old_data=True,
        capture_new_data=True,
        description="Updated role: {role_data.role_name}",
    )
    def update_role_by_uuid(self, role_uuid: str, role_data: RoleBase, **kwargs):
        role = role_dao.get_role_by_uuid(self.db, role_uuid)
        # protect mandatory roles
        mandatory_roles = ["Admin", "Super Admin", "HR", "General"]
        if role and role.role_name in mandatory_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role '{role.role_name}' is mandatory and cannot be renamed",
            )
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
            )

        self._check_duplicate_role(role_data.role_name, exclude_role_id=role.role_id)
        return role_dao.update_role_by_uuid(self.db, role_uuid, role_data)

    @audit_action_with_request(
        action_type="DELETE",
        entity_type="Role",
        get_entity_id=lambda self, role_uuid, *args, **kwargs: (
            role_dao.get_role_by_uuid(self.db, role_uuid).role_id
            if role_dao.get_role_by_uuid(self.db, role_uuid)
            else None
        ),
        capture_old_data=True,
        description="Deleted role by UUID: {role_uuid}",
    )
    def delete_role_by_uuid(self, role_uuid: str, **kwargs):
        role = role_dao.get_role_by_uuid(self.db, role_uuid)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
            )
        # protect mandatory roles
        mandatory_roles = ["Admin", "Super Admin", "HR", "General"]
        if role.role_name in mandatory_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role '{role.role_name}' is mandatory and cannot be deleted",
            )

        # 1. Get all users who have this role
        user_ids = role_dao.get_users_by_role(self.db, role.role_id)

        # 2. Cleanup dependent mappings (no cascade in DB)
        role_dao.delete_user_roles_by_role(self.db, role.role_id)
        role_dao.delete_role_permission_groups(self.db, role.role_id)

        # 3. Assign "General" role to users who now have no roles
        general_role = role_dao.get_role_by_name(self.db, "General")
        for user_id in user_ids:
            user_roles = role_dao.get_user_roles(self.db, user_id)
            if not user_roles:  # Only assign if user has zero roles left
                role_dao.assign_role(self.db, user_id, general_role.role_id)

        # 4. Finally delete the role
        return role_dao.delete_role(self.db, role.role_id)

    def update_role_permission_groups(
        self, role_id: int, payload: RolePermissionGroupUpdate
    ):
        return role_dao.update_role_groups(self.db, role_id, payload.group_ids)

    def get_permissions_by_role_uuid(self, role_uuid: str):
        role = role_dao.get_role_by_uuid(self.db, role_uuid)
        return role_dao.get_permissions_by_role(self.db, role.role_id)

    @audit_action_with_request(
        action_type="CREATE",
        entity_type="Role_Permission_Group",
        get_entity_id=lambda self, role_uuid, *args, **kwargs: (
            role_dao.get_role_by_uuid(self.db, role_uuid).role_id
            if role_dao.get_role_by_uuid(self.db, role_uuid)
            else None
        ),
        description="Added permission groups to role UUID: {role_uuid}",
    )
    def add_permission_groups_to_role(
        self,
        role_uuid: str,
        group_uuids: list[str],
        assigned_by: int,
        audit_data=None,
        **kwargs,
    ):
        new_groups = []
        for group_uuid in group_uuids:
            group = role_dao.get_permission_group_by_uuid(self.db, group_uuid)
            if group:
                new_groups.append(group.group_name)

        # Perform DB operation inside try/except for safety
        try:
            result = role_dao.add_permission_groups_to_role(
                self.db, role_uuid, group_uuids, assigned_by
            )
            # If commit succeeds, then prepare audit data
            audit_data["new_data"] = {"new_groups_added": new_groups}
            return result

        except Exception as e:
            # Rollback and log failure (if needed)
            self.db.rollback()
            raise HTTPException(
                status_code=500, detail=f"Failed to add permission groups: {str(e)}"
            )

    @audit_action_with_request(
        action_type="DELETE",
        entity_type="Role_Permission_Group",
        get_entity_id=lambda self, role_uuid, *args, **kwargs: (
            role_dao.get_role_by_uuid(self.db, role_uuid).role_id
            if role_dao.get_role_by_uuid(self.db, role_uuid)
            else None
        ),
        description="Removed permission group from role UUID: {role_uuid}",
    )
    def remove_permission_group_from_role(
        self, role_uuid: str, group_uuid: str, audit_data=None, **kwargs
    ):
        # Get group info for audit before deletion
        group = role_dao.get_permission_group_by_uuid(self.db, group_uuid)
        group_name = group.group_name if group else None

        try:
            # Perform the removal
            result = role_dao.remove_permission_group_from_role(
                self.db, role_uuid, group_uuid
            )

            # Only prepare audit data after a successful commit
            if audit_data is not None and group_name:
                audit_data["old_data"] = {"removed_group": group_name}

            return result

        except Exception as e:
            # Rollback on any failure
            self.db.rollback()
            raise HTTPException(
                status_code=500,
                detail=f"Failed to remove permission group from role: {str(e)}",
            )

    @audit_action_with_request(
        action_type="DELETE",
        entity_type="Role_Permission_Groups",
        get_entity_id=lambda self, role_uuid, *args, **kwargs: (
            role_dao.get_role_by_uuid(self.db, role_uuid).role_id
            if role_dao.get_role_by_uuid(self.db, role_uuid)
            else None
        ),
        description="Removed multiple permission groups from role UUID: {role_uuid}",
    )
    def remove_permission_groups_to_role(
        self, role_uuid: str, group_uuids: list[str], audit_data=None, **kwargs
    ):
        removed_groups = []
        for group_uuid in group_uuids:
            group = role_dao.get_permission_group_by_uuid(self.db, group_uuid)
            if group:
                removed_groups.append(group.group_name)

        print("Removed Groups for Audit:", removed_groups)
        try:
            result = role_dao.remove_permission_groups_from_role(
                self.db, role_uuid, group_uuids
            )

            if audit_data is not None:
                audit_data["old_data"] = {"removed_groups": removed_groups}

            return result

        except Exception as e:
            self.db.rollback()
            raise HTTPException(
                status_code=500, detail=f"Failed to remove permission groups: {str(e)}"
            )

    def update_permission_groups_for_role(self, role_id: int, group_ids: list[int]):
        return role_dao.update_permission_groups_for_role(self.db, role_id, group_ids)

    def update_permission_groups_for_role_uuid(
        self, role_uuid: str, group_uuids: list[str]
    ):
        role = role_dao.get_role_by_uuid(self.db, role_uuid)
        return role_dao.update_permission_groups_for_role(
            self.db, role.role_id, group_uuids
        )

    def get_permission_groups_by_role_uuid(self, role_uuid: str):
        role = role_dao.get_role_by_uuid(self.db, role_uuid)
        return role_dao.get_permission_groups_by_role(self.db, role.role_id)

    def get_unassigned_permission_groups(self, role_uuid: str):
        role = role_dao.get_role_by_uuid(self.db, role_uuid)
        return role_dao.get_unassigned_permission_groups(self.db, role.role_id)
