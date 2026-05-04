import re
from fastapi import HTTPException, status, UploadFile
import io
import pandas as pd
from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.permission_dao import PermissionDAO
from ...Data_Access_Layer.dao.group_dao import PermissionGroupDAO
from ...Data_Access_Layer.dao.access_point_dao import AccessPointDAO
from ..utils.generate_uuid7 import generate_uuid7
from ..utils.audit_decorator import audit_action_with_request
from sqlalchemy.exc import SQLAlchemyError

# Regex to allow only UPPERCASE letters separated by underscores
PERMISSION_CODE_PATTERN = re.compile(r"^[A-Z]+(_[A-Z]+)*$")


class PermissionService:
    def __init__(self, db: Session):
        self.db = db
        self.dao = PermissionDAO(db)
        self.group_dao = PermissionGroupDAO(db)
        self.access_point_dao = AccessPointDAO(db)

    @audit_action_with_request(
        action_type="CREATE",
        entity_type="Permissions",
        description="Created new permission",
    )
    def create_permission_minimal(
        self,
        permission_code: str,
        description: str,
        group_uuid: str = None,
        audit_data: dict = None,
        **kwargs,
    ):
        try:
            group_id = None

            # ✅ Validate empty or whitespace-only values
            if not permission_code or not permission_code.strip():
                raise HTTPException(
                    status_code=400, detail="Permission code cannot be empty"
                )
            if not description or not description.strip():
                raise HTTPException(
                    status_code=400, detail="Description cannot be empty"
                )

            # ✅ Validate format of permission_code
            permission_code = permission_code.strip()
            if not PERMISSION_CODE_PATTERN.fullmatch(permission_code):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Invalid permission code format. "
                        "Use only uppercase letters and underscores. "
                        "Example: VIEW_USER_PUBLIC"
                    ),
                )
            # ✅ Check if permission already exists
            existing = self.dao.get_by_code(permission_code)
            if existing:
                raise HTTPException(
                    status_code=400,
                    detail=f"Permission code '{permission_code}' already exists",
                )

            # ✅ Create new permission
            permission = self.dao.create(
                permission_code, description.strip(), generate_uuid7()
            )

            # ✅ Assign group
            if not group_uuid:
                default_group = self.group_dao.get_group_by_name(
                    "newly_created_permissions_group"
                )
                if not default_group:
                    raise HTTPException(
                        status_code=500, detail="Default group not found"
                    )
                group_uuid = default_group.group_uuid
                group_id = default_group.group_id
            else:
                print("Provided group UUID:", group_uuid)
                group = self.group_dao.get_group_by_uuid(group_uuid)
                if not group:
                    raise HTTPException(
                        status_code=404, detail="Provided group not found"
                    )
                group_id = group.group_id

            # ✅ Map permission to group
            self.dao.map_to_group(permission.permission_id, group_id)

            # ✅ Inject permission_uuid into kwargs for the audit decorator
            kwargs["permission_uuid"] = permission.permission_uuid

            audit_data["entity_id"] = permission.permission_id
            audit_data["new_data"] = {
                "permission_id": permission.permission_id,
                "permission_code": permission.permission_code,
                "description": permission.description,
                "assigned_group_id": group_id,
            }

            # ✅ Return response
            return {
                "message": "Permission created and assigned to group successfully",
                "permission_uuid": permission.permission_uuid,
                "group_uuid": group_uuid,
            }

        except ValueError as ve:
            # from map_to_group (duplicate mapping)
            self.db.rollback()
            raise HTTPException(status_code=400, detail=str(ve))

        except SQLAlchemyError as e:
            # DB-level error
            self.db.rollback()
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    @audit_action_with_request(
        action_type="CREATE",
        entity_type="Permissions",
        description="Created Bulk permissions via file upload",
    )
    def bulk_permissions_creation(
        self, file: UploadFile, audit_data: dict = None, **kwargs
    ):
        # Validate file type
        if not file.filename.endswith((".xlsx", ".xls")):
            raise HTTPException(
                status_code=400, detail="Only Excel files (.xlsx, .xls) are supported"
            )

        try:
            # Read the uploaded excel file into a pandas DataFrame
            contents = file.file.read()
            df = pd.read_excel(io.BytesIO(contents))

            required_columns = {"permission_code", "description"}

            missing_columns = required_columns - set(df.columns)
            if missing_columns:
                raise HTTPException(
                    status_code=400,
                    detail=f"Missing required columns: {', '.join(missing_columns)}",
                )
            if "group_name" not in df.columns:
                df["group_name"] = "newly_created_permissions_group"

            # Remove rows with missing required values
            df = df.dropna(subset=list(required_columns))

            if df.empty:
                raise HTTPException(
                    status_code=400, detail="No valid data found in the Excel file"
                )

            user_id = kwargs.get("current_user", {}).get("user_id")
            created_permissions = []
            failed_entries = []

            for index, row in df.iterrows():
                try:
                    permission_code = str(row["permission_code"]).strip()
                    description = str(row["description"]).strip()
                    if "group_name" in row and pd.notna(row["group_name"]):
                        group_name = str(row["group_name"]).strip()
                    else:
                        group_name = "newly_created_permissions_group"

                    # Validate empty or whitespace-only values
                    if not permission_code:
                        failed_entries.append(
                            f"Row {index + 2}: Permission code cannot be empty"
                        )
                        continue

                    if not description:
                        failed_entries.append(
                            f"Row {index + 2} ({permission_code}): Description cannot be empty"
                        )
                        continue

                    # Validate format of permission_code
                    if not PERMISSION_CODE_PATTERN.fullmatch(permission_code):
                        failed_entries.append(
                            f"Row {index + 2} ({permission_code}): Invalid permission code format.\
                            Use only uppercase letters and underscores"
                        )
                        continue

                    # Check if permission already exists
                    existing = self.dao.get_by_code(permission_code)
                    if existing:
                        failed_entries.append(
                            f"Row {index + 2} ({permission_code}): Permission code '{permission_code}' already exists"
                        )
                        continue

                    # Get or create group
                    group = self.group_dao.get_group_by_name(group_name)
                    if not group:
                        group = self.group_dao.create_group(
                            group_name, generate_uuid7(), user_id
                        )

                    # Create new permission
                    permission = self.dao.create(
                        permission_code, description, generate_uuid7()
                    )

                    # Map permission to group
                    self.dao.get_by_id(permission.permission_id).permission_uuid
                    self.group_dao.add_permissions_to_group(
                        group.group_id, [permission.permission_id], user_id
                    )

                    created_permissions.append(
                        {
                            "permission_uuid": permission.permission_uuid,
                            "permission_code": permission.permission_code,
                            "description": permission.description,
                            "group_name": group_name,
                            "message": "Permission created and assigned to group successfully",
                        }
                    )

                except ValueError as ve:
                    failed_entries.append(
                        f"Row {index + 2} ({row.get('permission_code', 'N/A')}): {str(ve)}"
                    )
                except Exception as e:
                    failed_entries.append(
                        f"Row {index + 2} ({row.get('permission_code', 'N/A')}): {str(e)}"
                    )

            # Update audit data
            audit_data["entity_id"] = None
            audit_data["new_data"] = {
                "total_rows": len(df),
                "successful_creates": len(created_permissions),
                "failed_creates": len(failed_entries),
                "errors": failed_entries[:10],
            }

            # Return with summary - REMOVED THE HTTPException RAISE
            response_data = {
                "summary": {
                    "total_rows": len(df),
                    "successful": len(created_permissions),
                    "failed": len(failed_entries),
                },
                "created_permissions": created_permissions,
                "failed_entries": failed_entries,
            }

            # ✅ Just return the response data, don't raise an exception
            return response_data

        except pd.errors.EmptyDataError:
            raise HTTPException(status_code=400, detail="Excel file is empty")
        except SQLAlchemyError as e:
            self.db.rollback()
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
        except HTTPException:
            # ✅ Re-raise HTTPException without catching it
            raise
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Failed to process Excel file: {str(e)}"
            )

    def list_permissions(self):
        return self.dao.get_all()

    def get_permission(self, permission_uuid: str):
        permission = self.dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        return permission

    @audit_action_with_request(
        action_type="UPDATE",
        entity_type="Permissions",
        get_entity_id=lambda self, permission_uuid, *args, **kwargs: (
            self.dao.get_by_uuid(permission_uuid).permission_id
            if self.dao.get_by_uuid(permission_uuid)
            else None
        ),
        description="Updated permission details",
    )
    def update_permission(
        self, permission_uuid: str, code: str, desc: str, audit_data=None, **kwargs
    ):
        permission = self.dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")

        # ✅ Initialize audit_data dictionary if not provided
        if audit_data is None:
            audit_data = {}

        # ✅ Store old data for audit
        audit_data["old_data"] = {
            "permission_code": permission.permission_code,
            "description": permission.description,
        }

        # ✅ Validate inputs
        if not code or not code.strip():
            raise HTTPException(
                status_code=400, detail="Permission code cannot be empty"
            )
        if not desc or not desc.strip():
            raise HTTPException(status_code=400, detail="Description cannot be empty")

        code = code.strip()
        if not PERMISSION_CODE_PATTERN.fullmatch(code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid permission code format. Use only uppercase letters and underscores.",
            )

        if permission.permission_code != code and self.dao.get_by_code(code):
            raise HTTPException(
                status_code=400, detail=f"Permission code '{code}' already exists"
            )

        # ✅ Perform update
        updated_permission = self.dao.update(permission, code, desc.strip())

        # ✅ Store new data for audit
        audit_data["new_data"] = {
            "permission_code": updated_permission.permission_code,
            "description": updated_permission.description,
        }

        return updated_permission

    @audit_action_with_request(
        action_type="DELETE",
        entity_type="Permissions",
        get_entity_id=lambda self, permission_uuid, *args, **kwargs: (
            self.dao.get_by_uuid(permission_uuid).permission_id
            if self.dao.get_by_uuid(permission_uuid)
            else None
        ),
        capture_old_data=True,
        capture_new_data=False,
        description="Deleted permission",
    )
    def delete_permission(self, permission_uuid: str, audit_data=None, **kwargs):
        permission = self.dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Permission with ID {permission_uuid} not found",
            )

        # ✅ Initialize audit_data dictionary if not provided
        if audit_data is None:
            audit_data = {}

        # ✅ Capture old data for audit
        audit_data["old_data"] = {
            "permission_code": permission.permission_code,
            "description": permission.description,
            "permission_uuid": permission.permission_uuid,
        }

        try:
            # Clear relationships to avoid FK constraint errors
            permission.access_mappings.clear()
            permission.permission_groups.clear()

            self.dao.delete(permission)
        except Exception as e:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete permission: {str(e)}",
            )

        return {"message": f"Permission with ID {permission_uuid} deleted successfully"}
    
    @audit_action_with_request(
    action_type="DELETE",
    entity_type="Permissions",
    capture_old_data=True,
    capture_new_data=False,
    description="Deleted permissions",
    )
    def delete_permissions(self, permission_uuids: list[str], audit_data=None, **kwargs):
        if audit_data is None:
            audit_data = {}

        if not permission_uuids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one permission UUID is required",
            )

        permission_uuids = list(set(permission_uuids))

        deleted_permissions_old_data = []
        failed_permissions = []

        try:
            for permission_uuid in permission_uuids:
                permission = self.dao.get_by_uuid(permission_uuid)

                if not permission:
                    failed_permissions.append(
                        {
                            "permission_uuid": permission_uuid,
                            "reason": "Permission not found",
                        }
                    )
                    continue

                deleted_permissions_old_data.append(
                    {
                        "permission_id": permission.permission_id,
                        "permission_uuid": permission.permission_uuid,
                        "permission_code": permission.permission_code,
                        "description": permission.description,
                    }
                )

                permission.access_mappings.clear()
                permission.permission_groups.clear()

                self.dao.delete(permission)

            if not deleted_permissions_old_data:
                self.db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "message": "No permissions were deleted",
                        "failed_permissions": failed_permissions,
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
                detail=f"Failed to delete permissions: {str(e)}",
            )

        audit_data["entity_id"] = None
        audit_data["old_data"] = {
            "deleted_count": len(deleted_permissions_old_data),
            "deleted_permissions": deleted_permissions_old_data,
            "failed_permissions": failed_permissions,
        }

        return {
            "message": "Permissions deleted successfully",
            "deleted_count": len(deleted_permissions_old_data),
            "deleted_permissions": deleted_permissions_old_data,
            "failed_permissions": failed_permissions,
        }

    def delete_permission_cascade(self, permission_uuid: str):
        if not self.dao.get_by_uuid(permission_uuid):
            raise HTTPException(status_code=404, detail="Permission not found")
        permission_id = self.dao.get_by_uuid(permission_uuid).permission_id
        self.dao.delete_cascade(permission_id)

    def reassign_group(self, permission_uuid: int, group_uuid: int):
        if not self.dao.get_by_uuid(permission_uuid):
            raise HTTPException(status_code=404, detail="Permission not found")
        if not self.group_dao.get_group_by_uuid(group_uuid):
            raise HTTPException(status_code=404, detail="Group not found")
        permission_id = self.dao.get_by_uuid(permission_uuid).permission_id
        group_id = self.group_dao.get_group_by_uuid(group_uuid).group_id
        self.dao.update_group_mapping(permission_id, group_id)

    def list_unmapped_permissions(self):
        return self.dao.get_unmapped()
