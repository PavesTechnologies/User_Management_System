from fastapi import HTTPException, status, UploadFile
from uuid import UUID
import pandas as pd
import io
from sqlalchemy.orm import Session
from ...Data_Access_Layer.dao.access_point_dao import AccessPointDAO
from ...Api_Layer.interfaces.access_point import (
    AccessPointCreate,
    AccessPointUpdate,
    AccessPointOut,
)
from typing import List
from ...Data_Access_Layer.utils.dependency import SessionLocal
from sqlalchemy.exc import IntegrityError
import re
from ..utils.generate_uuid7 import generate_uuid7
from ...Data_Access_Layer.dao.permission_dao import PermissionDAO
from ..utils.audit_decorator import audit_action_with_request
from ...Business_Layer.utils.redis_cache import (
    delete_access_point_cache_by_id,
    clear_all_access_point_cache,
    set_access_point_cache,
)


class AccessPointService:
    def __init__(self, db: Session = None):
        self.db: Session = db or SessionLocal()
        self.dao = AccessPointDAO(self.db)
        self.permission_dao = PermissionDAO(self.db)

    def normalize_endpoint(self, endpoint: str) -> str | None:
        """
        Convert endpoint with {params} into regex pattern.
        Static endpoints are returned unchanged.
        """
        if "{" not in endpoint:  # static path
            return None

        # Replace {param} with a named regex group (allowing digits/letters/_/-)
        pattern = re.sub(r"\{(\w*)\}", r"([^/]+)", endpoint)

        return "^" + pattern + "$"

    def _invalidate_cache(self, access_id: int):
        """
        Clear cache for an access point using its UUID.

        Args:
            access_uuid: The UUID of the access point

        Example:
            self._invalidate_cache("123e4567-e89b-12d3-a456-426614174000")
        """
        if access_id is None:
            clear_all_access_point_cache()
        else:
            delete_access_point_cache_by_id(access_id)

    @audit_action_with_request(
        action_type="CREATE",
        entity_type="AccessPoint",
        capture_new_data=True,
        description="Created new access point",
    )
    def create_access_point(
        self, data: AccessPointCreate, created_by_user_id: int, **kwargs
    ):
        audit_data = kwargs.get("audit_data", {})

        ap_dict = data.dict(exclude_unset=True)

        # Normalize endpoint_path before saving
        ap_dict["regex_pattern"] = self.normalize_endpoint(ap_dict["endpoint_path"])
        ap_dict["created_by"] = created_by_user_id
        ap_dict["access_uuid"] = generate_uuid7()

        existing = self.dao.get_access_point_by_path_and_method(
            ap_dict["endpoint_path"], ap_dict["method"]
        )

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Access point with this endpoint_path AND method '{ap_dict['method']}' already exists",
            )

        try:
            access_point = self.dao.create_access_point(**ap_dict)
        except IntegrityError as e:
            print("IntegrityError details:", e.orig)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid data or constraint violation",
            ) from e
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create access point",
            ) from e

        # Set entity_id for audit (since we're returning a dict, not the object)
        audit_data["entity_id"] = access_point.access_id  # or whatever your PK is
        audit_data["new_data"] = {
            "access_id": access_point.access_id,
            "access_uuid": access_point.access_uuid,
            "endpoint_path": access_point.endpoint_path,
            "method": access_point.method,
            "module": access_point.module,
            "is_public": access_point.is_public,
            "created_by": access_point.created_by,
            "created_at": str(access_point.created_at),
        }
        set_access_point_cache(
            access_point.method,
            access_point.endpoint_path,
            {
                "access_point": {
                    "is_public": access_point.is_public,
                    "access_id": access_point.access_id,
                },
                "required_permissions": [],
            },
        )
        return {
            "access_uuid": access_point.access_uuid,
            "message": "Access point created successfully",
        }

    @audit_action_with_request(
        action_type="CREATE",
        entity_type="AccessPoint",
        capture_new_data=True,
        description="Bulk created access points from Excel file",
    )
    def bulk_create_access_points(
        self, file: UploadFile, created_by_user_id: int, **kwargs
    ):
        audit_data = kwargs.get("audit_data", {})

        # Validate file type
        if not file.filename or not file.filename.endswith((".xlsx", ".xls")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only Excel files (.xlsx, .xls) are supported",
            )

        try:
            # Read file content into BytesIO (THIS IS THE FIX)
            contents = file.file.read()
            df1 = pd.read_excel(io.BytesIO(contents))

            # Validate required columns
            required_columns = ["endpoint_path", "method", "module"]
            missing_columns = [
                col for col in required_columns if col not in df1.columns
            ]

            if missing_columns:
                print(f"Missing columns in Excel: {missing_columns}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Missing required columns: {', '.join(missing_columns)}",
                )

            # Optional column with default value
            if "is_public" not in df1.columns:
                df1["is_public"] = False

            # Remove rows with missing required values
            df = df1.dropna(subset=required_columns)

            if df.empty:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No valid data found in the Excel file",
                )

            created_access_points = []
            errors = []

            # Process each row
            for index, row in df.iterrows():
                if bool(row["is_public"]) or row["is_public"] not in [
                    1,
                    "1",
                    True,
                    "True",
                ]:
                    is_public_value = 0
                else:
                    is_public_value = 1
                try:
                    ap_dict = {
                        "endpoint_path": str(row["endpoint_path"]).strip(),
                        "method": str(row["method"]).strip().upper(),
                        "module": str(row["module"]).strip(),
                        "is_public": is_public_value,
                        "regex_pattern": self.normalize_endpoint(
                            str(row["endpoint_path"]).strip()
                        ),
                        "created_by": created_by_user_id,
                        "access_uuid": generate_uuid7(),
                    }

                    # Check if access point already exists
                    existing = self.dao.get_access_point_by_path_and_method(
                        ap_dict["endpoint_path"], ap_dict["method"]
                    )

                    if existing:
                        errors.append(
                            {
                                "row": index + 2,
                                "endpoint_path": ap_dict["endpoint_path"],
                                "method": ap_dict["method"],
                                "error": "Access point with this endpoint_path and method already exists",
                            }
                        )
                        continue

                    # Create access point
                    access_point = self.dao.create_access_point(**ap_dict)

                    # Set cache
                    set_access_point_cache(
                        access_point.method,
                        access_point.endpoint_path,
                        {
                            "access_point": {
                                "is_public": access_point.is_public,
                                "access_id": access_point.access_id,
                            },
                            "required_permissions": [],
                        },
                    )

                    created_access_points.append(
                        {
                            "access_uuid": access_point.access_uuid,
                            "message": "Access point created successfully",
                        }
                    )

                except IntegrityError:
                    errors.append(
                        {
                            "row": index + 2,
                            "endpoint_path": row.get("endpoint_path", "N/A"),
                            "method": row.get("method", "N/A"),
                            "error": "Invalid data or constraint violation",
                        }
                    )
                except Exception as e:
                    errors.append(
                        {
                            "row": index + 2,
                            "endpoint_path": row.get("endpoint_path", "N/A"),
                            "method": row.get("method", "N/A"),
                            "error": str(e),
                        }
                    )

            # Update audit data
            audit_data["entity_id"] = None
            audit_data["new_data"] = {
                "total_rows": len(df),
                "successful_creates": len(created_access_points),
                "failed_creates": len(errors),
                "errors": errors[:10],
            }

            # Return with summary
            response_data = {
                "summary": {
                    "total_rows": len(df1),
                    "missing_data_rows": len(df1) - len(df),
                    "successful": len(created_access_points),
                    "failed": len(errors),
                },
                "created_access_points": created_access_points,
                "errors": errors if errors else [],
            }

            # if not created_access_points and errors:
            #     raise HTTPException(
            #         status_code=status.HTTP_400_BAD_REQUEST,
            #         detail=response_data
            #     )

            return response_data

        except pd.errors.EmptyDataError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Excel file is empty"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to process Excel file: {str(e)}",
            )

    def list(self):
        access_points = self.dao.get_all_access_points()
        result = []
        for ap in access_points:
            permission_mapping = (
                ap.permission_mappings[0] if ap.permission_mappings else None
            )
            permission_code = (
                permission_mapping.permission.permission_code
                if permission_mapping and permission_mapping.permission
                else None
            )
            permission_uuid = (
                permission_mapping.permission.permission_uuid
                if permission_mapping and permission_mapping.permission
                else None
            )

            result.append(
                AccessPointOut(
                    access_uuid=ap.access_uuid,
                    endpoint_path=ap.endpoint_path,
                    method=ap.method,
                    module=ap.module,
                    is_public=ap.is_public,
                    permission_uuid=permission_uuid,
                    permission_code=permission_code,
                    created_at=ap.created_at,
                    updated_at=ap.updated_at,
                )
            )
        return result

    def get(self, access_uuid: str):
        ap = self.dao.get_access_point_by_uuid(access_uuid)
        if not ap:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found"
            )

        permission_mapping = (
            ap.permission_mappings[0] if ap.permission_mappings else None
        )
        permission_code = (
            permission_mapping.permission.permission_code
            if permission_mapping and permission_mapping.permission
            else None
        )
        permission_uuid = (
            permission_mapping.permission.permission_uuid
            if permission_mapping and permission_mapping.permission
            else None
        )

        return AccessPointOut(
            access_uuid=ap.access_uuid,
            endpoint_path=ap.endpoint_path,
            method=ap.method,
            module=ap.module,
            is_public=ap.is_public,
            permission_uuid=permission_uuid,
            permission_code=permission_code,
        )

    def list_modules(self) -> List[str]:
        return self.dao.get_distinct_modules()

    @audit_action_with_request(
        action_type="UPDATE",
        entity_type="AccessPoint",
        capture_old_data=False,  # Manual capture
        capture_new_data=False,  # Manual capture
        description="Updated access point",
    )
    def update(self, access_uuid: str, data: AccessPointUpdate, **kwargs):
        audit_data = kwargs.get("audit_data", {})

        update_dict = data.dict(exclude_unset=True)

        # --- Fetch the existing access point ---
        current_ap = self.dao.get_access_point_by_uuid(access_uuid)
        if not current_ap:
            raise HTTPException(status_code=404, detail="Access point not found")

        # Set entity_id for audit
        audit_data["entity_id"] = current_ap.access_id

        # ✅ CREATE A SNAPSHOT of old values BEFORE any changes
        old_permission_code = self.dao.get_permission_code_by_access_id(
            current_ap.access_id
        )
        old_snapshot = {
            "access_id": current_ap.access_id,
            "access_uuid": str(current_ap.access_uuid),
            "endpoint_path": current_ap.endpoint_path,
            "method": current_ap.method,
            "module": current_ap.module,
            "is_public": current_ap.is_public,
            "regex_pattern": current_ap.regex_pattern,
            "permission_code": old_permission_code,
        }

        audit_data["old_data"] = old_snapshot

        # --- Handle permission logic ---
        permission_changed = False
        new_permission_code = update_dict.get("permission_code", None)
        if "permission_code" in update_dict:
            if (
                new_permission_code == "Null"
                or new_permission_code is None
                or new_permission_code == ""
            ):
                # ✅ User wants to delete permission mapping
                self.dao.update_access_point_permission(current_ap.access_id, "Null")
                permission_changed = True
                new_permission_code = None
            else:
                # ❌ User tried to change/add permission (not allowed)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="You can only delete permission mappings, not modify or add new ones",
                )
            # Remove permission_code from update_dict so it's not updated in AccessPoint
            del update_dict["permission_code"]

        # --- Handle endpoint/method changes ---
        if "endpoint_path" in update_dict or "method" in update_dict:
            new_endpoint = update_dict.get("endpoint_path", current_ap.endpoint_path)
            new_method = update_dict.get("method", current_ap.method)
            regex_pattern = self.normalize_endpoint(new_endpoint)
            update_dict["regex_pattern"] = regex_pattern

            # Check for duplicate (endpoint_path + method)
            existing = self.dao.get_access_point_by_path_and_method_without_regex_check(
                new_endpoint, new_method
            )
            if existing and existing.access_uuid != access_uuid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Another access point with this endpoint and method already exists",
                )
        else:
            new_endpoint = current_ap.endpoint_path
            new_method = current_ap.method

        # --- Other fields (module, is_public) ---
        new_module = update_dict.get("module", current_ap.module)
        new_is_public = update_dict.get("is_public", current_ap.is_public)

        # --- Perform AccessPoint update ---
        updated_ap = self.dao.update_access_point(current_ap.access_id, **update_dict)

        # --- Prepare updated permission code for response ---
        if not permission_changed:
            permission_code = self.dao.get_permission_code_by_access_id(
                current_ap.access_id
            )
        else:
            permission_code = new_permission_code

        if updated_ap is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Access point update failed",
            )

        # ✅ Compare against the OLD SNAPSHOT, not current_ap
        changes = {}
        if updated_ap.endpoint_path != old_snapshot["endpoint_path"]:
            changes["endpoint_path"] = {
                "old": old_snapshot["endpoint_path"],
                "new": updated_ap.endpoint_path,
            }
        if updated_ap.method != old_snapshot["method"]:
            changes["method"] = {
                "old": old_snapshot["method"],
                "new": updated_ap.method,
            }
        if updated_ap.module != old_snapshot["module"]:
            changes["module"] = {
                "old": old_snapshot["module"],
                "new": updated_ap.module,
            }
        if updated_ap.is_public != old_snapshot["is_public"]:
            changes["is_public"] = {
                "old": old_snapshot["is_public"],
                "new": updated_ap.is_public,
            }
        if (
            "regex_pattern" in update_dict
            and updated_ap.regex_pattern != old_snapshot["regex_pattern"]
        ):
            changes["regex_pattern"] = {
                "old": old_snapshot["regex_pattern"],
                "new": updated_ap.regex_pattern,
            }
        if permission_changed and old_permission_code != permission_code:
            changes["permission_code"] = {
                "old": old_permission_code,
                "new": permission_code,
            }

        audit_data["new_data"] = changes if changes else None
        print(
            f"old snapshot: {old_snapshot['method']}, {old_snapshot['regex_pattern']}"
        )
        self._invalidate_cache(old_snapshot["access_id"])

        # --- Build and return response ---
        return AccessPointOut(
            access_uuid=UUID(access_uuid),
            endpoint_path=new_endpoint,
            method=new_method,
            module=new_module,
            is_public=new_is_public,
            permission_code=permission_code,
        )

    @audit_action_with_request(
        action_type="DELETE",
        entity_type="AccessPoint",
        get_entity_id=lambda self, access_uuid, *args, **kwargs: (
            self.dao.get_access_point_by_uuid(access_uuid).access_id
            if self.dao.get_access_point_by_uuid(access_uuid)
            else None
        ),
        capture_old_data=True,
        capture_new_data=False,
        description="Deleted an access point",
    )
    def delete(self, access_uuid: str, **kwargs):
        access_point = self.dao.get_access_point_by_uuid(access_uuid)
        if not access_point:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Access point with UUID {access_uuid} not found",
            )
        audit_data = kwargs.get("audit_data", {})
        audit_data["old_data"] = {
            "access_id": access_point.access_id,
            "access_uuid": access_point.access_uuid,
            "endpoint_path": access_point.endpoint_path,
            "method": access_point.method,
            "module": access_point.module,
            "is_public": access_point.is_public,
            "created_by": access_point.created_by,
            "created_at": str(access_point.created_at),
        }
        success = self.dao.delete_access_point(access_point.access_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete access point",
            )
        self._invalidate_cache(access_point.access_id)

        return {"message": "Access point  deleted successfully"}

    @audit_action_with_request(
        action_type="Update",
        entity_type="AccessPointPermission",
        capture_old_data=False,
        capture_new_data=False,
        description="Mapped a permission to an access point",
    )
    def map_permission(
        self, access_uuid: str, permission_uuid: str, assigned_by: int, **kwargs
    ):
        access_point = self.dao.get_access_point_by_uuid(access_uuid)
        if not access_point:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found"
            )
        access_id = access_point.access_id

        audit_data = kwargs.get("audit_data", {})
        audit_data["entity_id"] = access_id

        permission = self.permission_dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
            )
        permission_id = permission.permission_id

        ap = self.dao.get_access_point_by_id(access_id)
        if not ap:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found"
            )
        self.dao.create_access_permission_mapping(
            access_id, permission_id, assigned_by=assigned_by
        )

        audit_data["new_data"] = {
            "assigned_permission": {
                "access_uuid": access_uuid,
                "permission_uuid": permission_uuid,
                "permission_code": permission.permission_code,
                "assigned_by": assigned_by,
            }
        }
        self._invalidate_cache(access_id)
        return {
            "message": "Permission mapped successfully",
            "access_uuid": access_point.access_uuid,
            "permission_uuid": permission.permission_uuid,
        }

    @audit_action_with_request(
        action_type="Update",
        entity_type="AccessPointPermission",
        capture_old_data=False,
        capture_new_data=False,
        description="mapping a permission for an access point",
    )
    def map_permission_bulk(self, file: UploadFile, assigned_by: int, **kwargs):
        audit_data = kwargs.get("audit_data", {})

        # Validate file type
        if not file.filename or not file.filename.endswith((".xlsx", ".xls")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only Excel files (.xlsx, .xls) are supported",
            )

        # Read file content
        contents = file.file.read()
        df = pd.read_excel(io.BytesIO(contents))

        # Validate columns
        required_columns = [
            "access_point_name",
            "access_point_method",
            "permission_name",
        ]
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing required columns: {', '.join(missing_columns)}",
            )

        # Clean data
        df = df.dropna(subset=required_columns)
        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid data found in the Excel file",
            )

        successful_mappings = []
        errors = []
        valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

        # Process with transaction (pseudo-code - adjust to your ORM)
        try:
            # Begin transaction
            for index, row in df.iterrows():
                access_point_name = str(row["access_point_name"]).strip()
                permission_name = str(row["permission_name"]).strip()
                access_point_method = str(row["access_point_method"]).strip().upper()

                # Validate HTTP method
                if access_point_method not in valid_methods:
                    errors.append(
                        {
                            "row": index + 2,
                            "access_point_name": access_point_name,
                            "permission_name": permission_name,
                            "error": f"Invalid HTTP method: {access_point_method}",
                        }
                    )
                    continue

                try:
                    # Get access point
                    access_point = self.dao.get_access_point_by_path_and_method(
                        access_point_name, access_point_method
                    )
                    if not access_point:
                        errors.append(
                            {
                                "row": index + 2,
                                "access_point_name": access_point_name,
                                "permission_name": permission_name,
                                "error": "Access point not found",
                            }
                        )
                        continue

                    # ✅ Validate format of permission_code
                    PERMISSION_CODE_PATTERN = re.compile(r"^[A-Z]+(_[A-Z]+)*$")
                    if not PERMISSION_CODE_PATTERN.fullmatch(permission_name):
                        errors.append(
                            {
                                "row": index + 2,
                                "access_point_name": access_point_name,
                                "permission_name": permission_name,
                                "error": "Invalid permission code format",
                            }
                        )
                        continue
                    permission = self.permission_dao.get_by_code(permission_name)
                    if not permission:
                        errors.append(
                            {
                                "row": index + 2,
                                "access_point_name": access_point_name,
                                "permission_name": permission_name,
                                "error": "Permission not found",
                            }
                        )
                        continue

                    # Check if mapping already exists
                    existing = self.dao.get_mapping(access_point.access_id)
                    if existing:
                        permission_name = self.permission_dao.get_by_id(
                            existing.permission_id
                        ).permission_code
                        errors.append(
                            {
                                "row": index + 2,
                                "access_point_name": access_point_name,
                                "permission_name": permission_name,
                                "existing_permission": permission_name,
                                "error": "Mapping already exists",
                            }
                        )
                        continue

                    # Create mapping
                    self.dao.create_access_permission_mapping(
                        access_point.access_id,
                        permission.permission_id,
                        assigned_by=assigned_by,
                    )

                    successful_mappings.append(
                        {
                            "row": index + 2,
                            "access_point_name": access_point_name,
                            "permission_name": permission_name,
                            "message": "Permission mapped successfully",
                        }
                    )

                except Exception as e:
                    errors.append(
                        {
                            "row": index + 2,
                            "access_point_name": access_point_name,
                            "permission_name": permission_name,
                            "error": str(e),
                        }
                    )

            # Commit transaction

        except Exception as e:
            # Rollback transaction
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Bulk operation failed: {str(e)}",
            )

        # Update audit data AFTER the loop
        audit_data["new_data"] = {
            "summary": {
                "total_rows": len(df),
                "successful_mappings": len(successful_mappings),
                "failed_mappings": len(errors),
                "errors": errors[:10],  # Limit to first 10 errors
            },
            "assigned_by": assigned_by,
        }

        # Return summary
        return {
            "total_rows": len(df),
            "successful": len(successful_mappings),
            "failed": len(errors),
            "successful_mappings": successful_mappings,
            "errors": errors,
        }

    def unmap_permission(self, access_id: int):
        success = self.dao.delete_mapping_by_access_id(access_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No mapping found to delete",
            )
        ap = self.dao.get_access_point_by_id(access_id)
        if ap is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Access point not found",
            )
        self._invalidate_cache(access_id)
        return {"message": "Permission unmapped successfully"}

    @audit_action_with_request(
        action_type="Update",
        entity_type="AccessPointPermission",
        description="Unmapped a permission from an access point",
    )
    def unmap_permission_both(
        self, access_uuid: str, permission_uuid: str, **kwargs
    ) -> dict:
        audit_data = kwargs.get("audit_data", {})
        access_point = self.dao.get_access_point_by_uuid(access_uuid)
        if not access_point:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Access point not found"
            )
        access_id = access_point.access_id
        audit_data["entity_id"] = access_id
        permission = self.permission_dao.get_by_uuid(permission_uuid)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
            )
        permission_id = permission.permission_id

        audit_data["entity_id"] = access_id
        audit_data["old_data"] = {
            "access_uuid": access_point.access_uuid,
            "endpoint_path": access_point.endpoint_path,
            "method": access_point.method,
            "module": access_point.module,
            "is_public": access_point.is_public,
            "permission_uuid": permission.permission_uuid,
            "permission_code": permission.permission_code,
        }

        success = self.dao.unmap_permission_dao(access_id, permission_id)
        if not success:
            return {"message": "Mapping not found or failed to delete"}
        audit_data["new_data"] = {
            "removed_mapping": {
                "permission_uuid": permission.permission_uuid,
                "permission_code": permission.permission_code,
            }
        }
        self._invalidate_cache(access_id)
        return {"message": "Permission unmapped from access point successfully"}

    def get_unmapped_access_points(self):
        all_aps = self.dao.get_all_access_points()
        return [
            AccessPointOut(
                access_uuid=ap.access_uuid,
                endpoint_path=ap.endpoint_path,
                method=ap.method,
                module=ap.module,
                is_public=ap.is_public,
                permission_code=None,
                permission_uuid=None,
                created_at=ap.created_at,
                updated_at=ap.updated_at,
            )
            for ap in all_aps
            if not ap.permission_mappings
        ]

    def get_unmapped_permissions(self):
        permissions = self.dao.get_unmapped_permissions()
        return [
            {
                "permission_uuid": perm.permission_uuid,
                "code": perm.permission_code,
                "description": perm.description,
            }
            for perm in permissions
        ]
