from sqlalchemy.orm import Session
from fastapi import HTTPException, Request
from ...Data_Access_Layer.dao.user_dao import UserDAO
from ...Data_Access_Layer.models import models
from ..utils.password_utils import hash_password
from ..utils.email_utils import send_welcome_email
from ..utils.input_validators import (
    validate_email_format,
    validate_password_strength,
    validate_name,
    validate_contact_number,
)
from ..utils.generate_uuid7 import generate_uuid7

# Import the audit decorator
from ..utils.audit_decorator import audit_action_with_request, _get_ip_address
import pandas as pd
import re
from datetime import datetime
from typing import Optional
import time
import logging

logger = logging.getLogger(__name__)


class UserService:
    def __init__(self, db: Session):
        self.db = db
        self.dao = UserDAO(self.db)

    def count_users(self):
        return self.dao.count_users()

    def count_active_users(self):
        return self.dao.count_active_users()

    def list_users(self, page: int, limit: int, search: Optional[str] = None):
        t_start = time.time()
        print("  🟢 START service.list_users")

        result = self.dao.get_paginated_users(page, limit, search)

        t_end = time.time()
        elapsed = (t_end - t_start) * 1000
        print(f"  ✅ END service.list_users - {elapsed:.2f}ms")

        return result

    def get_users_with_roles(self, page: int, limit: int, search: Optional[str] = None):
        users_data = self.dao.get_users_with_roles(page, limit, search)

        return users_data

    def get_users_with_roles_id(self):
        users = self.dao.get_users_with_roles_id()
        return users

    def get_user_uuid(self, current_user, user_uuid):
        current_user_roles = current_user["roles"]
        user = self.dao.get_user_by_uuid(user_uuid)
        if not user:
            raise ValueError("User not found")
        user_uuid = user.user_uuid
        user_roles = self.get_user_roles_by_uuid(user_uuid)

        if "Super Admin" not in current_user_roles and "Super Admin" in user_roles:
            raise HTTPException(
                status_code=403,
                detail="Only Super Admins can edit Super Admin accounts.",
            )

        return user

    def get_user(self, user_id):
        return self.dao.get_user_by_id(user_id)

    @audit_action_with_request(
        action_type="CREATE",
        entity_type="User",
        get_entity_id=lambda *args, **kwargs: None,  # Will be extracted from result
        capture_new_data=True,
        description="Created new user: {mail}",
    )
    def create_user(self, user_schema, created_by_user_id: int, **kwargs):
        existing = self.dao.get_user_by_email(user_schema.mail)
        if existing:
            raise ValueError("User already exists")
        validate_email_format(user_schema.mail)
        validate_name(user_schema.first_name)
        validate_name(user_schema.last_name)
        validate_contact_number(user_schema.contact)
        validate_password_strength(user_schema.password)

        hashed_password = hash_password(user_schema.password)
        new_user = models.User(
            user_uuid=generate_uuid7(),
            first_name=user_schema.first_name,
            last_name=user_schema.last_name,
            mail=user_schema.mail,
            contact=user_schema.contact,
            password=hashed_password,
            is_active=user_schema.is_active,
        )
        send_welcome_email(
            user_schema.mail, user_schema.first_name, user_schema.password
        )

        # Step 1: Create user
        created_user = self.dao.create_user(new_user)

        # Step 2: Get General role
        general_role = self.dao.get_role_by_name("General")
        if not general_role:
            raise ValueError("Role 'General' not found")

        # Step 3: Map user to role
        self.dao.map_user_role(
            created_user.user_id, general_role.role_id, created_by_user_id
        )

        return created_user

    def bulk_create_users(self, df: pd.DataFrame, created_by_user_id: int):
        def clean_contact(contact):
            """
            Safely clean and normalize contact numbers from Excel.
            Handles:
            - Scientific notation (9.18097E+11)
            - Float rounding
            - String or numeric formats
            - Non-digit characters
            """
            if pd.isna(contact):
                return ""

            # Case 1: float values (scientific notation or plain float)
            if isinstance(contact, (float, int)):
                # Check if float is too large and rounded by Excel
                if contact > 1e11:  # likely 12-digit Indian number
                    # Convert with integer precision (no decimals)
                    contact_str = f"{int(contact):.0f}"
                else:
                    contact_str = str(int(contact))
            else:
                # Case 2: string input
                contact_str = str(contact).strip()

            # Remove anything that’s not a digit
            contact_str = re.sub(r"\D", "", contact_str)

            # If number looks truncated (e.g., 918097000000), warn
            if len(contact_str) < 10 or len(contact_str) > 15:
                raise ValueError(f"Invalid or truncated contact number: {contact}")

            return contact_str

        def generate_password(first_name, contact):
            contact_str = str(contact)
            return (
                f"{first_name[:1].upper()+first_name[1:4]}@{contact_str[-4:]}"
                if len(contact_str) >= 4
                else f"{first_name[:1].upper()+first_name[1:4]}@0000"
            )

    def create_bulk_user(
        self,
        df: pd.DataFrame,
        created_by_user_id: int,
        current_user: dict = None,
        request: Request = None,
        audit_data: dict = None,
    ):

        """
        Bulk create users from Excel with validation, audit logs, and partial success handling.
        Skips invalid rows and continues with valid ones.
        Returns dict with 'success' and 'failed' results.
        """

        def clean_string(value, field_name="value", required=True):
            """
            Safely cleans Excel string values like name, mail, designation, department.
            """
            if pd.isna(value):
                if required:
                    raise ValueError(f"{field_name} is required")
                return ""

            value = str(value).strip()

            if required and not value:
                raise ValueError(f"{field_name} is required")

            return value

        def clean_contact(contact):
            """
            Handles Excel contact values safely.
            Examples:
            9876543210
            9876543210.0
            '+91 98765 43210'
            """
            if pd.isna(contact):
                raise ValueError("Contact number is required")

            if isinstance(contact, float):
                contact_str = str(int(contact))
            elif isinstance(contact, int):
                contact_str = str(contact)
            else:
                contact_str = str(contact).strip()

            # Remove spaces, +, -, brackets, etc.
            contact_str = re.sub(r"\D", "", contact_str)

            if not contact_str:
                raise ValueError("Contact number is required")

            if len(contact_str) < 10 or len(contact_str) > 15:
                raise ValueError(f"Invalid contact number: {contact}")

            return contact_str

        def generate_password(first_name, contact):
            """
            Password format:
            First 4 chars from first_name + @ + last 4 digits of contact

            """
            first_name = str(first_name).strip()

            if not first_name:
                name_part = "User"
            else:
                # Keep alphabets only for password name part
                name_part = re.sub(r"[^A-Za-z]", "", first_name)

                if not name_part:
                    name_part = "User"

            # First letter uppercase, remaining lowercase
            name_part = name_part.capitalize()

            # Ensure minimum 4 chars
            if len(name_part) < 4:
                name_part = name_part.ljust(4, "x")
            else:
                name_part = name_part[:4]

            contact_str = str(contact)
            last4 = contact_str[-4:] if len(contact_str) >= 4 else "0000"

            return f"{name_part}@{last4}"

        def parse_status_to_is_active(status):
            """
            Converts Excel Status column to boolean.
            Accepted active values:
            Active, true, yes, 1

            Accepted inactive values:
            Inactive, false, no, 0
            """
            if pd.isna(status):
                return True

            status_value = str(status).strip().lower()

            active_values = {"active", "true", "yes", "1", "enabled"}
            inactive_values = {"inactive", "false", "no", "0", "disabled"}

            if status_value in active_values:
                return True

            if status_value in inactive_values:
                return False

            raise ValueError(f"Invalid Status value: {status}")

        if audit_data is None:
            audit_data = {}

        cleaned_rows = []
        failed_rows = []
        seen_emails = set()

        # Step 1: Validate each row
        for index, row in df.iterrows():
            row_num = index + 2

            try:
                first_name = clean_string(row.get("first_name"), "first_name")
                last_name = clean_string(row.get("last_name"), "last_name")
                mail = clean_string(row.get("mail"), "mail").lower()
                contact = clean_contact(row.get("contact"))
                employee_id = clean_string(row.get("employee_id"), "employee_id", required=False)
                # designation = clean_string(row.get("Designation"), "Designation", required=False)
                # department = clean_string(row.get("Department"), "Department", required=False)
                # is_active = parse_status_to_is_active(row.get("Status"))
                is_active = True  # Default to active, or use the Status column if you want

                user_uuid = row.get("user_uuid")

                if pd.isna(user_uuid) or str(user_uuid).strip() == "":
                    user_uuid = generate_uuid7()
                else:
                    user_uuid = str(user_uuid).strip()

                # Duplicate email inside same Excel file
                if mail in seen_emails:
                    raise ValueError("Duplicate email found in Excel file")

                seen_emails.add(mail)

                password = generate_password(first_name, contact)
                # print(f"Generated password for row {row_num}: {password}")

                validate_email_format(mail)
                validate_name(first_name)
                validate_name(last_name)
                validate_contact_number(contact)

                cleaned_rows.append(
                    {
                        "first_name": first_name,
                        "last_name": last_name,
                        "mail": mail,
                        "contact": contact,
                        "password": password,
                        "row_num": row_num,
                        "is_active": is_active,
                        "employee_id": employee_id,
                        "user_uuid": user_uuid,
                        # "designation": designation,
                        # "department": department,
                        "status": row.get("Status"),
                    }
                )

            except Exception as e:
                failed_rows.append(
                    {
                        "row": row_num,
                        "mail": row.get("mail", ""),
                        "error": str(e),
                    }
                )

        # Step 2: If all failed
        if not cleaned_rows:
            return {
                "success": [],
                "failed": failed_rows,
                "message": "All rows failed validation.",
            }

        # Step 3: Check already existing users
        existing_emails = self.dao.get_users_by_emails(
            [r["mail"] for r in cleaned_rows]
        )

        existing_emails = {email.lower() for email in existing_emails} if existing_emails else set()

        remaining_rows = []

        for r in cleaned_rows:
            if r["mail"].lower() in existing_emails:
                failed_rows.append(
                    {
                        "row": r["row_num"],
                        "mail": r["mail"],
                        "error": "User already exists",
                    }
                )
            else:
                remaining_rows.append(r)

        cleaned_rows = remaining_rows

        if not cleaned_rows:
            return {
                "success": [],
                "failed": failed_rows,
                "message": "No valid new users to create.",
            }

        # Step 4: Get default role
        general_role = self.dao.get_role_by_name("General")

        if not general_role:
            raise ValueError("Role 'General' not found")

        # Step 5: Hash passwords
        for r in cleaned_rows:
            r["hashed_password"] = hash_password(r["password"])

        # Step 6: Create user objects
        user_objects = [
            models.User(
                user_uuid=r["user_uuid"],
                first_name=r["first_name"],
                last_name=r["last_name"],
                mail=r["mail"],
                contact=r["contact"],
                password=r["hashed_password"],
                is_active=r["is_active"],
                employee_id=r["employee_id"],

                # Add these only if these columns exist in your User model
                # designation=r["designation"],
                # department=r["department"],
            )
            for r in cleaned_rows
        ]

        created_users = self.dao.create_users_batch(user_objects)

        # Step 7: Map General role
        user_role_mappings = [
            (user.user_id, general_role.role_id, created_by_user_id)
            for user in created_users
        ]

        self.dao.map_user_roles_batch(user_role_mappings)

        # Step 8: Audit logs
        ip_address = _get_ip_address(request=request) if request else None
        audit_logs = []

        for user in created_users:
            new_data = {
                "user_id": user.user_id,
                "user_uuid": user.user_uuid,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "mail": user.mail,
                "contact": user.contact,
                "is_active": user.is_active,
                "employee_id": user.employee_id,
                "created_at": user.created_at.isoformat() if user.created_at else None,
            }

            description = f"Created new user: {user.mail}"

            audit_logs.append(
                models.AuditTrail(
                    user_id=created_by_user_id,
                    action_type="CREATE",
                    entity_type="User",
                    entity_id=user.user_id,
                    old_data=None,
                    new_data=new_data,
                    ip_address=ip_address,
                    description=description,
                    created_at=datetime.utcnow(),
                )
            )

        if audit_logs:
            self.dao.create_audit_logs_batch(audit_logs)

        # Step 9: Send welcome emails
        for user, row in zip(created_users, cleaned_rows):
            send_welcome_email(user.mail, user.first_name, row["password"])

        # Step 10: Final summary
        success_data = [
            {
                "row": r["row_num"],
                "mail": r["mail"],
                "status": "created",
            }
            for r in cleaned_rows
        ]

        return {
            "success": success_data,
            "failed": failed_rows,
            "message": f"Created {len(success_data)} users, {len(failed_rows)} failed.",
        }

    @audit_action_with_request(
        action_type="UPDATE",
        entity_type="User",
        get_entity_id=lambda self, user_uuid, *args, **kwargs: (
            self.dao.get_user_by_uuid(user_uuid).user_id
            if self.dao.get_user_by_uuid(user_uuid)
            else None
        ),
        capture_old_data=True,
        capture_new_data=True,
    )
    def update_user_uuid(self, user_uuid, user_schema, **kwargs):
        user = self.dao.get_user_by_uuid(user_uuid)
        if not user:
            raise ValueError("User not found")
        # Validations
        validate_email_format(user_schema.mail)
        validate_name(user_schema.first_name)
        validate_name(user_schema.last_name)
        validate_contact_number(user_schema.contact)
        if user.mail != user_schema.mail:
            existing = self.dao.get_user_by_email(user_schema.mail)
            if existing:
                raise ValueError("User already exists")
        updated_data = {
            "first_name": user_schema.first_name,
            "last_name": user_schema.last_name,
            "mail": user_schema.mail,
            "contact": user_schema.contact,
            "is_active": user_schema.is_active,
        }
        password_changed = False
        # Password update handling (SAFE)
        if user_schema.password and user_schema.password.strip() != "":
            # Assume anything provided is a NEW plain password (frontend never sends old hash)
            # Validate and hash it
            validate_password_strength(user_schema.password)
            updated_data["password"] = hash_password(user_schema.password)
            password_changed = True
        else:
            # Keep existing hashed password as-is
            updated_data["password"] = user.password
        success = self.dao.update_user(user, updated_data)
        if success:
            if password_changed:
                self.dao.password_last_updated(user.user_id)
            return self.dao.get_user_by_id(user.user_id)
        else:
            raise RuntimeError("User update failed")

    @audit_action_with_request(
        action_type="UPDATE",
        entity_type="User",
        get_entity_id=lambda self, user_id, *args, **kwargs: user_id,
        capture_old_data=True,
        capture_new_data=True,
    )
    def update_user(self, user_id, user_schema, **kwargs):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        # Validations
        validate_email_format(user_schema.mail)
        validate_name(user_schema.first_name)
        validate_name(user_schema.last_name)
        validate_contact_number(user_schema.contact)
        if user.mail != user_schema.mail:
            existing = self.dao.get_user_by_email(user_schema.mail)
            if existing:
                raise ValueError("User already exists")
        updated_data = {
            "first_name": user_schema.first_name,
            "last_name": user_schema.last_name,
            "mail": user_schema.mail,
            "contact": user_schema.contact,
            "is_active": user_schema.is_active,
        }
        password_changed = False
        # Password update handling (SAFE)
        if user_schema.password and user_schema.password.strip() != "":
            # Assume anything provided is a NEW plain password (frontend never sends old hash)
            # Validate and hash it
            validate_password_strength(user_schema.password)
            updated_data["password"] = hash_password(user_schema.password)
            password_changed = True
        else:
            # Keep existing hashed password as-is
            updated_data["password"] = user.password
        success = self.dao.update_user(user, updated_data)
        if success:
            if password_changed:
                self.dao.password_last_updated(user_id)
            return self.dao.get_user_by_id(user_id)
        else:
            raise RuntimeError("User update failed")

    @audit_action_with_request(
        action_type="DELETE",
        entity_type="User",
        get_entity_id=lambda self, user_id, *args, **kwargs: user_id,
        capture_old_data=True,
        description="Deactivated user account",
    )
    def deactivate_user(self, user_id, **kwargs):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        self.dao.deactivate_user(user)

    @audit_action_with_request(
        action_type="DELETE",
        entity_type="User",
        get_entity_id=lambda self, user_uuid, *args, **kwargs: (
            self.dao.get_user_by_uuid(user_uuid).user_id
            if self.dao.get_user_by_uuid(user_uuid)
            else None
        ),
        capture_old_data=True,
        description="Deactivated user account",
    )
    def deactivate_user_uuid(self, user_uuid, current_user, **kwargs):
        current_user_roles = current_user["roles"]
        user = self.dao.get_user_by_uuid(user_uuid)
        if not user:
            raise ValueError("User not found")
        user_uuid = user.user_uuid
        user_roles = self.get_user_roles_by_uuid(user_uuid)

        if "Super Admin" not in current_user_roles and "Super Admin" in user_roles:
            raise HTTPException(
                status_code=403,
                detail="Only Super Admins can delete Super Admin accounts.",
            )

        self.dao.deactivate_user(user)

    @audit_action_with_request(
        action_type="PUT",
        entity_type="User",
        get_entity_id=lambda self, user_uuid, *args, **kwargs: (
            self.dao.get_user_by_uuid(user_uuid).user_id
            if self.dao.get_user_by_uuid(user_uuid)
            else None
        ),
        capture_old_data=True,
        description="Activated user account",
    )
    def activate_user_uuid(self, user_uuid, current_user, **kwargs):
        current_user_roles = current_user["roles"]
        user = self.dao.get_user_by_uuid(user_uuid)
        if not user:
            raise ValueError("User not found")

        user_roles = self.get_user_roles_by_uuid(user_uuid)

        # Restrict privilege escalation
        if "Super Admin" not in current_user_roles and "Super Admin" in user_roles:
            raise HTTPException(
                status_code=403,
                detail="Only Super Admins can activate Super Admin accounts.",
            )

        self.dao.activate_user(user)

    @audit_action_with_request(
        action_type="ASSIGN_ROLE",
        entity_type="User_Role",
        get_entity_id=lambda self, user_uuid, *args, **kwargs: (
            self.dao.get_user_by_uuid(user_uuid).user_id
            if self.dao.get_user_by_uuid(user_uuid)
            else None
        ),
        capture_old_data=False,
        capture_new_data=False,
        description="Updated user roles",
    )
    def update_user_roles_uuid(
        self, user_uuid, role_uuids, updated_by_user_id: int, audit_data=None, **kwargs
    ):
        if audit_data is None:
            audit_data = {}

        # Fetch the user
        user = self.dao.get_user_by_uuid(user_uuid)
        if not user:
            raise ValueError("User not found")

        if not user.is_active:
            raise ValueError("Cannot update roles for inactive user")

        # ----- Capture old roles (for audit display) -----
        old_roles = self.get_user_roles(user.user_id)  # Role names/details for audit
        audit_data["old_data"] = {"roles": old_roles}

        # ----- Get current role UUIDs -----
        current_roles_uuids = self.dao.get_user_roles_uuids(user.user_id)
        print("Current roles in DB:", current_roles_uuids)
        current_role_set = set(current_roles_uuids)

        # ----- Handle empty role_uuids (assign General role) -----
        if not role_uuids:
            general_role = (
                self.db.query(models.Role).filter_by(role_name="General").first()
            )
            if not general_role:
                raise RuntimeError("'General' role not found")
            role_uuids = [general_role.role_uuid]

        # ----- Validate and deduplicate incoming role_uuids -----
        # Remove duplicates from input and convert to set
        new_role_set = set(role_uuids)
        print("New roles requested:", new_role_set)
        print("Current roles:", current_role_set)
        # ----- Calculate differences using set operations -----
        roles_to_add = new_role_set - current_role_set  # New roles to assign
        roles_to_remove = current_role_set - new_role_set  # Roles to remove
        print(roles_to_add, roles_to_remove)

        # ----- Remove roles that are no longer needed -----
        if roles_to_remove:
            for role_uuid in roles_to_remove:
                self.dao.remove_role_by_uuid(user.user_id, role_uuid)

        # ----- Add only new roles (preserves existing roles' assigned_by) -----
        if roles_to_add:
            for role_uuid in roles_to_add:
                # Double-check role doesn't exist before inserting (safety check)
                existing = (
                    self.db.query(models.User_Role)
                    .join(models.Role)
                    .filter(
                        models.User_Role.user_id == user.user_id,
                        models.Role.role_uuid == role_uuid,
                    )
                    .first()
                )

                if not existing:
                    self.dao.assign_role_uuid(
                        user.user_id, role_uuid, updated_by_user_id
                    )

        # ----- Capture new roles for audit -----
        # Only query if there were actual changes
        if roles_to_add or roles_to_remove:
            new_roles = self.get_user_roles(user.user_id)
        else:
            new_roles = old_roles  # No changes, reuse old data

        audit_data["new_data"] = {"roles": new_roles}

        # ----- Return meaningful message -----
        if not roles_to_add and not roles_to_remove:
            return "No role changes needed"

        changes = []
        if roles_to_add:
            changes.append(f"{len(roles_to_add)} role(s) added")
        if roles_to_remove:
            changes.append(f"{len(roles_to_remove)} role(s) removed")

        return "Roles updated successfully"

    @audit_action_with_request(
        action_type="ASSIGN_ROLE",
        entity_type="User",
        get_entity_id=lambda self, user_id, *args, **kwargs: user_id,
        capture_old_data=True,
        capture_new_data=True,
        description="Updated user roles",
    )
    def update_user_roles(self, user_id, role_ids, updated_by_user_id: int, **kwargs):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        if not user.is_active:
            raise ValueError("Cannot update roles for inactive user")

        self.dao.clear_roles(user.user_id)

        if not role_ids:
            general_role = (
                self.db.query(models.Role).filter_by(role_name="General").first()
            )
            if not general_role:
                raise RuntimeError("'General' role not found")
            self.dao.assign_role(user.user_id, general_role.role_id, updated_by_user_id)
            return "No roles provided. Assigned 'General' role."

        for role_id in role_ids:
            self.dao.assign_role(user.user_id, int(role_id), updated_by_user_id)

        return "Roles updated successfully"

    def get_user_roles(self, user_id):
        return [r for r in self.dao.get_user_roles(user_id)]

    def get_user_roles_by_uuid(self, user_uuid):
        return [r for r in self.dao.get_user_roles_by_uuid(user_uuid)]

    def update_user_profile(self, user_id, profile_data):
        user = self.dao.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        update_fields = {
            "first_name": profile_data.first_name,
            "last_name": profile_data.last_name,
            "contact": profile_data.contact,
        }

        return self.dao.update_user_profile(user_id, update_fields)

    def search_public_users(self, search_term: str):
        return self.dao.search_public_users(search_term)
