"""
Data Access Layer for User Management
File: Data_Access_Layer/dao/user_dao.py
"""

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import or_, not_
from ..models import models
from typing import Optional, List, Tuple, Dict
from fastapi import HTTPException
from datetime import datetime
import uuid
from sqlalchemy import func

import logging

logger = logging.getLogger(__name__)


class UserDAO:
    """Data Access Object for User Profile operations"""

    def __init__(self, db: Session):
        self.db = db

    # --------------------------
    # USER READ OPERATIONS
    # --------------------------

    def get_user_by_email(self, email: str) -> Optional[models.User]:
        return self.db.query(models.User).filter_by(mail=email).first()
    
    def get_user_by_employee_id(self, employee_id: int) -> Optional[models.User]:
        return self.db.query(models.User).filter_by(employee_id=employee_id).first()

    def get_user_by_id(self, user_id: int) -> Optional[models.User]:
        return self.db.query(models.User).filter_by(user_id=user_id).first()

    def get_user_by_uuid(self, user_uuid: str) -> Optional[models.User]:
        return self.db.query(models.User).filter_by(user_uuid=user_uuid).first()

    def count_users(self) -> int:
        return self.db.query(models.User).count()

    def count_active_users(self) -> int:
        return self.db.query(models.User).filter(models.User.is_active).count()

    def get_all_users(self) -> List[models.User]:
        return self.db.query(models.User).all()

    def get_paginated_users(self, page: int, limit: int, search: Optional[str] = None):

        # base_query = (
        #     self.db.query(
        #         models.User.user_id,
        #         models.User.user_uuid,
        #         models.User.first_name,
        #         models.User.last_name,
        #         models.User.mail,
        #         models.User.contact,
        #         models.User.is_active,
        #         models.User.gender
        #     )
        # )
        base_query = self.db.query(models.User)
        # Apply search filter
        if search:
            search = search.strip().lower()
            search_pattern = f"%{search}%"
            base_query = base_query.filter(
                or_(
                    func.lower(models.User.first_name).like(search_pattern),
                    func.lower(models.User.last_name).like(search_pattern),
                    func.lower(models.User.mail).like(search_pattern),
                    models.User.contact.like(search_pattern),
                )
            )

        total = base_query.count()

        # Data fetch query
        users = (
            base_query.order_by(models.User.first_name)
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )

        # Build response
        result = {"total": total, "users": users}
        return result

    def get_all_active_users(self) -> List[models.User]:
        return self.db.query(models.User).filter(models.User.is_active).all()

    def get_users_by_emails(self, emails: List[str]) -> List[str]:
        """
        Check which emails already exist in database.
        Returns list of existing email addresses.

        Args:
            emails: List of email addresses to check

        Returns:
            List of emails that already exist in database
        """
        if not emails:
            return []

        existing = (
            self.db.query(models.User.mail).filter(models.User.mail.in_(emails)).all()
        )
        return [email[0] for email in existing]

    def check_emails_exist(self, emails: List[str]) -> dict:
        """
        Check multiple emails at once.

        Args:
            emails: List of email addresses to check

        Returns:
            Dict with emails as keys and boolean as values
        """
        existing_emails = self.get_users_by_emails(emails)
        return {email: email in existing_emails for email in emails}

    def get_users_with_roles_id(self) -> List[Dict]:
        """
        Returns users with a list of roles per user.
        Example:
        [
            {"user_id": 1, "name": "John Doe", "roles": ["Admin", "HR"], "mail": "john@..."},
            ...
        ]
        """
        results = (
            self.db.query(
                models.User.user_id,
                models.User.first_name,
                models.User.last_name,
                models.User.mail,
                models.Role.role_name,
            )
            .join(models.User_Role, models.User.user_id == models.User_Role.user_id)
            .join(models.Role, models.User_Role.role_id == models.Role.role_id)
            .order_by(models.User.user_id)
            .all()
        )

        user_map = {}
        for row in results:
            uid = row.user_id
            if uid not in user_map:
                user_map[uid] = {
                    "user_id": row.user_id,
                    "name": f"{row.first_name} {row.last_name}".strip(),
                    "mail": row.mail,
                    "roles": [row.role_name],
                }
            else:
                user_map[uid]["roles"].append(row.role_name)

        return list(user_map.values())

    def get_users_with_roles(
        self, page: int, limit: int, search: Optional[str] = None
    ) -> Dict:
        # ✅ Build aggregated user-roles subquery once
        user_roles_sq = (
            self.db.query(
                models.User.user_id,
                models.User.user_uuid,
                models.User.first_name,
                models.User.last_name,
                models.User.mail,
                func.group_concat(models.Role.role_name).label("roles"),
            )
            .join(models.User_Role, models.User.user_id == models.User_Role.user_id)
            .join(models.Role, models.Role.role_id == models.User_Role.role_id)
            .group_by(
                models.User.user_id,
                models.User.user_uuid,
                models.User.first_name,
                models.User.last_name,
                models.User.mail,
            )
            .subquery()
        )

        # ✅ Query from subquery (reusable for both count and data fetch)
        main_query = self.db.query(user_roles_sq)

        # ✅ Apply search filter once
        if search:
            search_pattern = f"%{search.strip().lower()}%"
            main_query = main_query.filter(
                or_(
                    func.lower(user_roles_sq.c.first_name).like(search_pattern),
                    func.lower(user_roles_sq.c.last_name).like(search_pattern),
                    func.lower(user_roles_sq.c.mail).like(search_pattern),
                    func.lower(user_roles_sq.c.roles).like(search_pattern),
                )
            )

        # ✅ Efficient count (no nested subquery needed)
        total = main_query.count()

        # ✅ Paginate from the same filtered query
        users = (
            main_query.order_by(user_roles_sq.c.first_name)
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )

        # ✅ Transform result
        result_users = [
            {
                "user_uuid": u.user_uuid,
                "name": f"{u.first_name} {u.last_name}".strip(),
                "mail": u.mail,
                "roles": u.roles.split(",") if u.roles else [],
            }
            for u in users
        ]

        return {"total": total, "users": result_users}

    # --------------------------
    # USER SEARCH OPERATIONS
    # --------------------------

    def search_public_users(self, query: str, excluded_user_ids_subq):
        return (
            self.db.query(models.User)
            .filter(
                not_(models.User.user_id.in_(excluded_user_ids_subq)),
                or_(
                    models.User.first_name.ilike(f"%{query}%"),
                    models.User.last_name.ilike(f"%{query}%"),
                    models.User.mail.ilike(f"%{query}%"),
                    models.User.contact.ilike(f"%{query}%"),
                ),
            )
            .all()
        )

    def search_all_users(self, query: str) -> List[models.User]:
        return (
            self.db.query(models.User)
            .filter(
                or_(
                    models.User.first_name.ilike(f"%{query}%"),
                    models.User.last_name.ilike(f"%{query}%"),
                    models.User.mail.ilike(f"%{query}%"),
                    models.User.contact.ilike(f"%{query}%"),
                )
            )
            .all()
        )

    def search_non_admin_users(
        self, query: str, admin_ids: List[int]
    ) -> List[models.User]:
        return (
            self.db.query(models.User)
            .filter(
                not_(models.User.user_id.in_(admin_ids)),
                or_(
                    models.User.first_name.ilike(f"%{query}%"),
                    models.User.last_name.ilike(f"%{query}%"),
                    models.User.mail.ilike(f"%{query}%"),
                    models.User.contact.ilike(f"%{query}%"),
                ),
            )
            .all()
        )

    def search_all_suggestions(self, query: str) -> List[models.User]:
        return (
            self.db.query(models.User)
            .filter(
                or_(
                    models.User.first_name.ilike(f"%{query}%"),
                    models.User.last_name.ilike(f"%{query}%"),
                    models.User.mail.ilike(f"%{query}%"),
                )
            )
            .limit(10)
            .all()
        )

    def search_suggestions_exclude_admins(
        self, query: str, admin_ids: List[int]
    ) -> List[models.User]:
        return (
            self.db.query(models.User)
            .filter(
                not_(models.User.user_id.in_(admin_ids)),
                or_(
                    models.User.first_name.ilike(f"%{query}%"),
                    models.User.last_name.ilike(f"%{query}%"),
                    models.User.mail.ilike(f"%{query}%"),
                ),
            )
            .limit(10)
            .all()
        )

    # --------------------------
    # USER CREATE OPERATIONS
    # --------------------------

    def create_user(self, user: models.User) -> models.User:
        """Create a single user"""
        try:
            # Set timestamps manually in UTC
            now = datetime.utcnow()
            if not hasattr(user, "created_at") or user.created_at is None:
                user.created_at = now
            user.updated_at = now

            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            return user
        except SQLAlchemyError:
            self.db.rollback()
            raise

    def create_users_batch(self, user_objects: List[models.User]) -> List[models.User]:
        """
        Batch insert multiple users in a single database transaction.
        Returns the created users with their IDs and timestamps populated.

        Args:
            user_objects: List of User model objects to insert

        Returns:
            List of created users with IDs and timestamps populated

        Raises:
            Exception: If any validation or database error occurs (all rolled back)
        """
        if not user_objects:
            return []

        try:
            now = datetime.utcnow()
            for user in user_objects:
                if not hasattr(user, "created_at") or user.created_at is None:
                    user.created_at = now
                user.updated_at = now

            self.db.add_all(user_objects)
            self.db.commit()

            # Refresh to get auto-generated IDs and timestamps
            for user in user_objects:
                self.db.refresh(user)

            return user_objects
        except SQLAlchemyError:
            self.db.rollback()
            raise

    # --------------------------
    # USER UPDATE OPERATIONS
    # --------------------------

    def update_user(self, user: models.User, data: dict) -> bool:
        try:
            for field, value in data.items():
                setattr(user, field, value)

            now = datetime.utcnow()
            user.updated_at = now
            self.db.commit()
            self.db.refresh(user)
            return True
        except SQLAlchemyError:
            self.db.rollback()
            return False

    def update_user_profile(self, user, update_data: dict) -> bool:
        try:
            now = datetime.utcnow()
            user.updated_at = now
            for key, value in update_data.items():
                if hasattr(user, key):
                    setattr(user, key, value)
            self.db.commit()
            self.db.refresh(user)
            return True
        except Exception as e:
            self.db.rollback()
            print("Error updating user profile:", e)
            return False

    def password_last_updated(self, user_id: int) -> None:
        user = self.db.query(models.User).filter(models.User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        now = datetime.utcnow()
        user.password_last_updated = now
        user.updated_at = now
        self.db.commit()
        self.db.refresh(user)

    def deactivate_user(self, user: models.User) -> None:
        try:
            now = datetime.utcnow()
            user.updated_at = now
            user.is_active = False
            self.db.commit()
        except SQLAlchemyError:
            self.db.rollback()
            raise

    def activate_user(self, user: models.User) -> None:
        try:
            now = datetime.utcnow()
            user.updated_at = now
            user.is_active = True
            self.db.commit()
        except SQLAlchemyError:
            self.db.rollback()
            raise

    # --------------------------
    # USER DELETE OPERATIONS
    # --------------------------

    def delete_user(self, user: models.User):
        try:
            self.db.delete(user)
            self.db.commit()
        except SQLAlchemyError:
            self.db.rollback()
            raise

    # --------------------------
    # ROLE OPERATIONS
    # --------------------------

    def get_role_by_name(self, role_name: str) -> Optional[models.Role]:
        """Get role by role name"""
        return (
            self.db.query(models.Role)
            .filter(models.Role.role_name == role_name)
            .first()
        )

    def get_role_by_id(self, role_id: int) -> Optional[models.Role]:
        """Get role by role_id"""
        return self.db.query(models.Role).filter(models.Role.role_id == role_id).first()

    def get_admin_user_ids(self) -> List[int]:
        admin_ids = (
            self.db.query(models.User_Role.user_id)
            .join(models.Role)
            .filter(models.Role.role_name.in_(["Admin", "Super Admin"]))
            .distinct()
            .all()
        )
        return [uid[0] for uid in admin_ids]

    def get_non_admin_user_ids(self):
        return (
            self.db.query(models.User_Role.user_id)
            .join(models.Role)
            .filter(models.Role.role_name.in_(["Admin", "Super Admin"]))
            .subquery()
        )

    def get_user_roles(self, user_id: int) -> List[str]:
        roles = (
            self.db.query(models.Role.role_name)
            .join(models.User_Role)
            .filter(models.User_Role.user_id == user_id)
            .all()
        )
        return [role[0] for role in roles]

    def get_user_roles_uuids(self, user_id: int) -> List[str]:
        roles = (
            self.db.query(models.Role.role_uuid)
            .join(models.User_Role)
            .filter(models.User_Role.user_id == user_id)
            .all()
        )
        return [role[0] for role in roles]

    def get_user_roles_by_uuid(self, user_uuid: str) -> List[str]:
        user = self.get_user_by_uuid(user_uuid)
        return self.get_user_roles(user.user_id) if user else []

    def get_user_permissions(self, user_id: int) -> List[str]:
        permissions = (
            self.db.query(models.Permission.permission_name)
            .join(
                models.Role_Permission,
                models.Permission.permission_id == models.Role_Permission.permission_id,
            )
            .join(models.Role, models.Role_Permission.role_id == models.Role.role_id)
            .join(models.User_Role, models.User_Role.role_id == models.Role.role_id)
            .filter(models.User_Role.user_id == user_id)
            .distinct()
            .all()
        )
        return [p[0] for p in permissions]

    # --------------------------
    # USER-ROLE MAPPING OPERATIONS
    # --------------------------

    def map_user_role(
        self, user_id: int, role_id: int, created_by_user_id: int
    ) -> None:
        """Map a single user to a role"""
        try:
            self.db.execute(
                models.User_Role.__table__.insert().values(
                    user_id=user_id,
                    role_id=role_id,
                    assigned_by=created_by_user_id,
                    # assigned_at will auto default to CURRENT_TIMESTAMP
                )
            )
            self.db.commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            raise e

    def map_user_roles_batch(self, mappings: List[Tuple[int, int, int]]) -> None:
        """
        Batch insert user-role mappings in a single database transaction.

        Args:
            mappings: List of tuples (user_id, role_id, assigned_by_user_id)

        Raises:
            Exception: If any validation or database error occurs (all rolled back)
        """
        if not mappings:
            return

        try:
            # Build list of dictionaries for bulk insert
            mapping_data = [
                {
                    "user_id": user_id,
                    "role_id": role_id,
                    "assigned_by": assigned_by_user_id,
                    # assigned_at will auto default to CURRENT_TIMESTAMP
                }
                for user_id, role_id, assigned_by_user_id in mappings
            ]

            self.db.execute(models.User_Role.__table__.insert(), mapping_data)
            self.db.commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            raise e

    def assign_role(self, user_id: int, role_id: int, updated_by_user_id) -> None:
        try:
            now = datetime.utcnow()
            new_assignment = models.User_Role(
                user_id=user_id,
                role_id=role_id,
                assigned_by=updated_by_user_id,
                assigned_at=now,
            )
            self.db.add(new_assignment)
            self.db.commit()
        except SQLAlchemyError:
            self.db.rollback()
            raise

    def assign_role_uuid(self, user_id: int, role_uuid: str, assigned_by: int):
        """
        Assign a role to user (with duplicate prevention).
        """
        try:
            # Get role by UUID
            role = self.db.query(models.Role).filter_by(role_uuid=role_uuid).first()
            if not role:
                raise ValueError(f"Role with UUID {role_uuid} not found")

            # Check if already assigned (prevent duplicates)
            existing = (
                self.db.query(models.User_Role)
                .filter_by(user_id=user_id, role_id=role.role_id)
                .first()
            )

            if existing:
                # Already assigned, skip silently
                return

            # Create new assignment
            user_role = models.User_Role(
                user_id=user_id,
                role_id=role.role_id,
                assigned_by=assigned_by,
                assigned_at=datetime.utcnow(),
            )

            self.db.add(user_role)
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            raise e

    def clear_roles(self, user_id: int) -> None:
        try:
            self.db.query(models.User_Role).filter_by(user_id=user_id).delete()
            self.db.commit()
        except SQLAlchemyError:
            self.db.rollback()
            raise

    def remove_role_by_uuid(self, user_id: int, role_uuid: str):
        """
        Remove a specific role from a user by role UUID.
        """
        try:
            # Get role_id from role_uuid
            role = self.db.query(models.Role).filter_by(role_uuid=role_uuid).first()
            if not role:
                return  # Role doesn't exist, nothing to remove

            # Delete the user_role entry
            user_role = (
                self.db.query(models.User_Role)
                .filter_by(user_id=user_id, role_id=role.role_id)
                .first()
            )

            if user_role:
                self.db.delete(user_role)
                self.db.commit()
        except Exception as e:
            self.db.rollback()
            raise e

    # --------------------------
    # AUDIT TRAIL OPERATIONS
    # --------------------------

    def create_audit_log(self, audit_log: models.AuditTrail) -> models.AuditTrail:
        """Create a single audit log entry"""
        try:
            # Ensure UUID is set
            if not audit_log.audit_uuid:
                audit_log.audit_uuid = str(uuid.uuid4())

            self.db.add(audit_log)
            self.db.commit()
            self.db.refresh(audit_log)
            return audit_log
        except Exception as e:
            self.db.rollback()
            raise e

    def create_audit_logs_batch(
        self, audit_logs: List[models.AuditTrail]
    ) -> List[models.AuditTrail]:
        """
        Batch insert audit log entries in a single database transaction.
        Each audit log gets a unique UUID automatically if not provided.

        Args:
            audit_logs: List of AuditTrail objects

        Returns:
            List of created audit logs with audit_id and timestamps populated

        Raises:
            Exception: If any validation or database error occurs (all rolled back)
        """
        if not audit_logs:
            return []

        try:
            # Ensure each audit log has a UUID
            for audit in audit_logs:
                if not audit.audit_uuid:
                    audit.audit_uuid = str(uuid.uuid4())

            self.db.add_all(audit_logs)
            self.db.commit()

            # Refresh to get auto-generated IDs and timestamps
            for audit in audit_logs:
                self.db.refresh(audit)

            return audit_logs
        except Exception as e:
            self.db.rollback()
            raise e

    def get_audit_logs(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None,
        action_type: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[models.AuditTrail]:
        """
        Retrieve audit logs with optional filters

        Args:
            entity_type: Filter by entity type (e.g., "User")
            entity_id: Filter by entity ID
            action_type: Filter by action type (CREATE, UPDATE, DELETE, etc.)
            skip: Pagination offset
            limit: Pagination limit

        Returns:
            List of matching audit logs
        """
        query = self.db.query(models.AuditTrail)

        if entity_type:
            query = query.filter(models.AuditTrail.entity_type == entity_type)

        if entity_id:
            query = query.filter(models.AuditTrail.entity_id == entity_id)

        if action_type:
            query = query.filter(models.AuditTrail.action_type == action_type)

        return (
            query.order_by(models.AuditTrail.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_user_audit_logs(
        self, user_id: int, skip: int = 0, limit: int = 100
    ) -> List[models.AuditTrail]:
        """Get all audit logs for actions performed by a specific user"""
        return (
            self.db.query(models.AuditTrail)
            .filter(models.AuditTrail.user_id == user_id)
            .order_by(models.AuditTrail.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_entity_audit_logs(
        self, entity_type: str, entity_id: int, skip: int = 0, limit: int = 100
    ) -> List[models.AuditTrail]:
        """Get complete audit history for a specific entity"""
        return (
            self.db.query(models.AuditTrail)
            .filter(
                models.AuditTrail.entity_type == entity_type,
                models.AuditTrail.entity_id == entity_id,
            )
            .order_by(models.AuditTrail.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )
