from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from ..models import models
from typing import Optional
from ..models.otp import OTP
from datetime import datetime
from fastapi import HTTPException


class AuthDAO:
    """Data Access Object for Authentication operations"""

    def __init__(self, db: Session):
        self.db = db

    # --------------------------
    # USER OPERATIONS
    # --------------------------

    def get_user_by_email(self, email: str) -> Optional[models.User]:
        return self.db.query(models.User).filter_by(mail=email).first()

    def get_active_user_by_email(self, email: str) -> Optional[models.User]:
        return (
            self.db.query(models.User)
            .filter(models.User.mail == email, models.User.is_active)
            .first()
        )

    def get_user_login_data(self, email: str):
        print("email in get_user_login_data", email)

        # Step 1: Get user
        user = (
            self.db.query(models.User)
            .filter(models.User.mail == email, models.User.is_active)
            .first()
        )

        if not user:
            print("User not found in get_user_login_data")
            return None, None, None

        print("user details", user.user_id)

        # Step 2: Get roles (simple join — always works even if no permissions)
        role_results = (
            self.db.query(models.Role.role_name)
            .join(models.User_Role, models.User_Role.role_id == models.Role.role_id)
            .filter(models.User_Role.user_id == user.user_id)
            .distinct()
            .all()
        )
        roles = [r.role_name for r in role_results]
        print("roles in get_user_login_data", roles)

        # Step 3: Get permissions (separate query — won't affect roles if empty)
        permission_results = (
            self.db.query(models.Permissions.permission_code)
            .join(
                models.Permission_Group_Mapping,
                models.Permissions.permission_id
                == models.Permission_Group_Mapping.permission_id,
            )
            .join(
                models.Role_Permission_Group,
                models.Role_Permission_Group.group_id
                == models.Permission_Group_Mapping.group_id,
            )
            .join(
                models.User_Role,
                models.User_Role.role_id == models.Role_Permission_Group.role_id,
            )
            .filter(models.User_Role.user_id == user.user_id)
            .distinct()
            .all()
        )
        permissions = [p.permission_code for p in permission_results]
        # print("permissions in get_user_login_data", permissions)

        return user, roles, permissions

    def get_user_login_data_by_id(self, user_id: int):
        # Step 1: Get user
        user = (
            self.db.query(models.User)
            .filter(models.User.user_id == user_id, models.User.is_active)
            .first()
        )

        if not user:
            print("User not found in get_user_login_data_by_id")
            return None, None, None

        print("user details", user.user_id)

        # Step 2: Get roles (simple join — always works even if no permissions)
        role_results = (
            self.db.query(models.Role.role_name)
            .join(models.User_Role, models.User_Role.role_id == models.Role.role_id)
            .filter(models.User_Role.user_id == user.user_id)
            .distinct()
            .all()
        )
        roles = [r.role_name for r in role_results]
        print("roles in get_user_login_data_by_id", roles)

        # Step 3: Get permissions (separate query — won't affect roles if empty)
        permission_results = (
            self.db.query(models.Permissions.permission_code)
            .join(
                models.Permission_Group_Mapping,
                models.Permissions.permission_id
                == models.Permission_Group_Mapping.permission_id,
            )
            .join(
                models.Role_Permission_Group,
                models.Role_Permission_Group.group_id
                == models.Permission_Group_Mapping.group_id,
            )
            .join(
                models.User_Role,
                models.User_Role.role_id == models.Role_Permission_Group.role_id,
            )
            .filter(models.User_Role.user_id == user.user_id)
            .distinct()
            .all()
        )
        permissions = [p.permission_code for p in permission_results]
        # print("permissions in get_user_login_data_by_id", permissions)

        return user, roles, permissions

    def update_last_login(self, user_id: int, ip: str):
        user = self.db.query(models.User).filter(models.User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.last_login_at = datetime.utcnow()
        user.last_login_ip = ip
        print(
            f"Updated last login for user_id {user_id} to {user.last_login_at} from IP {ip}"
        )
        self.db.commit()

    def check_user_first_login(self, user_id: int) -> bool:
        user = self.db.query(models.User).filter(models.User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if user.last_login_at is None or user.password_last_updated is None:
            return True
        return False

    def first_time_login_check(self, email: str) -> bool:
        user = self.db.query(models.User).filter(models.User.mail == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if user.password_last_updated is None:
            return True
        return False

    def update_user_password(self, user: models.User, new_hashed_password: str) -> bool:
        try:
            now = datetime.utcnow()
            user.password = new_hashed_password
            user.is_active = True
            user.password_last_updated = now
            user.updated_at = now
            self.db.commit()
            return True
        except SQLAlchemyError:
            self.db.rollback()
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

    def update_user_password_by_mail(
        self, user_mail: str, new_hashed_password: str
    ) -> bool:
        user = self.db.query(models.User).filter(models.User.mail == user_mail).first()
        if user:
            return self.update_user_password(user, new_hashed_password)
        return False

    # --------------------------
    # ROLE OPERATIONS
    # --------------------------

    def get_general_role(self) -> Optional[models.Role]:
        return self.db.query(models.Role).filter_by(role_name="General").first()

    def assign_user_role(self, user_id: int, role_id: int):
        mapping = models.User_Role(user_id=user_id, role_id=role_id)
        self.db.add(mapping)
        self.db.commit()

    def get_user_roles(self, user_id: int) -> list[str]:
        result = (
            self.db.query(models.Role.role_name)
            .join(models.User_Role)
            .filter(models.User_Role.user_id == user_id)
            .all()
        )
        return [r[0] for r in result]

    # --------------------------
    # PERMISSION OPERATIONS
    # --------------------------

    def get_permission_group_ids_for_user(self, user_id: int) -> list[int]:
        result = (
            self.db.query(models.Role_Permission_Group.group_id)
            .join(
                models.User_Role,
                models.User_Role.role_id == models.Role_Permission_Group.role_id,
            )
            .filter(models.User_Role.user_id == user_id)
            .distinct()
            .all()
        )
        return [g[0] for g in result]

    def get_permissions_by_group_ids(self, group_ids: list[int]) -> list[str]:
        if not group_ids:
            return []

        result = (
            self.db.query(models.Permissions.permission_code)
            .join(
                models.Permission_Group_Mapping,
                models.Permissions.permission_id
                == models.Permission_Group_Mapping.permission_id,
            )
            .filter(models.Permission_Group_Mapping.group_id.in_(group_ids))
            .distinct()
            .all()
        )

        return [p[0] for p in result]

    def get_access_point(self, path: str, method: str) -> Optional[models.AccessPoint]:
        return (
            self.db.query(models.AccessPoint)
            .filter_by(endpoint_path=path, method=method)
            .first()
        )

    def get_permission_codes_for_access_point(self, access_id: int) -> list[str]:
        result = (
            self.db.query(models.Permissions.permission_code)
            .join(
                models.AccessPointPermission,
                models.Permissions.permission_code
                == models.AccessPointPermission.permission_code,
            )
            .filter(models.AccessPointPermission.access_id == access_id)
            .all()
        )
        return [p[0] for p in result]

    def get_user_permissions(self, user_id: int) -> list[str]:
        group_ids = self.get_permission_group_ids_for_user(user_id)
        return self.get_permissions_by_group_ids(group_ids)

    def get_valid_otp(self, email: str, otp: str) -> Optional[OTP]:
        return (
            self.db.query(OTP)
            .filter(
                OTP.email == email, OTP.otp == otp, OTP.expires_at > datetime.utcnow()
            )
            .first()
        )

    def delete_otp(self, otp_record: OTP):
        self.db.delete(otp_record)
        self.db.commit()
