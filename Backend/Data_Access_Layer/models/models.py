from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    Enum,
    Text,
    DateTime,
    func,
    JSON,
)
from sqlalchemy.orm import relationship
from ..utils.database import Base


# ----------------------- User Table -----------------------
class User(Base):
    __tablename__ = "user"

    user_id = Column(Integer, primary_key=True, index=True)
    user_uuid = Column(String(36), unique=True, nullable=False)
    employee_id = Column(String(20), unique=True)
    first_name = Column(String(100))
    last_name = Column(String(100))
    mail = Column(String(150), unique=True)
    contact = Column(String(15))
    password = Column(String(255))
    gender = Column(String(10), default="MALE", nullable=False)
    is_active = Column(Boolean, default=True)
    password_last_updated = Column(DateTime, default=None)
    last_login_at = Column(DateTime, default=None)
    last_login_ip = Column(String(45), default=None)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    assigned_roles = relationship(
        "User_Role",  # ✅ Fixed: Capital U and R
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="[User_Role.user_id]",
    )

    roles = relationship(
        "Role",  # ✅ Fixed: Capital R
        secondary="user_role",
        primaryjoin="User.user_id == User_Role.user_id",
        secondaryjoin="Role.role_id == User_Role.role_id",
        back_populates="users",
        viewonly=True,
    )

    assigned_permissions = relationship(
        "AccessPointPermission",
        back_populates="assigned_by_user",
        foreign_keys="[AccessPointPermission.assigned_by]",
    )
    created_permission_groups = relationship(
        "Permission_Group", back_populates="created_by_user"
    )
    created_access_points = relationship(
        "AccessPoint", back_populates="created_by_user"
    )
    audit_trails = relationship(
        "AuditTrail", back_populates="user", foreign_keys="[AuditTrail.user_id]"
    )


# ----------------------- Role Table -----------------------
class Role(Base):
    __tablename__ = "role"

    role_id = Column(Integer, primary_key=True, index=True)
    role_uuid = Column(String(36), unique=True, nullable=False)
    role_name = Column(String(100), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    user_roles = relationship(
        "User_Role", back_populates="role"  # ✅ Fixed: Capital U and R
    )

    users = relationship(
        "User",  # ✅ Fixed: Capital U
        secondary="user_role",
        primaryjoin="Role.role_id == User_Role.role_id",
        secondaryjoin="User.user_id == User_Role.user_id",
        back_populates="roles",
        viewonly=True,
    )

    permission_groups = relationship(
        "Permission_Group",  # ✅ Fixed: Capital P and G
        secondary="role_permission_group",
        back_populates="roles",
    )


# ----------------------- User_Role Mapping -----------------------
class User_Role(Base):
    __tablename__ = "user_role"

    user_id = Column(
        Integer, ForeignKey("user.user_id", ondelete="RESTRICT"), primary_key=True
    )
    role_id = Column(
        Integer, ForeignKey("role.role_id", ondelete="RESTRICT"), primary_key=True
    )
    assigned_by = Column(
        Integer, ForeignKey("user.user_id", ondelete="SET NULL"), nullable=True
    )
    assigned_at = Column(DateTime, server_default=func.now())

    user = relationship(
        "User",  # ✅ Fixed: Capital U
        back_populates="assigned_roles",
        foreign_keys=[user_id],
    )
    role = relationship("Role", back_populates="user_roles")  # ✅ Fixed: Capital R


# ----------------------- Permissions Table -----------------------
class Permissions(Base):
    __tablename__ = "permissions"

    permission_id = Column(Integer, primary_key=True, index=True)
    permission_uuid = Column(String(36), unique=True, nullable=False)
    permission_code = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    access_mappings = relationship(
        "AccessPointPermission",
        back_populates="permission",
        cascade="all, delete-orphan",
    )  # ✅ Fixed
    permission_groups = relationship(
        "Permission_Group",
        secondary="permission_group_mapping",
        back_populates="permissions",
    )  # ✅ Fixed


# ----------------------- Permission_Group Table -----------------------
class Permission_Group(Base):
    __tablename__ = "permission_group"

    group_id = Column(Integer, primary_key=True, index=True)
    group_uuid = Column(String(36), unique=True, nullable=False)
    group_name = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    created_by = Column(
        Integer, ForeignKey("user.user_id", ondelete="SET NULL"), nullable=True
    )

    created_by_user = relationship(
        "User", back_populates="created_permission_groups"
    )  # ✅ Fixed
    permissions = relationship(
        "Permissions",
        secondary="permission_group_mapping",
        back_populates="permission_groups",
    )  # ✅ Fixed
    roles = relationship(
        "Role", secondary="role_permission_group", back_populates="permission_groups"
    )  # ✅ Fixed


# ----------------------- Permission_Group_Mapping -----------------------
class Permission_Group_Mapping(Base):
    __tablename__ = "permission_group_mapping"

    permission_id = Column(
        Integer,
        ForeignKey("permissions.permission_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    group_id = Column(
        Integer,
        ForeignKey("permission_group.group_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    assigned_by = Column(
        Integer, ForeignKey("user.user_id", ondelete="SET NULL"), nullable=True
    )
    assigned_at = Column(DateTime, server_default=func.now())


class AccessPoint(Base):
    __tablename__ = "access_point"

    access_id = Column(Integer, primary_key=True, index=True)
    access_uuid = Column(String(36), unique=True, nullable=False)
    endpoint_path = Column(String(255), nullable=False)
    regex_pattern = Column(String(255), nullable=True)

    # ✅ Updated to include all common HTTP methods
    method = Column(
        Enum(
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "HEAD",
            "OPTIONS",
            "TRACE",
            "CONNECT",
            name="http_method_enum",
        ),
        nullable=False,
    )

    module = Column(String(100), nullable=False)
    is_public = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    created_by = Column(
        Integer, ForeignKey("user.user_id", ondelete="SET NULL"), nullable=True
    )

    # ✅ Relationships
    created_by_user = relationship("User", back_populates="created_access_points")
    permission_mappings = relationship(
        "AccessPointPermission",
        back_populates="access_point",
        cascade="all, delete-orphan",
    )


# ----------------------- AccessPointPermission Mapping -----------------------
class AccessPointPermission(Base):
    __tablename__ = "access_point_permission_mapping"

    id = Column(Integer, primary_key=True, index=True)
    access_id = Column(
        Integer, ForeignKey("access_point.access_id", ondelete="RESTRICT")
    )
    permission_id = Column(
        Integer, ForeignKey("permissions.permission_id", ondelete="RESTRICT")
    )
    assigned_by = Column(
        Integer, ForeignKey("user.user_id", ondelete="SET NULL"), nullable=True
    )
    assigned_at = Column(DateTime, server_default=func.now())

    access_point = relationship(
        "AccessPoint", back_populates="permission_mappings"
    )  # ✅ Fixed
    permission = relationship(
        "Permissions", back_populates="access_mappings"
    )  # ✅ Fixed
    assigned_by_user = relationship(
        "User", back_populates="assigned_permissions"
    )  # ✅ Fixed


# ----------------------- Role-Permission Group Mapping -----------------------
class Role_Permission_Group(Base):
    __tablename__ = "role_permission_group"

    role_id = Column(
        Integer, ForeignKey("role.role_id", ondelete="RESTRICT"), primary_key=True
    )
    group_id = Column(
        Integer,
        ForeignKey("permission_group.group_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    assigned_by = Column(
        Integer, ForeignKey("user.user_id", ondelete="SET NULL"), nullable=True
    )
    assigned_at = Column(DateTime, server_default=func.now())


# ----------------------- AuditTrail Table -----------------------
class AuditTrail(Base):
    __tablename__ = "audit_trail"

    audit_id = Column(Integer, primary_key=True, index=True)
    audit_uuid = Column(String(36), unique=True, nullable=False)
    user_id = Column(
        Integer, ForeignKey("user.user_id", ondelete="SET NULL"), nullable=True
    )
    action_type = Column(
        Enum(
            "CREATE",
            "UPDATE",
            "DELETE",
            "LOGIN",
            "LOGOUT",
            "ASSIGN_ROLE",
            "ASSIGN_PERMISSION",
            "OTHER",
            name="action_type_enum",
        ),
        nullable=False,
    )
    entity_type = Column(String(100), nullable=False)
    entity_id = Column(Integer, nullable=True)
    old_data = Column(JSON, nullable=True)
    new_data = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="audit_trails")  # ✅ Fixed
