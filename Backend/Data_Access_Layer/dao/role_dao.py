from sqlalchemy.orm import Session
from sqlalchemy import exists, select
from ..models import models
from ...Api_Layer.interfaces.role_mangement import RoleBase
from fastapi import HTTPException
from uuid import UUID
from datetime import datetime


def get_all_roles(db: Session):
    stmt = select(
        models.Role.role_id, models.Role.role_uuid, models.Role.role_name
    ).order_by(models.Role.role_id)
    result = db.execute(stmt).all()
    return result


def get_role(db: Session, role_id: int):
    return db.query(models.Role).filter(models.Role.role_id == role_id).first()


def get_role_by_uuid(db: Session, role_uuid: str):
    return db.query(models.Role).filter(models.Role.role_uuid == role_uuid).first()


def get_permission_group_by_uuid(db: Session, group_uuid: str):
    return (
        db.query(models.Permission_Group)
        .filter(models.Permission_Group.group_uuid == group_uuid)
        .first()
    )


def get_role_by_name(db: Session, name: str):
    return db.query(models.Role).filter(models.Role.role_name == name).first()


def create_role(db: Session, role_uuid: UUID, role: RoleBase):
    now = datetime.utcnow()
    new_role = models.Role(
        role_name=role.role_name, role_uuid=role_uuid, created_at=now, updated_at=now
    )
    db.add(new_role)
    db.commit()
    db.refresh(new_role)
    return new_role


def update_role(db: Session, role_id: int, role: RoleBase):
    role_db = get_role(db, role_id)
    if not role_db:
        raise Exception("Role not found")
    role_db.role_name = role.role_name
    db.commit()
    db.refresh(role_db)
    return role_db


def update_role_by_uuid(db: Session, role_uuid: str, role: RoleBase):
    role_db = get_role_by_uuid(db, role_uuid)
    if not role_db:
        raise Exception("Role not found")
    now = datetime.utcnow()
    role_db.role_name = role.role_name
    role_db.updated_at = now
    db.commit()
    db.refresh(role_db)
    return role_db


def get_users_by_role(db: Session, role_id: int) -> list[int]:
    results = db.query(models.User_Role.user_id).filter_by(role_id=role_id).all()
    print("results", results)
    return [r[0] for r in results]


def delete_user_roles_by_role(db: Session, role_id: int):
    role = get_role(db, role_id)
    if not role:
        raise Exception("Role not found")

    # delete all user-role mappings for this role
    db.query(models.User_Role).filter_by(role_id=role_id).delete()
    db.commit()


def delete_role_permission_groups(db: Session, role_id: int):
    role = get_role(db, role_id)
    if not role:
        raise Exception("Role not found")

    # delete all role-permission-group mappings for this role
    db.query(models.Role_Permission_Group).filter_by(role_id=role_id).delete()
    db.commit()


def get_user_roles(db: Session, user_id: int) -> list[int]:
    results = db.query(models.User_Role.role_id).filter_by(user_id=user_id).all()
    print("results", results)
    return [r[0] for r in results]


def assign_role(db: Session, user_id: int, role_id: int):
    db.add(models.User_Role(user_id=user_id, role_id=role_id))
    db.commit()


def delete_role(db: Session, role_id: int):
    role = get_role(db, role_id)
    if not role:
        raise Exception("Role not found")
    db.delete(role)
    db.commit()
    return {"message": "Role deleted successfully"}


def update_role_groups(db: Session, role_id: int, group_ids: list[int]):
    db.query(models.Role_Permission_Group).filter_by(role_id=role_id).delete()
    db.bulk_save_objects(
        [
            models.Role_Permission_Group(role_id=role_id, group_id=gid)
            for gid in group_ids
        ]
    )
    db.commit()
    return {"message": "Permissions updated for role"}


def get_permissions_by_role(db: Session, role_id: int):
    if not db.query(exists().where(models.Role.role_id == role_id)).scalar():
        raise Exception("Role not found")

    group_ids = (
        db.query(models.Role_Permission_Group.group_id).filter_by(role_id=role_id).all()
    )
    group_ids = [g[0] for g in group_ids]

    if not group_ids:
        return []

    permissions = (
        db.query(models.Permissions.permission_code, models.Permissions.description)
        .join(
            models.Permission_Group_Mapping,
            models.Permissions.permission_id
            == models.Permission_Group_Mapping.permission_id,
        )
        .filter(models.Permission_Group_Mapping.group_id.in_(group_ids))
        .distinct()
        .all()
    )

    return [{"code": code, "description": desc} for code, desc in permissions]


def get_permission_groups_by_role(db: Session, role_id: int):
    return (
        db.query(models.Permission_Group)
        .join(
            models.Role_Permission_Group,
            models.Permission_Group.group_id == models.Role_Permission_Group.group_id,
        )
        .filter(models.Role_Permission_Group.role_id == role_id)
        .all()
    )


def add_permission_groups_to_role(
    db: Session, role_uuid: str, group_uuids: list[str], assigned_by: int
):
    role = get_role_by_uuid(db, role_uuid)
    if not role:
        raise HTTPException(
            status_code=400, detail=f"Role ID {role_uuid} does not exist"
        )
    role_id = role.role_id
    group_ids = []
    for group_uuid in group_uuids:
        group = get_permission_group_by_uuid(db, group_uuid)
        if not group:
            raise HTTPException(
                status_code=400,
                detail=f"Permission group UUID {group_uuid} does not exist",
            )
        group_ids.append(group.group_id)
    group_ids = list({int(g) for g in group_ids})

    existing_group_ids = {
        gid for (gid,) in db.query(models.Permission_Group.group_id).all()
    }
    invalid_ids = [gid for gid in group_ids if gid not in existing_group_ids]
    if invalid_ids:
        raise HTTPException(
            status_code=400,
            detail=f"The following group IDs do not exist: {invalid_ids}",
        )

    now = datetime.utcnow()
    new_assignments = [
        models.Role_Permission_Group(
            role_id=role_id, group_id=gid, assigned_by=assigned_by, assigned_at=now
        )
        for gid in group_ids
        if not db.query(
            exists().where(
                models.Role_Permission_Group.role_id == role_id,
                models.Role_Permission_Group.group_id == gid,
            )
        ).scalar()
    ]

    if new_assignments:
        db.bulk_save_objects(new_assignments)
        db.commit()

    return {"message": "Permission groups added successfully"}


def remove_permission_group_from_role(db: Session, role_uuid: str, group_uuid: str):

    if not db.query(
        exists().where(models.Permission_Group.group_uuid == group_uuid)
    ).scalar():
        raise HTTPException(
            status_code=400, detail=f"Permission group ID {group_uuid} does not exist"
        )

    role = get_role_by_uuid(db, role_uuid)
    if not role:
        raise HTTPException(
            status_code=400, detail=f"Role ID {role_uuid} does not exist"
        )
    role_id = role.role_id
    group = get_permission_group_by_uuid(db, group_uuid)
    if not group:
        raise HTTPException(
            status_code=400, detail=f"Permission group ID {group_uuid} does not exist"
        )
    group_id = group.group_id
    assignment = (
        db.query(models.Role_Permission_Group)
        .filter_by(role_id=role_id, group_id=group_id)
        .first()
    )
    if not assignment:
        raise HTTPException(
            status_code=400,
            detail=f"Permission group ID {group_uuid} is not assigned to role ID {role_uuid}",
        )

    db.delete(assignment)
    db.commit()
    return {
        "message": f"Permission group ID {group_uuid} removed from role ID {role_uuid}"
    }


def remove_permission_groups_from_role(
    db: Session, role_uuid: str, group_uuids: list[str]
):
    role = get_role_by_uuid(db, role_uuid)
    if not role:
        raise HTTPException(
            status_code=400, detail=f"Role ID {role_uuid} does not exist"
        )

    role_id = role.role_id
    group_ids = []

    # Validate all group UUIDs first
    for group_uuid in group_uuids:
        group = get_permission_group_by_uuid(db, group_uuid)
        if not group:
            raise HTTPException(
                status_code=400,
                detail=f"Permission group UUID {group_uuid} does not exist",
            )
        group_ids.append(group.group_id)

    group_ids = list({int(g) for g in group_ids})
    print("group_ids to remove", group_ids)

    try:
        # Start transaction
        for gid in group_ids:
            assignment = (
                db.query(models.Role_Permission_Group)
                .filter_by(role_id=role_id, group_id=gid)
                .first()
            )
            if not assignment:
                raise HTTPException(
                    status_code=400,
                    detail=f"Permission group ID {gid} is not assigned to role ID {role_uuid}",
                )

            db.delete(assignment)

        # ✅ Commit only once if all deletions succeed
        db.commit()
        return {"message": "Permission groups removed successfully"}

    except Exception as e:
        # ⚠️ Rollback everything if any error occurs
        db.rollback()
        raise HTTPException(
            status_code=500, detail=f"Failed to remove permission groups: {str(e)}"
        )


def update_permission_groups_for_role(
    db: Session, role_id: int, group_uuids: list[int]
):
    role = get_role(db, role_id)
    if not role:
        raise Exception("Role not found")

    group_ids = []
    for group_uuid in group_uuids:
        group = get_permission_group_by_uuid(db, group_uuid)
        if not group:
            raise HTTPException(
                status_code=400,
                detail=f"Permission group UUID {group_uuid} does not exist",
            )
        group_ids.append(group.group_id)
    group_ids = list({int(g) for g in group_ids})
    existing_group_ids = {group.group_id for group in role.permission_groups}
    new_group_ids = set(group_ids) - existing_group_ids

    if new_group_ids:
        new_groups = (
            db.query(models.Permission_Group)
            .filter(models.Permission_Group.group_id.in_(new_group_ids))
            .all()
        )
        role.permission_groups.extend(new_groups)
        db.commit()

    return {"message": "Permission groups updated successfully."}


def get_unassigned_permission_groups(db: Session, role_id: int):
    assigned_group_ids = (
        db.query(models.Role_Permission_Group.group_id)
        .filter_by(role_id=role_id)
        .subquery()
    )
    return (
        db.query(models.Permission_Group)
        .filter(~models.Permission_Group.group_id.in_(assigned_group_ids))
        .all()
    )
def get_users_by_role_uuid_or_name(
    db: Session,
    role_uuid: str = None,
    role_name: str = None
) -> list[dict]:

    if not role_uuid and not role_name:
        raise HTTPException(
            status_code=400,
            detail="Either role_uuid or role_name must be provided"
        )

    query = db.query(
        models.User_Role.user_id,
        models.User.employee_id,
        models.Role.role_name
    ).join(
        models.Role, models.User_Role.role_id == models.Role.role_id
    ).join(
        models.User, models.User_Role.user_id == models.User.user_id
    )

    # ✅ Allow both filters together
    if role_uuid:
        query = query.filter(models.Role.role_uuid == role_uuid)

    if role_name:
        query = query.filter(models.Role.role_name == role_name)

    results = query.all()

    return [
        {
            "user_id": r.user_id,
            "employee_id": r.employee_id,
            "role_name": r.role_name
        }
        for r in results
    ]
