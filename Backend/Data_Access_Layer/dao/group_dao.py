from sqlalchemy.orm import Session
from ..models.models import Permission_Group, Permission_Group_Mapping, Permissions
from typing import List
from datetime import datetime


class PermissionGroupDAO:
    def __init__(self, db: Session):
        self.db = db

    def get_all_groups(self):
        return self.db.query(Permission_Group).all()

    def get_group_by_id(self, group_id: int):
        return self.db.query(Permission_Group).filter_by(group_id=group_id).first()

    def get_group_by_uuid(self, group_uuid: str):
        return self.db.query(Permission_Group).filter_by(group_uuid=group_uuid).first()

    def get_group_by_name(self, name: str):
        return self.db.query(Permission_Group).filter_by(group_name=name).first()

    def search_groups(self, keyword: str):
        return (
            self.db.query(Permission_Group)
            .filter(Permission_Group.group_name.ilike(f"%{keyword}%"))
            .all()
        )

    def create_group(self, group_name: str, group_uuid: str, created_by: int):
        now = datetime.utcnow()
        new_group = Permission_Group(
            group_name=group_name,
            group_uuid=group_uuid,
            created_at=now,
            updated_at=now,
            created_by=created_by,
        )
        self.db.add(new_group)
        self.db.commit()
        self.db.refresh(new_group)
        return new_group

    def update_group(self, group_uuid: str, group_name: str):
        now = datetime.utcnow()
        group = self.get_group_by_uuid(group_uuid)
        if group:
            group.group_name = group_name
            group.updated_at = now
            self.db.commit()
            self.db.refresh(group)
        return group

    def delete_group(self, group_id: int):
        group = self.get_group_by_id(group_id)
        if group:
            self.db.delete(group)
            self.db.commit()
        return group

    def delete_group_cascade(self, group_uuid: str):
        group = self.get_group_by_uuid(group_uuid)
        if not group:
            return False
        group_id = group.group_id
        self.db.query(Permission_Group_Mapping).filter_by(group_id=group_id).delete()
        group = self.get_group_by_id(group_id)
        if group:
            self.db.delete(group)
            self.db.commit()
        return True

    def get_unmapped_groups(self):
        mapped_ids = self.db.query(Permission_Group_Mapping.group_id).distinct()
        return (
            self.db.query(Permission_Group)
            .filter(~Permission_Group.group_id.in_(mapped_ids))
            .all()
        )

    def list_permissions_in_group(self, group_uuid: str):
        group = self.get_group_by_uuid(group_uuid)
        if not group:
            return []
        group_id = group.group_id
        rows = (
            self.db.query(
                Permissions.permission_uuid,
                Permissions.permission_code,
                Permissions.description,
            )
            .join(
                Permission_Group_Mapping,
                Permissions.permission_id == Permission_Group_Mapping.permission_id,
            )
            .filter(Permission_Group_Mapping.group_id == group_id)
            .all()
        )

        return [
            {"permission_uuid": row[0], "code": row[1], "description": row[2]}
            for row in rows
        ]

    def get_permission_by_code(self, code: str):
        return self.db.query(Permissions).filter_by(permission_code=code).first()

    # dao/permission_group_dao.py

    def get_permission_by_uuid(self, permission_uuid: str):
        return (
            self.db.query(Permissions)
            .filter_by(permission_uuid=permission_uuid)
            .first()
        )

    def add_permissions_to_group(
        self, group_id: int, permission_ids: list[int], assigned_by: int
    ):
        existing = (
            self.db.query(Permission_Group_Mapping.permission_id)
            .filter(
                Permission_Group_Mapping.group_id == group_id,
                Permission_Group_Mapping.permission_id.in_(permission_ids),
            )
            .all()
        )
        existing_ids = {e[0] for e in existing}

        new_mappings = [
            Permission_Group_Mapping(
                group_id=group_id,
                permission_id=pid,
                assigned_by=assigned_by,
                assigned_at=datetime.utcnow(),
            )
            for pid in permission_ids
            if pid not in existing_ids
        ]

        if not new_mappings:
            raise ValueError(
                "All selected permissions are already mapped to the group."
            )

        self.db.bulk_save_objects(new_mappings)
        self.db.commit()
        return new_mappings

    def get_permissions_by_ids(self, permission_ids: list[int]):
        return (
            self.db.query(Permissions)
            .filter(Permissions.permission_id.in_(permission_ids))
            .all()
        )

    def remove_permissions_from_group(self, group_id: int, permission_ids: list[int]):
        mappings = (
            self.db.query(Permission_Group_Mapping)
            .filter(
                Permission_Group_Mapping.group_id == group_id,
                Permission_Group_Mapping.permission_id.in_(permission_ids),
            )
            .all()
        )
        if not mappings:
            return False

        for mapping in mappings:
            self.db.delete(mapping)
        self.db.commit()
        return True

    def get_unmapped_permissions(self, group_id: int) -> List[Permissions]:
        subquery = (
            self.db.query(Permission_Group_Mapping.permission_id)
            .filter(Permission_Group_Mapping.group_id == group_id)
            .subquery()
        )

        query = self.db.query(Permissions).filter(
            Permissions.permission_id.notin_(subquery)
        )

        return query.all()

    def clear_group_permissions(self, group_id: int):
        group = self.get_group_by_id(group_id)
        if group:
            group.permissions.clear()  # assuming a relationship 'permissions'
            self.db.commit()

    def clear_group_roles(self, group_id: int):
        group = self.get_group_by_id(group_id)
        if group:
            group.roles.clear()  # assuming a relationship 'roles'
            self.db.commit()

    # def delete_group(self, group_id: int):
    #     group = self.get_group_by_id(group_id)
    #     if group:
    #         self.db.delete(group)
    #         self.db.commit()
    #         return True
    #     return False
