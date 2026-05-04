from fastapi import Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from uuid import UUID


class RoleBase(BaseModel):
    role_name: str


class RoleOut(RoleBase):
    role_uuid: str

    class Config:
        from_attributes = True


class RolePermissionGroupUpdate(BaseModel):
    group_ids: list[int]


class RoleGroupRequest(BaseModel):
    group_uuids: List[str]


class Group(BaseModel):
    group_uuid: UUID
    group_name: str
    created_at: datetime
    updated_at: datetime

class BulkDeleteRolesRequest(BaseModel):
    role_uuids: List[str]

class User_Role_input(BaseModel):
    role_uuid: Optional[str] = Query(None)
    role_name: Optional[str] = Query(None)
class User_Role(BaseModel):
    user_id: int
    employee_id: Optional[str]
    role_name: str


