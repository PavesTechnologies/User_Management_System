from git import List
from pydantic import BaseModel
from datetime import datetime


# Schemas
class GroupBase(BaseModel):
    group_name: str
    created_at: datetime
    updated_at: datetime


class GroupIn(BaseModel):
    group_name: str


class GroupOut(GroupBase):
    group_uuid: str

    class Config:
        from_attributes = True


class PermissionInGroup(BaseModel):
    code: str
    description: str


class PermissionInGroupwithId(BaseModel):
    permission_uuid: str
    code: str
    description: str

    class Config:
        from_attributes = True

class BulkDeletePermissionGroupsRequest(BaseModel):
    group_uuids: List[str]
