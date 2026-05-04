from pydantic import BaseModel
from typing import List
from enum import Enum
from datetime import datetime


class PermissionBase(BaseModel):
    permission_code: str
    description: str
    created_at: datetime
    updated_at: datetime


class PermissionBaseCreation(BaseModel):
    permission_code: str
    description: str


class PermissionOut(PermissionBase):
    permission_uuid: str

    class Config:
        from_attributes = True


class PermissionCreate(PermissionBaseCreation):
    group_uuid: str


class PermissionCreateU(PermissionBase):
    pass


class PermissionGroupUpdate(BaseModel):
    group_uuid: str


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


class AccessPointBase(BaseModel):
    endpoint_path: str
    method: HTTPMethod
    module: str
    is_public: bool = False


class AccessPointPermissionMappingIn(BaseModel):
    access_id: int
    permission_code: str


class PermissionResponse(BaseModel):
    permission_uuid: str
    permission_code: str
    description: str

    class Config:
        from_attributes = True


class BulkPermissionCreationResponse(BaseModel):
    created_permissions: List[PermissionBaseCreation]
    failed_entries: List[str]

class BulkDeletePermissionsRequest(BaseModel):
    permission_uuids: List[str]