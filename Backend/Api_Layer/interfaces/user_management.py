from pydantic import BaseModel
from typing import List, Optional


class UserBase(BaseModel):
    user_uuid: Optional[str] = None
    first_name: str
    last_name: str
    mail: str
    contact: str
    password: Optional[str] = None
    is_active: bool = True


class UserBaseIn(BaseModel):
    user_uuid: Optional[str] = None
    first_name: str
    last_name: str
    mail: str
    contact: str
    password: Optional[str] = None
    is_active: bool = True


class UserOut(UserBase):
    user_id: int
    user_uuid: str
    first_name: str
    last_name: str
    mail: str
    contact: str
    password: str
    is_active: bool
    gender: Optional[str] = None

class userOut_id(BaseModel):
    user_id : int
    user_uuid: str
    message: str

class EmployeeIDin(BaseModel):
    employee_ids: List[int]

class UserOut_uuid(UserBase):
    class Config:
        from_attributes = True


class UserRoleUpdate(BaseModel):
    role_ids: list[str]


class UserWithRoleNames(BaseModel):
    user_uuid: str
    name: str  # e.g., "John Doe"
    roles: List[str]  # Only role names
    mail: str

    class Config:
        from_attributes = True


class UserWithRoleNames_id(BaseModel):
    user_id: int
    name: str  # e.g., "John Doe"
    roles: List[str]  # Only role names
    mail: str

    class Config:
        from_attributes = True


class PaginatedUserResponse(BaseModel):
    total: int
    users: List[UserOut]


class PaginatedUserWithRolesResponse(BaseModel):
    total: int
    users: List[UserWithRoleNames]
