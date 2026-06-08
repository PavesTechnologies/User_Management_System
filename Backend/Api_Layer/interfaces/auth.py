from pydantic import BaseModel, Field
from enum import Enum


class GenderEnum(str, Enum):
    MALE = "male"
    FEMALE = "female"
    OTHER = "other"


class RegisterUser(BaseModel):
    mail: str
    password: str
    first_name: str
    last_name: str
    contact: str
    gender: GenderEnum
    is_active: bool = Field(default=True)


class LoginUser(BaseModel):
    email: str
    password: str


class ForgotPassword(BaseModel):
    email: str
    otp: str
    new_password: str


class ChangePasswordFirstLogin(BaseModel):
    email: str
    confirm_password: str
    new_password: str


class ChangePassword(BaseModel):
    confirm_password: str
    new_password: str


class PermissionCheck(BaseModel):
    method: str
    path: str


class RefreshTokenSchema(BaseModel):
    refresh_token: str
