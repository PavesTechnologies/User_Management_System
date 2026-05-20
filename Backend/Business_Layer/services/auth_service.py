from sqlalchemy.orm import Session
from fastapi import HTTPException, status, Request
import requests
import time
import jwt
from jwt import PyJWKClient

from ...Api_Layer.interfaces.auth import (
    RegisterUser,
    LoginUser,
    ForgotPassword,
    ChangePasswordFirstLogin,
    ChangePassword,
)
from ...Data_Access_Layer.dao.auth_dao import AuthDAO
from ...Data_Access_Layer.models import models
from ...Data_Access_Layer.dao.user_dao import UserDAO
from ...Api_Layer.JWT.token_creation.token_create import token_create, refresh_token_create
from ..utils.password_utils import (
    hash_password,
    verify_password,
)
from ...Api_Layer.JWT.jwt_validator.auth.jwt_validator import validate_jwt_token
from ...Business_Layer.utils.token_blacklist import blacklist_token, is_token_blacklisted
from ..utils.input_validators import validate_email_format, validate_password_strength
from ...Data_Access_Layer.utils.dependency import get_db  # only used here
from ...config.env_loader import get_env_var
from ..utils.generate_uuid7 import generate_uuid7


class AuthService:
    """
    Handles business logic and internally manages DB session.
    """

    def __init__(self):
        pass

    def _get_db_from_request(self, request: Request | None = None) -> Session:
        if request is not None and hasattr(request.state, "db"):
            return request.state.db
        return next(get_db())

    def _get_dao(self, request: Request | None = None) -> AuthDAO:
        db: Session = self._get_db_from_request(request)
        return AuthDAO(db)

    def _get_user_dao(self, request: Request | None = None) -> UserDAO:
        db: Session = self._get_db_from_request(request)
        return UserDAO(db)

    def get_client_ip(self, request: Request):
        """
        Safely get client IP considering trusted proxy headers.
        """
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            # X-Forwarded-For may contain multiple IPs, first is original client
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.client.host
        print("Client IP:", ip)
        return ip

    def register_user(self, user_data: RegisterUser, request: Request | None = None):
        dao = self._get_dao(request)
        user_dao = self._get_user_dao(request)
        print("mail:", user_data.mail)

        validate_email_format(user_data.mail)
        validate_password_strength(user_data.password)

        if dao.get_user_by_email(user_data.mail):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already exists with this email.",
            )

        hashed_password = hash_password(user_data.password)
        uuid = generate_uuid7()
        print("first name :", user_data.first_name)
        new_user = models.User(
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            mail=user_data.mail,
            password=hashed_password,
            user_uuid=uuid,
            contact=user_data.contact,
            is_active=user_data.is_active,
            gender=user_data.gender,
        )
        created_user = user_dao.create_user(new_user)

        # send_welcome_email(
        #     user_data.mail,
        #     user_data.first_name,
        #     user_data.password,
        # )

        return {
            "msg": "User registered successfully",
            "user_id": created_user.user_id,
            "user_uuid": created_user.user_uuid,
        }

    def login_user(self, credentials: LoginUser, client_ip: str, request: Request):
        dao = self._get_dao(request)
        validate_email_format(credentials.email)

        t = time.time()
        results = dao.get_user_login_data(credentials.email)
        if not results:
            raise HTTPException(status_code=404, detail="User not found or inactive")
        user, roles, permissions = results
        print(f"⏱ get_user_login_data: {(time.time()-t)*1000:.1f}ms")
        t = time.time()

        if not user:
            raise HTTPException(status_code=404, detail="User not found or inactive")

        verify_password(credentials.password, user.password)
        print(f"⏱ verify_password: {(time.time()-t)*1000:.1f}ms")
        t = time.time()

        token_data = {
            "sub": str(user.user_id),
            "user_id": user.user_id,
            "employee_id": user.employee_id,
            "user_uuid": user.user_uuid,
            "name": user.first_name + " " + user.last_name,
            "email": user.mail,
            "roles": roles,
            "permissions": permissions,
        }
        access_token = token_create(token_data, request=request, db=dao.db)
        refresh_token = refresh_token_create(token_data, request=request, db=dao.db)
        print(f"⏱ token_create: {(time.time()-t)*1000:.1f}ms")
        t = time.time()

        redirect = "/dashboard"
        if dao.check_user_first_login(user.user_id):
            redirect = "/change-password"
        print(f"⏱ check_user_first_login: {(time.time()-t)*1000:.1f}ms")
        t = time.time()

        dao.update_last_login(user.user_id, client_ip)
        print(f"⏱ update_last_login: {(time.time()-t)*1000:.1f}ms")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "redirect": redirect,
        }
    
    def refresh_token(self, refresh_token_str: str, request: Request):
        dao = self._get_dao(request)

        # ── Step 1: Validate signature + expiry ──────────────────
        # ✅ Reuse validate_jwt_token — it handles:
        #    - signature verification
        #    - key rotation (kid lookup)
        #    - expiry check
        #    - blacklist check (is_token_blacklisted inside)
        #    - issuer check
        try:
            payload = validate_jwt_token(refresh_token_str)
        except HTTPException as e:
            # re-raise with clearer message
            if e.status_code == 401:
                raise HTTPException(401, "Refresh token invalid or expired, please login again")
            raise

        # ── Step 2: Type guard ────────────────────────────────────
        # ✅ Make sure this is actually a refresh token
        #    (not an access token being misused)
        if payload.get("token_type") != "refresh":
            raise HTTPException(
                status_code=401,
                detail="Invalid token type"
            )

        # ── Step 3: Fetch fresh user data from DB ─────────────────
        # ✅ Use your existing dao pattern
        user_id = payload.get("user_id")
        results = dao.get_user_login_data_by_id(user_id)  # fetch by id
        if not results:
            raise HTTPException(401, "User not found or inactive")

        user, roles, permissions = results

        token_data = {
            "sub": str(user.user_id),
            "user_id": user.user_id,
            "employee_id": user.employee_id,
            "user_uuid": user.user_uuid,
            "name": user.first_name + " " + user.last_name,
            "email": user.mail,
            "roles": roles,           # ✅ fresh from DB
            "permissions": permissions,  # ✅ fresh from DB
        }

        # ── Step 4: Blacklist old refresh token ───────────────────
        # ✅ reuse blacklist_token as-is
        # But blacklist_token takes full token string, not jti!
        # blacklist_token(refresh_token_str)   # ✅ your existing signature
        if blacklist_token(refresh_token_str):
            print("Old refresh token blacklisted")

        # ── Step 5: Issue new tokens ──────────────────────────────
        new_access_token  = token_create(token_data, request=request, db=dao.db)
        new_refresh_token = refresh_token_create(token_data, request=request, db=dao.db)

        return {
            "access_token":  new_access_token,
            "refresh_token": new_refresh_token,
            "token_type":    "bearer"
        }

    def handle_microsoft_callback(self, code: str, client_ip, request: Request):
        # print("1. Received code:", code)

        token_url = f"https://login.microsoftonline.com/{get_env_var('TENANT_ID')}/oauth2/v2.0/token"
        print("2. Token URL:", token_url)

        data = {
            "client_id": get_env_var("CLIENT_ID"),
            "scope": "openid email",
            "code": code,
            "redirect_uri": get_env_var("REDIRECT_URI"),
            "grant_type": "authorization_code",
            "client_secret": get_env_var("CLIENT_SECRET"),
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(token_url, data=data, headers=headers)
        print("3. Token exchange status:", response.status_code)
        # print("4. Token response:", response.text)

        if response.status_code != 200:
            raise HTTPException(
                status_code=500, detail="Failed to exchange code for token"
            )

        token_response = response.json()
        id_token = token_response.get("id_token")
        # print("5. ID Token:", id_token)

        if not id_token:
            raise HTTPException(
                status_code=400, detail="ID token not found in response"
            )

        # Decode Token
        jwks_url = f"https://login.microsoftonline.com/{get_env_var('TENANT_ID')}/discovery/v2.0/keys"
        print("6. JWKS URL:", jwks_url)

        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)

        try:
            payload = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=get_env_var("CLIENT_ID"),
                options={"verify_exp": True},
            )
            # print("7. Decoded payload:", payload)
        except jwt.PyJWTError as e:
            raise HTTPException(
                status_code=403, detail=f"Token verification failed: {str(e)}"
            )

        email = payload.get("email") or payload.get("preferred_username")
        print("8. Email from token:", email)

        if not email:
            raise HTTPException(status_code=400, detail="Email not found in token")

        dao = self._get_dao()
        user = dao.get_active_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found or inactive")

        roles = dao.get_user_roles(user.user_id)
        group_ids = dao.get_permission_group_ids_for_user(user.user_id)
        permissions = dao.get_permissions_by_group_ids(group_ids)

        token_data = {
            "sub": str(user.user_id),
            "user_id": user.user_id,
            "employee_id": user.employee_id,
            "user_uuid": user.user_uuid,
            "name": user.first_name + " " + user.last_name,
            "email": user.mail,
            "roles": roles,
            "permissions": permissions,
        }

        access_token = token_create(token_data, request=request, db=dao.db)
        refresh_token = refresh_token_create(token_data, request=request, db=dao.db)
        redirect = "/dashboard"
        if dao.check_user_first_login(user.user_id):
            redirect = "/change-password"

        dao.update_last_login(user.user_id, client_ip)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "redirect": redirect,
        }

    def forgot_password(self, forgot_data: ForgotPassword):
        dao = self._get_dao()

        # 1. Check user exists
        validate_email_format(forgot_data.email)
        user = dao.get_user_by_email(forgot_data.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found with given email",
            )

        # 2. Validate OTP
        otp_record = dao.get_valid_otp(forgot_data.email, forgot_data.otp)
        if not otp_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP"
            )

        dao.delete_otp(otp_record)

        validate_password_strength(forgot_data.new_password)
        # 3. Hash new password
        hashed_pw = hash_password(forgot_data.new_password)

        # 4. Update password and activate user
        if not dao.update_user_password(user, hashed_pw):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password",
            )
        dao.password_last_updated(user.user_id)
        return {"message": "Password updated and user activated"}
    
    def change_password(self, payload: ChangePassword, request: Request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401, detail="Missing or invalid Authorization header"
            )
        token = auth_header.split(" ")[1]
        user = validate_jwt_token(token)
        user_mail = user.get("email")
        dao = self._get_dao()

        user = dao.get_user_by_email(user_mail)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        new_password = payload.new_password
        confirm_password = payload.confirm_password

        if new_password != confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match"
            )

        validate_password_strength(new_password)

        new_hashed_password = hash_password(new_password)

        if not dao.update_user_password(user, new_hashed_password):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password",
            )

        return {"message": "Password changed successfully"}

    def change_password_first_login(
        self, payload: ChangePasswordFirstLogin, user_id: int
    ):

        dao = self._get_dao()

        user_email = payload.email
        user = dao.get_user_by_email(user_email)

        # ✅ FIRST check if user exists
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        # ✅ THEN check ownership
        if user.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only change your own password",
            )

        new_password = payload.new_password
        confirm_password = payload.confirm_password

        if new_password != confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match"
            )

        validate_password_strength(new_password)

        new_hashed_password = hash_password(new_password)

        if not dao.update_user_password(user, new_hashed_password):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update password",
            )

        return {"message": "Password changed successfully"}

    def check_user_exists(self, email: str):
        dao = self._get_dao()

        validate_email_format(email)
        user = dao.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found with this email",
            )

        return {"msg": "User exists"}
