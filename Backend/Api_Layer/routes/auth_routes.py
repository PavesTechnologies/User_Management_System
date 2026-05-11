from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from ..interfaces.auth import (
    RegisterUser,
    RefreshTokenSchema,
    LoginUser,
    ForgotPassword,
    ChangePasswordFirstLogin,
)
from ...Business_Layer.services.auth_service import AuthService
from ...config.env_loader import get_env_var
from ...Business_Layer.utils.token_blacklist import blacklist_token

router = APIRouter()

# Instantiate service per request (no shared singleton)
# If needed, can cache in future
auth_service = AuthService()


@router.post("/register")
def register(user_data: RegisterUser, request: Request):
    return auth_service.register_user(user_data, request=request)


@router.post("/login")
def login(credentials: LoginUser, request: Request):
    client_ip = auth_service.get_client_ip(request)
    return auth_service.login_user(credentials, client_ip, request)


# router
@router.post("/logout")
def logout(request: Request, body: RefreshTokenSchema):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing access token")

    access_token = auth_header.split(" ")[1]

    access_blacklisted  = blacklist_token(access_token)
    refresh_blacklisted = blacklist_token(body.refresh_token)

    if access_blacklisted or refresh_blacklisted:
        return {"message": "Logged out successfully"}
    else:
        raise HTTPException(status_code=500, detail="Logout failed")


@router.get("/ms-login")
def ms_login():
    client_id = get_env_var("CLIENT_ID")
    tenant_id = get_env_var("TENANT_ID")
    redirect_uri = get_env_var("REDIRECT_URI")
    state = get_env_var("SESSION_SECRET")

    microsoft_auth_url = (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        f"?client_id={client_id}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope=openid profile email offline_access"
        f"&response_mode=query"
        f"&state={state}"
    )

    return RedirectResponse(url=microsoft_auth_url)


@router.get("/callback")
def handle_microsoft_callback(code: str, request: Request):
    try:
        # print("Received code:", code)
        client_ip = auth_service.get_client_ip(request)
        return auth_service.handle_microsoft_callback(code, client_ip, request)
    except HTTPException as http_exc:
        print("HTTPException:", http_exc.status_code, http_exc.detail)
        raise http_exc
    except Exception as e:
        import traceback

        print("Unhandled Exception:", str(e))
        traceback.print_exc()
        raise HTTPException(
            status_code=500, detail="OAuth callback failed unexpectedly"
        )


@router.get("/forgot-password/{email}")
def check_user_status(email: str):
    return auth_service.check_user_exists(email)


@router.post("/forgot-password")
def forgot_password(update: ForgotPassword):
    return auth_service.forgot_password(update)


@router.post("/first-login/change-password")
def change_password_first_login(payload: ChangePasswordFirstLogin, request: Request):
    current_user = request.state.user
    return auth_service.change_password_first_login(
        payload, current_user.get("user_id")
    )


@router.post("/refresh")
def refresh_token(
    body: RefreshTokenSchema,   # { refresh_token: str }
    request: Request
):
    return auth_service.refresh_token(body.refresh_token, request)
    
