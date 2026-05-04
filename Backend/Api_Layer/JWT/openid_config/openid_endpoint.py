# Backend/Api_Layer/JWT/openid_config/openid_endpoint.py
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import json
from jwcrypto import jwk
from Backend.config.env_loader import get_env_var
from ..jwt_validator.middleware.permission_utils import check_permission
from Backend.Api_Layer.interfaces.auth import PermissionCheck
from Backend.Api_Layer.JWT.token_creation.config import get_active_public_key
from Backend.Business_Layer.utils.jwt_encode import decrypt_key

router = APIRouter()
# Loading from Json file
# Static path to JWKS file
# JWKS_PATH = Path(__file__).resolve().parent.parent / "token_creation" / "jwks.json"

# Replace with your actual domain name or environment variable
# ISSUER = get_env_var("ISSUER")

# @router.get("/.well-known/jwks.json")
# def serve_jwks():
#     with open(JWKS_PATH, "r") as f:
#         jwks = json.load(f)
#     return JSONResponse(content=jwks)

# ISSUER = get_env_var("ISSUER")
ALLOWED_ISSUERS = get_env_var("ALLOWED_ISSUERS").split(",")

# Fetching public key from DB


@router.get("/.well-known/jwks.json")
def serve_jwks():
    print("Serving JWKS..")
    try:
        private_pem, public_pem, algorithm, kid = get_active_public_key()
        decrypted_public = decrypt_key(public_pem)

        key = jwk.JWK.from_pem(decrypted_public.encode("utf-8"))
        key_dict = json.loads(key.export_public())
        key_dict["use"] = "sig"
        key_dict["alg"] = algorithm
        key_dict["kid"] = kid

        return JSONResponse(content={"keys": [key_dict]})

    except Exception as e:
        print(f"❌ Failed to serve JWKS: {e}")
        return JSONResponse(status_code=500, content={"detail": "Failed to load JWKS"})


@router.get("/.well-known/openid-configuration")
def openid_config():
    config = {
        "issuer": ALLOWED_ISSUERS[0],
        "jwks_uri": f"{ALLOWED_ISSUERS[0]}/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"],
    }
    return JSONResponse(content=config)


@router.post("/middleware/check-permission")
async def permission_check_endpoint(request: Request, data: PermissionCheck):
    try:
        print("✅ POST ENDPOINT HIT!")
        print(f"📍 Method: {request.method}")
        print(f"📍 Path: {request.url.path}")
        print(f"📍 Client IP: {request.client.host if request.client else 'Unknown'}")
        print(f"📥 Data: path={data.path}, method={data.method}")

        if not hasattr(request.state, "user") or request.state.user is None:
            print("❌ No user data in request.state")
            return JSONResponse(
                status_code=401, content={"detail": "Unauthorized - no user data"}
            )

        token_data = request.state.user
        db = getattr(request.state, "db", None)
        print(f"💾 DB session: {'Available' if db else 'Not available'}")

        response = check_permission(data.path, data.method, token_data, db_session=db)

        if isinstance(response, JSONResponse):
            print("❌ Permission denied")
            return response

        print("✅ Permission granted")
        return {"allowed": True}

    except Exception as e:
        print(f"💥 ERROR in permission_check_endpoint: {e}")
        import traceback

        traceback.print_exc()
        return JSONResponse(
            status_code=500, content={"detail": f"Internal error: {str(e)}"}
        )


@router.get("/middleware/check-permission")
async def permission_check_get_handler(request: Request):
    print("❌ GET REQUEST RECEIVED - This endpoint only accepts POST")
    print(f"📍 Client: {request.client}")
    print(f"📍 Headers: {dict(request.headers)}")
    return JSONResponse(
        status_code=405,
        content={"error": "Method Not Allowed. Use POST instead of GET"},
    )
