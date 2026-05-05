# Backend/Api_Layer/JWT/token_creation/token_create.py
from datetime import datetime, timedelta, timezone
import jwt
import time
from .config import get_jwt_keys
from Backend.Business_Layer.utils.jwt_encode import decrypt_key
from Backend.config.env_loader import get_env_var
from ....Business_Layer.utils.generate_uuid7 import generate_uuid7

ACCESS_TOKEN_EXPIRE_MINUTES = int(get_env_var("ACCESS_TOKEN_EXPIRE_MINUTES"))
KEYS_CACHE_TTL = 300  # refresh keys every 5 minutes

_private_key = None
_public_key = None
_algorithm = None
_kid = None
_keys_loaded_at = 0  # timestamp, not bool


def get_issuer_from_request(request) -> str:
    scheme = request.url.scheme
    host = request.headers.get("host")
    issuer = f"{scheme}://{host}"
    print("Determined Issuer from request:", issuer)
    return issuer


def _load_keys(db=None):
    global _private_key, _public_key, _algorithm, _kid, _keys_loaded_at

    # ✅ Reload if never loaded OR cache expired
    if time.time() - _keys_loaded_at < KEYS_CACHE_TTL:
        return  # still fresh

    private_key_enc, public_key_enc, _algorithm, _kid = get_jwt_keys(db=db)
    _private_key = decrypt_key(private_key_enc)
    _public_key = decrypt_key(public_key_enc)
    _keys_loaded_at = time.time()
    print("✅ JWT keys decrypted and cached in memory")


def token_create(token_data: dict, request=None, issuer=None, db=None) -> str:
    _load_keys(db=db)

    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = generate_uuid7()

    if issuer is None and request is not None:
        issuer = get_issuer_from_request(request)
    elif issuer is None:
        raise ValueError("Either 'request' or 'issuer' must be provided")

    payload = {
        "jti": jti,
        "user_id": token_data["user_id"],
        "email": token_data["email"],
        "name": token_data["name"],
        "employee_id": token_data["employee_id"],
        "obs_user_uuid": token_data["user_uuid"],
        "roles": token_data["roles"],
        "permissions": token_data["permissions"],
        "iss": issuer,
        "exp": expire,
    }

    return jwt.encode(
        payload, _private_key, algorithm=_algorithm, headers={"kid": _kid}
    )
