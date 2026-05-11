# jwt_validator/auth/jwt_utils.py

import jwt
from .oidc_config import get_oidc_validator


def decode_access_token(token: str) -> dict:
    """Full validation — signature + expiry + blacklist. For API route guards."""
    from .jwt_validator import validate_jwt_token
    return validate_jwt_token(token)


def decode_any_token(token: str) -> dict:
    """
    Minimal decode — signature only, NO expiry check, NO blacklist check.
    Used ONLY by blacklist_token() to extract jti from any token type.
    """
    validator = get_oidc_validator()
    header    = jwt.get_unverified_header(token)
    kid       = header.get("kid")
    key       = validator.get_signing_key(kid)

    return jwt.decode(
        token,
        key=key,
        algorithms=["RS256"],
        options={"verify_exp": False},    # ✅ blacklist even expired tokens
        issuer=validator.allowed_issuers,
        audience=None,
    )