# jwt_validator/auth/jwt_validator.py

import jwt
from fastapi import HTTPException
from .....Business_Layer.utils.token_blacklist import is_token_blacklisted
from .oidc_config import get_oidc_validator


def validate_jwt_token(token: str):
    try:
        print("Starting JWT validation via OIDC...")
        validator = get_oidc_validator()
        print("OIDC Validator fetched successfully.")

        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        print(f"Token header 'kid': {kid}")
        
        token_issuer = jwt.decode(token, options={"verify_signature": False}).get("iss")
        print("Allowed issuers:", validator.allowed_issuers)
        print("Issuer from token:", token_issuer)

        try:
            key = validator.get_signing_key(kid)
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e))
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=str(e))

        # ✅ Pass list — PyJWT checks if token issuer is in the list
        decoded = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=None,
            issuer=validator.allowed_issuers,   # ← list now
        )

        jti = decoded.get("jti")
        try:
            if jti and is_token_blacklisted(jti):
                print(f"🚫 Token blacklisted (jti={jti})")
                raise HTTPException(status_code=401, detail="Token has been revoked")
        except HTTPException:
            raise
        except Exception as e:
            print(f"⚠️ Blacklist check error (ignored): {e}")
        return decoded

    except jwt.ExpiredSignatureError:
        print("⏰ Token expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        print(f"❌ Invalid token: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Unexpected validation error: {e}")
        raise HTTPException(status_code=401, detail=f"JWT validation failed: {str(e)}")