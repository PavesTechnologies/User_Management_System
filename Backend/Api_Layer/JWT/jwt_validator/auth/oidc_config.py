# jwt_validator/auth/oidc_config.py

import json
import threading
import traceback
from jwt import algorithms
from typing import Optional
from jwcrypto import jwk as jwk_lib

from Backend.config.env_loader import get_env_var
from Backend.Api_Layer.JWT.token_creation.config import get_active_public_key
from Backend.Business_Layer.utils.jwt_encode import decrypt_key

# ISSUER = get_env_var("ISSUER")
ALLOWED_ISSUERS = get_env_var("ALLOWED_ISSUERS").split(",")


class OIDCValidator:
    def __init__(self):
        self.issuer = ALLOWED_ISSUERS[0]
        self.allowed_issuers = ALLOWED_ISSUERS
        self.jwks_dict = {}
        self._config_loaded = False
        self._config_lock = threading.Lock()

        # Load keys on creation
        self._load_config_from_memory()

    def _load_config_from_memory(self, force_reload=False):
        """
        Load public key directly from memory cache.
        No file reading, no HTTP calls.
        Falls back to DB only on cold start.
        """
        with self._config_lock:
            if self._config_loaded and not force_reload:
                return

            try:
                if force_reload:
                    print("🔄 Force reloading OIDC config from memory cache...")
                else:
                    print("📂 Loading OIDC config from memory cache...")

                # ✅ Get from memory cache (DB only on cold start)
                private_pem, public_pem, algorithm, kid = get_active_public_key()
                decrypted_public = decrypt_key(public_pem)

                # Convert PEM → JWK dict → RSA key object
                jwk_obj = jwk_lib.JWK.from_pem(decrypted_public.encode())
                jwk_dict = json.loads(jwk_obj.export_public())
                jwk_dict["use"] = "sig"
                jwk_dict["alg"] = algorithm
                jwk_dict["kid"] = kid

                rsa_key = algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk_dict))

                # Clear old keys if force reloading
                if force_reload:
                    old_kids = list(self.jwks_dict.keys())
                    self.jwks_dict.clear()
                    print(f"🗑️ Cleared cached keys: {old_kids}")

                self.jwks_dict[kid] = rsa_key
                self._config_loaded = True
                print(f"✅ OIDC config loaded from memory. KID: {kid}")

            except Exception as e:
                print(f"❌ Failed to load OIDC config: {e}")
                traceback.print_exc()
                raise

    def is_ready(self):
        """Check if configuration is loaded"""
        return self._config_loaded

    def get_signing_key(self, kid: str):
        """
        Get signing key by KID.
        Auto-reloads from memory if KID not found (handles key rotation).
        """
        if not self.is_ready():
            raise RuntimeError("OIDC configuration not loaded.")

        if kid not in self.jwks_dict:
            print(f"⚠️ KID '{kid}' not in cache, reloading...")
            print(f"   Current cached KIDs: {list(self.jwks_dict.keys())}")

            # Force reload — handles key rotation case
            self._load_config_from_memory(force_reload=True)

            if kid not in self.jwks_dict:
                raise ValueError(
                    f"Key ID '{kid}' not found even after reload. "
                    f"Available keys: {list(self.jwks_dict.keys())}"
                )

            print(f"✅ Key '{kid}' loaded after reload")

        return self.jwks_dict[kid]


# --- Global helpers ---

_oidc_validator: Optional[OIDCValidator] = None
_oidc_lock = threading.Lock()


def get_oidc_validator():
    """Returns singleton OIDC validator (lazy-loaded)."""
    global _oidc_validator

    # Fast path — already ready
    if _oidc_validator is not None and _oidc_validator.is_ready():
        return _oidc_validator

    with _oidc_lock:
        # Create if not exists — __init__ calls _load_config_from_memory
        if _oidc_validator is None:
            print("🔐 Initializing OIDC validator...")
            _oidc_validator = OIDCValidator()

        # Retry load if init failed
        if not _oidc_validator.is_ready():
            _oidc_validator._load_config_from_memory()

        return _oidc_validator


def reset_oidc_validator():
    """
    Reset validator — call this after key rotation
    so next request picks up the new key.
    """
    global _oidc_validator
    with _oidc_lock:
        _oidc_validator = None
        print("🔄 OIDC validator reset.")


def check_oidc_health():
    """Health check for OIDC validator."""
    try:
        validator = get_oidc_validator()
        return validator.is_ready()
    except Exception as e:
        print(f"❌ OIDC health check failed: {e}")
        return False
