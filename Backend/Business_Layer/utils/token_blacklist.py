# Backend/Business_Layer/utils/token_blacklist.py
import time
from .redis_client import get_redis_client
# from ...Api_Layer.JWT.jwt_validator.auth.jwt_utils import decode_access_token
from ...Api_Layer.JWT.jwt_validator.auth.jwt_utils import decode_any_token
BLACKLIST_PREFIX = "blacklist:"

# ---- Local in-memory cache ----
_local_blacklist: dict[str, float] = {}  # jti -> expiry timestamp
_last_cleanup = time.time()


def _cleanup_local_cache():
    """Remove expired entries from local cache."""
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < 60:  # cleanup every 60s
        return
    expired = [jti for jti, exp in _local_blacklist.items() if now > exp]
    for jti in expired:
        del _local_blacklist[jti]
    _last_cleanup = now


def blacklist_token(token: str):
    redis_client = get_redis_client()

    try:
        payload = decode_any_token(token)
        jti = payload.get("jti")
        exp = float(payload.get("exp", 0))
        ttl = int(exp - time.time())

        if ttl > 0 and jti:
            # ✅ Always add to local cache immediately (instant)
            _local_blacklist[jti] = time.time() + ttl

            # ✅ Also persist to Redis if available (best effort)
            if redis_client:
                try:
                    redis_client.setex(f"{BLACKLIST_PREFIX}{jti}", ttl, "1")
                except Exception as e:
                    print(f"⚠️ Redis blacklist write failed: {e}")

            return True
    except Exception as e:
        print(f"⚠️ Blacklist failed: {e}")

    return False


def is_token_blacklisted(jti: str) -> bool:
    _cleanup_local_cache()

    # ✅ Check local memory FIRST — zero network cost
    if jti in _local_blacklist:
        if time.time() < _local_blacklist[jti]:
            return True
        else:
            del _local_blacklist[jti]  # expired

    # ✅ Only hit Redis if not in local cache
    redis_client = get_redis_client()
    if not redis_client:
        return False

    try:
        result = redis_client.exists(f"{BLACKLIST_PREFIX}{jti}") == 1
        if result:
            # Cache it locally so next check is instant
            ttl = redis_client.ttl(f"{BLACKLIST_PREFIX}{jti}")
            if ttl > 0:
                _local_blacklist[jti] = time.time() + ttl
        return result
    except Exception as e:
        print(f"⚠️ Redis blacklist check failed: {e}")
        return False
