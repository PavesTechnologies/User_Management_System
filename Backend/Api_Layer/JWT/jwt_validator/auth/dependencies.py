# auth/dependencies.py
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from fastapi.routing import compile_path
import re

from .jwt_utils import decode_access_token
from .....Data_Access_Layer.utils.dependency import get_db  # only used here

bearer_scheme = HTTPBearer()


def get_current_user(token: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        payload = decode_access_token(token.credentials)
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def admin_required(current_user: dict = Depends(get_current_user)):
    roles = current_user.get("roles", [])
    if "Admin" not in roles and "Super_Admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def path_matches(request_path: str, db_path: str) -> bool:
    """Check if request_path matches db_path with {params}."""
    regex, _, _ = compile_path(db_path)  # unpack all 3 values
    return re.fullmatch(regex, request_path) is not None


def check_permission(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    path = request.url.path
    print("Request Path:", path)
    method = request.method

    # Get all access points with same method
    rows = db.execute(
        """
        SELECT ap.access_id, ap.endpoint_path, p.permission_code, ap.is_public
        FROM Access_Point ap
        JOIN Access_Point_Permission_Mapping apm ON ap.access_id = apm.access_id
        JOIN Permissions p ON apm.permission_id = p.permission_id
        WHERE ap.method = :method
    """,
        {"method": method},
    ).fetchall()

    required_permission = None
    for row in rows:
        if path_matches(path, row[1]):  # row[1] = endpoint_path
            required_permission = row[2]  # row[2] = permission_code
            is_public = row[3]  # row[3] = is_public
            print("Matched Path:", row[1], "Requires Permission:", required_permission)
            break

    if not required_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Access point not registered"
        )

    if (
        required_permission not in current_user.get("permissions", [])
        and is_public == 1
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required permission: {required_permission}",
        )

    return current_user
