from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..interfaces.general_user import EditProfile, EditProfileHr
from ...Business_Layer.services.profile_service import ProfileService

router = APIRouter()


# --- Service injector (use db session from middleware) ---
def get_profile_service(request: Request) -> ProfileService:
    """Injects ProfileService with the request's db connection."""
    return ProfileService(request.state.db)


# --- Profile Endpoints ---
@router.get("/profile")
def get_profile(
    request: Request,
    service: ProfileService = Depends(get_profile_service),
):
    """Fetch logged-in user's profile."""
    return service.get_profile(request.state.user)


@router.put("/profile")
def update_profile(
    profile: EditProfile,
    request: Request,
    service: ProfileService = Depends(get_profile_service),
):
    """Update logged-in user's own profile."""
    return service.update_profile(profile, current_user=request.state.user)


# --- User Search Endpoints ---
@router.get("/search")
def search_users(
    request: Request,
    query: str = Query(..., description="Search by name, email, or contact"),
    service: ProfileService = Depends(get_profile_service),
):
    """Search for users by name, email, or contact."""
    return service.search_users(query, current_user=request.state.user)


@router.get("/search/suggestions")
def user_search_suggestions(
    request: Request,
    query: str = Query(..., min_length=1, description="Autocomplete suggestions"),
    service: ProfileService = Depends(get_profile_service),
):
    """Get user search suggestions for autocomplete."""
    return service.user_search_suggestions(query, current_user=request.state.user)


# --- Admin/HR Profile Management Endpoints ---
@router.get("/edit-user/{user_id}")
def get_user_by_id(
    user_id: int,
    request: Request,
    service: ProfileService = Depends(get_profile_service),
):
    """Fetch a user profile by ID (Admin/HR access)."""
    return service.get_user_by_id(user_id, current_user=request.state.user)


@router.put("/edit-user/{user_id}")
def update_user_by_id(
    user_id: int,
    profile: EditProfileHr,
    request: Request,
    service: ProfileService = Depends(get_profile_service),
):
    """Allow Admin/Super_Admin to edit any profile or self-edit."""
    current_user = request.state.user
    roles = [role.lower() for role in current_user.get("roles", [])]

    # Condition 1: Admin or Super_Admin can edit any profile
    if "admin" in roles or "Super_Admin" in roles:
        return service.update_user_by_id(user_id, profile, current_user)

    # Condition 2: Allow only self-edit
    if current_user["user_id"] == user_id:
        return service.update_user_by_id(user_id, profile, current_user)

    # Condition 3: Deny access
    raise HTTPException(
        status_code=403, detail="You are not authorized to edit this profile."
    )
