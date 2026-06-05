"""
Audit Trail Decorator for FastAPI/SQLAlchemy Applications
Place this in: Business_Layer/utils/audit_decorator.py
"""

from functools import wraps
from typing import Callable, Optional, Any, Dict
from sqlalchemy.orm import Session
from datetime import datetime
from ...Data_Access_Layer.models import models
from ...Business_Layer.utils.generate_uuid7 import generate_uuid7


def audit_action_with_request(
    action_type: str,
    entity_type: str,
    get_entity_id: Optional[Callable] = None,
    capture_old_data: bool = False,
    capture_new_data: bool = False,
    description: Optional[str] = None,
):
    """
    Decorator to log audit trail for CRUD operations with optional old/new data capture.
    Fully supports mutable audit_data dict passed from function.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            service_instance = args[0] if args else None
            db: Session = getattr(service_instance, "db", None)
            if not db:
                return func(*args, **kwargs)

            # Extract context
            user_id = _extract_user_id(*args, **kwargs)
            ip_address = _get_ip_address(*args, **kwargs)
            entity_id = None
            if get_entity_id:
                try:
                    entity_id = get_entity_id(*args, **kwargs)
                except Exception:
                    pass

            # Initialize audit_data if not present
            if "audit_data" not in kwargs:
                kwargs["audit_data"] = {}

            audit_data = kwargs["audit_data"]

            # Capture old data BEFORE function execution (if enabled and not manually set)
            old_data = audit_data.get("old_data")
            if old_data is None and capture_old_data and entity_id:
                old_data = _capture_entity_state(db, entity_type, entity_id)
                audit_data["old_data"] = old_data

            # Execute the actual function
            result = func(*args, **kwargs)

            # NOW check audit_data AFTER function execution for any updates
            # This is the key fix - check the dict after the function has modified it
            old_data = audit_data.get("old_data")
            new_data = audit_data.get("new_data")

            # Check if function manually set entity_id
            if "entity_id" in audit_data:
                entity_id = audit_data["entity_id"]

            # Only auto-capture if not manually set by the function
            if new_data is None and capture_new_data:
                new_data, entity_id = _capture_new_data(
                    result, db, entity_type, entity_id
                )
                audit_data["new_data"] = new_data

            # Keep only changed fields for UPDATE
            if action_type == "UPDATE" and old_data and new_data:
                new_data = _filter_changed_fields(old_data, new_data)

            # Generate description
            final_description = _build_description(
                description, action_type, entity_type, old_data, new_data, kwargs
            )

            # Log audit entry
            _log_audit(
                db=db,
                user_id=user_id,
                action_type=action_type,
                entity_type=entity_type,
                entity_id=entity_id,
                old_data=old_data,
                new_data=new_data,
                ip_address=ip_address,
                description=final_description,
            )

            return result

        return wrapper

    return decorator


# ---------------- Helper Functions ----------------


def _extract_user_id(*args, **kwargs) -> Optional[int]:
    for key in ["current_user", "user_info", "auth_user"]:
        if key in kwargs:
            user_data = kwargs[key]
            if isinstance(user_data, dict):
                return user_data.get("user_id")
            elif hasattr(user_data, "user_id"):
                return user_data.user_id
    for key in ["created_by_user_id", "updated_by_user_id"]:
        if key in kwargs:
            return kwargs[key]
    return None


def _get_ip_address(*args, **kwargs) -> Optional[str]:
    request = kwargs.get("request")
    if request and hasattr(request, "client") and request.client:
        return request.client.host
    return None


def _capture_entity_state(
    db: Session, entity_type: str, entity_id: Any
) -> Optional[Dict[str, Any]] | list[Dict[str, Any]]:
    try:
        model_class = getattr(models, entity_type, None)
        if not model_class:
            return None
        if entity_type in ["User_Role", "User_Permission"]:
            return [
                s
                for r in db.query(model_class).filter_by(user_id=entity_id).all()
                if (s := _serialize_entity(r)) is not None
            ]
        entity = (
            db.query(model_class)
            .filter_by(**{f"{entity_type.lower()}_id": entity_id})
            .first()
        )
        if entity:
            return _serialize_entity(entity)
    except Exception as e:
        print(f"Failed to capture entity state: {e}")
    return None


def _serialize_entity(entity) -> Optional[Dict[str, Any]]:
    if not entity:
        return None
    result: Dict[str, Any] = {}
    for column in entity.__table__.columns:
        value = getattr(entity, column.name)
        if isinstance(value, datetime):
            result[column.name] = value.isoformat()
        elif isinstance(value, (str, int, float, bool, type(None))):
            result[column.name] = value
        else:
            result[column.name] = str(value)
    return result


def _capture_new_data(result, db: Session, entity_type: str, entity_id: Any):
    new_data: Optional[Dict[str, Any]] | list[Dict[str, Any]] = None
    if hasattr(result, "__dict__"):
        new_data = _serialize_entity(result)
        # Try multiple ID field naming conventions
        # e.g., for 'Permission_Group': permission_group_id, group_id, id
        entity_lower = entity_type.lower()

        # Extract last word after underscore for shortened version (e.g., Permission_Group -> group)
        last_part = entity_lower.split("_")[-1] if "_" in entity_lower else entity_lower

        possible_id_fields = [
            f"{entity_lower}_id",  # permission_group_id
            f"{last_part}_id",  # group_id
            "id",  # id
            f"{entity_lower.replace('_', '')}_id",  # permissiongroup_id
        ]

        for field in possible_id_fields:
            if hasattr(result, field):
                entity_id = getattr(result, field)
                if entity_id is not None:
                    break
    elif isinstance(result, dict):
        new_data = result
        if not entity_id:
            possible_ids = [k for k in result.keys() if "id" in k.lower()]
            if possible_ids:
                entity_id = result[possible_ids[0]]
    elif entity_id:
        new_data = _capture_entity_state(db, entity_type, entity_id)
    return new_data, entity_id


def _filter_changed_fields(old_data: Dict, new_data: Dict) -> Optional[Dict]:
    if not old_data or not new_data:
        return None
    changes = {}
    for key in new_data.keys():
        old_val = old_data.get(key)
        new_val = new_data.get(key)
        if old_val != new_val and key not in ["updated_at", "password"]:
            changes[key] = {"old": old_val, "new": new_val}
    return changes or None


def _build_description(
    template: Optional[str],
    action_type: str,
    entity_type: str,
    old_data: Optional[Dict],
    new_data: Optional[Dict],
    kwargs: Dict,
) -> str:
    if template:
        try:
            return template.format(**kwargs)
        except KeyError:
            pass
    if action_type == "UPDATE" and old_data and new_data:
        if isinstance(new_data, dict) and all(
            isinstance(v, dict) for v in new_data.values()
        ):
            fields = ", ".join(new_data.keys())
            return f"Updated {entity_type}: changed fields - {fields}"
        changes = []
        for key, new_val in new_data.items():
            old_val = old_data.get(key)
            if old_val != new_val and key not in ["updated_at", "password"]:
                changes.append(f"{key}: '{old_val}' → '{new_val}'")
        if changes:
            return f"Updated {entity_type}: {', '.join(changes[:5])}"
    return f"{action_type} operation on {entity_type}"


def _log_audit(
    db: Session,
    user_id: Optional[int],
    action_type: str,
    entity_type: str,
    entity_id: Optional[int],
    old_data: Optional[Dict],
    new_data: Optional[Dict],
    ip_address: Optional[str],
    description: str,
):
    try:
        audit_entry = models.AuditTrail(
            audit_uuid=generate_uuid7(),
            user_id=user_id,
            action_type=action_type,
            entity_type=entity_type,
            entity_id=entity_id,
            old_data=old_data,
            new_data=new_data,
            ip_address=ip_address,
            description=description,
            created_at=datetime.utcnow(),
        )
        db.add(audit_entry)
        db.commit()
    except Exception as e:
        print(f"Audit logging failed: {e}")
        db.rollback()
