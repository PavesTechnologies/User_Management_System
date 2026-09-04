from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from ...Data_Access_Layer.utils.dependency import SessionLocal
from ...Data_Access_Layer.models.otp import OTP
from ..utils.email_utils import generate_otp, send_otp_email
from ...Data_Access_Layer.dao.auth_dao import AuthDAO
from ...Data_Access_Layer.utils.dependency import get_db
from ..utils.input_validators import validate_email_format
from fastapi import HTTPException, status


def send_otp_service(email: str):
    db: Session = next(get_db())  # Single DB session for entire function
    dao = AuthDAO(db)

    # 1. Validate email format
    validate_email_format(email)

    # 2. Check if user exists
    user = dao.get_user_by_email(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found or inactive"
        )
    name = user.first_name + " " + user.last_name  # Assuming user has first_name and last_name attributes
    # 3. Remove existing OTPs for this email
    db.query(OTP).filter(OTP.email == email).delete()

    # 4. Generate new OTP
    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    # 5. Store OTP in DB
    db_otp = OTP(email=email, otp=otp, expires_at=expires_at)
    db.add(db_otp)
    db.commit()

    # 6. Send OTP email
    send_otp_email(email, name, otp)

    return {"message": "OTP sent successfully"}


def validate_otp_service(email: str, otp: str):
    db: Session = SessionLocal()

    db_otp = db.query(OTP).filter(OTP.email == email, OTP.otp == otp).first()
    if db_otp and db_otp.expires_at > datetime.utcnow():
        db.delete(db_otp)
        db.commit()
        return {"message": "OTP validated successfully"}
    else:
        raise Exception("Invalid or expired OTP")
