import smtplib
import random
import time
import traceback
from email.message import EmailMessage

from ...config.env_loader import get_env_var

EMAIL_USER = get_env_var("EMAIL_USER")
EMAIL_PASSWORD = get_env_var("EMAIL_PASSWORD")
EMAIL_HOST = get_env_var("EMAIL_HOST")
EMAIL_PORT = int(get_env_var("EMAIL_PORT"))
FRONTEND_URL = get_env_var("FRONTEND_URL")


# def send_email(
#     to_email: str,
#     subject: str,
#     content: str,
# ):
#     msg = EmailMessage()

#     msg["Subject"] = subject
#     msg["From"] = EMAIL_USER
#     msg["To"] = to_email

#     # Plain text fallback
#     msg.set_content(
#         "This email requires an HTML-supported email client."
#     )

#     # HTML content
#     msg.add_alternative(content, subtype="html")

#     # SMTP connection with timeout
#     with smtplib.SMTP(
#         EMAIL_HOST,
#         EMAIL_PORT,
#         timeout=30,
#     ) as smtp:

#         smtp.ehlo()

#         smtp.starttls()

#         smtp.ehlo()

#         smtp.login(
#             EMAIL_USER,
#             EMAIL_PASSWORD,
#         )

#         smtp.send_message(msg)


def send_email(
    to_email: str,
    subject: str,
    content: str,
):
    overall_start = time.time()

    try:
        print(f"[EMAIL] Starting email send to {to_email}")

        msg = EmailMessage()

        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = to_email

        msg.set_content("This email requires an HTML-supported email client.")

        msg.add_alternative(
            content,
            subtype="html",
        )

        # -----------------------------
        # SMTP CONNECT
        # -----------------------------
        step_start = time.time()

        smtp = smtplib.SMTP(
            EMAIL_HOST,
            EMAIL_PORT,
            timeout=30,
        )

        print(f"[EMAIL] SMTP Connect: " f"{time.time() - step_start:.2f}s")

        # Uncomment if you want SMTP protocol logs
        # smtp.set_debuglevel(1)

        # -----------------------------
        # EHLO
        # -----------------------------
        step_start = time.time()

        smtp.ehlo()

        print(f"[EMAIL] EHLO: " f"{time.time() - step_start:.2f}s")

        # -----------------------------
        # STARTTLS
        # -----------------------------
        step_start = time.time()

        smtp.starttls()

        print(f"[EMAIL] STARTTLS: " f"{time.time() - step_start:.2f}s")

        # -----------------------------
        # EHLO AGAIN
        # -----------------------------
        step_start = time.time()

        smtp.ehlo()

        print(f"[EMAIL] EHLO2: " f"{time.time() - step_start:.2f}s")

        # -----------------------------
        # LOGIN
        # -----------------------------
        step_start = time.time()

        smtp.login(
            EMAIL_USER,
            EMAIL_PASSWORD,
        )

        print(f"[EMAIL] LOGIN: " f"{time.time() - step_start:.2f}s")

        # -----------------------------
        # SEND EMAIL
        # -----------------------------
        step_start = time.time()

        smtp.send_message(msg)

        print(f"[EMAIL] SEND_MESSAGE: " f"{time.time() - step_start:.2f}s")

        # -----------------------------
        # QUIT
        # -----------------------------
        step_start = time.time()

        smtp.quit()

        print(f"[EMAIL] QUIT: " f"{time.time() - step_start:.2f}s")

        print(f"[EMAIL] TOTAL TIME: " f"{time.time() - overall_start:.2f}s")

    except Exception as e:
        print(f"[EMAIL] ERROR: {str(e)}")

        traceback.print_exc()

        print(f"[EMAIL] FAILED AFTER: " f"{time.time() - overall_start:.2f}s")

        raise


def generate_otp(length: int = 6) -> str:
    """Generate a numeric OTP of given length."""
    return "".join([str(random.randint(0, 9)) for _ in range(length)])


def send_otp_email(to_email: str, otp: str):

    subject = "Your OTP Code"

    content = f"""
    <html>
    <body style="font-family: Arial, sans-serif;">

        <p>Your OTP code is:</p>

        <h2>{otp}</h2>

        <p>It is valid for 5 minutes.</p>

    </body>
    </html>
    """

    send_email(
        to_email,
        subject,
        content,
    )


def send_welcome_email(
    to_email: str,
    name: str,
    temp_password: str,
):
    subject = "Welcome to Paves Technologies"

    content = f"""
    <!DOCTYPE html>
    <html xmlns:th="http://www.thymeleaf.org" lang="en">
    <head>
    <meta charset="UTF-8">
    <title>{subject}</title>
    </head>
    
    <body style="margin:0; padding:0; background:#f3f5f9; font-family:Arial, Helvetica, sans-serif;">
    
    <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 0; background:#f3f5f9;">
    <tr>
    <td align="center">
    
        <!-- MAIN CARD -->
        <table width="640" cellpadding="0" cellspacing="0"
               style="background:#ffffff; border-radius:10px; border:1px solid #e0e4ec;">
    
            <!-- OUTLOOK-SAFE GRADIENT BAR -->
            <tr>
                <td style="height:8px; padding:0; margin:0; line-height:8px;">
                    <div style="background:linear-gradient(90deg, #0A1A44, #3B0E57, #1A4DFF);
                                height:8px; width:100%;"></div>
                </td>
            </tr>
    
            <!-- HEADER -->
            <tr>
                <td style="padding:32px 40px 20px;">
                    <h2 style="margin:0; font-size:22px; color:#0A1A44; font-weight:700;">
                        Welcome to Paves Technologies
                    </h2>
                    <p style="margin:8px 0 0; font-size:14px; color:#666;">
                        Your Enterprise App account has been successfully created
                    </p>
                </td>
            </tr>
    
            <!-- BODY -->
            <tr>
                <td style="padding:10px 40px 30px; font-size:15px; color:#444; line-height:1.7;">
    
                    <!-- Greeting -->
                    <p style="margin:0 0 18px;">
                        Hello <b>{name}</b>,
                    </p>
    
                    <!-- Main message -->
                    <p style="margin:0 0 25px;">
                        Welcome to <b>Paves Technologies</b>!<br><br>
                        Please find your login details below:
                    </p>
    
                    <!-- Details Section -->
                    <div>
                        <div style="margin:0 0 15px;">
                            <div style="font-size:15px; font-weight:700; color:#0A1A44;
                                        border-left:4px solid #1A4DFF; padding-left:10px;">
                                Login Details
                            </div>
                        </div>
    
                        <table width="100%" cellpadding="0" cellspacing="0"
                               style="background:#fafbff; border:1px solid #e2e6ef; border-radius:8px;">
                            <tr>
                                <td style="padding:20px 25px;">
                                    <table width="100%" cellpadding="0" cellspacing="0"
                                           style="font-size:14px; color:#333;">
                                        <tr>
                                            <td style="padding:8px 0; width:150px; font-weight:bold;">
                                                Temporary Password : 
                                            </td>
                                            <td style="padding:8px 0;">
                                                {temp_password}
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </div>
    
                    <!-- Closing message -->
                    <p style="margin:25px 0 10px; color:#555;">
                        For security reasons, you must change your password after logging in for the first time.
                    </p>
    
                    <!-- CTA BUTTON -->
                    <div style="text-align:center; margin:32px 0;">
                        <a href="{FRONTEND_URL}"
                           style="
                               background:#0A1A44;
                               padding:12px 32px;
                               color:#ffffff !important;
                               font-weight:600;
                               font-size:15px;
                               border-radius:6px;
                               text-decoration:none;
                               display:inline-block;
                               border:1px solid #1A4DFF;
                               font-family:Arial, Helvetica, sans-serif;
                           ">
                            Log in to Reset Password
                        </a>
                    </div>
    
                </td>
            </tr>
    
            <!-- FOOTER -->
            <tr>
                <td style="background:#f6f7fb; text-align:center;
                           padding:14px; font-size:12px; color:#888;">
                    © 2024 Paves Technologies. All rights reserved.
                </td>
            </tr>
    
        </table>
    </td>
    </tr>
    </table>
    
    </body>
    </html>
    """

    send_email(
        to_email,
        subject,
        content,
    )

