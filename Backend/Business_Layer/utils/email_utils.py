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


from datetime import datetime


def send_otp_email(to_email: str, name: str, otp: str):

    subject = "OTP Verification"

    # Add spacing between each OTP digit
    formatted_otp = "".join(
        f'<span style="display:inline-block; margin-right:6px;">{digit}</span>'
        for digit in otp
    )

    content = f"""
    <!DOCTYPE html>
    <html xmlns:th="http://www.thymeleaf.org" lang="en">
    <head>
    <meta charset="UTF-8">
    <title><b>{subject}</b></title>
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
                                background-image:linear-gradient(90deg, #0A1A44, #3B0E57, #1A4DFF);
                                height:8px; width:100%;"></div>
                </td>
            </tr>
    
            <!-- HEADER -->
            <tr>
                <td style="padding:32px 40px 20px;">
                    <h2 style="margin:0; font-size:22px; color:#0A1A44; font-weight:700;">
                        Your OTP Code
                    </h2>
                    <p style="margin:8px 0 0; font-size:14px; color:#666;">
                        Notification from Paves Technologies User Management System
                    </p>
                </td>
            </tr>
    
            <!-- BODY -->
            <tr>
                <td style="padding:10px 40px 30px; font-size:15px; color:#444; line-height:1.7;">
    
                    <!-- Greeting -->
                    <p style="margin:0 0 18px;">
                        Dear <b>{name}</b>,
                    </p>

                    <p style="margin:0 0 18px;">
                        Please use the following One-Time Password (OTP) to complete your verification for Enterprise Apps.
                    </p>
    
                    <!-- Main Message -->
                    <div>
                        <div style="margin:0 0 15px;">
                            <div style="font-size:15px; font-weight:700; color:#0A1A44;
                                        border-left:4px solid #1A4DFF; padding-left:10px;">
                               Your OTP is valid for 5 minutes. Please do not share this code with anyone.
                            </div>
                        </div>
    
                        <table width="100%" cellpadding="0" cellspacing="0"
                               style="background:#fafbff; border:1px solid #e2e6ef; border-radius:8px;">
                            <tr>
                                <td style="padding:20px 25px; text-align:center;">
                                    
                                    <div style="
                                        font-size:24px;
                                        font-weight:700;
                                        color:#0A1A44;
                                        font-family:Arial, Helvetica, sans-serif;
                                        letter-spacing:6px;
                                        line-height:1.4;
                                    ">
                                        {formatted_otp}
                                    </div>

                                </td>
                            </tr>
                        </table>
                    </div>

                    <div style="text-align:center; margin:32px 0;">
                        <a href="https://d2id2c6d521acd.cloudfront.net"
                           style="
                            background:#1A4DFF;
                            padding:12px 32px;
                            color:#ffffff !important;
                            font-weight:600;
                            font-size:15px;
                            border-radius:6px;
                            text-decoration:none;
                            display:inline-block;
                            border:1px solid #1A4DFF;
                            font-family:Arial, Helvetica, sans-serif;
                            text-align:center;
                        ">
                        <span style="color:#ffffff !important;">
                            View in User Management System
                        </span>
                        </a>
                    </div>
    
                </td>
            </tr>
    
            <!-- FOOTER -->
            <tr>
                <td style="background:#f6f7fb; text-align:center;
                           padding:14px; font-size:12px; color:#888;">
                    © 2026 Paves Technologies. All rights reserved.
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

def send_welcome_email(
    to_email: str,
    name: str,
    temp_password: str,
):

    subject = "Welcome to Paves Technologies"

    content = f"""
    <html>
    <body
        style="
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333333;
        "
    >

        <p>Hello {name},</p>

        <p>
            Welcome to
            <b>Paves Technologies</b>!
        </p>

        <p>
            Your intranet account has been successfully created.
        </p>

        <p>
            Please find your login details below:
        </p>

        <p>
            <b>Temporary Password:</b>
            {temp_password}
        </p>

        <p>
            <b>Important:</b>
            For security reasons, you must change your password
            after logging in for the first time.
            You will not be able to continue using the intranet
            until your password has been updated.
        </p>

        <p>
            You can log in and reset your password here:
            <br>

            <a href="{FRONTEND_URL}">
                {FRONTEND_URL}
            </a>
        </p>

        <p>
            If you did not expect this email or believe it was
            sent in error, please contact the system administrator
            immediately.
        </p>

        <br>

        <table
            cellpadding="0"
            cellspacing="0"
            border="0"
            width="100%"
        >
            <tr>
                <td>

                    <p style="margin:0;">
                        Best regards,
                    </p>

                    <p style="margin:8px 0;">
                        <b>User Management Team</b>
                    </p>

                    <!-- PUBLIC IMAGE URL -->
                    <img
                        src="https://pavestechnologies.com/wp-content/uploads/2023/05/Paves-Logo.png"
                        alt="Paves Technologies"
                        width="180"
                        style="display:block;"
                    >

                    <p style="margin:0;">
                        <b>Paves Technologies</b>
                    </p>

                    <p style="margin:5px 0;">
                        Vasavi Sky City,
                        10th Floor,
                        Quick Start Co-working,
                        <br>

                        Telecom Nagar,
                        Gachibowli,
                        Hyderabad
                    </p>

                    <p style="margin:5px 0;">
                        +91 9059364400
                    </p>

                    <p style="margin:5px 0;">
                        <a href="https://pavestechnologies.com/">
                            https://pavestechnologies.com/
                        </a>
                    </p>

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
