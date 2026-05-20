import smtplib
import random
from email.message import EmailMessage

from ...config.env_loader import get_env_var

EMAIL_USER = get_env_var("EMAIL_USER")
EMAIL_PASSWORD = get_env_var("EMAIL_PASSWORD")
EMAIL_HOST = get_env_var("EMAIL_HOST")
EMAIL_PORT = int(get_env_var("EMAIL_PORT"))
FRONTEND_URL = get_env_var("FRONTEND_URL")


def send_email(
    to_email: str,
    subject: str,
    content: str,
):
    msg = EmailMessage()

    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    # Plain text fallback
    msg.set_content(
        "This email requires an HTML-supported email client."
    )

    # HTML content
    msg.add_alternative(content, subtype="html")

    # SMTP connection with timeout
    with smtplib.SMTP(
        EMAIL_HOST,
        EMAIL_PORT,
        timeout=30,
    ) as smtp:

        smtp.ehlo()

        smtp.starttls()

        smtp.ehlo()

        smtp.login(
            EMAIL_USER,
            EMAIL_PASSWORD,
        )

        smtp.send_message(msg)


def generate_otp(length: int = 6) -> str:
    """Generate a numeric OTP of given length."""
    return "".join(
        [str(random.randint(0, 9)) for _ in range(length)]
    )


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