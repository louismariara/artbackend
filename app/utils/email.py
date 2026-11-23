from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask import current_app
from .logging import logger


def send_password_reset_email(to_email, reset_link):
    message = Mail(
        from_email=(current_app.config['SENDGRID_FROM_EMAIL'], 'Art Website'),
        to_emails=to_email,
        subject='Reset your password',
        html_content=f'<p>Click the link below to reset your password. This link expires in 15 minutes.</p><p><a href="{reset_link}">{reset_link}</a></p>'
    )
    try:
        sg = SendGridAPIClient(current_app.config['SENDGRID_API_KEY'])
        response = sg.send(message)
        logger.info(f"Password reset email sent to {to_email}, status {response.status_code}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {to_email}: {str(e)}")
        return False
    

def send_otp_email(to_email, otp_code):
    message = Mail(
        from_email=(current_app.config['SENDGRID_FROM_EMAIL'], 'Art Website'),
        to_emails=to_email,
        subject='Your account unlock code',
        html_content=f'<p>Your one-time code to unlock your account is:</p><p style="font-size:24px;font-weight:bold;">{otp_code}</p><p>This code expires in 10 minutes. If you did not request this, you can ignore this email.</p>'
    )
    try:
        sg = SendGridAPIClient(current_app.config['SENDGRID_API_KEY'])
        response = sg.send(message)
        logger.info(f"OTP email sent to {to_email}, status {response.status_code}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {to_email}: {str(e)}")
        return False