from flask import Blueprint, jsonify, request, current_app
from ..models.session import Session
import bcrypt
from sqlalchemy.exc import IntegrityError
import re
from ..extensions import db
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt, create_refresh_token
from ..models.member import Member
from ..models.role import Role
from ..schemas.member import MemberSchema
from ..utils.logging import logger
from datetime import datetime, timedelta
from ..extensions import limiter
import secrets
import hashlib
from ..utils.email import send_password_reset_email
from ..utils.email import send_otp_email
from  ..utils.notify import notify_all_admins
from ..utils.helpers import resolve_request_org, initialize_roles, RESERVED_SUBDOMAINS, is_valid_slug, normalize_slug, SLUG_RULES_MESSAGE, build_reset_link
from ..models.organization import Organization

auth_bp = Blueprint('auth', __name__)
member_schema = MemberSchema()

REQUIRED_SIGNUP_FIELDS = ['name', 'email', 'password']

def _email_key():
    """Rate-limit bucket for one email on one gallery. The same address on two
    galleries is two separate accounts, so it must be two separate buckets —
    otherwise hammering one gallery would throttle the other."""
    data = request.get_json(silent=True) or {}
    org = resolve_request_org(data)
    gallery = org.slug if org else 'no-gallery'
    email = str(data.get('email', 'unknown')).strip().lower()
    return f"{gallery}:{email}"
def _ip_limit_alarm(request_limit):
    data = request.get_json(silent=True) or {}
    org = resolve_request_org(data)
    member = Member.query.filter_by(organization_id=org.id, email=data.get('email')).first() if org else None
    if member:
        _register_violation(member, 'ip')
    logger.warning(f"IP rate limit breached on {request.path} — possible multi-account or automated attack: {request.remote_addr}")
    notify_all_admins(f"IP rate limit breached on {request.path} from {request.remote_addr}", member.organization_id if member else None)    
def _email_limit_alarm(request_limit):
    data = request.get_json(silent=True) or {}
    org = resolve_request_org(data)
    member = Member.query.filter_by(organization_id=org.id, email=data.get('email')).first() if org else None
    if member:
        _register_violation(member, 'email')
    logger.warning(f"Email rate limit breached on {request.path} — possible targeted attack on account: {data.get('email')}")
    notify_all_admins(f"Email rate limit breached on {request.path} for account {data.get('email')}", member.organization_id if member else None)    
def _register_violation(member, kind):
    if kind == 'email':
        violations_attr, locked_attr, cap_minutes = 'email_rate_violations', 'email_rate_locked_until', 15
    else:
        violations_attr, locked_attr, cap_minutes = 'ip_rate_violations', 'ip_rate_locked_until', 5

    violations = getattr(member, violations_attr) + 1
    wait_seconds = min(30 * (2 ** (violations - 1)), cap_minutes * 60)
    setattr(member, violations_attr, violations)
    setattr(member, locked_attr, datetime.now() + timedelta(seconds=wait_seconds))
    db.session.commit()

    if wait_seconds >= cap_minutes * 60:
        logger.warning(f"{kind.upper()} rate-limit escalation maxed for {member.email} — possible sustained attack")


def _check_escalation_lock(member):
    now = datetime.now()
    for locked_attr in ['email_rate_locked_until', 'ip_rate_locked_until']:
        locked_until = getattr(member, locked_attr)
        if locked_until and locked_until > now:
            wait = int((locked_until - now).total_seconds())
            return jsonify({"message": f"Too many attempts. Try again in {wait} seconds."}), 429
    return None
def _issue_tokens_and_session(member):
    """Create an access+refresh token pair that share one session ID (sid),
    and one Session row tracking that pair. Both tokens carry the same sid
    as a custom claim, so /refresh, /logout, and the blocklist check can all
    look a session up regardless of which of the two tokens they were given
    — a single login only ever needs one Session row, not one per token."""
    session_id = secrets.token_hex(16)
    access_token = create_access_token(identity=str(member.id), additional_claims={"sid": session_id, "org_id": member.organization_id})
    refresh_token = create_refresh_token(identity=str(member.id), additional_claims={"sid": session_id, "org_id": member.organization_id})

    new_session = Session(
        organization_id=member.organization_id,
        member_id=member.id,
        jti=session_id,
        device_info=request.headers.get('User-Agent'),
        ip_address=request.remote_addr
    )
    db.session.add(new_session)

    # Opportunistic cleanup: remove this member's own sessions older than 7 days
    week_ago = datetime.now() - timedelta(days=7)
    Session.query.filter(Session.member_id == member.id, Session.created_at < week_ago).delete()

    db.session.commit()
    return access_token, refresh_token
def _is_gallery_creation():
    """True when this sign-up is creating a brand-new gallery (rather than
    joining one that already exists)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return False
    return bool(data.get('gallery_name') and data.get('gallery_slug')) and resolve_request_org(data) is None

@auth_bp.route("/sign-up", methods=["POST"])
@limiter.limit(lambda: current_app.config['GALLERY_CREATE_LIMIT'], exempt_when=lambda: not _is_gallery_creation())
@limiter.limit("15 per minute", on_breach=_ip_limit_alarm)
@limiter.limit("8 per minute", key_func=_email_key, on_breach=_email_limit_alarm)
def signup():
    data = request.get_json(silent=True)

    if data is None:
        logger.warning("Signup failed: request body was missing or not valid JSON")
        return jsonify({"message": "Request body must be valid JSON"}), 400

    required_fields = ['name', 'email', 'password']
    missing = [field for field in required_fields if not data.get(field)]
    if missing:
        logger.warning(f"Signup failed: missing/empty field(s) {missing}. Received keys: {list(data.keys())}")
        return jsonify({
            "message": f"Missing or empty field(s): {', '.join(missing)}",
            "missing_fields": missing,
            "received_fields": list(data.keys())
        }), 400

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    try:
        if name.isspace():
            return jsonify({"message": "Name cannot be just spaces"}), 400

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({"message": "Email format is invalid"}), 400

        password_errors = []
        if len(password) < 8:
            password_errors.append("at least 8 characters")
        if not re.search(r'[A-Z]', password):
            password_errors.append("an uppercase letter")
        if not re.search(r'[a-z]', password):
            password_errors.append("a lowercase letter")
        if not re.search(r'\d', password):
            password_errors.append("a number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            password_errors.append("a special character")
        if password_errors:
            return jsonify({
                "message": f"Password must contain: {', '.join(password_errors)}",
                "password_requirements": password_errors
            }), 400
        org = resolve_request_org(data)

        if org:
            if org.status != 'active':
                return jsonify({"message": "This gallery has been suspended"}), 403
            # Joining an existing gallery — always as 'member'. Promotion to
            # curator/admin is an existing admin's job (PUT /members/<id>/role),
            # never something signup grants directly.
            role_name = 'member'
        else:

            # No gallery resolved from the subdomain or org_slug — only
            # treat this as "create a new gallery" if the request clearly
            # says so. Otherwise it's just an unresolvable join attempt,
            # same as login's 404.
            gallery_name = data.get('gallery_name')
            gallery_slug = data.get('gallery_slug')
            if not gallery_name or not gallery_slug:
                return jsonify({
                    "message": "Gallery not found. To join an existing gallery, include 'org_slug'. To create a new one, include 'gallery_name' and 'gallery_slug'."
                }), 404
            if not isinstance(gallery_name, str) or not gallery_name.strip() or len(gallery_name.strip()) > 150:
                return jsonify({"message": "gallery_name must be 1-150 characters"}), 400
            gallery_name = gallery_name.strip()

            gallery_slug = normalize_slug(gallery_slug)
            if not is_valid_slug(gallery_slug):
                return jsonify({"message": f"gallery_slug {SLUG_RULES_MESSAGE}"}), 400
            if gallery_slug in RESERVED_SUBDOMAINS:
                return jsonify({"message": "That gallery address is reserved — choose another"}), 400
            if Organization.query.filter_by(slug=gallery_slug).first():
                return jsonify({"message": "That gallery address is already taken"}), 400

            org = Organization(name=gallery_name, slug=gallery_slug)
            db.session.add(org)
            db.session.flush()  # gives the gallery an id without saving it yet
            initialize_roles(db, org.id, commit=False)
            role_name = 'admin'  # first member of a brand-new gallery

        if Member.query.filter_by(organization_id=org.id, email=email).first():
            return jsonify({"message": "Email already exists for this gallery"}), 400

        role = Role.query.filter_by(organization_id=org.id, name=role_name).first()
        if not role:
            return jsonify({"message": f"Role '{role_name}' not found for this gallery"}), 500

        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)


        new_member = Member(
            organization_id=org.id,
            name=name,
            email=email,
            role_id=role.id,
            password=hashed_password.decode('utf-8'),
        )
        db.session.add(new_member)
        db.session.commit()
        logger.info(f"New user signed up: '{name}' <{email}> as {role_name} of '{org.name}'")
        return jsonify({
            "message": "Sign up successful",
            "gallery": {"id": org.id, "name": org.name, "slug": org.slug}
        }), 201
    except IntegrityError:
        # Two people grabbed the same address (or email) at the same moment.
        db.session.rollback()
        logger.warning(f"Signup conflict for '{email}': address or email already taken at save time")
        return jsonify({"message": "That gallery address or email is already in use"}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Unexpected error during signup for email '{email}': {str(e)}")
        return jsonify({"message": "An error occurred during signup"}), 500

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("15 per minute", on_breach=_ip_limit_alarm)
@limiter.limit("8 per minute", key_func=_email_key, on_breach=_email_limit_alarm)
def login():
    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    missing = [field for field in ['email', 'password'] if not data.get(field)]
    if missing:
        return jsonify({
            "message": f"Missing field(s): {', '.join(missing)}",
            "missing_fields": missing
        }), 400

    email = data.get("email")
    password = data.get("password")
    

    try:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({"message": "Invalid email or password"}), 401

        org = resolve_request_org(data)
        if not org:
            return jsonify({"message": "Gallery not found. Check your gallery's web address, or include 'org_slug' in the request."}), 404
        if org.status != 'active':
            return jsonify({"message": "This gallery has been suspended"}), 403

        member = Member.query.filter_by(organization_id=org.id, email=email).first()
        if not member:
            return jsonify({"message": "Invalid email or password"}), 401
        escalation_response = _check_escalation_lock(member)
        if escalation_response:
            return escalation_response

        # Hard lock — only an admin can clear this, regardless of anything else.
        if member.admin_locked:
            return jsonify({"message": "This account has been blocked. Contact an admin to regain access."}), 403

        # Temporary lock — still active, even a correct password is rejected.
        if member.locked_until and member.locked_until > datetime.now():
            return jsonify({
                "message": "This account is temporarily locked due to failed login attempts. Use the unlock route to regain access."
            }), 403

        if not bcrypt.checkpw(password.encode('utf-8'), member.password.encode('utf-8')):
            member.failed_attempts += 1
            if member.failed_attempts >= 4:
                member.locked_until = datetime.now() + timedelta(minutes=30)
                logger.warning(f"Account locked after 4 failed attempts: {email}")
            db.session.commit()
            return jsonify({"message": "Invalid email or password"}), 401

        # Correct password — reset the counter and log them in normally.
        member.failed_attempts = 0
        member.email_rate_violations = 0
        member.email_rate_locked_until = None
        member.ip_rate_violations = 0
        member.ip_rate_locked_until = None
        db.session.commit()

        access_token, refresh_token = _issue_tokens_and_session(member)
        logger.info(f"Successful login for user: {member.email}")
        return jsonify({
            "message": f"Welcome {member.name}",
            "member": member_schema.dump(member),
            "access_token": access_token,
            "refresh_token": refresh_token
        })
    except Exception as e:
        logger.error(f"Unexpected error during login for email '{email}': {str(e)}")
        return jsonify({"message": "An error occurred during login"}), 500

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        session_id = get_jwt().get('sid')

        session = Session.query.filter_by(jti=session_id).first()
        if not session or session.revoked:
            return jsonify({"message": "Session no longer valid"}), 401

        member = Member.query.get(current_user_id)
        if not member:
            return jsonify({"message": "Session no longer valid"}), 401

        if member.organization and member.organization.status != 'active':
            return jsonify({"message": "This gallery has been suspended"}), 403

        # Same session ID on the new pair — this is still the same login
        # session, just renewed tokens. No need to touch the Session row at
        # all; it stays valid exactly as it was.
        new_access_token = create_access_token(identity=current_user_id, additional_claims={"sid": session_id, "org_id": member.organization_id})
        new_refresh_token = create_refresh_token(identity=current_user_id, additional_claims={"sid": session_id, "org_id": member.organization_id})
        return jsonify({
            "access_token": new_access_token,
            "refresh_token": new_refresh_token
        })
    except Exception as e:
        logger.error(f"Error during token refresh: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500    
@auth_bp.route("/login/unlock/request-otp", methods=["POST"])
@limiter.limit("15 per minute", on_breach=_ip_limit_alarm)
@limiter.limit("1 per 2 minutes", key_func=_email_key, on_breach=_email_limit_alarm)
def request_unlock_otp():
    data = request.get_json(silent=True)
    if not data or not data.get('email'):
        return jsonify({"message": "email is required"}), 400

    email = data.get('email')
    try:
        org = resolve_request_org(data)
        member = Member.query.filter_by(organization_id=org.id, email=email).first() if org else None
        # Same response whether or not the account exists / is locked, so
        # this route can't be used to probe which emails exist or are locked.
        generic_response = jsonify({"message": "Account is locked, a code has been sent to its email."})

        if not member:
            return generic_response
        if member.admin_locked:
            return generic_response
        if not member.locked_until or member.locked_until <= datetime.now():
            return generic_response

        otp_code = f"{secrets.randbelow(1000000):06d}"
        salt = bcrypt.gensalt()
        member.otp_code_hash = bcrypt.hashpw(otp_code.encode('utf-8'), salt).decode('utf-8')
        member.otp_expires_at = datetime.now() + timedelta(minutes=10)
        member.otp_attempts = 0
        db.session.commit()

        send_otp_email(member.email, otp_code)
        logger.info(f"OTP requested for locked account: {email}")
        return generic_response
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error requesting unlock OTP: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@auth_bp.route("/login/unlock/verify-otp", methods=["POST"])
@limiter.limit("15 per minute", on_breach=_ip_limit_alarm)
@limiter.limit("8 per minute", key_func=_email_key, on_breach=_email_limit_alarm)
def verify_unlock_otp():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    missing = [field for field in ['email', 'otp_code'] if not data.get(field)]
    if missing:
        return jsonify({
            "message": f"Missing field(s): {', '.join(missing)}",
            "missing_fields": missing
        }), 400

    email = data.get('email')
    otp_code = data.get('otp_code')

    try:
        org = resolve_request_org(data)
        member = Member.query.filter_by(organization_id=org.id, email=email).first() if org else None
        if not member:
            return jsonify({"message": "Invalid email or code"}), 401

        escalation_response = _check_escalation_lock(member)
        if escalation_response:
            return escalation_response

        if member.admin_locked:
            return jsonify({"message": "This account has been blocked by an admin. This route cannot unlock it — contact an admin."}), 403

        if not member.locked_until or member.locked_until <= datetime.now():
            return jsonify({"message": "This account is not currently locked."}), 400

        if not member.otp_code_hash or not member.otp_expires_at or member.otp_expires_at <= datetime.now():
            return jsonify({"message": "No valid code found. Request a new one."}), 400

        code_correct = bcrypt.checkpw(otp_code.encode('utf-8'), member.otp_code_hash.encode('utf-8'))

        if not code_correct:
            member.otp_attempts += 1
            if member.otp_attempts >= 3:
                member.otp_code_hash = None
                member.otp_expires_at = None
                logger.warning(f"OTP verification failed 3 times, code invalidated: {email}")
            db.session.commit()
            return jsonify({"message": "Invalid or expired code"}), 401

        # Correct code — clear the lock entirely and log them in.
        member.locked_until = None
        member.failed_attempts = 0
        member.otp_attempts = 0
        member.otp_code_hash = None
        member.otp_expires_at = None
        member.email_rate_violations = 0
        member.email_rate_locked_until = None
        member.ip_rate_violations = 0
        member.ip_rate_locked_until = None
        db.session.commit()

        access_token, refresh_token = _issue_tokens_and_session(member)
        logger.info(f"Account unlocked via OTP: {email}")
        return jsonify({
            "message": f"Account unlocked. Welcome {member.name}",
            "member": member_schema.dump(member),
            "access_token": access_token,
            "refresh_token": refresh_token
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error verifying unlock OTP: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
@auth_bp.route("/login/request-recovery", methods=["POST"])
@limiter.limit("5 per minute", key_func=_email_key)
def request_recovery():
    data = request.get_json(silent=True)
    if not data or not data.get('email'):
        return jsonify({"message": "Email is required"}), 400

    email = data.get('email')
    org = resolve_request_org(data)
    member = Member.query.filter_by(organization_id=org.id, email=email).first() if org else None

    # Always return the same generic message, whether or not the account
    # exists — same enumeration protection as login.
    if member:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        member.password_reset_token = token_hash
        member.password_reset_expires = datetime.now() + timedelta(minutes=15)
        db.session.commit()

        reset_link = build_reset_link(org, token)    
        send_password_reset_email(member.email, reset_link)

    return jsonify({"message": "If an account with that email exists, a recovery link has been sent."})


@auth_bp.route("/login/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True)
    if not data or not data.get('token') or not data.get('new_password'):
        return jsonify({"message": "Token and new_password are required"}), 400

    token = data.get('token')
    new_password = data.get('new_password')

    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    member = Member.query.filter_by(password_reset_token=token_hash).first()
    if not member or not member.password_reset_expires or member.password_reset_expires < datetime.now():
        return jsonify({"message": "This reset link is invalid or has expired"}), 400

    password_errors = []
    if len(new_password) < 8:
        password_errors.append("at least 8 characters")
    if not re.search(r'[A-Z]', new_password):
        password_errors.append("an uppercase letter")
    if not re.search(r'[a-z]', new_password):
        password_errors.append("a lowercase letter")
    if not re.search(r'\d', new_password):
        password_errors.append("a number")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        password_errors.append("a special character")
    if password_errors:
        return jsonify({
            "message": f"Password must contain: {', '.join(password_errors)}",
            "password_requirements": password_errors
        }), 400

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), salt)
    member.password = hashed.decode('utf-8')

    # Successful reset proves ownership — clear the reset token AND every
    # lockout/rate-limit state, same as a manual admin unblock.
    member.password_reset_token = None
    member.password_reset_expires = None
    member.failed_attempts = 0
    member.locked_until = None
    member.unlock_attempts = 0
    member.email_rate_violations = 0
    member.email_rate_locked_until = None
    member.ip_rate_violations = 0
    member.ip_rate_locked_until = None
    Session.query.filter_by(member_id=member.id, revoked=False).update({
        "revoked": True,
        "revoked_at": datetime.now(),
        "revoked_by": "password_reset"
    })
    db.session.commit()

    logger.info(f"Password reset completed for {member.email}")
    return jsonify({"message": "Password reset successful. You can now log in with your new password."})
@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    try:
        session_id = get_jwt().get('sid')
        session = Session.query.filter_by(jti=session_id).first()
        if session:
            session.revoked = True
            session.revoked_at = datetime.now()
            session.revoked_by = "self"
            db.session.commit()
        return jsonify({"message": "Logged out successfully"})
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500