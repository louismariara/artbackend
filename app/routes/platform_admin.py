from flask import Blueprint, jsonify, request, g
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt, get_jwt_identity
import hashlib
from datetime import datetime, timedelta, date
import bcrypt
import re
import secrets
from ..extensions import db, limiter
from ..models.super_admin import SuperAdmin
from ..models.super_admin_session import SuperAdminSession
from ..models.organization import Organization
from ..models.member import Member
from ..models.role import Role
from ..models.artwork import Artwork
from ..utils.logging import logger
from ..utils.decorators import super_admin_required
from ..utils.helpers import RESERVED_SUBDOMAINS, apply_lease, is_valid_slug, normalize_slug, SLUG_RULES_MESSAGE, build_reset_link
from ..utils.email import send_password_reset_email, send_lease_reminder_email
from ..utils.notify import notify_all_admins

platform_admin_bp = Blueprint('platform_admin', __name__, url_prefix='/platform-admin')

LEASE_NOTICE_DAYS = 14


def _lease_view(org):
    """How the platform should describe a gallery's paid period.
    unset: nobody has recorded a payment yet.
    current: more than two weeks left.
    expiring: two weeks or less.
    expired: the paid-through date has passed."""
    today = date.today()
    paid = org.paid_until
    if paid is None:
        return {"paid_until": None, "lease_state": "unset", "days_left": None}
    days_left = (paid - today).days
    if days_left < 0:
        state = "expired"
    elif days_left <= LEASE_NOTICE_DAYS:
        state = "expiring"
    else:
        state = "current"
    return {"paid_until": paid.isoformat(), "lease_state": state, "days_left": days_left}


def _issue_super_admin_tokens(super_admin):
    """Same pattern as auth.py's _issue_tokens_and_session, but for platform
    accounts: tokens carry 'scope': 'platform' instead of an org_id, and the
    session is tracked in SuperAdminSession, not the gallery-member Session table."""
    session_id = secrets.token_hex(16)
    access_token = create_access_token(
        identity=str(super_admin.id),
        additional_claims={"sid": session_id, "scope": "platform"}
    )
    refresh_token = create_refresh_token(
        identity=str(super_admin.id),
        additional_claims={"sid": session_id, "scope": "platform"}
    )

    new_session = SuperAdminSession(
        super_admin_id=super_admin.id,
        jti=session_id,
        device_info=request.headers.get('User-Agent'),
        ip_address=request.remote_addr
    )
    db.session.add(new_session)
    week_ago = datetime.now() - timedelta(days=7)
    SuperAdminSession.query.filter(
        SuperAdminSession.super_admin_id == super_admin.id,
        SuperAdminSession.created_at < week_ago
    ).delete()
    db.session.commit()
    return access_token, refresh_token
def _platform_email_key():
    data = request.get_json(silent=True) or {}
    return f"platform-login:{str(data.get('email', 'unknown')).lower()}"


def _platform_login_breach(request_limit):
    data = request.get_json(silent=True) or {}
    logger.warning(f"Platform-admin login rate limit breached from {request.remote_addr} for email '{data.get('email')}'")


# Checked against when the email doesn't exist, so a wrong email takes as
# long to reject as a wrong password (no timing clue about which emails exist).
_DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt())


@platform_admin_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute", on_breach=_platform_login_breach)
@limiter.limit("5 per minute", key_func=_platform_email_key, on_breach=_platform_login_breach)
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
    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({"message": "Invalid email or password"}), 401

    try:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({"message": "Invalid email or password"}), 401

        super_admin = SuperAdmin.query.filter_by(email=email).first()
        hash_to_check = super_admin.password.encode('utf-8') if super_admin else _DUMMY_HASH
        password_ok = bcrypt.checkpw(password.encode('utf-8'), hash_to_check)
        if not super_admin or not password_ok:
            logger.warning(f"Failed super admin login for '{email}' from {request.remote_addr}")
            return jsonify({"message": "Invalid email or password"}), 401

        access_token, refresh_token = _issue_super_admin_tokens(super_admin)
        logger.info(f"Super admin logged in: {super_admin.email}")
        return jsonify({
            "message": f"Welcome {super_admin.name}",
            "super_admin": {"id": super_admin.id, "name": super_admin.name, "email": super_admin.email},
            "access_token": access_token,
            "refresh_token": refresh_token
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during super admin login: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
@platform_admin_bp.route("/galleries", methods=["GET"])
@super_admin_required
def list_galleries():
    try:
        orgs = Organization.query.order_by(Organization.created_at.desc()).all()
        galleries = []
        for org in orgs:
            apply_lease(org)
            galleries.append({
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
                "status": org.status,
                "created_at": org.created_at.isoformat(),
                "member_count": Member.query.filter_by(organization_id=org.id).count(),
                "artwork_count": Artwork.query.filter_by(organization_id=org.id).count(),
                **_lease_view(org),
            })
        return jsonify({"galleries": galleries}), 200
    except Exception as e:
        logger.error(f"Error listing galleries: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
@platform_admin_bp.route("/galleries/<int:org_id>/suspend", methods=["PATCH"])
@super_admin_required
def suspend_gallery(org_id):
    try:
        org = Organization.query.get(org_id)
        if not org:
            return jsonify({"message": "Gallery not found"}), 404
        if org.status == 'suspended':
            return jsonify({"message": "Gallery is already suspended"}), 400

        org.status = 'suspended'
        org.suspended_reason = 'manual'
        db.session.commit()
        logger.info(f"Gallery '{org.name}' (id={org.id}) suspended by super admin {g.current_super_admin.email}")
        return jsonify({"message": f"'{org.name}' has been suspended", "gallery": {"id": org.id, "status": org.status}}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error suspending gallery {org_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@platform_admin_bp.route("/galleries/<int:org_id>/reactivate", methods=["PATCH"])
@super_admin_required
def reactivate_gallery(org_id):
    try:
        org = Organization.query.get(org_id)
        if not org:
            return jsonify({"message": "Gallery not found"}), 404
        if org.status == 'active':
            return jsonify({"message": "Gallery is already active"}), 400
        if org.paid_until is not None and org.paid_until < date.today():
            return jsonify({
                "message": "This gallery's paid period has ended. Set a new paid-through date before reactivating it."
            }), 400

        org.status = 'active'
        org.suspended_reason = None
        db.session.commit()
        logger.info(f"Gallery '{org.name}' (id={org.id}) reactivated by super admin {g.current_super_admin.email}")
        return jsonify({"message": f"'{org.name}' has been reactivated", "gallery": {"id": org.id, "status": org.status}}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error reactivating gallery {org_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
@platform_admin_bp.route("/galleries/<int:org_id>", methods=["PATCH"])
@super_admin_required
def update_gallery(org_id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    new_name = data.get('name')
    new_slug = data.get('slug')
    if new_name is None and new_slug is None:
        return jsonify({"message": "Provide 'name' and/or 'slug' to update"}), 400

    try:
        org = Organization.query.get(org_id)
        if not org:
            return jsonify({"message": "Gallery not found"}), 404

        # Validate everything first, apply only once all of it passes — so a
        # bad slug can't leave a half-applied name change sitting in the session.
        if new_name is not None:
            new_name = new_name.strip()
            if not new_name or len(new_name) > 150:
                return jsonify({"message": "name must be 1-150 characters"}), 400

        if new_slug is not None:
            new_slug = normalize_slug(new_slug)
            if not is_valid_slug(new_slug):
                return jsonify({"message": f"slug {SLUG_RULES_MESSAGE}"}), 400
            if new_slug in RESERVED_SUBDOMAINS:
                return jsonify({"message": "That gallery address is reserved — choose another"}), 400
            taken = Organization.query.filter(Organization.slug == new_slug, Organization.id != org.id).first()
            if taken:
                return jsonify({"message": "That gallery address is already taken"}), 400

        old_name, old_slug = org.name, org.slug
        if new_name is not None:
            org.name = new_name
        if new_slug is not None:
            org.slug = new_slug
        db.session.commit()

        logger.info(f"Gallery id={org.id} updated by super admin {g.current_super_admin.email}: name '{old_name}' -> '{org.name}', slug '{old_slug}' -> '{org.slug}'")
        return jsonify({
            "message": "Gallery updated",
            "gallery": {"id": org.id, "name": org.name, "slug": org.slug, "status": org.status, **_lease_view(org)}
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating gallery {org_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
@platform_admin_bp.route("/galleries/<int:org_id>/members", methods=["GET"])
@super_admin_required
def view_gallery_members(org_id):
    """Read-only support view. Builds each row from an explicit allow-list of
    fields, so password hashes, OTP hashes and reset tokens can never leak."""
    try:
        org = Organization.query.get(org_id)
        if not org:
            return jsonify({"message": "Gallery not found"}), 404

        now = datetime.now()
        members = Member.query.filter_by(organization_id=org.id).order_by(Member.id).all()
        return jsonify({
            "gallery": {"id": org.id, "name": org.name, "slug": org.slug, "status": org.status, "currency": org.currency, **_lease_view(org)},
            "members": [{
                "id": m.id,
                "name": m.name,
                "email": m.email,
                "role": m.role.name if m.role else None,
                "admin_locked": m.admin_locked,
                "locked": bool(m.locked_until and m.locked_until > now),
                "locked_until": m.locked_until.isoformat() if m.locked_until else None,
            } for m in members]
        }), 200
    except Exception as e:
        logger.error(f"Error viewing members of gallery {org_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@platform_admin_bp.route("/galleries/<int:org_id>/artworks", methods=["GET"])
@super_admin_required
def view_gallery_artworks(org_id):
    try:
        org = Organization.query.get(org_id)
        if not org:
            return jsonify({"message": "Gallery not found"}), 404

        artworks = Artwork.query.filter_by(organization_id=org.id).order_by(Artwork.id).all()
        return jsonify({
            "gallery": {"id": org.id, "name": org.name, "slug": org.slug, "status": org.status, "currency": org.currency},
            "artworks": [{
                "id": a.id,
                "title": a.title,
                "artist": a.artist,
                "category": a.category,
                "price": float(a.price) if a.price is not None else None,
                "views": a.views,
                "owner_member_id": a.member_id,
            } for a in artworks]
        }), 200
    except Exception as e:
        logger.error(f"Error viewing artworks of gallery {org_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
@platform_admin_bp.route("/galleries/<int:org_id>/lease", methods=["PATCH"])
@super_admin_required
def set_gallery_lease(org_id):
    """Record how long this gallery has paid for. There is no payment
    provider yet, so a super admin types the paid-through date by hand.
    Send paid_until as YYYY-MM-DD, or null to clear it."""
    data = request.get_json(silent=True)
    if data is None or 'paid_until' not in data:
        return jsonify({"message": "Provide paid_until as YYYY-MM-DD, or null to clear it"}), 400

    raw = data.get('paid_until')
    try:
        org = Organization.query.get(org_id)
        if not org:
            return jsonify({"message": "Gallery not found"}), 404
        if raw in (None, ''):
            org.paid_until = None
        else:
            if not isinstance(raw, str):
                return jsonify({"message": "paid_until must be a date like 2026-12-31"}), 400
            org.paid_until = date.fromisoformat(raw)
        db.session.commit()
        apply_lease(org)
        logger.info(f"Gallery '{org.name}' paid_until set to {org.paid_until} by {g.current_super_admin.email}")
        return jsonify({
            "message": "Lease updated",
            "gallery": {"id": org.id, "name": org.name, "status": org.status, **_lease_view(org)}
        }), 200
    except ValueError:
        return jsonify({"message": "paid_until must be a date like 2026-12-31"}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error setting lease for gallery {org_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@platform_admin_bp.route("/galleries/<int:org_id>/lease-reminder", methods=["POST"])
@super_admin_required
def remind_gallery_lease(org_id):
    """Tell the gallery's own admins that the lease needs a payment.
    Always leaves an in-app notice. Also emails them when SendGrid is configured."""
    try:
        org = Organization.query.get(org_id)
        if not org:
            return jsonify({"message": "Gallery not found"}), 404

        admins = (Member.query
                  .join(Role, Member.role_id == Role.id)
                  .filter(Member.organization_id == org.id, Role.name == 'admin')
                  .all())
        if not admins:
            return jsonify({"message": "This gallery has no admin to remind"}), 400

        when = org.paid_until.isoformat() if org.paid_until else "not recorded"
        notice = f"The lease for {org.name} is paid through {when}. Please arrange the next payment."
        notify_all_admins(notice, org.id)

        emailed = []
        failed = []
        for admin in admins:
            if send_lease_reminder_email(admin.email, org.name, org.paid_until):
                emailed.append(admin.email)
            else:
                failed.append(admin.email)

        logger.info(f"Lease reminder for '{org.name}' by {g.current_super_admin.email}: emailed {emailed}, failed {failed}")
        if failed and not emailed:
            return jsonify({
                "message": "The gallery admin was notified in the app. The email could not be sent. Check SENDGRID_API_KEY and SENDGRID_FROM_EMAIL.",
                "emailed": emailed,
                "failed": failed,
            }), 200
        if failed:
            return jsonify({
                "message": f"Reminder emailed to {', '.join(emailed)}. Could not email {', '.join(failed)}.",
                "emailed": emailed,
                "failed": failed,
            }), 200
        return jsonify({
            "message": f"Reminder emailed to {', '.join(emailed)}, and left in their notifications.",
            "emailed": emailed,
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error sending lease reminder for gallery {org_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


def _get_gallery_member(org_id, member_id):
    """Looks the member up inside the gallery named in the URL, so an id that
    belongs to a different gallery can never be touched by mistake."""
    org = Organization.query.get(org_id)
    if not org:
        return None, None
    member = Member.query.filter_by(id=member_id, organization_id=org.id).first()
    return org, member
def _tell_gallery_admins(org, text):
    """Leave a notification for the gallery's own admins about a platform-support
    action on one of their members. Best effort: the support action has already
    succeeded by now, so a notification problem must never turn it into an error."""
    try:
        notify_all_admins(text, org.id)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Could not notify admins of gallery {org.id}: {str(e)}")

@platform_admin_bp.route("/galleries/<int:org_id>/members/<int:member_id>/unlock", methods=["POST"])
@super_admin_required
def unlock_gallery_member(org_id, member_id):
    data = request.get_json(silent=True) or {}
    clear_admin_block = data.get('clear_admin_block') is True

    try:
        org, member = _get_gallery_member(org_id, member_id)
        if not org:
            return jsonify({"message": "Gallery not found"}), 404
        if not member:
            return jsonify({"message": "Member not found in this gallery"}), 404

        # Temporary lockouts: failed-login lock, OTP state, rate-limit escalation.
        member.failed_attempts = 0
        member.locked_until = None
        member.unlock_attempts = 0
        member.otp_code_hash = None
        member.otp_expires_at = None
        member.otp_attempts = 0
        member.email_rate_violations = 0
        member.email_rate_locked_until = None
        member.ip_rate_violations = 0
        member.ip_rate_locked_until = None

        # A block set by one of the gallery's own admins is a deliberate act,
        # so it is only lifted when the request explicitly asks for it.
        if clear_admin_block:
            member.admin_locked = False
        db.session.commit()

        logger.info(f"Member {member.email} (id={member.id}) of gallery '{org.name}' unlocked by super admin {g.current_super_admin.email} (clear_admin_block={clear_admin_block})")
        
        if clear_admin_block:
            what = "unlocked and lifted the admin block on"
        elif member.admin_locked:
            what = "cleared the temporary locks on (still blocked by a gallery admin)"
        else:
            what = "unlocked"
        _tell_gallery_admins(org, f"Platform support {what} {member.name} ({member.email}).")

        if member.admin_locked:
            message = "Temporary locks cleared, but this member is still blocked by a gallery admin. Send {\"clear_admin_block\": true} to lift that block too."
        else:
            message = f"{member.name} has been unlocked"
        return jsonify({
            "message": message,
            "member": {"id": member.id, "email": member.email, "admin_locked": member.admin_locked}
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error unlocking member {member_id} of gallery {org_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@platform_admin_bp.route("/galleries/<int:org_id>/members/<int:member_id>/reset-password", methods=["POST"])
@super_admin_required
def send_member_password_reset(org_id, member_id):
    """Emails the member their own reset link (same 15-minute link as the
    normal forgot-password flow). The super admin never sees or sets the
    password, and the link is never returned in the response."""
    try:
        org, member = _get_gallery_member(org_id, member_id)
        if not org:
            return jsonify({"message": "Gallery not found"}), 404
        if not member:
            return jsonify({"message": "Member not found in this gallery"}), 404

        token = secrets.token_urlsafe(32)
        member.password_reset_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
        member.password_reset_expires = datetime.now() + timedelta(minutes=15)
        db.session.commit()

        reset_link = build_reset_link(org, token)
        if not send_password_reset_email(member.email, reset_link):
            member.password_reset_token = None
            member.password_reset_expires = None
            db.session.commit()
            return jsonify({"message": "The reset email could not be sent"}), 502

        logger.info(f"Password reset link sent to {member.email} (id={member.id}) of gallery '{org.name}' by super admin {g.current_super_admin.email}")
        _tell_gallery_admins(org, f"Platform support sent a password reset link to {member.name} ({member.email}).")
        return jsonify({"message": f"A password reset link has been emailed to {member.email}. It expires in 15 minutes."}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error sending password reset for member {member_id} of gallery {org_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
    


@platform_admin_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Same session id on the new pair, like the gallery-member refresh. The
    blocklist check has already rejected revoked or unknown sessions by now."""
    try:
        claims = get_jwt()
        if claims.get("scope") != "platform":
            return jsonify({"message": "Platform admin access required"}), 403

        super_admin = SuperAdmin.query.get(int(get_jwt_identity()))
        if not super_admin:
            return jsonify({"message": "Session no longer valid"}), 401

        identity = str(super_admin.id)
        extra = {"sid": claims.get("sid"), "scope": "platform"}
        return jsonify({
            "access_token": create_access_token(identity=identity, additional_claims=extra),
            "refresh_token": create_refresh_token(identity=identity, additional_claims=extra)
        }), 200
    except Exception as e:
        logger.error(f"Error refreshing super admin token: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@platform_admin_bp.route("/logout", methods=["POST"])
@super_admin_required
def logout():
    try:
        session = SuperAdminSession.query.filter_by(jti=get_jwt().get("sid")).first()
        if session and not session.revoked:
            session.revoked = True
            session.revoked_at = datetime.now()
            session.revoked_by = "self"
            db.session.commit()
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during super admin logout: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@platform_admin_bp.route("/logout-all", methods=["POST"])
@super_admin_required
def logout_all():
    """Emergency button: revokes every session of this super admin, including
    the one making the request."""
    try:
        count = SuperAdminSession.query.filter_by(
            super_admin_id=g.current_super_admin.id, revoked=False
        ).update({
            "revoked": True,
            "revoked_at": datetime.now(),
            "revoked_by": "logout_all"
        })
        db.session.commit()
        logger.warning(f"Super admin {g.current_super_admin.email} revoked all sessions ({count})")
        return jsonify({"message": f"{count} session(s) revoked"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during super admin logout-all: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500