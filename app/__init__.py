from flask import Flask
from flask_cors import CORS
from datetime import datetime
from .extensions import db, jwt, ma, migrate
from .config import Config, INSECURE_DEFAULTS
from .models import Role, Artwork
from .routes.auth import auth_bp
from .routes.artwork import artwork_bp
from .routes.inventory import inventory_bp
from .routes.profile import profile_bp
from .routes.role import role_bp
from .routes.upload import upload_bp  
from .utils.helpers import initialize_roles
from .utils.logging import logger
from .routes.comment import comment_bp
from .routes.wishlist import wishlist_bp
from .routes.collection import collection_bp
from .models.session import Session
from .models.super_admin_session import SuperAdminSession
from .models.super_admin import SuperAdmin
from .extensions import limiter
from .routes.notification import notification_bp
from .routes.platform_admin import platform_admin_bp
from .routes.gallery import gallery_bp
from .routes.gallery_settings import gallery_settings_bp
import os
import click
import bcrypt


def create_app():
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(Config)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    weak_keys = [
        name for name in ('SECRET_KEY', 'JWT_SECRET_KEY')
        if app.config[name] in INSECURE_DEFAULTS or len(app.config[name]) < 32
    ]
    if weak_keys:
        # Fail closed: weak or default keys are allowed ONLY when APP_ENV is
        # explicitly set to 'development'. Forgetting APP_ENV on a live server
        # must never leave it running with publicly known signing keys.
        if app.config['APP_ENV'] != 'development':
            raise RuntimeError(
                f"Refusing to start: {', '.join(weak_keys)} must be set in the environment "
                "to a random value of at least 32 characters. (For local development only, "
                "set APP_ENV=development to allow weak keys.)"
            )
        logger.warning(f"Using weak or default {', '.join(weak_keys)} — fine for local development, never for production.")

    CORS(app, resources={r"/*": {"origins": app.config['CORS_ORIGINS']}}, supports_credentials=True)

    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    ma.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    from .models.member import Member

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        session_id = jwt_payload.get('sid')
        if not session_id:
            # Any token without our sid claim predates this session system
            # (or was tampered with) — reject it rather than let it through.
            return True

        # Platform-admin tokens are a separate identity space (no Member/
        # Organization behind them) and carry their own sid — check those
        # against SuperAdminSession instead of the gallery-member Session table.
        if jwt_payload.get('scope') == 'platform':
            admin_session = SuperAdminSession.query.filter_by(jti=session_id).first()
            if not admin_session:
                return True
            if admin_session.revoked:
                return True
            return False

        session = Session.query.filter_by(jti=session_id).first()
        if not session:
            return True
        if session.revoked:
            return True

        member = Member.query.get(session.member_id)
        if member and member.tokens_valid_after:
            issued_at = datetime.fromtimestamp(jwt_payload['iat'])
            if issued_at < member.tokens_valid_after:
                return True

        return False

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(artwork_bp)
    app.register_blueprint(inventory_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(role_bp)
    app.register_blueprint(upload_bp) 
    app.register_blueprint(comment_bp)
    app.register_blueprint(wishlist_bp)
    app.register_blueprint(collection_bp)
    app.register_blueprint(notification_bp)
    app.register_blueprint(platform_admin_bp)
    app.register_blueprint(gallery_bp)
    app.register_blueprint(gallery_settings_bp)
    
    # Seed default roles via `flask init-roles` (run once, after `flask db upgrade`).
    # This is NOT called automatically here — doing so broke `flask db migrate`
    # on a fresh database, since it tried to query a table that doesn't exist yet.
    @app.cli.command("init-roles")
    @click.argument("organization_id", type=int)
    def init_roles_command(organization_id):
        initialize_roles(db, organization_id)
        print(f"Roles initialized for organization {organization_id}.")
    
    # Builds two sandbox galleries with identical, known data so the cross-gallery
    # boundary test has something to attack. Safe to re-run (skips what exists).
    # Never touches real galleries, and refuses to run in production.
    @app.cli.command("seed-sandbox")
    def seed_sandbox_command():
        if app.config['APP_ENV'] == 'production':
            print("Refusing to seed sandbox data in production.")
            return

        import bcrypt
        from .models.organization import Organization
        from .models.collection import Collection

        sandbox_password = "SandboxPass123!"
        password_hash = bcrypt.hashpw(sandbox_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        for slug, gallery_name in (("test-gallery-a", "Test Gallery A"), ("test-gallery-b", "Test Gallery B")):
            org = Organization.query.filter_by(slug=slug).first()
            if not org:
                org = Organization(name=gallery_name, slug=slug, status='active')
                db.session.add(org)
                db.session.flush()

            initialize_roles(db, org.id)
            roles = {r.name: r for r in Role.query.filter_by(organization_id=org.id).all()}

            # Same three emails in BOTH galleries on purpose: it exercises
            # "one account per gallery per email".
            members = {}
            for role_name in ('admin', 'curator', 'member'):
                email = f"{role_name}@sandbox.test"
                member = Member.query.filter_by(organization_id=org.id, email=email).first()
                if not member:
                    member = Member(
                        organization_id=org.id,
                        name=f"{gallery_name} {role_name}",
                        email=email,
                        password=password_hash,
                        role_id=roles[role_name].id
                    )
                    db.session.add(member)
                    db.session.flush()
                members[role_name] = member

            for title, artist in (("Sunrise Study", "Ana Rivera"), ("Blue Harbor", "Ben Okoye"), ("Quiet Fields", "Chen Wu")):
                full_title = f"{gallery_name} - {title}"
                if not Artwork.query.filter_by(organization_id=org.id, title=full_title).first():
                    db.session.add(Artwork(
                        organization_id=org.id, title=full_title, artist=artist,
                        medium="Oil on canvas", condition="good", category="Painting",
                        price=100, member_id=members['curator'].id
                    ))

            collection_name = f"{gallery_name} - Featured"
            if not Collection.query.filter_by(organization_id=org.id, name=collection_name).first():
                db.session.add(Collection(
                    organization_id=org.id, name=collection_name,
                    description="Sandbox collection", curator_id=members['curator'].id
                ))

            db.session.commit()
            print(f"{gallery_name} (id={org.id}, slug={slug}): 3 roles, 3 members, 3 artworks, 1 collection")

        print(f"Sandbox logins: admin@sandbox.test / curator@sandbox.test / member@sandbox.test  password: {sandbox_password}")
        print("Log in with the matching org_slug: test-gallery-a or test-gallery-b.")
    # Platform-admin accounts are never created via a public route — only
    # ever seeded from the command line, so there's no way for anyone to
    # sign themselves up as a super admin over the API.
    @app.cli.command("create-super-admin")
    @click.argument("name")
    @click.argument("email")
    def create_super_admin_command(name, email):
        if SuperAdmin.query.filter_by(email=email).first():
            print(f"A super admin with email {email} already exists.")
            return
        # Asked for with hidden input, so the password never appears on screen
        # or in the shell history.
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        if len(password) < 10:
            print("Password must be at least 10 characters. Nothing was created.")
            return
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        super_admin = SuperAdmin(name=name, email=email, password=hashed.decode('utf-8'))
        db.session.add(super_admin)
        db.session.commit()
        print(f"Super admin '{name}' <{email}> created.")
    # One-off: move pre-tenant files from uploads/ into uploads/<gallery id>/ and
    # update that gallery's artworks. Run once, only when ALL legacy files belong
    # to that one gallery. Safe to delete this command afterwards.
    @app.cli.command("move-legacy-uploads")
    @click.argument("organization_id", type=int)
    def move_legacy_uploads_command(organization_id):
        import shutil
        import uuid
        allowed_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}
        upload_root = app.config['UPLOAD_FOLDER']
        target_folder = os.path.join(upload_root, str(organization_id))
        os.makedirs(target_folder, exist_ok=True)

        moved_to = {}  # old flat file name -> new '<org>/<name>', so a file shared by two artworks is moved once
        moved = 0
        for artwork in Artwork.query.filter_by(organization_id=organization_id).all():
            old_path = artwork.image_path
            if not old_path:
                continue
            prefix = 'uploads/' if old_path.startswith('uploads/') else ''
            flat_name = old_path[len(prefix):]
            if '/' in flat_name:
                continue  # already inside a gallery folder

            if flat_name not in moved_to:
                extension = os.path.splitext(flat_name)[1].lower()
                source = os.path.join(upload_root, flat_name)
                if extension not in allowed_extensions:
                    print(f"Skipping artwork {artwork.id}: '{flat_name}' has an unexpected extension")
                    continue
                if not os.path.isfile(source):
                    print(f"Skipping artwork {artwork.id}: file '{flat_name}' not found in uploads")
                    continue
                new_name = f"{uuid.uuid4().hex}{extension}"
                shutil.move(source, os.path.join(target_folder, new_name))
                moved_to[flat_name] = f"{organization_id}/{new_name}"
                moved += 1

            artwork.image_path = prefix + moved_to[flat_name]
        db.session.commit()
        print(f"Moved {moved} file(s) into uploads/{organization_id}/ and updated their artworks.")

        leftovers = [f for f in os.listdir(upload_root) if os.path.isfile(os.path.join(upload_root, f))]
        if leftovers:
            print(f"{len(leftovers)} file(s) still directly in uploads/ (not used by this gallery's artworks): {', '.join(leftovers)}")
    return app