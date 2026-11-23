import re
from ..models.role import Role
from ..utils.logging import logger
from flask import g, request, current_app
# Subdomains that are never a gallery slug: platform infrastructure, look-alikes
# of login/admin pages, and names kept for future use. The backend is the single
# source of truth: /gallery-info answers reason "reserved" for these, so the
# frontend never needs its own copy.
RESERVED_SUBDOMAINS = {
    'www', 'api', 'app',
    'admin', 'administrator', 'platform', 'platform-admin', 'superadmin',
    'login', 'signin', 'signup', 'sign-up', 'register', 'account', 'accounts',
    'mail', 'email', 'smtp', 'ftp',
    'static', 'assets', 'cdn', 'uploads', 'media',
    'support', 'help', 'docs', 'status', 'blog', 'billing',
    'test', 'demo', 'staging', 'dev',
}

SLUG_RULES_MESSAGE = (
    "must be 3-50 characters: lowercase letters, numbers and single hyphens, "
    "starting and ending with a letter or number"
)
_SLUG_PATTERN = re.compile(r'[a-z0-9]+(?:-[a-z0-9]+)*')


def normalize_slug(value):
    """Trim and lowercase a typed slug. Anything that is not a string becomes
    None, which is_valid_slug then rejects."""
    return value.strip().lower() if isinstance(value, str) else None


def is_valid_slug(slug):
    """A gallery slug becomes a subdomain, so it must be a valid DNS label:
    3-50 chars, lowercase letters/digits with single hyphens between them. That
    rejects a leading or trailing hyphen, '--' (which also rules out 'xn--'
    look-alike prefixes), and, because it uses fullmatch, a trailing newline."""
    return (isinstance(slug, str) and 3 <= len(slug) <= 50
            and _SLUG_PATTERN.fullmatch(slug) is not None)
def is_valid_image_path(path, org_id):
    """An artwork's image_path must be empty or one of THIS gallery's uploads
    ('<org_id>/<32 hex chars>.<ext>'). The frontend stores the path with an
    'uploads/' prefix, so that prefix is accepted too."""
    if path in (None, ''):
        return True
    if not isinstance(path, str):
        return False
    if path.startswith('uploads/'):
        path = path[len('uploads/'):]
    match = re.fullmatch(r'(\d+)/[0-9a-f]{32}\.(?:png|jpg|jpeg|gif|webp)', path)
    return bool(match) and int(match.group(1)) == org_id
def initialize_roles(db_session, organization_id, commit=True):
    """Create the three built-in roles for ONE gallery (safe to re-run).
    Pass commit=False to leave saving to the caller, e.g. gallery creation,
    where the gallery, its roles and its first admin must all save together."""
    for name in ('admin', 'curator', 'member'):
        exists = Role.query.filter_by(organization_id=organization_id, name=name).first()
        if not exists:
            db_session.session.add(Role(organization_id=organization_id, name=name))
            logger.info(f"Created {name} role for organization {organization_id}")
    if commit:
        db_session.session.commit()
def scoped_query(model):
    """Returns a query for `model` filtered to the current request's organization.
    Must be called inside a route wrapped with @tenant_required (so g.org_id exists)."""
    return model.query.filter_by(organization_id=g.org_id)

def scoped_get(model, record_id):
    """Fetch a single row by id, scoped to the current organization.
    Returns None if not found — callers must check explicitly and return
    their own 404 JSON response, since abort(404) would get swallowed by
    this codebase's existing `except Exception: return 500` pattern."""
    return scoped_query(model).filter_by(id=record_id).first()



def get_subdomain():
    """Extract the gallery label from the request's Host header, e.g. 'acme'
    from 'acme.yoursite.co.ke'. When BASE_DOMAIN is set (production) it is
    exact for any domain, including multi-part ones like .co.ke. Without it
    (local development) it falls back to a simple guess. Returns None for the
    bare domain, localhost, or a raw IP."""
    host = request.host.split(':')[0].lower()
    base_domain = current_app.config.get('BASE_DOMAIN')

    if base_domain:
        suffix = '.' + base_domain.lower()
        if host.endswith(suffix):
            label = host[:-len(suffix)]
            return label if label and '.' not in label else None
        return None

    parts = host.split('.')
    if host.replace('.', '').isdigit():
        return None  # raw IP like 127.0.0.1
    if parts[-1] == 'localhost':
        return parts[0] if len(parts) > 1 else None  # 'gallery1.localhost' vs bare 'localhost'
    return parts[0] if len(parts) > 2 else None
def resolve_org_from_subdomain():
    """Look up the Organization whose slug matches the current request's
    subdomain. Returns None if there's no subdomain, it's a reserved name,
    or no matching gallery exists — callers decide what that means for them."""
    from ..models.organization import Organization  # local import avoids a circular import with models

    subdomain = get_subdomain()
    if not subdomain or subdomain in RESERVED_SUBDOMAINS:
        return None
    return Organization.query.filter_by(slug=subdomain).first()
def resolve_request_org(data=None):
    """Resolve which gallery an unauthenticated request (signup/login) is for.
    The subdomain wins if it resolves to a real org — that's the real
    production path. Falls back to an explicit 'org_slug' in the request
    body otherwise, so API clients and local Postman testing don't have to
    spoof the Host header on every request. Returns None if neither source
    resolves to a real gallery."""
    from ..models.organization import Organization  # local import avoids a circular import with models

    org = resolve_org_from_subdomain()
    if org:
        return org

    if data:
        org_slug = data.get('org_slug')
        if org_slug:
            return Organization.query.filter_by(slug=org_slug).first()

    return None
def build_reset_link(org, token):
    """Password-reset link on the member's own gallery address. A gallery slug can
    only contain a-z, 0-9 and hyphens (is_valid_slug), so it is safe to put in a URL."""
    template = current_app.config.get('FRONTEND_URL_TEMPLATE')
    base = template.format(slug=org.slug) if template else current_app.config['FRONTEND_URL']
    return f"{base.rstrip('/')}/reset-password?token={token}"