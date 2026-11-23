"""Cross-gallery boundary test.

Logs in to the two sandbox galleries (test-gallery-a / test-gallery-b, created by
`flask seed-sandbox`) and tries to reach, read, change and delete the OTHER
gallery's data through every route. Every attempt must be refused, nothing in the
victim gallery may change, and every list must contain only the caller's own rows.

Run from the project root, with the venv active:   python boundary_test.py
It never touches Jiu Gallery (or any real gallery) on purpose, and it refuses to
run in production. Re-run limit: it logs in 6 times per run, and login is limited
to 15 per minute per IP, so wait a minute between runs.
"""
import sys
import json

from app import create_app
from app.models import (Organization, Role, Artwork, Member, Comment, Wishlist,
                        ArtworkCollaborator, Collection, CollectionArtwork,
                        CollectionCurator, Session)
from app.models.notification import Notification

PASSWORD = "SandboxPass123!"
SLUGS = {"A": "test-gallery-a", "B": "test-gallery-b"}

app = create_app()
if app.config.get("APP_ENV") == "production":
    sys.exit("Refusing to run boundary tests against a production configuration.")
client = app.test_client()

passed = 0
failures = []


def check(label, ok, detail=""):
    global passed
    if ok:
        passed += 1
    else:
        failures.append(label)
        print(f"  FAIL  {label}  {detail}")


def login(slug, role):
    response = client.post("/login", json={
        "email": f"{role}@sandbox.test", "password": PASSWORD, "org_slug": slug})
    if response.status_code != 200:
        sys.exit(f"Could not log in as {role} on {slug} (status {response.status_code}). "
                 "Did you run `flask seed-sandbox`? If you ran this test more than twice "
                 "in a minute, wait a minute and retry.")
    data = response.get_json()
    return data["access_token"], data["member"]


def call(token, method, path, body=None):
    kwargs = {"method": method}
    if token:
        kwargs["headers"] = {"Authorization": f"Bearer {token}"}
    if body is not None:
        kwargs["json"] = body
    response = client.open(path, **kwargs)
    return response.status_code, response.get_data(as_text=True)


def items(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, list):
        return [i for i in data if isinstance(i, dict)]
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
    return []


def gallery_facts(slug):
    with app.app_context():
        org = Organization.query.filter_by(slug=slug).first()
        if not org:
            sys.exit(f"Gallery '{slug}' not found. Run `flask seed-sandbox` first.")
        notes = Notification.query.filter_by(organization_id=org.id).first()
        return {
            "org_id": org.id,
            "name": org.name,
            "roles": {r.name: r.id for r in Role.query.filter_by(organization_id=org.id)},
            "members": {m.email.split("@")[0]: m.id
                        for m in Member.query.filter_by(organization_id=org.id)
                        if m.email.endswith("@sandbox.test")},
            "artworks": [a.id for a in Artwork.query.filter_by(organization_id=org.id).order_by(Artwork.id)],
            "collections": [c.id for c in Collection.query.filter_by(organization_id=org.id).order_by(Collection.id)],
            "note": notes.id if notes else None,
        }


def own_ids(org_id):
    with app.app_context():
        return {
            "artworks": {a.id for a in Artwork.query.filter_by(organization_id=org_id)},
            "collections": {c.id for c in Collection.query.filter_by(organization_id=org_id)},
            "members": {m.id for m in Member.query.filter_by(organization_id=org_id)},
            "roles": {r.id for r in Role.query.filter_by(organization_id=org_id)},
            "sessions": {s.id for s in Session.query.filter_by(organization_id=org_id)},
        }


def fingerprint(org_id):
    """Everything a cross-gallery attack could change in the victim gallery."""
    with app.app_context():
        q = lambda model: model.query.filter_by(organization_id=org_id)
        return {
            "artworks": sorted((a.id, a.title, a.description, a.member_id, a.image_path, str(a.price)) for a in q(Artwork)),
            "collections": sorted((c.id, c.name, c.description, c.curator_id) for c in q(Collection)),
            "roles": sorted((r.id, r.name) for r in q(Role)),
            "members": sorted((m.id, m.name, m.email, m.role_id, m.admin_locked) for m in q(Member)),
            "comments": q(Comment).count(),
            "wishlist": q(Wishlist).count(),
            "collaborators": q(ArtworkCollaborator).count(),
            "collection_artworks": q(CollectionArtwork).count(),
            "collection_curators": q(CollectionCurator).count(),
            "sessions_revoked": q(Session).filter_by(revoked=True).count(),
        }


def victim_session_id(org_id):
    with app.app_context():
        session = Session.query.filter_by(organization_id=org_id).first()
        return session.id if session else None


def build_attacks(att, vic, me_id, vic_session):
    va, vc = vic["artworks"][0], vic["collections"][0]
    v_curator, v_member = vic["members"]["curator"], vic["members"]["member"]
    v_roles = vic["roles"]
    aa, ac = att["artworks"][0], att["collections"][0]
    foreign_image = f"{vic['org_id']}/{'a' * 32}.jpg"

    attacks = [
        # --- artworks: victim's artwork ---
        ("read victim artwork", "GET", f"/artworks/{va}", None),
        ("edit victim artwork", "PUT", f"/artworks/{va}", {"title": "HACKED title"}),
        ("delete victim artwork", "DELETE", f"/artworks/{va}", None),
        ("read victim artwork activity", "GET", f"/artworks/{va}/activity", None),
        ("list victim artwork collaborators", "GET", f"/artworks/{va}/collaborators", None),
        ("add collaborator to victim artwork", "POST", f"/artworks/{va}/collaborators", {"member_id": v_curator}),
        ("remove collaborator from victim artwork", "DELETE", f"/artworks/{va}/collaborators/{v_curator}", None),
        ("comment on victim artwork", "POST", f"/artworks/{va}/comments", {"content": "hello from another gallery"}),
        ("read comments on victim artwork", "GET", f"/artworks/{va}/comments", None),
        # --- collections: victim's collection ---
        ("read victim collection", "GET", f"/collections/{vc}", None),
        ("edit victim collection", "PUT", f"/collections/{vc}", {"name": "HACKED"}),
        ("delete victim collection", "DELETE", f"/collections/{vc}", None),
        ("add artwork to victim collection", "POST", f"/collections/{vc}/artworks", {"artwork_id": va}),
        ("remove artwork from victim collection", "DELETE", f"/collections/{vc}/artworks/{va}", None),
        ("add co-curator to victim collection", "POST", f"/collections/{vc}/curators", {"member_id": v_curator}),
        ("remove co-curator from victim collection", "DELETE", f"/collections/{vc}/curators/{v_curator}", None),
        # --- own resources pointing at victim ids ---
        ("put victim artwork in own collection", "POST", f"/collections/{ac}/artworks", {"artwork_id": va}),
        ("make victim member own co-curator", "POST", f"/collections/{ac}/curators", {"member_id": v_curator}),
        ("make victim member own collaborator", "POST", f"/artworks/{aa}/collaborators", {"member_id": v_curator}),
        ("wishlist victim artwork", "POST", "/wishlist", {"artwork_id": va}),
        ("remove victim artwork from wishlist", "DELETE", f"/wishlist/{va}", None),
        ("give self victim's admin role", "PUT", f"/members/{me_id}/role", {"role_id": v_roles["admin"]}),
        ("create artwork with victim's image folder", "POST", "/artworks",
         {"title": "Sneaky one", "artist": "Nobody", "image_path": foreign_image}),
        ("point own artwork at victim's image folder", "PUT", f"/artworks/{aa}", {"image_path": foreign_image}),
        # --- admin routes against victim ids ---
        ("rename victim role", "PUT", "/roles", {"id": v_roles["member"], "name": "hacked"}),
        ("delete victim role", "DELETE", f"/roles/{v_roles['member']}", None),
        ("change victim member's role", "PUT", f"/members/{v_member}/role", {"role_id": v_roles["admin"]}),
        ("block victim member", "POST", f"/admin/members/{v_member}/block", {}),
        ("unblock victim member", "POST", f"/admin/members/{v_member}/unblock", {}),
        # --- platform routes: a gallery token must never open these ---
        ("platform: list galleries", "GET", "/platform-admin/galleries", None),
        ("platform: victim's members", "GET", f"/platform-admin/galleries/{vic['org_id']}/members", None),
        ("platform: suspend victim", "PATCH", f"/platform-admin/galleries/{vic['org_id']}/suspend", None),
        ("platform: reset victim member's password", "POST",
         f"/platform-admin/galleries/{vic['org_id']}/members/{v_member}/reset-password", None),
    ]
    if vic_session:
        attacks.append(("revoke victim session", "DELETE", f"/admin/sessions/{vic_session}", None))
    if vic["note"]:
        attacks.append(("mark victim notification read", "PUT", f"/notifications/{vic['note']}/read", None))
    return attacks


LIST_ROUTES = [
    ("/artworks", "artworks"), ("/featured-artworks", "artworks"),
    ("/search-artworks?q=Test", "artworks"), ("/my-artworks", "artworks"),
    ("/inventory-alerts", "artworks"), ("/collections", "collections"),
    ("/members", "members"), ("/members/eligible-collaborators", "members"),
    ("/roles", "roles"), ("/admin/sessions", "sessions"),
    ("/wishlist", None), ("/notifications", None), ("/profile", None),
]


def run_direction(att_key, vic_key):
    att, vic = FACTS[att_key], FACTS[vic_key]
    print(f"\n=== Gallery {att_key} attacking gallery {vic_key} ===")

    vic_admin_token, _ = login(SLUGS[vic_key], "admin")
    vic_session = victim_session_id(vic["org_id"])
    before = fingerprint(vic["org_id"])

    # Without any token, every route must refuse with 401.
    for label, method, path, body in build_attacks(att, vic, 0, vic_session):
        status, _ = call(None, method, path, body)
        check(f"[{att_key}->{vic_key}] no token: {label}", status == 401, f"got {status}")

    for role in ("curator", "admin"):  # admin last: it ends with logout-all
        token, me = login(SLUGS[att_key], role)
        who = f"[{att_key}->{vic_key} {role}]"

        # Positive controls: the token really works on the caller's own data,
        # so a refusal below means "blocked", not "broken token".
        status, _ = call(token, "GET", f"/artworks/{att['artworks'][0]}")
        check(f"{who} control: read own artwork", status == 200, f"got {status}")
        status, _ = call(token, "GET", f"/collections/{att['collections'][0]}")
        check(f"{who} control: read own collection", status == 200, f"got {status}")

        for label, method, path, body in build_attacks(att, vic, me["id"], vic_session):
            status, text = call(token, method, path, body)
            refused = 400 <= status < 500 and status != 429
            check(f"{who} {label}", refused, f"got {status} (expected 4xx refusal)")
            check(f"{who} {label} leaks nothing", vic["name"] not in text,
                  f"response mentions '{vic['name']}'")

        own = own_ids(att["org_id"])
        for path, kind in LIST_ROUTES:
            status, text = call(token, "GET", path)
            check(f"{who} list {path} status", status in (200, 403), f"got {status}")
            check(f"{who} list {path} has no {vic['name']} data", vic["name"] not in text)
            if kind and status == 200:
                foreign = [i.get("id") for i in items(text)
                           if i.get("id") is not None and i["id"] not in own[kind]]
                check(f"{who} list {path} only own {kind}", not foreign, f"foreign ids: {foreign}")

        if role == "admin":
            status, _ = call(token, "POST", "/admin/logout-all", {})
            check(f"{who} logout-all on own gallery works", status == 200, f"got {status}")

    after = fingerprint(vic["org_id"])
    for key in before:
        check(f"[{att_key}->{vic_key}] victim '{key}' unchanged", before[key] == after[key])
    status, _ = call(vic_admin_token, "GET", "/profile")
    check(f"[{att_key}->{vic_key}] victim admin still logged in after attacker's logout-all",
          status == 200, f"got {status}")


FACTS = {key: gallery_facts(slug) for key, slug in SLUGS.items()}

# Same email in both galleries must resolve to the right gallery each time.
for key, slug in SLUGS.items():
    _, member = login(slug, "admin")
    check(f"login admin@sandbox.test on {slug} lands in {slug}",
          member["organization_id"] == FACTS[key]["org_id"])

run_direction("A", "B")
run_direction("B", "A")

print(f"\n{passed} checks passed, {len(failures)} failed.")
if failures:
    print("FAILED:")
    for label in failures:
        print(f"  - {label}")
    sys.exit(1)
print("Tenant isolation holds on every route tested.")