"""Proves gallery creation is all-or-nothing.

It makes the signup fail halfway (after the gallery and its roles are prepared,
before the admin is saved) and then checks that NO half-created gallery is left.
Run from the project root with the venv active, and APP_ENV=development in .env:
    python atomic_test.py
"""
import sys
from unittest import mock

from app import create_app
from app.models import Organization

app = create_app()
if app.config.get("APP_ENV") == "production":
    sys.exit("Refusing to run against a production configuration.")
client = app.test_client()

SLUG = "atomic-check-gallery"

with app.app_context():
    if Organization.query.filter_by(slug=SLUG).first():
        sys.exit(f"A gallery '{SLUG}' already exists. Delete it first, then re-run.")

payload = {
    "name": "Atomic Tester",
    "email": "atomic-check@example.com",
    "password": "Atomic-Test1!",
    "gallery_name": "Atomic Check Gallery",
    "gallery_slug": SLUG,
}

# Force a crash at the password-hashing step: after the gallery is flushed,
# before the first admin is saved.
with mock.patch("app.routes.auth.bcrypt.hashpw", side_effect=RuntimeError("simulated failure")):
    response = client.post("/sign-up", json=payload)

with app.app_context():
    leftover = Organization.query.filter_by(slug=SLUG).first()

print(f"status returned: {response.status_code}")
if response.status_code == 500 and leftover is None:
    print("PASS: the failed signup left no half-created gallery behind.")
else:
    print("FAIL: a gallery was left behind (or the failure was not simulated).")
    sys.exit(1)
    