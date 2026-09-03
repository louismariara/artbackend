from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import bcrypt
import re
from ..extensions import db
from ..models.member import Member
from ..models.role import Role
from ..schemas.member import MemberSchema
from ..utils.logging import logger

auth_bp = Blueprint('auth', __name__)
member_schema = MemberSchema()

REQUIRED_SIGNUP_FIELDS = ['name', 'email', 'password']

@auth_bp.route("/sign-up", methods=["POST"])
def signup():
    data = request.get_json(silent=True)

    if data is None:
        logger.warning("Signup failed: request body was missing or not valid JSON")
        return jsonify({"message": "Request body must be valid JSON"}), 400

    # Field-level validation: tell the frontend dev exactly which field(s)
    # are missing, rather than a single generic error.
    missing = [field for field in REQUIRED_SIGNUP_FIELDS if not data.get(field)]
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
            logger.warning("Signup failed: name was only whitespace")
            return jsonify({"message": "Name cannot be just spaces"}), 400

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            logger.warning(f"Signup failed: invalid email format '{email}'")
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
            logger.warning(f"Signup failed: password missing {password_errors} for email '{email}'")
            return jsonify({
                "message": f"Password must contain: {', '.join(password_errors)}",
                "password_requirements": password_errors
            }), 400

        if Member.query.filter_by(email=email).first():
            logger.warning(f"Signup failed: email '{email}' already exists")
            return jsonify({"message": "Email already exists"}), 400

        is_first_user = Member.query.count() == 0
        role_name = 'admin' if is_first_user else 'member'
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            logger.error(f"Signup failed: role '{role_name}' not found in database — run 'flask init-roles'")
            return jsonify({"message": f"Role '{role_name}' not found — run 'flask init-roles' first"}), 500

        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        new_member = Member(name=name, email=email, role_id=role.id, password=hashed.decode('utf-8'))
        db.session.add(new_member)
        db.session.commit()
        logger.info(f"New user signed up: '{name}' <{email}> as {role_name}")
        return jsonify({"message": "Sign up successful"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Unexpected error during signup for email '{email}': {str(e)}")
        return jsonify({"message": "An error occurred during signup"}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if data is None:
        logger.warning("Login failed: request body was missing or not valid JSON")
        return jsonify({"message": "Request body must be valid JSON"}), 400

    missing = [field for field in ['email', 'password'] if not data.get(field)]
    if missing:
        logger.warning(f"Login failed: missing field(s) {missing}. Received keys: {list(data.keys())}")
        return jsonify({
            "message": f"Missing field(s): {', '.join(missing)}",
            "missing_fields": missing
        }), 400

    email = data.get("email")
    password = data.get("password")

    try:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            logger.warning(f"Login failed: invalid email format '{email}'")
            return jsonify({"message": "Invalid email or password"}), 401

        member = Member.query.filter_by(email=email).first()
        if not member or not bcrypt.checkpw(password.encode('utf-8'), member.password.encode('utf-8')):
            logger.warning(f"Login failed: bad credentials for email '{email}'")
            return jsonify({"message": "Invalid email or password"}), 401

        access_token = create_access_token(identity=str(member.id))
        logger.info(f"Successful login for user: {member.email}")
        return jsonify({
            "message": f"Welcome {member.name}",
            "member": member_schema.dump(member),
            "access_token": access_token
        })
    except Exception as e:
        logger.error(f"Unexpected error during login for email '{email}': {str(e)}")
        return jsonify({"message": "An error occurred during login"}), 500