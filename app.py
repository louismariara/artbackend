from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
import bcrypt
import os
import logging
import re
from datetime import datetime, timedelta
from sqlalchemy import or_


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from dotenv import load_dotenv
load_dotenv()

# Validate environment variables
required_env_vars = ['DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_PORT', 'DB_NAME', 'JWT_SECRET_KEY']
for var in required_env_vars:
    if not os.getenv(var):
        raise ValueError(f"Environment variable '{var}' not set")

app = Flask(__name__)
CORS(app)

# Configure the SQLAlchemy part of the app instance
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

db = SQLAlchemy(app)
jwt = JWTManager(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    members = db.relationship('Member', back_populates="role")

class Artwork(db.Model):
    __tablename__ = 'artworks'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    artist = db.Column(db.String(100), nullable=False, index=True)
    medium = db.Column(db.String(100))
    dimensions = db.Column(db.String(100))
    condition = db.Column(db.String(50))
    location = db.Column(db.String(255))
    theme = db.Column(db.String(100), index=True)
    views = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=True)
    member = db.relationship('Member', back_populates='artworks')
    image_path = db.Column(db.String(255), nullable=True)  
    description = db.Column(db.Text, nullable=True)
    def __repr__(self):
        return f'<Artwork {self.title} by {self.artist}>'

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(500), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    
    role = db.relationship("Role", back_populates="members")
    artworks = db.relationship('Artwork', back_populates='member')

class MemberSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Member
        load_instance = True

member_schema = MemberSchema()

class ArtworkSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Artwork
        load_instance = True
        fields = ('id', 'title', 'artist', 'medium', 'dimensions', 'condition', 'location', 'theme', 'views', 'updated_at', 'member_id', 'image_path', 'description')

artwork_schema = ArtworkSchema()
artworks_schema = ArtworkSchema(many=True)

class RoleSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Role
        load_instance = True

role_schema = RoleSchema()
roles_schema = RoleSchema(many=True)

# Function to initialize roles if they do not exist
def initialize_roles():
    role_admin = Role.query.filter_by(name='admin').first()
    role_curator = Role.query.filter_by(name='curator').first()
    
    if not role_admin:
        role_admin = Role(name='admin')
        db.session.add(role_admin)
        logger.info("Created admin role")
    
    if not role_curator:
        role_curator = Role(name='curator')
        db.session.add(role_curator)
        logger.info("Created curator role")

    db.session.commit()
@app.route('/')
def index():
    # Query for artworks to display on the homepage
    featured_artworks = Artwork.query.order_by(Artwork.views.desc(), Artwork.updated_at.desc()).limit(5).all()
    
    # Prepare data for rendering
    artworks_data = []
    for artwork in featured_artworks:
        artworks_data.append({
            'id': artwork.id,
            'title': artwork.title,
            'artist': artwork.artist,
            'image_path': f"/uploads/{artwork.image_path}" if artwork.image_path else None,
            'description': artwork.description if hasattr(artwork, 'description') else ''  
        })
    
    # Here, you'd return this data to your template for rendering
    return jsonify(artworks_data)  
@app.route("/sign-up", methods=["POST"])
def signup():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    role_id = data.get('role_id')
    password = data.get('password')

    try:
        # Name validation
        if not name or name.isspace():
            return jsonify({"message": "Name cannot be empty or just spaces"}), 400
        
        # Password validation
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'\d', password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return jsonify({"message": "Password must be at least 8 characters long, include uppercase, lowercase, numbers, and special characters"}), 400
                
        # Check if role exists
        role = Role.query.get(role_id)
        if not role:
            return jsonify({"message": "Role does not exist"}), 400

        # Check if email already exists
        if Member.query.filter_by(email=email).first():
            return jsonify({"message": "Email already exists"}), 400

        # Hash the password
        salt = bcrypt.gensalt()
        byte_pass = password.encode('utf-8')
        hashed = bcrypt.hashpw(byte_pass, salt)

        # Create new member
        new_member = Member(name=name, email=email, role_id=role_id, password=hashed.decode('utf-8'))

        db.session.add(new_member)
        db.session.commit()
        logger.info(f"New user signed up: {name}")
        return jsonify({"message": "Sign up successful"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during signup: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    try:
         # Email validation
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({"message": "Invalid email format"}), 400

        # Fetch member by email
        member = Member.query.filter_by(email=email).first()

        if not member:
            return jsonify({"message": f"User with email {email} does not exist"}), 400

        # Check password
        if not bcrypt.checkpw(password.encode('utf-8'), member.password.encode('utf-8')):
            return jsonify({"message": "Invalid password"}), 400

        # Don't return the actual password, mask it
        member.password = "########"

        # Create access token
        access_token = create_access_token(identity=str(member.id), expires_delta=timedelta(minutes=60))
        logger.info(f"Successful login for user: {member.email}")
        return jsonify({
            "message": f"Welcome {member.name}",
            "member": member_schema.dump(member),
            "access_token": access_token
        })
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route("/artworks", methods=["GET"])
@jwt_required()
def get_artworks():
    try:
        current_user_id = get_jwt_identity()
        member = Member.query.filter_by(id=int(current_user_id)).first()
        
        if member and member.role.name not in ["admin", "curator"]:
            return jsonify({"msg": "You do not have permission to view artworks"}), 403
        
        artworks = Artwork.query.all()
        return jsonify({"artworks": artworks_schema.dump(artworks)})
    except Exception as e:
        logger.error(f"Error retrieving artworks: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route("/artworks", methods=["POST"])
@jwt_required()
def create_artwork():
    data = request.get_json()
    
    try:
        # Required fields validation
        required_fields = ['title', 'artist']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"message": f"{field.capitalize()} is required"}), 400
        
        # Field length validation for title
        if len(data.get('title', '')) > 200 or len(data.get('title', '')) < 3:
            return jsonify({"message": "Title must be between 3 and 200 characters"}), 400
        
        # Condition validation
        valid_conditions = ['good', 'fair', 'poor']
        if data.get('condition') and data.get('condition') not in valid_conditions:
            return jsonify({"message": "Invalid condition. Must be one of: good, fair, poor"}), 400
    
        # Existing permission check
        current_user_id = get_jwt_identity()
        member = Member.query.filter_by(id=int(current_user_id)).first()
        if member.role.name not in ["admin", "curator"]:
            return jsonify({"msg": "No art adding for you!"}), 403
        
        # Make a new artwork with the data sent
        new_artwork = Artwork(
            title=data.get('title'),
            artist=data.get('artist'),
            medium=data.get('medium'),
            dimensions=data.get('dimensions'),
            condition=data.get('condition'),
            location=data.get('location'),
            theme=data.get('theme'),
            image_path=data.get('image_path'),  
            description=data.get('description')
        )
        
        db.session.add(new_artwork)
        db.session.commit()
        logger.info(f"New art on the wall: {new_artwork.title}")
        return jsonify({"message": "Artwork added!", "artwork": artwork_schema.dump(new_artwork)}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Oops, art creation failed: {str(e)}")
        return jsonify({"message": f"Uh-oh: {str(e)}"}), 500

@app.route("/artworks/<int:artwork_id>", methods=["GET"])
@jwt_required()
def get_artwork(artwork_id):
    try:
        # Fetch a specific artwork from the database by ID
        artwork = Artwork.query.get(id)    
        return jsonify({"artwork": artwork_schema.dump(artwork)})
    except Exception as e:
        logger.error(f"Art not found: {str(e)}")
        return jsonify({"message": f"Art not found: {str(e)}"}), 404  

@app.route("/artworks/<int:id>", methods=["PUT"])
@jwt_required()
def update_artwork(id):
    data = request.get_json()
    try:
        # Find the artwork to update
        artwork = Artwork.query.get_or_404(id)
        
        # Field validation for each field being updated
        if 'title' in data and (len(data['title']) > 200 or len(data['title']) < 3):
            return jsonify({"message": "Title must be between 3 and 200 characters"}), 400

        if 'condition' in data and data['condition'] not in ['good', 'fair', 'poor']:
            return jsonify({"message": "Invalid condition. Must be one of: good, fair, poor"}), 400

        # Check if the user can update artworks
        current_user_id = get_jwt_identity()
        member = Member.query.filter_by(id=int(current_user_id)).first()
        if member.role.name not in ["admin", "curator"]:
            return jsonify({"msg": "You can't edit this art!"}), 403

        # Update the artwork's attributes with new values
        for key, value in data.items():
            setattr(artwork, key, value)
        
        db.session.commit()
        logger.info(f"Artwork updated: {artwork.title}")
        return jsonify({"message": "Artwork updated!", "artwork": artwork_schema.dump(artwork)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update art: {str(e)}")
        return jsonify({"message": f"Update failed: {str(e)}"}), 500

@app.route("/artworks/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_artwork(id):
    try:
        # Find the artwork to delete
        artwork = Artwork.query.get_or_404(id)
        
        # Check if the user can delete artworks
        current_user_id = get_jwt_identity()
        member = Member.query.filter_by(id=int(current_user_id)).first()
        if member.role.name not in ["admin", "curator"]:
            return jsonify({"msg": "You can't remove this art!"}), 403

        db.session.delete(artwork)
        db.session.commit()
        logger.info(f"Artwork vanished: {artwork.title}")
        return jsonify({"message": "Artwork deleted!"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Artwork removal failed: {str(e)}")
        return jsonify({"message": f"Delete failed: {str(e)}"}), 500

@app.route("/inventory-alerts", methods=["GET"])
@jwt_required()
def check_inventory_alerts():
    try:
        # Find artworks that need attention
        six_months_ago = datetime.now() - timedelta(days=180)
        
        alerts = Artwork.query.filter(
            (Artwork.condition == 'poor') | 
            (Artwork.updated_at < six_months_ago)
        ).all()
        
        return jsonify({"alerts": artworks_schema.dump(alerts)})
    except Exception as e:
        logger.error(f"Alert system down: {str(e)}")
        return jsonify({"message": f"Alert check failed: {str(e)}"}), 500

@app.route("/search-artworks", methods=["GET"])
@jwt_required()
def search_artworks():
    try:
        # Get the search term from the URL
        query = request.args.get('q', '')
        artworks = Artwork.query.filter(
            or_(
                Artwork.title.ilike(f'%{query}%'),
                Artwork.artist.ilike(f'%{query}%'),
                Artwork.theme.ilike(f'%{query}%')
            )
        ).all()
        return jsonify({"artworks": artworks_schema.dump(artworks)})
    except Exception as e:
        logger.error(f"Search mission failed: {str(e)}")
        return jsonify({"message": f"Search failed: {str(e)}"}), 500

@app.route("/featured-artworks", methods=["GET"])
@jwt_required()
def get_featured_artworks():
    try:
        # Fetch artworks with high views or recently added
        featured_artworks = Artwork.query.order_by(Artwork.views.desc(), Artwork.updated_at.desc()).limit(5).all()
        return jsonify({"artworks": artworks_schema.dump(featured_artworks)})
    except Exception as e:
        logger.error(f"Error retrieving featured artworks: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500
    
@app.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    try:
        current_user_id = get_jwt_identity()
        member = Member.query.get_or_404(current_user_id)
        # Don't return the actual password, mask it
        member.password = "########"
        return jsonify({"member": member_schema.dump(member)})
    except Exception as e:
        logger.error(f"Error retrieving profile: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500
    
@app.route("/update-profile", methods=["PUT"])
@jwt_required()
def update_profile():
    data = request.get_json()
    try:
        # Get the current user's ID from the JWT token
        current_user_id = get_jwt_identity()
        member = Member.query.get_or_404(current_user_id)

        # Update user info based on the data sent
        if 'name' in data:
            member.name = data['name']
        if 'email' in data:
            # Check if the new email is unique
            if Member.query.filter(Member.id != member.id, Member.email == data['email']).first():
                return jsonify({"message": "Email already in use"}), 400
            member.email = data['email']
            
        db.session.commit()
        logger.info(f"User profile updated: {member.name}")
        return jsonify({"message": "Profile updated successfully", "member": member_schema.dump(member)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating profile: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route("/roles", methods=["POST", "PUT"])
@jwt_required()
def manage_role():
    data = request.get_json()
    try:
        # Only admins can manage roles
        current_user_id = get_jwt_identity()
        member = Member.query.filter_by(id=int(current_user_id)).first()
        if member.role.name != "admin":
            return jsonify({"msg": "Only admins can manage roles"}), 403

        if request.method == "POST":
            new_role = Role(name=data.get('name'))
            db.session.add(new_role)
        else:  # PUT
            role = Role.query.get(data.get('id'))
            if not role:
                return jsonify({"message": "Role not found"}), 404
            role.name = data.get('name')

        db.session.commit()
        return jsonify({"message": f"Role {'created' if request.method == 'POST' else 'updated'} successfully", "role": role_schema.dump(role if request.method == "PUT" else new_role)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error managing role: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route("/roles/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_role(id):
    try:
        # Only admins can manage roles
        current_user_id = get_jwt_identity()
        member = Member.query.filter_by(id=int(current_user_id)).first()
        if member.role.name != "admin":
            return jsonify({"msg": "Only admins can manage roles"}), 403

        role = Role.query.get_or_404(id)
        # Prevent deleting roles if they are in use
        if role.members:
            return jsonify({"message": "Cannot delete role; it's assigned to users"}), 400

        db.session.delete(role)
        db.session.commit()
        logger.info(f"Role deleted: {role.name}")
        return jsonify({"message": "Role deleted successfully"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting role: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/upload-image', methods=['POST'])
@jwt_required()
def upload_image():
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No file selected for uploading"}), 400
    if file:
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        return jsonify({"message": "File successfully uploaded", "filename": file.filename})
    
    return jsonify({"message": "Something went wrong"}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename) 
if __name__ == '__main__':
    # Initialize roles before running the app
    with app.app_context():
        initialize_roles()
    port = int(os.environ.get("PORT", 5000))  # Get port from environment, default to 5000
    app.run(debug=False, host='0.0.0.0', port=port)