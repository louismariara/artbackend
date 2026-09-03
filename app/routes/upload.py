from flask import Blueprint, jsonify, request, send_from_directory, current_app
from werkzeug.utils import secure_filename
from ..utils.logging import logger
from ..utils.decorators import role_required
import os
import uuid

upload_bp = Blueprint('upload', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


def _allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@upload_bp.route('/upload-image', methods=['POST'])
@role_required('admin', 'curator')
def upload_image():
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No file selected for uploading"}), 400

    if not _allowed_file(file.filename):
        logger.warning(f"Upload rejected: disallowed extension for filename '{file.filename}'")
        return jsonify({
            "message": f"File type not allowed. Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        }), 400

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE:
        logger.warning(f"Upload rejected: file too large ({size} bytes) for filename '{file.filename}'")
        return jsonify({"message": f"File too large. Max size is {MAX_FILE_SIZE // (1024*1024)}MB"}), 400

    # secure_filename() strips path separators, "..", null bytes, and
    # other dangerous characters — but KEEPS the user's chosen name
    # (e.g. "My Painting!.jpg" becomes "My_Painting.jpg"), it doesn't
    # replace it outright.
    safe_filename = secure_filename(file.filename)

    if not safe_filename:
        # Can happen if the original name was ONLY unsafe characters
        # (e.g. "../../../.jpg"), leaving nothing usable after cleaning.
        return jsonify({"message": "Filename is invalid"}), 400

    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_filename)

    # If that name is already taken, don't silently overwrite the
    # existing file — append a short unique suffix instead, so both
    # files survive.
    if os.path.exists(filepath):
        name, ext = os.path.splitext(safe_filename)
        safe_filename = f"{name}-{uuid.uuid4().hex[:8]}{ext}"
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_filename)

    file.save(filepath)
    logger.info(f"File uploaded: '{safe_filename}' (original name: '{file.filename}')")
    return jsonify({"message": "File successfully uploaded", "filename": safe_filename})


@upload_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    safe_filename = secure_filename(filename)
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], safe_filename)