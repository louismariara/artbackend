from flask import Blueprint, jsonify, request, send_from_directory, current_app, g
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


def _looks_like_image(header):
    """The extension is only a label the uploader chose — check the file's
    first bytes really match PNG, JPEG, GIF or WebP."""
    return (
        header.startswith(b'\x89PNG\r\n\x1a\n')
        or header.startswith(b'\xff\xd8\xff')
        or header.startswith(b'GIF87a')
        or header.startswith(b'GIF89a')
        or (header[:4] == b'RIFF' and header[8:12] == b'WEBP')
    )


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

    header = file.read(12)
    file.seek(0)
    if not _looks_like_image(header):
        logger.warning(f"Upload rejected: '{file.filename}' is not a real image file")
        return jsonify({"message": "That file is not a valid image"}), 400

    # Each gallery gets its own folder, and the stored name is random (128 bits),
    # so the URL can't be guessed and never collides with another gallery's file.
    extension = '.' + file.filename.rsplit('.', 1)[1].lower()
    gallery_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], str(g.org_id))
    os.makedirs(gallery_folder, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex}{extension}"
    file.save(os.path.join(gallery_folder, stored_name))

    image_path = f"{g.org_id}/{stored_name}"
    logger.info(f"File uploaded: '{image_path}' (original name: '{file.filename}')")
    return jsonify({"message": "File successfully uploaded", "filename": image_path})


@upload_bp.route('/uploads/<int:org_id>/<filename>')
def uploaded_file(org_id, filename):
    safe_filename = secure_filename(filename)
    folder = os.path.join(current_app.config['UPLOAD_FOLDER'], str(org_id))
    response = send_from_directory(folder, safe_filename)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

