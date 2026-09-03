import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-jwt-secret-key')
    DB_USER = os.getenv('DB_USER')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = os.getenv('DB_PORT')
    DB_NAME = os.getenv('DB_NAME')

    if DB_HOST:
        SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    else:
        # No Postgres configured in .env — fall back to a local SQLite file
        # so the app is still runnable for quick testing. Add DB_HOST etc.
        # back to .env whenever Postgres is ready to use again.
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'local.db'
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

    # Comma-separated list in .env, e.g. CORS_ORIGINS=http://localhost:5173,https://yourdomain.com
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5173').split(',')