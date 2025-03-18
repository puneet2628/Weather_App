import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'mysecretkey'  # Fallback if SECRET_KEY is not set in .env
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI') or 'sqlite:///users.db'  # Default to SQLite
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))  # Default to 587 if not set
    MAIL_USE_TLS = bool(os.environ.get('MAIL_USE_TLS', True))  # Default to True if not set
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')  # Email address for sending password reset emails
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')  # Email password for the above account
