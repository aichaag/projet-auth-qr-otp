import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-a-changer-en-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///auth_system.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PREFERRED_URL_SCHEME = 'https'