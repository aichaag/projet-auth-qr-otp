from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
import bcrypt

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )


class PendingAuth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    qr_token = db.Column(db.String(64), unique=True, nullable=True)
    otp_code_hash = db.Column(db.String(128), nullable=True)
    otp_expires_at = db.Column(db.DateTime, nullable=True)
    qr_expires_at = db.Column(db.DateTime, nullable=True)
    method = db.Column(db.String(3), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class LoginLog(db.Model):
    """Journalisation de toutes les tentatives de connexion."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    email = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    success = db.Column(db.Boolean, nullable=False)
    failure_reason = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='login_logs', foreign_keys=[user_id])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))