from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models import LoginLog

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
@main_bp.route('/dashboard')
@login_required
def dashboard():
    # Récupère les 10 dernières tentatives de connexion de l'utilisateur
    logs = (LoginLog.query
            .filter_by(user_id=current_user.id)
            .order_by(LoginLog.timestamp.desc())
            .limit(10)
            .all())
    return render_template('dashboard.html', logs=logs)