from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, PendingAuth, LoginLog
from app.forms import LoginForm, RegisterForm, TwoFAChoiceForm, OTPForm
import secrets
import bcrypt
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)


def log_attempt(email, success, method=None, failure_reason=None, user_id=None):
    """Enregistre une tentative de connexion dans login_logs."""
    entry = LoginLog(
        user_id=user_id,
        email=email,
        ip_address=request.remote_addr,
        method=method,
        success=success,
        failure_reason=failure_reason
    )
    db.session.add(entry)
    db.session.commit()


# ─────────────────────────────────────────
#  INSCRIPTION
# ─────────────────────────────────────────
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Cet email est déjà utilisé.', 'danger')
            return render_template('register.html', form=form)

        user = User(
            full_name=form.full_name.data,
            email=form.email.data,
            phone_number=form.phone.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash('Compte créé avec succès ! Vous pouvez vous connecter.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)


# ─────────────────────────────────────────
#  CONNEXION
# ─────────────────────────────────────────
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            session_token = secrets.token_hex(32)
            pending = PendingAuth(
                user_id=user.id,
                session_token=session_token
            )
            db.session.add(pending)
            db.session.commit()
            session['pending_token'] = session_token
            session['user_id'] = user.id
            session['pending_email'] = user.email
            return redirect(url_for('auth.twofa_choice'))
        else:
            log_attempt(
                email=form.email.data,
                success=False,
                failure_reason='bad_password'
            )
            flash('Email ou mot de passe incorrect.', 'danger')

    return render_template('login.html', form=form)


# ─────────────────────────────────────────
#  CHOIX 2FA
# ─────────────────────────────────────────
@auth_bp.route('/2fa-choice', methods=['GET', 'POST'])
def twofa_choice():
    if 'pending_token' not in session:
        return redirect(url_for('auth.login'))

    form = TwoFAChoiceForm()
    if form.validate_on_submit():
        pending = PendingAuth.query.filter_by(session_token=session['pending_token']).first()
        if not pending:
            flash('Session expirée, veuillez vous reconnecter.', 'danger')
            return redirect(url_for('auth.login'))

        if form.method.data == 'qr':
            return redirect(url_for('auth.twofa_qr'))
        else:
            return redirect(url_for('auth.twofa_otp'))

    return render_template('2fa_choice.html', form=form)


# ─────────────────────────────────────────
#  2FA — OTP
# ─────────────────────────────────────────
@auth_bp.route('/2fa/otp', methods=['GET', 'POST'])
def twofa_otp():
    if 'pending_token' not in session:
        return redirect(url_for('auth.login'))

    pending = PendingAuth.query.filter_by(session_token=session['pending_token']).first()
    if not pending:
        flash('Session expirée.', 'danger')
        return redirect(url_for('auth.login'))

    # Génération de l'OTP (une seule fois)
    if not pending.otp_code_hash:
        otp = str(secrets.randbelow(1000000)).zfill(6)
        pending.otp_code_hash = bcrypt.hashpw(
            otp.encode('utf-8'), bcrypt.gensalt()
        ).decode('utf-8')
        pending.otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
        pending.method = 'otp'
        db.session.commit()

        user = User.query.get(pending.user_id)
        print("==========================================")
        print(f"  OTP : {otp}")
        print(f"  Envoyé au numéro : {user.phone_number}")
        print("==========================================")

        last_digits = user.phone_number[-3:] if user.phone_number else "***"
        flash(f'Un code a été envoyé au numéro se terminant par ***{last_digits}.', 'info')

    user = User.query.get(pending.user_id)
    form = OTPForm()
    if form.validate_on_submit():

        # Trop de tentatives
        if pending.attempts >= 3:
            log_attempt(user.email, False, method='otp',
                        failure_reason='max_attempts', user_id=user.id)
            db.session.delete(pending)
            db.session.commit()
            session.clear()
            flash('Trop de tentatives. Veuillez vous reconnecter.', 'danger')
            return redirect(url_for('auth.login'))

        # Code expiré
        if datetime.utcnow() > pending.otp_expires_at:
            log_attempt(user.email, False, method='otp',
                        failure_reason='otp_expired', user_id=user.id)
            db.session.delete(pending)
            db.session.commit()
            session.clear()
            flash('Code expiré. Veuillez vous reconnecter.', 'danger')
            return redirect(url_for('auth.login'))

        # Vérification du code
        if bcrypt.checkpw(form.code.data.encode('utf-8'),
                          pending.otp_code_hash.encode('utf-8')):
            log_attempt(user.email, True, method='otp', user_id=user.id)
            pending.is_verified = True
            db.session.commit()
            login_user(user)
            session.pop('pending_token', None)
            session.pop('user_id', None)
            session.pop('pending_email', None)
            flash('Connexion réussie !', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            pending.attempts += 1
            db.session.commit()
            flash(f'Code incorrect. Tentatives restantes : {3 - pending.attempts}', 'danger')

    return render_template('2fa_otp.html', form=form, user=user)


# ─────────────────────────────────────────
#  2FA — QR CODE
# ─────────────────────────────────────────
@auth_bp.route('/2fa/qr')
def twofa_qr():
    if 'pending_token' not in session:
        return redirect(url_for('auth.login'))

    pending = PendingAuth.query.filter_by(session_token=session['pending_token']).first()
    if not pending:
        flash('Session expirée.', 'danger')
        return redirect(url_for('auth.login'))

    import qrcode
    from io import BytesIO
    import base64

    if not pending.qr_token:
        pending.qr_token = secrets.token_hex(32)
        pending.qr_expires_at = datetime.utcnow() + timedelta(seconds=60)
        pending.method = 'qr'
        db.session.commit()

    if datetime.utcnow() > pending.qr_expires_at:
        log_attempt(
            email=User.query.get(pending.user_id).email,
            success=False,
            method='qr',
            failure_reason='qr_expired',
            user_id=pending.user_id
        )
        db.session.delete(pending)
        db.session.commit()
        session.clear()
        flash('QR Code expiré. Veuillez vous reconnecter.', 'danger')
        return redirect(url_for('auth.login'))

    scan_url = url_for('auth.verify_scan', token=pending.qr_token, _external=True)
    qr = qrcode.make(scan_url)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template('2fa_qr.html', qr_code=qr_base64)


@auth_bp.route('/verify-scan')
def verify_scan():
    token = request.args.get('token')
    if not token:
        return render_template('scan_result.html', success=False, message='Token manquant.')

    pending = PendingAuth.query.filter_by(qr_token=token).first()
    if not pending:
        return render_template('scan_result.html', success=False, message='Token invalide.')

    if datetime.utcnow() > pending.qr_expires_at:
        db.session.delete(pending)
        db.session.commit()
        return render_template('scan_result.html', success=False, message='QR Code expiré.')

    pending.is_verified = True
    db.session.commit()
    return render_template('scan_result.html', success=True,
                           message='Authentification confirmée ! Vous pouvez retourner à votre ordinateur.')


@auth_bp.route('/2fa/qr/check')
def check_qr():
    if 'pending_token' not in session:
        return {'status': 'error'}

    pending = PendingAuth.query.filter_by(session_token=session['pending_token']).first()
    if not pending:
        return {'status': 'expired'}

    if pending.is_verified:
        user = User.query.get(session['user_id'])
        log_attempt(user.email, True, method='qr', user_id=user.id)
        login_user(user)
        session.pop('pending_token', None)
        session.pop('user_id', None)
        session.pop('pending_email', None)
        return {'status': 'verified'}

    if pending.qr_expires_at and datetime.utcnow() > pending.qr_expires_at:
        return {'status': 'expired'}

    return {'status': 'waiting'}


# ─────────────────────────────────────────
#  DÉCONNEXION
# ─────────────────────────────────────────
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('auth.login'))