# routes/auth_routes.py

import hashlib
import re
import pyotp
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import validate_csrf, CSRFError, generate_csrf
from db import get_db
from routes.send_email import send_email

auth_bp = Blueprint('auth_bp', __name__)

PASSWORD_RE = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*]).{12,}$')

def sha256_hash(password: str) -> str:
    """SHA-256 hash for the password."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def check_password(password: str, stored_hash: str) -> bool:
    """Compare a plain-text password (SHA-256) to a stored hash."""
    return sha256_hash(password) == stored_hash

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
        except CSRFError:
            flash('Invalid CSRF token. Please try again.', 'danger')
            return redirect(url_for('auth_bp.login'))

        db = get_db()
        user_input = request.form.get('user_input')  # email or username
        password_plain = request.form.get('password')
        mfa_code = request.form.get('mfa_code')

        # Find user
        user_doc = None
        email_query = db.collection('users').where('email', '==', user_input).get()
        if email_query:
            user_doc = email_query[0]
        else:
            un_query = db.collection('users').where('username', '==', user_input).get()
            if un_query:
                user_doc = un_query[0]

        if not user_doc:
            flash('Invalid credentials. (User not found)', 'danger')
            return redirect(url_for('auth_bp.login'))

        user_data = user_doc.to_dict()
        # Check password with SHA-256
        if not check_password(password_plain, user_data['password']):
            flash('Invalid credentials. (Wrong password)', 'danger')
            return redirect(url_for('auth_bp.login'))

        # Must have completed 2FA
        if not user_data.get('two_factor_verified'):
            flash("You haven't completed 2FA setup yet.", 'danger')
            return redirect(url_for('auth_bp.register'))

        # TOTP check
        totp = pyotp.TOTP(user_data['mfa_secret'])
        if not mfa_code or not totp.verify(mfa_code):
            flash('Invalid or missing 2FA code.', 'danger')
            return redirect(url_for('auth_bp.login'))

        # Success
        session['user_id'] = user_doc.id
        session['username'] = user_data['username']
        session['role'] = user_data.get('role', 'user')
        flash('Login successful!', 'success')
        return redirect(url_for('main_bp.index'))

    return render_template('login.html', csrf_token=generate_csrf())

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
        except CSRFError:
            flash('Invalid CSRF token. Please try again.', 'danger')
            return redirect(url_for('auth_bp.register'))

        db = get_db()
        username = request.form.get('username')
        email = request.form.get('email')
        password_plain = request.form.get('password')

        # Validate password complexity
        if not PASSWORD_RE.match(password_plain):
            flash('Password must be >=12 chars, with uppercase, lowercase, number, special char.', 'danger')
            return render_template('register.html', prev_username=username, prev_email=email, csrf_token=generate_csrf())

        # Check duplicates
        if db.collection('users').where('email', '==', email).get():
            flash('Email already registered!', 'danger')
            return render_template('register.html', prev_username=username, csrf_token=generate_csrf())
        if db.collection('users').where('username', '==', username).get():
            flash('Username already taken!', 'danger')
            return render_template('register.html', prev_email=email, csrf_token=generate_csrf())

        # Hash password with SHA-256
        pw_hash = sha256_hash(password_plain)

        # TOTP secret
        secret = pyotp.random_base32()

        new_user_data = {
            'username': username,
            'email': email,
            'password': pw_hash,
            'mfa_secret': secret,
            'role': 'user',
            'two_factor_verified': False,
            'created_at': datetime.utcnow().isoformat()
        }
        user_ref = db.collection('users').add(new_user_data)
        user_id = user_ref[1].id

        # Build TOTP URI
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=email, issuer_name="TicketSecure")

        # Store pending user
        session['pending_user_id'] = user_id
        flash('Registration successful. Complete 2FA setup to finish.', 'info')
        return render_template('mfa_setup.html', uri=uri, totp_secret=secret, csrf_token=generate_csrf())
    else:
        return render_template('register.html', csrf_token=generate_csrf())

@auth_bp.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    try:
        validate_csrf(request.form.get('csrf_token'))
    except CSRFError:
        flash('Invalid CSRF token. Please try again.', 'danger')
        return redirect(url_for('auth_bp.register'))

    db = get_db()
    user_id = session.get('pending_user_id')
    if not user_id:
        flash('No pending user found. Please register again.', 'danger')
        return redirect(url_for('auth_bp.register'))

    mfa_code = request.form.get('mfa_code')
    user_doc = db.collection('users').document(user_id).get()
    if not user_doc.exists:
        flash('User not found in database.', 'danger')
        return redirect(url_for('auth_bp.register'))

    user_data = user_doc.to_dict()
    totp = pyotp.TOTP(user_data['mfa_secret'])
    if mfa_code and totp.verify(mfa_code):
        db.collection('users').document(user_id).update({'two_factor_verified': True})
        session.pop('pending_user_id', None)
        flash('2FA setup successful! You can now log in.', 'success')
        return redirect(url_for('auth_bp.login'))
    else:
        flash('Invalid 2FA code. Try again.', 'danger')
        return redirect(url_for('auth_bp.register'))

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main_bp.index'))

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    User enters email + 2FA code. If correct, we generate a random new password,
    send it via email, and update Firestore with the new hashed password.
    """
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
        except CSRFError:
            flash('Invalid CSRF token. Please try again.', 'danger')
            return redirect(url_for('auth_bp.forgot_password'))

        db = get_db()
        email_input = request.form.get('email')
        mfa_code = request.form.get('mfa_code')

        # Find user by email
        user_query = db.collection('users').where('email', '==', email_input).get()
        if not user_query:
            flash('No user found with that email.', 'danger')
            return redirect(url_for('auth_bp.forgot_password'))

        user_doc = user_query[0]
        user_data = user_doc.to_dict()
        # Must have two_factor_verified = True
        if not user_data['two_factor_verified']:
            flash('2FA not set up for this account. Cannot reset password.', 'danger')
            return redirect(url_for('auth_bp.forgot_password'))

        # Check TOTP
        totp = pyotp.TOTP(user_data['mfa_secret'])
        if not mfa_code or not totp.verify(mfa_code):
            flash('Invalid or missing 2FA code.', 'danger')
            return redirect(url_for('auth_bp.forgot_password'))

        # Generate new random password
        import secrets
        new_pass_plain = secrets.token_hex(8)  # 16 hex chars ~ 8 bytes
        new_pass_hash = sha256_hash(new_pass_plain)

        # Update Firestore
        db.collection('users').document(user_doc.id).update({'password': new_pass_hash})

        # Email user the new password
        send_email(
            to=user_data['email'],
            subject="Password Reset",
            body=f"Your password has been reset.\n\nNew Password: {new_pass_plain}"
        )
        flash('Password reset successful. Check your email for the new password.', 'success')
        return redirect(url_for('auth_bp.login'))

    return render_template('forgot_password.html', csrf_token=generate_csrf())
