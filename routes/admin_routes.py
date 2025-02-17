# routes/admin_routes.py

import os
import uuid
import pyotp
import re
from datetime import datetime
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_wtf.csrf import validate_csrf, CSRFError, generate_csrf
from db import get_db
from routes.auth_routes import sha256_hash
from routes.send_email import send_email
from config import Config

admin_bp = Blueprint('admin_bp', __name__, url_prefix='/admin')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['png', 'jpg', 'jpeg']

@admin_bp.before_request
def check_admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('main_bp.index'))

@admin_bp.route('/')
def admin_dashboard():
    """
    Admin main page: seed events, add event, create admin user.
    """
    return render_template('admin.html', csrf_token=generate_csrf())

@admin_bp.route('/seed_dummy_events')
def seed_dummy_events():
    db = get_db()
    dummy_events = [
        {
            "name": "Rock Fest",
            "date": "2025-10-10",
            "time": "19:00",
            "description": "Enjoy rock music all night long!",
            "banner": "/static/images/rock.jpg",
            "price": 50.00,
            "seats": {f"Seat {i}": "available" for i in range(1, 11)}
        },
        {
            "name": "Jazz Night",
            "date": "2025-11-05",
            "time": "20:00",
            "description": "Smooth jazz in an intimate setting.",
            "banner": "/static/images/jazz.jpg",
            "price": 40.00,
            "seats": {f"Seat {i}": "available" for i in range(1, 11)}
        }
    ]
    for ev in dummy_events:
        db.collection('concerts').add(ev)

    flash('Dummy events added!', 'success')
    return redirect(url_for('admin_bp.admin_dashboard'))

@admin_bp.route('/add_event', methods=['POST'])
def add_event():
    """
    Add a new event with a price (in GBP).
    """
    try:
        validate_csrf(request.form.get('csrf_token'))
    except CSRFError:
        flash('Invalid CSRF token.', 'danger')
        return redirect(url_for('admin_bp.admin_dashboard'))

    db = get_db()
    name = request.form.get('name')
    date = request.form.get('date')
    time = request.form.get('time')
    description = request.form.get('description')
    price_str = request.form.get('price', '0')
    try:
        price = float(price_str)
    except ValueError:
        price = 0.00
    
    file = request.files.get('banner')
    banner_url = "/static/images/default.jpg"
    if file and allowed_file(file.filename):
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        save_path = os.path.join("static", "images", unique_name)
        file.save(save_path)  # Save into static/images/
        banner_url = f"/static/images/{unique_name}"
    
    new_event = {
        "name": name,
        "date": date,
        "time": time,
        "description": description,
        "banner": banner_url,
        "price": price,
        "seats": {f"Seat {i}": "available" for i in range(1, 11)}
    }
    db.collection('concerts').add(new_event)
    flash("Event added successfully!", 'success')
    return redirect(url_for('admin_bp.admin_dashboard'))

@admin_bp.route('/create_admin', methods=['POST'])
def create_admin():
    """
    Create new admin user. Then let them do TOTP if needed.
    """
    try:
        validate_csrf(request.form.get('csrf_token'))
    except CSRFError:
        flash('Invalid CSRF token.', 'danger')
        return redirect(url_for('admin_bp.admin_dashboard'))

    db = get_db()
    email = request.form.get('email')
    username = request.form.get('username')
    password_plain = request.form.get('password')

    # Check duplicates
    if db.collection('users').where('email', '==', email).get():
        flash('Email already registered!', 'danger')
        return redirect(url_for('admin_bp.admin_dashboard'))
    if db.collection('users').where('username', '==', username).get():
        flash('Username already taken!', 'danger')
        return redirect(url_for('admin_bp.admin_dashboard'))

    if len(password_plain) < 12:
        flash('Password too weak for admin!', 'danger')
        return redirect(url_for('admin_bp.admin_dashboard'))

    # Hash with SHA-256
    pw_hash = sha256_hash(password_plain)
    import pyotp
    secret = pyotp.random_base32()

    admin_data = {
        'username': username,
        'email': email,
        'password': pw_hash,
        'mfa_secret': secret,
        'role': 'admin',
        'two_factor_verified': False,
        'created_at': datetime.utcnow().isoformat()
    }
    user_ref = db.collection('users').add(admin_data)
    user_id = user_ref[1].id

    # We reuse the normal 'pending_user_id' to unify TOTP flow
    session['pending_user_id'] = user_id

    # Generate TOTP URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="TicketSecure")

    flash('Admin created. Complete 2FA now.', 'info')
    return render_template('mfa_setup.html', uri=uri, totp_secret=secret, csrf_token=generate_csrf())
