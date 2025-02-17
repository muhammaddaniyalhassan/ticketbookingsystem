# routes/booking_routes.py

import os
import stripe
import pyotp
import json
from flask import Blueprint, request, render_template, flash, redirect, url_for, session, jsonify
from flask_wtf.csrf import validate_csrf, CSRFError, generate_csrf
from datetime import datetime, timedelta
from db import get_db
from config import Config
from routes.send_email import send_email
from routes.auth_routes import sha256_hash

booking_bp = Blueprint('booking_bp', __name__)
stripe.api_key = Config.STRIPE_SECRET_KEY

@booking_bp.route('/booking/<concert_id>')
def view_event(concert_id):
    if 'user_id' not in session:
        flash('Please login to book tickets.', 'info')
        return redirect(url_for('auth_bp.login'))

    db = get_db()
    doc_ref = db.collection('concerts').document(concert_id).get()
    if not doc_ref.exists:
        flash('Event not found.', 'danger')
        return redirect(url_for('main_bp.index'))

    cleanup_locked_seats(concert_id)
    concert_data = doc_ref.to_dict()
    concert_data['id'] = doc_ref.id

    from flask_wtf.csrf import generate_csrf
    return render_template(
        'booking.html',
        concert=concert_data,
        csrf_token=generate_csrf()  # pass a string
    )


@booking_bp.route('/lock_seat', methods=['POST'])
def lock_seat():
    try:
        validate_csrf(request.form.get('csrf_token'))
    except CSRFError:
        return jsonify({'error': 'Invalid CSRF token'}), 403

    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 403

    db = get_db()
    concert_id = request.form.get('concert_id')
    seat_id = request.form.get('seat_id')

    concert_ref = db.collection('concerts').document(concert_id)
    concert_doc = concert_ref.get()
    if not concert_doc.exists:
        return jsonify({'error': 'Concert not found'}), 404

    concert_data = concert_doc.to_dict()
    seats = concert_data['seats']
    cleanup_locked_seats(concert_id)

    if seats.get(seat_id) in ('booked', 'locked'):
        return jsonify({'error': 'Seat not available'}), 400

    seats[seat_id] = 'locked'
    locked_info = concert_data.get('lockedInfo', {})
    locked_info[seat_id] = {
        'lockedBy': session['user_id'],
        'lockedAt': datetime.utcnow().isoformat()
    }
    concert_ref.update({'seats': seats, 'lockedInfo': locked_info})
    
    return jsonify({'message': 'Seat locked'}), 200

@booking_bp.route('/checkout', methods=['POST'])
def checkout():
    """
    Final stripe payment with currency GBP. 
    Price is from event doc * 100 (for pence).
    """
    try:
        validate_csrf(request.form.get('csrf_token'))
    except CSRFError:
        flash('Invalid CSRF token', 'danger')
        return redirect(url_for('main_bp.index'))

    if 'user_id' not in session:
        flash('Please login first.', 'danger')
        return redirect(url_for('auth_bp.login'))

    db = get_db()
    concert_id = request.form.get('concert_id')
    seat_id = request.form.get('seat_id')
    attendee_name = request.form.get('attendee_name')
    attendee_email = request.form.get('attendee_email')

    concert_ref = db.collection('concerts').document(concert_id)
    concert_doc = concert_ref.get()
    if not concert_doc.exists:
        flash('Concert not found.', 'danger')
        return redirect(url_for('main_bp.index'))

    concert_data = concert_doc.to_dict()
    price = concert_data.get('price', 0)  # in GBP
    seats = concert_data.get('seats', {})

    cleanup_locked_seats(concert_id)
    if seats.get(seat_id) != 'locked':
        flash('Seat reservation expired. Please try again.', 'danger')
        return redirect(url_for('booking_bp.view_event', concert_id=concert_id))

    # Stripe Payment
    amount_pence = int(price * 100)  # Convert GBP to pence
    try:
        charge = stripe.Charge.create(
            amount=amount_pence,
            currency='gbp',
            source='tok_visa',  # test token
            description=f"Booking for {concert_data['name']} - Seat {seat_id}"
        )
    except stripe.error.StripeError as e:
        flash(f"Payment failed: {str(e)}", 'danger')
        return redirect(url_for('booking_bp.view_event', concert_id=concert_id))

    # Mark seat as booked
    seats[seat_id] = 'booked'
    locked_info = concert_data.get('lockedInfo', {})
    if seat_id in locked_info:
        del locked_info[seat_id]
    concert_ref.update({
        'seats': seats,
        'lockedInfo': locked_info
    })

    # Store booking record
    booking_data = {
        'user_id': session['user_id'],
        'concert_id': concert_id,
        'seat_id': seat_id,
        'attendee_name': attendee_name,
        'attendee_email': attendee_email,
        'booking_time': datetime.utcnow().isoformat()
    }
    db.collection('bookings').add(booking_data)

    # Send confirmation email
    user_doc = db.collection('users').document(session['user_id']).get()
    user_email = user_doc.to_dict().get('email')
    if user_email:
        send_email(
            to=user_email,
            subject="Booking Confirmation",
            body=(
                f"Your booking for {concert_data['name']} is confirmed.\n"
                f"Seat: {seat_id}\nPrice: £{price}\nAttendee: {attendee_name}"
            )
        )

    flash(f"Seat {seat_id} booked successfully!", 'success')
    return redirect(url_for('booking_bp.my_bookings'))

@booking_bp.route('/my_bookings')
def my_bookings():
    if 'user_id' not in session:
        return redirect(url_for('auth_bp.login'))

    db = get_db()
    user_id = session['user_id']
    booking_docs = db.collection('bookings').where('user_id', '==', user_id).stream()
    bookings = []
    for doc in booking_docs:
        bdata = doc.to_dict()
        bdata['id'] = doc.id
        bookings.append(bdata)

    return render_template('dashboard.html', bookings=bookings)

def cleanup_locked_seats(concert_id):
    """
    Any locked seats older than 5 min => revert to 'available'.
    """
    db = get_db()
    concert_ref = db.collection('concerts').document(concert_id)
    doc = concert_ref.get()
    if not doc.exists:
        return

    data = doc.to_dict()
    seats = data.get('seats', {})
    locked_info = data.get('lockedInfo', {})
    changed = False
    from datetime import datetime, timedelta

    for seat_id, lock_data in list(locked_info.items()):
        locked_at_str = lock_data['lockedAt']
        locked_at = datetime.fromisoformat(locked_at_str)
        if datetime.utcnow() - locked_at > timedelta(minutes=5):
            if seats.get(seat_id) == 'locked':
                seats[seat_id] = 'available'
            del locked_info[seat_id]
            changed = True

    if changed:
        concert_ref.update({'seats': seats, 'lockedInfo': locked_info})
