# routes/main_routes.py

from flask import Blueprint, render_template
from db import get_db

main_bp = Blueprint('main_bp', __name__)

@main_bp.route('/')
def index():
    """
    Home page route. Lists events or shows a message if none exist.
    """
    db = get_db()
    events = db.collection('concerts').stream()
    event_list = []
    for doc in events:
        ev_data = doc.to_dict()
        ev_data['id'] = doc.id
        event_list.append(ev_data)
    return render_template('index.html', events=event_list)
