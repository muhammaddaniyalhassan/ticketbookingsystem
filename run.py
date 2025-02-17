# run.py

import os
from dotenv import load_dotenv
load_dotenv()  # Load .env first

from flask import Flask
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from config import Config
from db import init_firebase

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize CSRF
    csrf = CSRFProtect(app)

    # Apply Talisman for security headers (optional; can be removed if not needed)
    Talisman(
    app,
    force_https=False,
    strict_transport_security=False,
    content_security_policy={
        'default-src': "'self'",
        # Add a font-src directive to allow external fonts
        'font-src': [
            "'self'",
            'https://cdn.jsdelivr.net',  # or '*'
        ],
        # Also might need style-src, script-src, img-src, etc. for cdn.jsdelivr.net
        'style-src': [
            "'self'",
            'https://cdn.jsdelivr.net',
            "'unsafe-inline'"
            "'unsafe-inline'"
        ],
        'script-src': [
            "'self'",
            'https://cdn.jsdelivr.net',
            'https://js.stripe.com'
        ],
        'img-src': [
            "'self'",
            'https://api.qrserver.com',
            'data:'
        ]
    }
)


    # Initialize Firebase
    init_firebase()

    # Register Blueprints
    from routes.main_routes import main_bp
    from routes.auth_routes import auth_bp
    from routes.admin_routes import admin_bp
    from routes.booking_routes import booking_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(booking_bp)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
