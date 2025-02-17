# config.py

import os
import binascii
from dotenv import load_dotenv

load_dotenv()  # Just in case, but run.py also does this

class Config:
    # Security
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'fallback_secret_key')
    WTF_CSRF_SECRET_KEY = SECRET_KEY  # Use same key for CSRF
    AES_KEY = binascii.unhexlify(os.environ.get('AES_KEY', ''))  # 32 bytes in hex

    # Firebase
    FIREBASE_SERVICE_ACCOUNT = "serviceAccountKey.json"

    # Stripe
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_xxx')

    # Email
    EMAIL_HOST = 'smtp.gmail.com'
    EMAIL_PORT = 587
    EMAIL_USER = os.environ.get('EMAIL_USER', 'vlogit1998@gmail.com')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'Simran461')

    @staticmethod
    def init_app(app):
        pass
