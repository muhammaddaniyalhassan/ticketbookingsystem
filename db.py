# db.py

import firebase_admin
from firebase_admin import credentials, firestore
from config import Config

db_client = None

def init_firebase():
    global db_client
    if not db_client:
        cred = credentials.Certificate(Config.FIREBASE_SERVICE_ACCOUNT)
        firebase_admin.initialize_app(cred)
        db_client = firestore.client()
    return db_client

def get_db():
    if not db_client:
        init_firebase()
    return db_client
