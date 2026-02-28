import firebase_admin
from firebase_admin import credentials
import platform
import os
from pathlib import Path

# Set Firebase credentials path based on OS
if platform.system() == "Windows":
    firebase_cred_path = r"C:\Users\DELL-001\nbs-backend\NBS-Backend\cred\firebase.json"
else:
    firebase_cred_path = "/home/ubuntu/myapp/cred/firebase.json"

# Fallback to .env variable if exists
firebase_cred_path = os.getenv("FIREBASE_CRED_PATH", firebase_cred_path)

def initialize_firebase():
    if not firebase_admin._apps:
        if Path(firebase_cred_path).exists():
            cred = credentials.Certificate(firebase_cred_path)
            firebase_admin.initialize_app(cred)
        else:
            print(f"Warning: Firebase credentials not found at {firebase_cred_path}. Push notifications may not work.")
