import firebase_admin
from firebase_admin import credentials
from core.config import settings

# Set Firebase credentials path relative to project root
firebase_cred_path = settings.BASE_DIR / "cred" / "firebase.json"

def initialize_firebase():
    if not firebase_admin._apps:
        # Check if path exists (Path object works here)
        if firebase_cred_path.exists():
            # Convert Path to string for Certificate
            cred = credentials.Certificate(str(firebase_cred_path))
            firebase_admin.initialize_app(cred)
        else:
            print(f"Warning: Firebase credentials not found at {firebase_cred_path}. Push notifications may not work.")
