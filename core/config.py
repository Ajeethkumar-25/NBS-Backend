import os
import platform
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Settings:
    PROJECT_NAME = "Photo Studio & Matrimony API"
    VERSION = "1.0.0"
    SECRET_KEY = os.getenv("SECRET_KEY", "annularSecretKey")
    REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "annularRefreshSecretKey")
    ALGORITHM = os.getenv("ALGORITHM", "HS512")
    ACCESS_TOKEN_EXPIRE_MINUTES = 120
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    OTP_EXPIRE_MINUTES = 5
    
    if platform.system() == "Windows":
        UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "uploads"))
        PHOTOS_DIR = Path(os.getenv("PHOTOS_DIR", "myapp/uploaded_photos"))
        HOROSCOPES_DIR = Path(os.getenv("HOROSCOPES_DIR", "myapp/uploaded_horoscopes"))
    else:
        UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/home/ubuntu/uploads"))
        PHOTOS_DIR = Path(os.getenv("PHOTOS_DIR", "/home/ubuntu/myapp/uploaded_photos"))
        HOROSCOPES_DIR = Path(os.getenv("HOROSCOPES_DIR", "/home/ubuntu/myapp/uploaded_horoscopes"))
    
    DB_CONFIG = {
        "dbname": os.getenv("dbname"),
        "user": os.getenv("user"),
        "password": os.getenv("password"),
        "host": os.getenv("host"),
        "port": os.getenv("port")
    }
    
    BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")

settings = Settings()
