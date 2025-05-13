import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import tempfile
import bcrypt
import re
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Query, Form
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
# from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, ValidationError, ConfigDict, validator
from passlib.context import CryptContext
from contextlib import asynccontextmanager
import psycopg2
from psycopg2.extras import DictCursor, RealDictCursor
from datetime import datetime, time, timedelta, date, timezone
from typing import List, Optional, Dict, Any, Union
import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError
from jose.exceptions import JWTError, ExpiredSignatureError
import os
from pathlib import Path
import platform
import shutil
import uuid
from uuid import uuid4
import base64
import logging
import firebase_admin
from firebase_admin import credentials, messaging
from googletrans import Translator
import random
import json
from twilio.rest import Client
from dotenv import load_dotenv
import traceback
from astrology_terms import ASTROLOGY_TERMS

# Twilio credentials (hardcoded)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")



# Initialize Twilio client
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Initialize FastAPI app with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code to run on startup
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Delete expired refresh tokens
        cur.execute("DELETE FROM refresh_tokens WHERE expires_at <= NOW()")
        conn.commit()
        logger.info("Expired refresh tokens cleaned up")
    except Exception as e:
        conn.rollback()
        logger.error(f"Error cleaning up expired refresh tokens: {str(e)}")
    finally:
        cur.close()
        conn.close()
    
    # Ensure all necessary directories exist
    (settings.UPLOAD_DIR / "photos").mkdir(parents=True, exist_ok=True)
    (settings.UPLOAD_DIR / "horoscopes").mkdir(parents=True, exist_ok=True)
    
    yield  # The application is now running

    # Code to run on shutdown (optional)
    logger.info("Shutting down...")

app = FastAPI(lifespan=lifespan, title="Photo Studio & Matrimony API", debug=True)

# Check OS and set paths accordingly
if platform.system() == "Windows":
    uploads_dir = r"C:\Users\Premalatha\Desktop\NBS-Backend\uploads"
    photos_dir = r"C:\Users\Premalatha\Desktop\NBS-Backend\myapp\uploaded_photos"
    horoscopes_dir = r"C:\Users\Premalatha\Desktop\NBS-Backend\myapp\uploaded_horoscopes"
else:
    uploads_dir = "/home/ubuntu/uploads"
    photos_dir = "/home/ubuntu/myapp/uploaded_photos"
    horoscopes_dir = "/home/ubuntu/myapp/uploaded_horoscopes"

# Ensure the uploads directory exists
Path(uploads_dir).mkdir(parents=True, exist_ok=True)

# Mount static file routes
app.mount("/static", StaticFiles(directory=uploads_dir), name="static")
app.mount("/static/photos", StaticFiles(directory=photos_dir), name="static_photos")
app.mount("/static/horoscopes", StaticFiles(directory=horoscopes_dir), name="static_horoscopes")

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "https://admin.newbrindha.com/", "https://newbrindha.com/"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
load_dotenv(dotenv_path=Path(".env"), encoding="utf-8-sig")

# Configuration
class Settings:
    PROJECT_NAME = "Photo Studio & Matrimony API"
    VERSION = "1.0.0"
    SECRET_KEY = "annularSecretKey"  # Hardcoded secret key
    REFRESH_SECRET_KEY = "annularRefreshSecretKey"  # Hardcoded refresh secret key
    ALGORITHM = "HS512"
    ACCESS_TOKEN_EXPIRE_MINUTES = 120
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    OTP_EXPIRE_MINUTES = 5
    UPLOAD_DIR = Path("uploads")
    DB_CONFIG ={
    "dbname" : os.getenv("dbname"),
    "user" : os.getenv("user"),
    "password" : os.getenv("password"),
    "host" : os.getenv("host"),
    "port" : os.getenv("port")
}
    AWS_S3_BUCKET_NAME = "nbs-matrimonybucket1"  # Add this line
    AWS_S3_REGION = "ap-south-1"  # Add this line
    
settings = Settings()

# Ensure all necessary directories exist
(settings.UPLOAD_DIR / "photos").mkdir(parents=True, exist_ok=True)
(settings.UPLOAD_DIR / "horoscopes").mkdir(parents=True, exist_ok=True)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Set Firebase credentials path based on OS
if platform.system() == "Windows":
    firebase_cred_path = r"C:\Users\Premalatha\Desktop\NBS-Backend\myapp\cred\firebase.json"
else:
    firebase_cred_path = "/home/ubuntu/myapp/cred/firebase.json"

# Initialize Firebase
cred = credentials.Certificate(firebase_cred_path)
firebase_admin.initialize_app(cred)


# Database connection
def get_db_connection():
    try:
        # Access the individual settings from the DB_CONFIG attribute
        db_config = settings.DB_CONFIG
        
        conn = psycopg2.connect(
            dbname=db_config["dbname"],
            user=db_config["user"],
            password=db_config["password"],
            host=db_config["host"],
            port=db_config["port"]
        )
        
        return conn
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database connection error: {str(e)}"
        )

# Models

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    user_type: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    email: str
    user_type: str

class RefreshToken(BaseModel):
    refresh_token: str

class EventForm(BaseModel):
    name: str
    contact: str
    event_date: str
    event_time: str
    event_type: str
    
class FileResponse(BaseModel):
    id: int
    filename: str
    file_url: str
    file_base64: str
    uploaded_by: int
    uploaded_at: datetime

class FileUploadRequest(BaseModel):
    category: str

class FileData(BaseModel):
    private_files_id: int
    selected_urls: List[str]

class FileSelectionsRequest(BaseModel):
    private_files: List[FileData]

# Define Pydantic model
class GetFileUpdate(BaseModel):
    file_id: int
    file_type: str
    file_url: str
    category: str

class MatrimonyProfile(BaseModel):
    full_name: str
    age: int
    gender: str
    date_of_birth: str
    height: float
    weight: float
    email: EmailStr
    phone_number: str
    occupation: str
    annual_income: str
    education: str
    password: str

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class MatrimonyRegister(BaseModel):
    full_name: str
    age: str
    gender: str
    date_of_birth: str
    email: str
    password: str
    phone_number: str
    height: Optional[str] = None
    weight: Optional[str] = None
    occupation: Optional[str] = None
    annual_income: Optional[str] = None
    education: Optional[str] = None
    mother_tongue: Optional[str] = None
    profile_created_by: Optional[str] = None
    address: Optional[str] = None
    work_type: Optional[str] = None
    company: Optional[str] = None
    work_location: Optional[str] = None
    work_country: Optional[str] = None
    mother_name: Optional[str] = None
    father_name: Optional[str] = None
    sibling_count: Optional[int] = None
    elder_brother: Optional[str] = None
    elder_sister: Optional[str] = None
    younger_sister: Optional[str] = None
    younger_brother: Optional[str] = None
    native: Optional[str] = None
    mother_occupation: Optional[str] = None
    father_occupation: Optional[str] = None
    religion: Optional[str] = None
    caste: Optional[str] = None
    sub_caste: Optional[str] = None
    nakshatra: Optional[str] = None
    rashi: Optional[str] = None
    birth_time: Optional[str] = None
    birth_place: Optional[str] = None
    ascendent: Optional[str] = None
    dhosham: Optional[str] = None
    other_dhosham: Optional[str] = None
    quarter: Optional[str] = None
    user_type: Optional[str] = None
    preferred_age_min: Optional[str] = None
    preferred_age_max: Optional[str] = None
    preferred_height_min: Optional[str] = None
    preferred_height_max: Optional[str] = None
    preferred_religion: Optional[str] = None
    preferred_caste: Optional[str] = None
    preferred_sub_caste: Optional[str] = None
    preferred_nakshatra: Optional[str] = None
    preferred_rashi: Optional[str] = None
    preferred_location: Optional[str] = None
    preferred_work_status: Optional[str] = None

# Define a Pydantic model for the response
class MatrimonyRegisterResponse(BaseModel):
    message: str
    user_id: int

# Matrimony Login
class MatrimonyLoginRequest(BaseModel):
    matrimony_id: str  # Unique ID for the user
    password: Optional[str] = None  
    phone_number: Optional[str] = None  
    via_link: Optional[bool] = False

# Model for login request
class MatrimonyToken(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class MatrimonyProfileResponse(BaseModel):
    matrimony_id: str
    full_name: str
    age: str
    gender: str
    date_of_birth: str
    email: str
    phone_number: str
    height: Optional[str]
    weight: Optional[str]
    occupation: Optional[str]
    annual_income: Optional[int]
    education: Optional[str]
    mother_tongue: Optional[str]
    profile_created_by: Optional[str]
    address: Optional[str]
    work_type: Optional[str]
    company: Optional[str]
    work_location: Optional[str]
    work_country: Optional[str]
    mother_name: Optional[str]
    father_name: Optional[str]
    sibling_count: Optional[str]
    elder_brother: Optional[str] 
    elder_sister: Optional[str] 
    younger_sister: Optional[str] 
    younger_brother: Optional[str]
    native: Optional[str]
    mother_occupation: Optional[str]
    father_occupation: Optional[str]
    religion: Optional[str]
    caste: Optional[str]
    sub_caste: Optional[str]
    nakshatra: Optional[str]
    rashi: Optional[str]
    birth_time: Optional[str]
    birth_place: Optional[str]
    ascendent: Optional[str]
    user_type: Optional[str]
    preferred_age_min: Optional[str]
    preferred_age_max: Optional[str]
    preferred_height_min: Optional[str]
    preferred_height_max: Optional[str]
    preferred_religion: Optional[str]
    preferred_caste: Optional[str]
    preferred_sub_caste: Optional[str]
    preferred_nakshatra: Optional[str]
    preferred_rashi: Optional[str]
    preferred_location: Optional[str]
    preferred_work_status: Optional[str]
    photo: Optional[str] = None
    photos: Optional[List[str]] = []  # If photos should be a list of strings (URLs)
    horoscope_documents: Optional[List[str]] = []
    dhosham: Optional[str]
    other_dhosham: Optional[str]    
    quarter: Optional[str]    

class OTPRequest(BaseModel):
    mobile_number: str
    full_name: str

class OTPVerify(BaseModel):
    mobile_number: str
    full_name: str
    otp: str

class FrameDetails(BaseModel):
    frame_name: str
    phone_number: str
    user_photo: List[UploadFile]  # Accepting multiple photo files
    frame_size: str
    frame_color: List[UploadFile]  # Accepting multiple image files

# Response Model -
class RefreshTokenRequest(BaseModel):
    refresh_token: str

# Pydantic model for token response
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class IncrementMatrimonyIdRequest(BaseModel):
    last_matrimony_id: str 

# Full Rashi compatibility data
RASHI_COMPATIBILITY = {
    ("mesha", "simha"): "High Compatibility",
    ("mesha", "dhanu"): "High Compatibility",
    ("vrishabha", "kanya"): "Good Compatibility",
    ("vrishabha", "makara"): "Good Compatibility",
    ("mithuna", "tula"): "Moderate Compatibility",
    ("mithuna", "kumbha"): "Good Compatibility",
    ("kataka", "vrischika"): "Very High Compatibility",
    ("kataka", "meena"): "Very High Compatibility",
    ("simha", "dhanu"): "Excellent Compatibility",
    ("tula", "mithuna"): "Strong Compatibility",
    ("dhanu", "mesha"): "High Compatibility",
    ("makara", "vrishabha"): "Good Compatibility",
    ("kumbha", "mithuna"): "Good Compatibility",
    ("meena", "kataka"): "Very High Compatibility",
}

# Full Nakshatra compatibility data
NAKSHATRA_COMPATIBILITY = {
    ("ashwini", "bharani"): "Very Compatible",
    ("rohini", "mrigashira"): "Very Compatible",
    ("magha", "purva_phalguni"): "Good Compatibility",
    ("hasta", "chitra"): "Good Compatibility",
    ("moola", "uttara_ashadha"): "Moderate Compatibility",
    ("swati", "vishakha"): "Very High Compatibility",
    ("chitra", "hasta"): "Strong Compatibility",
    ("mrigashira", "revati"): "Good Compatibility",
    ("shravana", "uttara_bhadrapada"): "Excellent Compatibility",
    ("dhanishta", "shatabhisha"): "Very Compatible",
    ("uttara_phalguni", "hasta"): "High Compatibility",
    ("anuradha", "jyestha"): "Good Compatibility",
    ("purva_bhadrapada", "uttara_bhadrapada"): "Excellent Compatibility",
}

class CompatibilityRequest(BaseModel):
    groom_rashi: str
    groom_nakshatra: str
    bride_rashi: str
    bride_nakshatra: str

class S3Handler:
    def __init__(self):
        self.aws_access_key = os.getenv("aws_access_key")
        self.aws_secret_key = os.getenv("aws_secret_key")
        self.region = os.getenv("region")
        self.bucket_name = os.getenv("bucket_name")
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
            region_name=self.region
        )

    def upload_to_s3(self, file: UploadFile, folder: str) -> str:
        """Uploads a file to S3 and returns the file URL."""
        try:
            filename = file.filename.strip().replace(" ", "_")
            s3_key = f"{folder}/{filename}"

            file.file.seek(0)  # ⚠️ Important fix
            self.s3_client.upload_fileobj(file.file, self.bucket_name, s3_key, ExtraArgs={'ContentType': file.content_type})

            file_url = f"https://{self.bucket_name}.s3.{self.region}.amazonaws.com/{s3_key}"
            logging.info(f"File uploaded successfully: {file_url}")
            return file_url

        except NoCredentialsError:
            logging.error("AWS credentials not found.")
            raise HTTPException(status_code=500, detail="AWS credentials not found.")

        except ClientError as e:
            logging.error(f"Failed to upload {filename}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to upload {filename}: {str(e)}")


    def list_files_in_s3(self, folder: str):
        """Lists all files inside the specified S3 folder."""
        try:
            response = self.s3_client.list_objects_v2(Bucket=self.bucket_name, Prefix=folder)
            if "Contents" in response:
                file_list = [obj["Key"] for obj in response["Contents"]]
                logging.info(f"Files in {folder}: {file_list}")
                return file_list
            else:
                logging.info(f"No files found in {folder}")
                return []

        except ClientError as e:
            logging.error(f"Error listing files: {str(e)}")
            return []
        
    def process_s3_urls(value, folder_name):
        if value and isinstance(value, str) and value.strip():  # Ensure it's not empty
            return [
                f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{item.strip()}"
                for item in value.replace("{", "").replace("}", "").split(',')
                if item.strip()
            ]
        return None  # Return `None` if empty
    def delete_from_s3(self, file_url: str):
        from urllib.parse import urlparse

        parsed_url = urlparse(file_url)
        key = parsed_url.path.lstrip('/')

        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=key)
            logging.info(f"Deleted {key} from {self.bucket_name}")
        except ClientError as e:
            logging.error(f"Failed to delete {file_url}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to delete file: {str(e)}")
        
# Helper functions
def generate_otp():
    return str(random.randint(1000, 9999))

# Helper function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def send_sms(to_number, message):
    try:
        message = twilio_client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=to_number
        )
        return {"status": "success", "message_sid": message.sid}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def create_token(data: dict, expires_delta: timedelta, secret_key: str) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=settings.ALGORITHM)

# Function to create an access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

# Function to create a refresh token
def create_refresh_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=7))
    to_encode.update({"exp": expire, "token_type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


# Function to store refresh token in the database
async def store_refresh_token(conn, matrimony_id: int, refresh_token: str):
    try:
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=7)  # Token valid for 7 days
        query = """
        INSERT INTO matrimony_refresh_tokens (matrimony_id, token, expires_at, is_valid)
        VALUES (%s, %s, %s, %s)
        """
        await conn.execute(query, (matrimony_id, refresh_token, expires_at, True))
    except Exception as e:
        await conn.rollback()
        print(f"❌ Error while storing refresh token: {e}")
        raise HTTPException(status_code=500, detail="Could not store refresh token")

# Function to verify refresh token
async def verify_refresh_token(refresh_token: str) -> Dict:
    try:
        # Decode refresh token
        payload = jwt.decode(
            refresh_token,
            settings.REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        # Ensure token type is "refresh"
        if payload.get("token_type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        # Verify token in the database
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT matrimony_id, expires_at, is_valid 
            FROM matrimony_refresh_tokens 
            WHERE token = %s AND is_valid = true
            """,
            (refresh_token,)
        )
        token_data = cur.fetchone()

        if not token_data:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        # Check if token has expired
        if token_data[1] < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Refresh token has expired")

        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()


async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
        user_type = payload.get("user_type")
        
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        
        # Fetch user details from the database
        conn = get_db_connection()
        cur = conn.cursor()
        
        if user_type == "admin":
            # Admin can access both Photo Studio and Matrimony
            cur.execute(
                "SELECT id, email, user_type FROM users WHERE email = %s",
                (email,)
            )
            user = cur.fetchone()
        else:
            # Regular user (Photo Studio or Matrimony)
            cur.execute(
                "SELECT id, email, user_type FROM users WHERE email = %s UNION SELECT id, email, user_type FROM matrimony_profiles WHERE email = %s",
                (email, email)
            )
            user = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Return user details as a dictionary
        return {
            "id": user[0],
            "email": user[1],
            "user_type": user[2]
        }
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
def get_current_user_matrimony(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, "your_secret_key", algorithms=["HS256"])
        user_id = payload.get("sub")
        user_type = payload.get("user_type")
        
        if not user_id or not user_type:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        if user_type == "admin":
            cur.execute("SELECT id, email, user_type FROM users WHERE email = %s", (user_id,))
        else:
            cur.execute("SELECT * FROM matrimony_profiles WHERE matrimony_id = %s", (user_id,))
        
        user = cur.fetchone()
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

def generate_matrimony_id():
    conn = psycopg2.connect(**settings.DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        # Create a sequence if not exists (One-time setup)
        cur.execute("""
            CREATE SEQUENCE IF NOT EXISTS matrimony_id_seq START 11111 INCREMENT 1;
        """)

        # Get the next sequence value
        cur.execute("SELECT nextval('matrimony_id_seq')")
        new_numeric_part = cur.fetchone()["nextval"]

        # Format new matrimony_id
        new_matrimony_id = f"NBS{new_numeric_part:05d}"

        conn.commit()
        return new_matrimony_id

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error generating matrimony_id: {str(e)}")

    finally:
        cur.close()
        conn.close()


# Helper functions to save files
# Allowed file types and max file size
ALLOWED_FILE_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"
}
MAX_FILE_SIZE = 1000 * 1024 * 1024  # 1000 MB

def validate_file(file: UploadFile):
    """Validate file type and size before saving"""
    if not file or not file.filename.strip():
        raise HTTPException(status_code=400, detail="Invalid file uploaded")

    if file.content_type not in ALLOWED_FILE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{file.content_type}' not allowed. Allowed types: {', '.join(ALLOWED_FILE_TYPES)}"
        )

    # Read file contents to check size
    file_contents = file.file.read()
    file_size = len(file_contents)

    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File size exceeds maximum allowed size of {MAX_FILE_SIZE / (1024 * 1024)}MB"
        )

    # Restore file cursor position (important for later reading)
    file.file.seek(0)


def save_upload_file(file: UploadFile, folder: str) -> str:
    """Save an uploaded file to a specified folder"""
    validate_file(file)  # Ensure file is valid before saving

    try:
        # Ensure the directory exists before saving the file
        upload_dir = f'uploads/{folder}'
        os.makedirs(upload_dir, exist_ok=True)

        # Avoid overwriting by appending a unique identifier
        filename = f"{file.filename}"
        file_location = os.path.join(upload_dir, filename)

        # Save the file
        with open(file_location, "wb") as f:
            f.write(file.file.read())

        return file_location
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")

def is_zodiac_compatible(user_rashi: str, match_rashi: str) -> bool:
    compatible_pairs = {
        "Aries": ["Leo", "Sagittarius", "Gemini", "Aquarius"],
        "Taurus": ["Virgo", "Capricorn", "Cancer", "Pisces"],
        "Gemini": ["Libra", "Aquarius", "Aries", "Leo"],
        "Cancer": ["Scorpio", "Pisces", "Taurus", "Virgo"],
        "Leo": ["Aries", "Sagittarius", "Gemini", "Libra"],
        "Virgo": ["Taurus", "Capricorn", "Cancer", "Scorpio"],
        "Libra": ["Gemini", "Aquarius", "Leo", "Sagittarius"],
        "Scorpio": ["Cancer", "Pisces", "Virgo", "Capricorn"],
        "Sagittarius": ["Aries", "Leo", "Libra", "Aquarius"],
        "Capricorn": ["Taurus", "Virgo", "Scorpio", "Pisces"],
        "Aquarius": ["Gemini", "Libra", "Aries", "Sagittarius"],
        "Pisces": ["Cancer", "Scorpio", "Taurus", "Capricorn"],
    }
    return match_rashi in compatible_pairs.get(user_rashi, [])


# Function to generate the next matrimony_id
async def get_current_user_matrimony(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    try:
        # Decode JWT to extract user information
        print(f"Received token: {token}")  # Debug log
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        print(f"Decoded payload: {payload}")  # Debug log
        user_id = payload.get("sub")  # Should match the login function
        user_type = payload.get("user_type")

        if not user_id or not user_type:
            raise HTTPException(status_code=401, detail="Invalid authentication token")

        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)  # Use RealDictCursor for clean responses

        if user_type == "admin":
            # Admin should use `email` as the sub in the token
            cur.execute("SELECT id, email, user_type FROM users WHERE email = %s", (user_id,))
        elif user_type == "user":
            # Matrimony users should use `matrimony_id`
            cur.execute("""
                SELECT id, matrimony_id, email, user_type, gender 
                FROM matrimony_profiles 
                WHERE matrimony_id = %s
            """, (user_id,))
        
        user = cur.fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user  # Since we use `RealDictCursor`, it's already a dictionary

    except ExpiredSignatureError:
        logger.error("Token has expired.")
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError as e:
        logger.error(f"JWT Error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    except Exception as e:
        logger.error(f"Internal server error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

def send_push_notification(token: str, title: str, body: str):
    """
    Send a push notification to a specific device token.
    """
    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        token=token,
    )
    
    try:
        response = messaging.send(message)
        logger.info(f"Successfully sent message: {response}")
        return {"message": "Notification sent successfully", "response": response}
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to send notification: {str(e)}")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Routes
@app.post("/photostudio/admin/register", response_model=Dict[str, Any])
async def register(user: UserCreate):
    logger.info(f"Received registration request: {user}")
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Check existing user
        cur.execute("SELECT id FROM users WHERE email = %s", (user.email,))
        if cur.fetchone():
            logger.warning(f"Email already registered: {user.email}")
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user
        hashed_password = pwd_context.hash(user.password)
        cur.execute(
            "INSERT INTO users (email, password_hash, user_type) VALUES (%s, %s, %s) RETURNING id",
            (user.email, hashed_password, user.user_type)
        )
        user_id = cur.fetchone()[0]
        conn.commit()

        return {
            "message": "Registration successful",
            "user_id": user_id
        }
    except Exception as e:
        logger.error(f"Error occurred during registration: {str(e)}")
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
    finally:
        cur.close()
        conn.close()


@app.post("/photostudio/admin/login", response_model=Token)
async def login(user: UserLogin):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            "SELECT id, email, password_hash, user_type FROM users WHERE email = %s",
            (user.email,)
        )
        db_user = cur.fetchone()
        
        if not db_user or not pwd_context.verify(user.password, db_user[2]):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )
        
        # Generate tokens
        access_token = create_token(
            {"sub": db_user[1], "user_type": db_user[3]},  # Include user_type in the payload
            timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            settings.SECRET_KEY
        )
        refresh_token = create_token(
            {"sub": db_user[1], "user_type": db_user[3]},  # Include user_type in the payload
            timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            settings.REFRESH_SECRET_KEY
        )
        
        # Store refresh token
        cur.execute(
            """
            INSERT INTO refresh_tokens (token, user_id, expires_at)
            VALUES (%s, %s, %s)
            """,
            (
                refresh_token,
                db_user[0],
                datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            )
        )
        conn.commit()
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": db_user[1],
            "user_type": db_user[3]  # Include user_type in the response
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.post("/photostudio/user/eventform", response_model=Dict[str, Any])
async def create_event_form(
    event: EventForm  # Use the Pydantic model for JSON payloads
):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Insert event form data into the database
        cur.execute(
            """
            INSERT INTO event_forms (name, contact, event_date, event_time, event_type)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                event.name,
                event.contact,
                event.event_date,
                event.event_time,
                event.event_type
            )
        )
        event_id = cur.fetchone()[0]
        conn.commit()
        
        return {
            "message": "Event form submitted successfully",
            "event_id": event_id
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.get("/photostudio/admin/eventform", response_model=List[Dict[str, Any]])
async def get_event_forms():
    """
    Retrieve all event forms
    :return: List of event forms
    """
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT name, contact, event_date, event_time, event_type, 
                   created_at  
            FROM event_forms
            ORDER BY created_at DESC
        """)
        rows = cur.fetchall()

        # Convert list of tuples to list of dicts
        columns = [desc[0] for desc in cur.description]
        event_forms = [dict(zip(columns, row)) for row in rows]

        return event_forms
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving event forms: {str(e)}")
    finally:
        cur.close()
        conn.close()

@app.post("/photostudio/refresh-token", response_model=Token)
async def refresh_token(token: RefreshToken):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Decode the refresh token
        payload = jwt.decode(
            token.refresh_token,
            settings.REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        email = payload.get("sub")
        if email is None:
            logger.error("Invalid refresh token: missing email in payload")
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        # Check if the refresh token exists in the database and is still valid
        cur.execute(
            """
            SELECT user_id, expires_at
            FROM refresh_tokens
            WHERE token = %s AND expires_at > NOW()
            """,
            (token.refresh_token,)
        )
        db_token = cur.fetchone()
        if not db_token:
            logger.error("Invalid or expired refresh token")
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        
        # Generate new tokens
        access_token = create_token(
            {"sub": email},
            timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            settings.SECRET_KEY
        )
        new_refresh_token = create_token(
            {"sub": email},
            timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            settings.REFRESH_SECRET_KEY
        )
        
        # Store the new refresh token in the database
        cur.execute(
            """
            INSERT INTO refresh_tokens (token, user_id, expires_at)
            VALUES (%s, %s, %s)
            """,
            (
                new_refresh_token,
                db_token[0],
                datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            )
        )
        
        # Delete the old refresh token
        cur.execute(
            "DELETE FROM refresh_tokens WHERE token = %s",
            (token.refresh_token,)
        )
        conn.commit()
        
        logger.info(f"New tokens issued for user: {email}")
        
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "email": email
        }
    except jwt.ExpiredSignatureError:
        logger.error("Refresh token has expired")
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except jwt.InvalidTokenError:
        logger.error("Invalid refresh token")
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        conn.rollback()
        logger.error(f"Internal server error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.post("/photostudio/admin/fileupload", response_model=Dict[str, Any])
async def admin_upload_files(
    files: List[UploadFile] = File(...),
    category: str = Form(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can access this endpoint")
    
    uploaded_files = []
    s3_handler = S3Handler()
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        print(f"Received {len(files)} files")  # Debugging statement

        for file in files:
            print(f"Processing file: {file.filename}")  # Debugging statement

            # Upload file to S3
            try:
                file_url = s3_handler.upload_to_s3(file, "admin_files")
                print(f"Upload result for {file.filename}: {file_url}")  # Debugging output
                if not file_url:
                    print(f"Skipping {file.filename} - S3 upload failed")  # Debugging output
                    continue  # Skip if upload fails
            except Exception as e:
                print(f"S3 Upload Error: {e}")  # Debugging output
                continue  # Skip this file
            
            # Extract MIME type
            file_type = file.content_type  
            print(f"File Type: {file_type}")  # Debugging output

            # Insert into database
            try:
                cur.execute(
                    """
                    INSERT INTO files (filename, file_type, category, file_url, uploaded_by, uploaded_at)
                    VALUES (%s, %s, %s, %s, %s, NOW()) RETURNING id;
                    """,
                    (file.filename, file_type, category, file_url, current_user["id"])
                )
                file_id = cur.fetchone()
                print(f"Inserted file {file.filename} with ID: {file_id}")  # Debugging output
                
                if not file_id:
                    print(f"Skipping {file.filename} - Database insert failed")  # Debugging output
                    continue  # Skip if insert fails

                uploaded_files.append({
                    "id": file_id[0],
                    "filename": file.filename,
                    "file_type": file_type,
                    "category": category,
                    "uploaded_by": current_user["id"],
                    "file_url": file_url
                })

            except psycopg2.Error as e:
                conn.rollback()
                print(f"Database Error for {file.filename}: {str(e)}")  # Debugging output
                continue  # Skip to next file

        conn.commit()

        if not uploaded_files:
            raise HTTPException(status_code=500, detail="No files were uploaded successfully")

        return {
            "message": "Files uploaded successfully by admin",
            "file_urls": [file["file_url"] for file in uploaded_files],
            "uploaded_files": uploaded_files
        }

    except Exception as e:
        conn.rollback()
        print(f"Unexpected Error: {str(e)}")  # Debugging output
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    finally:
        cur.close()
        conn.close()


@app.get("/photostudio/user/fileupload", response_model=List[Dict[str, Any]])
async def get_uploaded_files(
    category: str = Query(..., description="Category of the uploaded files"),
    limit: int = Query(10, description="Number of files per page"),
    offset: int = Query(0, description="Page offset"),
    language: str = Query("en", description="Language for response (e.g., 'en', 'ta')")
):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Retrieve files without base64
        cur.execute(
            """
            SELECT id, category, filename, file_url, uploaded_by, uploaded_at
            FROM files
            WHERE category = %s
            LIMIT %s OFFSET %s
            """,
            (category, limit, offset)
        )
        files = cur.fetchall()
        
        if not files:
            raise HTTPException(status_code=404, detail="No files found")
        
        # Translate the category if language is Tamil
        if language == "ta":
            translator = Translator()
            category = translator.translate(category, dest="ta").text
        
        
        # Format the response
        uploaded_files = [
            {
                "id": file[0],
                "category": category,
                "filename": file[2],
                "file_url": file[3],  # Construct the file URL
                "uploaded_by": file[4],
                "uploaded_at": file[5]
            }
            for file in files
        ]
        
        return uploaded_files
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve files: {str(e)}")
    finally:
        cur.close()
        conn.close()

@app.post("/photostudio/user/product_frame")
async def create_product_frame(
    frame_name: str = Form(...),
    phone_number: str = Form(...),
    user_photos: List[UploadFile] = File(...),
    frame_size: str = Form(...),
    frame_colors: List[UploadFile] = File(...),
):
    conn = get_db_connection()
    cur = conn.cursor()
    s3_handler = S3Handler()

    try:
        # Upload images to S3
        user_photo_urls = [s3_handler.upload_to_s3(photo, "user_photos") for photo in user_photos]
        frame_color_urls = [s3_handler.upload_to_s3(color, "frame_colors") for color in frame_colors]

        cur.execute(
            """
            INSERT INTO product_frames (frame_name, phone_number, frame_size, user_photo_urls, frame_color_urls)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (frame_name, phone_number, frame_size, user_photo_urls, frame_color_urls)
        )
        frame_id = cur.fetchone()[0]
        conn.commit()

        return {
            "frame_id": frame_id,
            "frame_name": frame_name,
            "phone_number": phone_number,
            "frame_size": frame_size,
            "user_photo_urls": user_photo_urls,
            "frame_color_urls": frame_color_urls
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    finally:
        cur.close()
        conn.close()

@app.get("/photostudio/admin/product_frames", response_model=List[Dict[str, Any]])
async def get_product_frames(
    limit: int = Query(10, description="Number of frames per page"),
    offset: int = Query(0, description="Page offset"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    # Ensure only admins can access
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id, frame_name, phone_number, frame_size, user_photo_urls, frame_color_urls, created_at
            FROM product_frames
            LIMIT %s OFFSET %s;
            """,
            (limit, offset)
        )
        frames = cur.fetchall()

        if not frames:
            raise HTTPException(status_code=404, detail="No product frames found")

        product_frames = [
            {
                "id": frame[0],
                "frame_name": frame[1],
                "phone_number": frame[2],
                "frame_size": frame[3],
                "user_photo_filenames": frame[4],  # TEXT[] from PostgreSQL
                "frame_color_filenames": frame[5],  # TEXT[] from PostgreSQL
                "created_at": frame[6]
            }
            for frame in frames
        ]

        return product_frames
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve product frames: {str(e)}")
    finally:
        cur.close()
        conn.close()

# Private Register Module
@app.post("/photostudio/private/admin/register", response_model=Dict[str, Any])
async def register(user: UserCreate):
    logger.info(f"Received registration request: {user}")
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        hashed_password = pwd_context.hash(user.password)

        # Check if the user exists
        cur.execute("SELECT id FROM users WHERE email = %s", (user.email,))
        existing_user = cur.fetchone()

        if existing_user:
            user_id = existing_user[0]
            # Update password, user_type, and set is_active = TRUE
            cur.execute(
                """
                UPDATE users
                SET password_hash = %s, user_type = %s, is_active = TRUE
                WHERE id = %s
                """,
                (hashed_password, user.user_type, user_id)
            )
            is_active = True
            message = "Existing user updated"
        else:
            # Insert new user with is_active = FALSE
            cur.execute(
                """
                INSERT INTO users (email, password_hash, user_type, is_active)
                VALUES (%s, %s, %s, FALSE) RETURNING id
                """,
                (user.email, hashed_password, user.user_type)
            )
            user_id = cur.fetchone()[0]
            is_active = False
            message = "New user registered"

        conn.commit()

        return {
            "status": "success",
            "message": message,
            "data": {
                "user_id": user_id,
                "is_active": is_active,
                "email": user.email,
                "password": user.password
            }
        }

    except Exception as e:
        conn.rollback()
        logger.error(f"Registration failed: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    finally:
        cur.close()
        conn.close()


# Login 
@app.post("/photostudio/private/admin/login", response_model=Dict[str, Any])
async def login (user: UserLogin):
    logger.info(f"Received Login request: {user}")  # Log the request payload
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT id, email, password_hash, user_type FROM users WHERE email = %s",
            (user.email,)
        )
        db_user = cur.fetchone()
        
        if not db_user or not pwd_context.verify(user.password, db_user[2]):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )
        
        # Generate tokens
        access_token = create_access_token(
            {"sub": db_user[1], "user_type": db_user[3]},  # Payload
            timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)  # Expiry time
        )

        refresh_token = create_refresh_token(
            {"sub": db_user[1], "user_type": db_user[3]},  # Include user_type in the payload
            timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)  # Expiry time
        )
        
        # Store refresh token
        cur.execute(
            """
            INSERT INTO refresh_tokens (token, user_id, expires_at)
            VALUES (%s, %s, %s)
            """,
            (
                refresh_token,
                db_user[0],
                datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            )
        )
        conn.commit()
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "data": {            
                "email": db_user[1],
                "user_type": db_user[3]  # Include user_type in the response
            }
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()    

# Login Refresh_token


@app.post("/photostudio/private/admin/refresh", response_model=Dict[str, Any])
async def refresh_token(token: RefreshToken):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        payload = jwt.decode(
            token.refresh_token,
            settings.REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        email = payload.get("sub")
        if email is None:
            logger.error("Invalid refresh token: missing email in payload")
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        # Check if refresh token exists in DB
        cur.execute(
            """
            SELECT user_id, expires_at
            FROM refresh_tokens
            WHERE token = %s AND expires_at > NOW()
            """,
            (token.refresh_token,)
        )
        db_token = cur.fetchone()
        if not db_token:
            logger.error("Invalid or expired refresh token")
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        
        # Fetch user info using user_id
        cur.execute(
            "SELECT id, email, user_type FROM users WHERE id = %s",
            (db_token[0],)
        )
        db_user = cur.fetchone()
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Generate new tokens
        access_token = create_access_token(
            {"sub": db_user[1], "user_type": db_user[2]},
            timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        new_refresh_token = create_refresh_token(
            {"sub": db_user[1], "user_type": db_user[2]},
            timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        )
        
        # Store new refresh token
        cur.execute(
            """
            INSERT INTO refresh_tokens (token, user_id, expires_at)
            VALUES (%s, %s, %s)
            """,
            (
                new_refresh_token,
                db_user[0],
                datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            )
        )

        # Delete old refresh token
        cur.execute(
            "DELETE FROM refresh_tokens WHERE token = %s",
            (token.refresh_token,)
        )
        conn.commit()

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "email": db_user[1],
            "user_type": db_user[2]
        }
    except JWTError:
        logger.error("Invalid refresh token")
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        conn.rollback()
        logger.error(f"Internal server error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        cur.close()
        conn.close()

# Photo_File_upload - post (Photo, video, pdf, File_size upto 1000 MB)
@app.post("/photostudio/admin/private/fileupload", response_model=Dict[str, Any])
async def admin_upload_files(
    files: List[UploadFile] = File(...),
    category: str = Form(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "user":
        raise HTTPException(status_code=403, detail="Only user can access this endpoint")

    s3_handler = S3Handler()
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Check if a private_files record already exists
        cur.execute(
            "SELECT private_files_id FROM private_files WHERE uploaded_by = %s AND category = %s",
            (current_user["id"], category)
        )
        result = cur.fetchone()

        if result:
            private_files_id = result[0]
        else:
            # Create new private_files record
            cur.execute(
                "INSERT INTO private_files (uploaded_by, category) VALUES (%s, %s) RETURNING private_files_id",
                (current_user["id"], category)
            )
            private_files_id = cur.fetchone()[0]

        uploaded_file_info = []

        for file in files:
            try:
                file_url = s3_handler.upload_to_s3(file, "admin_files")
                if not file_url:
                    print(f"Skipping {file.filename} - upload failed")
                    continue

                file_type = file.content_type

                # Insert into private_files_url
                cur.execute(
                    """
                    INSERT INTO private_files_url (private_files_id, file_type, file_url, uploaded_at)
                    VALUES (%s, %s, %s, NOW())
                    RETURNING id, file_url, file_type, uploaded_at
                    """,
                    (private_files_id, file_type, file_url)
                )
                uploaded = cur.fetchone()
                uploaded_file_info.append({
                    "url": uploaded[1],
                    "file_type": uploaded[2],
                    "uploaded_at": uploaded[3]
                })

            except Exception as e:
                print(f"S3 Upload Error for {file.filename}: {e}")
        
        if not uploaded_file_info:
            raise HTTPException(status_code=400, detail="No files were uploaded successfully")

        conn.commit()

        return {
            "message": "Files uploaded successfully by admin",
            "private_files_id": private_files_id,
            "uploaded_by": current_user["id"],
            "category": category,
            "uploaded_files": uploaded_file_info
        }

    except Exception as e:
        conn.rollback()
        print(f"[ERROR] {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    finally:
        cur.close()
        conn.close()

@app.get("/photostudio/admin/private/get_files", response_model=Dict[str, Any])
async def get_user_uploaded_files(
    current_user: Dict[str, Any] = Depends(get_current_user),
    file_id: int = Query(None, alias="file_id")  # Optional query parameter for file_id
):
    if current_user.get("user_type") != "user":
        raise HTTPException(status_code=403, detail="Only users can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Step 1: Get all private_files_ids for the user
        cur.execute(
            """
            SELECT private_files_id, category 
            FROM private_files 
            WHERE uploaded_by = %s
            """,
            (current_user["id"],)
        )

        private_file_records = cur.fetchall()

        if not private_file_records:
            return {"message": "No selected files found", "selected_files": []}

        all_files_data = []

        for private_files_id, category_value in private_file_records:
            # Step 2: If file_id is provided, filter by it
            query = """
                SELECT file_url, file_type, user_selected_files, uploaded_at, id
                FROM private_files_url
                WHERE private_files_id = %s
            """
            params = [private_files_id]

            if file_id:
                query += " AND id = %s"
                params.append(file_id)

            # Fetch the files based on the query
            cur.execute(query + " ORDER BY uploaded_at DESC", tuple(params))
            files = cur.fetchall()

            if files:
                files_data = [
                    {
                        "file_url": row[0],
                        "file_type": row[1],
                        "user_selected_files": row[2],
                        "uploaded_at": row[3],
                        "id": row[4],
                        "category": category_value,
                        "private_files_id": private_files_id
                    }
                    for row in files
                ]
                all_files_data.extend(files_data)

        if not all_files_data:
            raise HTTPException(status_code=404, detail="No files found for this user")

        return {
            "uploaded_by": current_user["id"],
            "uploaded_files": all_files_data
        }

    except Exception as e:
        print(f"[GET Error] {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve uploaded files")

    finally:
        cur.close()
        conn.close()

@app.put("/photostudio/admin/private/fileupdate", response_model=Dict[str, Any])
async def update_uploaded_file(
    request_data: GetFileUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "user":
        raise HTTPException(status_code=403, detail="Only user can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Validate access
        cur.execute(
            """
            SELECT pf.private_files_id 
            FROM private_files_url pfu
            JOIN private_files pf ON pf.private_files_id = pfu.private_files_id
            WHERE pfu.id = %s AND pf.uploaded_by = %s AND pf.category = %s
            """,
            (request_data.file_id, current_user["id"], request_data.category)
        )
        result = cur.fetchone()

        if not result:
            raise HTTPException(status_code=200, detail="File not found or not accessible")

        private_files_id = result[0]

        # Perform update
        cur.execute(
            """
            UPDATE private_files_url 
            SET file_url = %s, file_type = %s
            WHERE id = %s
            """,
            (request_data.file_url, request_data.file_type, request_data.file_id)
        )
        conn.commit()

        return {
            "message": "File updated successfully",
            "updated_file": {
                "file_url": request_data.file_url,
                "file_type": request_data.file_type,
                "file_id": request_data.file_id,
                "private_files_id": private_files_id,
                "category": request_data.category
            }
        }

    except Exception as e:
        print(f"[PUT Error] {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Error while validating file access")

    finally:
        cur.close()
        conn.close()

# Delete for File_Upload
@app.delete("/photostudio/admin/private/filedelete", response_model=Dict[str, Any])
async def delete_uploaded_file(
    file_id: int = Query(...),  # File ID as a query parameter
    category: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "user":
        raise HTTPException(status_code=403, detail="Only user can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Ensure that the file exists and is associated with the current user and the specified category
        cur.execute(
            """
            SELECT private_files_id FROM private_files_url 
            WHERE id = %s AND private_files_id IN (
                SELECT private_files_id FROM private_files WHERE uploaded_by = %s AND category = %s
            )
            """,
            (file_id, current_user["id"], category)
        )
        result = cur.fetchone()

        if not result:
            raise HTTPException(status_code=200, detail="File not found or not accessible")

        private_files_id = result[0]

        # Delete the file from private_files_url table
        cur.execute(
            """
            DELETE FROM private_files_url WHERE id = %s
            """,
            (file_id,)
        )

        conn.commit()

        # Return confirmation of deletion
        return {
            "message": "File deleted successfully",
            "deleted_file_id": file_id,
            "private_files_id": private_files_id,
            "category": category
        }

    except Exception as e:
        print(f"[DELETE Error] {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete file")

    finally:
        cur.close()
        conn.close()
        
# All-Delete
@app.delete("/photostudio/admin/private/delete_all", response_model=Dict[str, Any])
async def delete_files_by_private_id(
    private_files_id: int = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "user":
        raise HTTPException(status_code=403, detail="Only user can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Validate user ownership of the private_files_id
        cur.execute(
            """
            SELECT 1 FROM private_files 
            WHERE private_files_id = %s AND uploaded_by = %s
            """,
            (private_files_id, current_user["id"])
        )
        if not cur.fetchone():
            raise HTTPException(status_code=200, detail="private_files_id not found or not owned by user")

        # Delete files from private_files_url
        cur.execute(
            """
            DELETE FROM private_files_url 
            WHERE private_files_id = %s
            """,
            (private_files_id,)
        )
        conn.commit()

        return {
            "message": "All files under the given private_files_id deleted successfully",
            "private_files_id": private_files_id
        }

    except Exception as e:
        print(f"[DELETE by private_files_id Error] {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete files")

    finally:
        cur.close()
        conn.close()


# Selected Files
@app.post("/photostudio/user/private/select-files", response_model=Dict[str, Any])
async def user_select_files(
    request: FileSelectionsRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "user":
        raise HTTPException(status_code=403, detail="Only users can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        updated_records = []

        for file_data in request.private_files:
            private_files_id = file_data.private_files_id
            selected_urls = file_data.selected_urls

            # Step 1: Fetch category
            cur.execute("""
                SELECT category FROM private_files
                WHERE private_files_id = %s
            """, (private_files_id,))
            result = cur.fetchone()
            if not result:
                raise HTTPException(status_code=404, detail=f"Invalid private_files_id: {private_files_id}")
            category = result[0]

            # Step 2: Fetch file URLs
            cur.execute("""
                SELECT id, file_url, user_selected_files FROM private_files_url
                WHERE private_files_id = %s
            """, (private_files_id,))
            all_files = cur.fetchall()

            # Step 3: Update selection
            for fid, url, existing_selection in all_files:
                is_selected = url in selected_urls
                updated_selection = json.dumps({"selected": is_selected})

                cur.execute("""
                    UPDATE private_files_url
                    SET user_selected_files = %s
                    WHERE id = %s
                    RETURNING id, file_url, user_selected_files
                """, (updated_selection, fid))
                record = cur.fetchone()
                updated_records.append((record[0], record[1], record[2], category))

        conn.commit()

        updated_result = [
            {
                "file_id": row[0],
                "file_url": row[1],
                "selected_status": row[2] if isinstance(row[2], dict) else json.loads(row[2]),
                "category": row[3]
            }
            for row in updated_records
        ]

        return {
            "message": "File selections updated successfully.",
            "private_files_id": private_files_id,
            "updated_files": updated_result
        }

    except Exception as e:
        conn.rollback()
        print(f"Error updating selections: {e}")
        raise HTTPException(status_code=500, detail=f"Something went wrong while saving your selection: {str(e)}")

    finally:
        cur.close()
        conn.close()


@app.get("/photostudio/user/private/get_select_files", response_model=Dict[str, Any])
async def user_get_all_selected_files(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "user":
        raise HTTPException(status_code=403, detail="Only users can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Step 1: Fetch file IDs and categories
        cur.execute("""
            SELECT private_files_id, category FROM private_files
            WHERE uploaded_by = %s
        """, (current_user["id"],))
        private_files = cur.fetchall()

        all_files_result = []

        for private_files_id, category in private_files:
            # Step 2: Fetch file URLs
            cur.execute("""
                SELECT id, file_url, user_selected_files FROM private_files_url
                WHERE private_files_id = %s
            """, (private_files_id,))
            all_files = cur.fetchall()

            updated_result = [
                {
                    "file_id": row[0],
                    "file_url": row[1],
                    "selected_status": row[2] if isinstance(row[2], dict) else (json.loads(row[2]) if row[2] else {})
                }
                for row in all_files
            ]

            all_files_result.append({
                "category": category,
                "private_files_id": private_files_id,
                "selected_files": updated_result
            })

        return {
            "message": "File selection data fetched successfully.",
            "files_data": all_files_result
        }

    except Exception as e:
        print(f"Error fetching file selections: {e}")
        raise HTTPException(status_code=500, detail=f"Something went wrong while fetching the selections: {str(e)}")

    finally:
        cur.close()
        conn.close()


# Admin-product_frame
@app.post("/photostudio/admin/product_frame", response_model=Dict[str, Any])
async def create_admin_product_frame(
    frame_name: str = Form(...),
    phone_number: str = Form(...),
    user_photos: List[UploadFile] = File(...),
    frame_size: str = Form(...),
    frame_colors: List[UploadFile] = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()
    s3_handler = S3Handler()

    try:
        # Upload images to S3
        user_photo_urls = [s3_handler.upload_to_s3(photo, "admin_user_photos") for photo in user_photos]
        frame_color_urls = [s3_handler.upload_to_s3(color, "admin_frame_colors") for color in frame_colors]

        # Insert into database
        cur.execute(
            """
            INSERT INTO product_frames (
                frame_name, phone_number, frame_size,
                user_photo_urls, frame_color_urls, uploaded_by, uploaded_by_type
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (
                frame_name, phone_number, frame_size,
                user_photo_urls, frame_color_urls,
                current_user["id"], "admin"
            )
        )
        frame_id = cur.fetchone()[0]
        conn.commit()

        return {
            "frame_id": frame_id,
            "frame_name": frame_name,
            "phone_number": phone_number,
            "frame_size": frame_size,
            "user_photo_urls": user_photo_urls,
            "frame_color_urls": frame_color_urls,
            "uploaded_by": current_user["id"]
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    finally:
        cur.close()
        conn.close()


# Matrimony Endpoints
@app.post("/matrimony/send-otp", response_model=Dict[str, Any])
async def send_otp(request: OTPRequest):
    logger.info(f"Received OTPRequest: {request}")
    mobile_number = request.mobile_number
    full_name = request.full_name  # This should be available now
    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
    
    # Save OTP and full_name to PostgreSQL
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Delete any existing OTP for the mobile number
        cur.execute(
            "DELETE FROM otp_storage WHERE mobile_number = %s",
            (mobile_number,)
        )
        
        # Insert new OTP and full_name
        cur.execute(
            """
            INSERT INTO otp_storage (mobile_number, full_name, otp, expires_at)
            VALUES (%s, %s, %s, %s)
            """,
            (mobile_number, full_name, otp, expires_at)
        )
        conn.commit()
        
        # Send OTP via Twilio
        try:
            message = twilio_client.messages.create(
                body=f"Your OTP is {otp}. It will expire in 5 minutes.",
                from_=TWILIO_PHONE_NUMBER,
                to=mobile_number
            )
            logger.info(f"OTP sent to {mobile_number}: {otp}")
            return {"message": "OTP sent successfully", "mobile_number": mobile_number, "full_name": full_name}
        except Exception as e:
            logger.error(f"Failed to send OTP via Twilio: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to send OTP: {str(e)}")
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        cur.close()
        conn.close()

@app.post("/matrimony/verify-otp", response_model=Dict[str, Any])
async def verify_otp(request: OTPVerify):
    mobile_number = request.mobile_number
    otp = request.otp
    full_name = request.full_name  # Added full_name
    
    # Fetch OTP and full_name from PostgreSQL
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT otp, full_name, expires_at FROM otp_storage
            WHERE mobile_number = %s AND expires_at > NOW()
            """,
            (mobile_number,)
        )
        db_otp = cur.fetchone()
        
        if not db_otp or db_otp[0] != otp or db_otp[1] != full_name:
            raise HTTPException(status_code=400, detail="Invalid OTP or full name")
        
        # Delete OTP after verification
        cur.execute(
            "DELETE FROM otp_storage WHERE mobile_number = %s",
            (mobile_number,)
        )
        conn.commit()
        
        return {"message": "OTP verified successfully", "mobile_number": mobile_number, "full_name": full_name}
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        cur.close()
        conn.close()
        
        
def convert_empty_to_none(value):
    """ Convert empty strings to None (NULL in PostgreSQL) """
    return None if value == "" else value

@app.post("/matrimony/register")
async def register_matrimony(
    full_name: str = Form(...),
    age: str = Form(...),  # Store as string
    gender: str = Form(...),
    date_of_birth: str = Form(...),  # Store as string
    email: EmailStr = Form(...),
    password: str = Form(...),
    phone_number: str = Form(...),
    height: Optional[str] = Form(None),
    weight: Optional[str] = Form(None),
    occupation: Optional[str] = Form(None),
    annual_income: Optional[str] = Form(None),
    education: Optional[str] = Form(None),
    mother_tongue: Optional[str] = Form(None),
    profile_created_by: Optional[str] = Form(None),
    address: Optional[str] = Form(None),
    work_type: Optional[str] = Form(None),
    company: Optional[str] = Form(None),
    work_location: Optional[str] = Form(None),
    work_country: Optional[str] = Form(None),
    mother_name: Optional[str] = Form(None),
    father_name: Optional[str] = Form(None),
    sibling_count: Optional[str] = Form(None),
    elder_brother: Optional[str] = Form(None),
    elder_sister: Optional[str] = Form(None),
    younger_sister: Optional[str] = Form(None),
    younger_brother: Optional[str] = Form(None),
    native: Optional[str] = Form(None),
    mother_occupation: Optional[str] = Form(None),
    father_occupation: Optional[str] = Form(None),
    religion: Optional[str] = Form(None),
    caste: Optional[str] = Form(None),
    sub_caste: Optional[str] = Form(None),
    nakshatra: Optional[str] = Form(None),
    rashi: Optional[str] = Form(None),
    other_dhosham: Optional[str] = Form(None),
    quarter: Optional[str] = Form(None),
    birth_time: Optional[str] = Form(None),
    birth_place: Optional[str] = Form(None),
    ascendent: Optional[str] = Form(None),
    dhosham: Optional[str] = Form(None),
    user_type: Optional[str] = Form(None),
    marital_status:Optional[str]=Form(None),
    preferred_age_min: Optional[str] = Form(None),
    preferred_age_max: Optional[str] = Form(None),
    preferred_height_min: Optional[str] = Form(None),
    preferred_height_max: Optional[str] = Form(None),
    preferred_religion: Optional[str] = Form(None),
    preferred_caste: Optional[str] = Form(None),
    preferred_sub_caste: Optional[str] = Form(None),
    preferred_nakshatra: Optional[str] = Form(None),
    preferred_rashi: Optional[str] = Form(None),
    preferred_location: Optional[str] = Form(None),
    preferred_work_status: Optional[str] = Form(None),
    photo: Optional[UploadFile] = File(None),
    photos: Optional[List[UploadFile]] = File(None),
    horoscope_documents: Optional[List[UploadFile]] = File(None),
    matrimony_id: Optional[str] = Form(None)

):
    try:
        s3_handler = S3Handler()
        hashed_password = pwd_context.hash(password)

        # Handle single profile photo
        photo_url = None
        if photo:
            try:
                photo_url = s3_handler.upload_to_s3(photo, "profile_photos")
                logger.info(f"Profile photo uploaded to: {photo_url}")
            except Exception as e:
                logger.error(f"Profile photo upload failed: {str(e)}")
                raise HTTPException(status_code=400, detail="Profile photo upload failed")

        # Handle multiple photos
        photos_urls = []
        if photos:
            for p in photos:
                try:
                    url = s3_handler.upload_to_s3(p, "photos")
                    photos_urls.append(url)
                    logger.info(f"Uploaded photo: {url}")
                except Exception as e:
                    logger.error(f"Photo upload failed: {str(e)}")
                    continue

        # Handle horoscope documents
        horoscope_urls = []
        if horoscope_documents:
            for h in horoscope_documents:
                try:
                    url = s3_handler.upload_to_s3(h, "horoscopes")
                    horoscope_urls.append(url)
                    logger.info(f"Uploaded horoscope: {url}")
                except Exception as e:
                    logger.error(f"Horoscope upload failed: {str(e)}")
                    continue

        def format_array(urls):
            return "{" + ",".join(urls) + "}" if urls else None

        photos_array = format_array(photos_urls)
        horoscope_array = format_array(horoscope_urls)

        matrimony_id = matrimony_id or generate_matrimony_id()

        values = tuple(convert_empty_to_none(v) for v in [
            matrimony_id, full_name, age, gender, date_of_birth,
            email, hashed_password, phone_number, height, weight,
            occupation, annual_income, education, mother_tongue,
            profile_created_by, address, work_type, company,
            work_location, work_country, mother_name, father_name,
            sibling_count, elder_brother, elder_sister, younger_sister, younger_brother,
            native, mother_occupation, father_occupation, religion, caste,
            sub_caste, nakshatra, rashi, birth_time, birth_place,
            ascendent, user_type, preferred_age_min, preferred_age_max,
            preferred_height_min, preferred_height_max, preferred_religion,
            preferred_caste, preferred_sub_caste, preferred_nakshatra,
            preferred_rashi, preferred_location, preferred_work_status,
            photo_url, photos_array, horoscope_array, dhosham, other_dhosham, quarter, marital_status
        ])

        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        query = f"""
        INSERT INTO matrimony_profiles (
            matrimony_id, full_name, age, gender, date_of_birth,
            email, password, phone_number, height, weight, occupation,
            annual_income, education, mother_tongue, profile_created_by,
            address, work_type, company, work_location, work_country,
            mother_name, father_name, sibling_count, elder_brother, elder_sister, younger_sister, younger_brother,
            native, mother_occupation, father_occupation,
            religion, caste, sub_caste, nakshatra, rashi, birth_time,
            birth_place, ascendent, user_type, preferred_age_min,
            preferred_age_max, preferred_height_min, preferred_height_max,
            preferred_religion, preferred_caste, preferred_sub_caste,
            preferred_nakshatra, preferred_rashi, preferred_location,
            preferred_work_status, photo_path, photos, 
            horoscope_documents, dhosham, other_dhosham, quarter, marital_status
        ) VALUES (
            {','.join(['%s'] * len(values))}
        ) ON CONFLICT (email) DO NOTHING
        RETURNING matrimony_id;
        """

        cur.execute(query, values)
        result = cur.fetchone()
        conn.commit()

        return {
            "status": "success",
            "message": "Profile registered successfully",
            "matrimony_id": result["matrimony_id"] if result else matrimony_id,
            "email": email,
            "password": password
        }

    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()
        
@app.post("/matrimony/login", response_model=MatrimonyToken)
async def login_matrimony(request: MatrimonyLoginRequest):
    try:
        print("Login request received:", request.dict())

        if not request.password and not request.phone_number:
            raise HTTPException(
                status_code=400,
                detail="Either password or phone_number must be provided",
            )

        # Connect to DB
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Fetch user by matrimony_id
        cur.execute(
            "SELECT * FROM matrimony_profiles WHERE matrimony_id = %s",
            (request.matrimony_id,)
        )
        user = cur.fetchone()
        print("Fetched user:", user)

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        stored_password = user.get("password")
        stored_phone = user.get("phone_number")

        # Authentication logic
        if request.via_link:
            if not request.password:
                raise HTTPException(status_code=400, detail="Password is required for link login")
            if not stored_password or not pwd_context.verify(request.password, stored_password):
                raise HTTPException(status_code=401, detail="Invalid password for link login")
        else:
            if request.password:
                if not stored_password or not pwd_context.verify(request.password, stored_password):
                    raise HTTPException(status_code=401, detail="Invalid password")
            elif request.phone_number:
                if request.phone_number != stored_phone:
                    raise HTTPException(status_code=401, detail="Invalid phone number")
            else:
                raise HTTPException(status_code=400, detail="Password or phone number is required")

        # Token creation
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["matrimony_id"], "user_type": "user"},
            expires_delta=access_token_expires
        )

        refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = create_refresh_token(
            data={"sub": user["matrimony_id"], "user_type": "user"},
            expires_delta=refresh_token_expires
        )

        # Save refresh token
        expires_at = datetime.now(timezone.utc) + refresh_token_expires
        cur.execute("""
            INSERT INTO matrimony_refresh_tokens (matrimony_id, token, expires_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (matrimony_id) DO UPDATE
            SET token = EXCLUDED.token,
                expires_at = EXCLUDED.expires_at
        """, (user["matrimony_id"], refresh_token, expires_at))
        conn.commit()

        print("Login successful. Returning tokens.")
        return MatrimonyToken(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    except psycopg2.Error as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error: {type(e).__name__}: {str(e)}")
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.get("/matrimony/lastMatrimonyId")
def get_last_matrimony_id():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT matrimony_id FROM matrimony_profiles ORDER BY matrimony_id DESC LIMIT 1;")
        result = cur.fetchone()
        
        cur.close()
        conn.close()

        if result:
            return {"last_matrimony_id": result[0]}
        else:
            return {"last_matrimony_id": 11111}  # Default if no entry exists

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# Endpoint to update the last matrimony ID in the database
@app.put("/matrimony/incrementMatrimonyId")
def increment_matrimony_id(request: IncrementMatrimonyIdRequest):
    conn = None
    cur = None
    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get the numeric part from the provided last_matrimony_id
        numeric_part = int(re.search(r'\d+', request.last_matrimony_id).group())

        # Increment and generate new matrimony_id
        new_numeric_part = numeric_part + 1
        new_matrimony_id = f"NBS{new_numeric_part:05d}"

        # Insert new ID into tracker table
        insert_query = """
        INSERT INTO matrimony_id_tracker (last_matrimony_id, updated_at)
        VALUES (%s, CURRENT_TIMESTAMP)
        """
        cur.execute(insert_query, (new_matrimony_id,))
        conn.commit()

        return {
            "success": True,
            "last_matrimony_id": new_matrimony_id
        }

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
            
@app.post("/matrimony/refresh-token", response_model=TokenResponse)
async def matrimony_refresh_token(token: RefreshTokenRequest):
    logger.debug(f"Received refresh token: {token.refresh_token}")
    conn = None
    cur = None

    try:
        # Decode JWT token
        payload = jwt.decode(token.refresh_token, settings.REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
        logger.debug(f"Decoded refresh token payload: {payload}")

        matrimony_id = payload.get("sub")
        if not matrimony_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token: missing user ID")

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        logger.error("JWT decode error:\n%s", traceback.format_exc())
        raise HTTPException(status_code=500, detail="Invalid token format")

    try:
        # DB operations (separate try block)
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT is_valid FROM matrimony_refresh_tokens WHERE token = %s", (token.refresh_token,))
        db_token = cur.fetchone()

        if not db_token or not db_token[0]:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        # Generate and store new tokens
        access_token = create_access_token({"sub": matrimony_id, "user_type": "user"})
        new_refresh_token = create_refresh_token({"sub": matrimony_id, "user_type": "user"})

        cur.execute("UPDATE matrimony_refresh_tokens SET is_valid = false WHERE token = %s", (token.refresh_token,))
        cur.execute("""
            INSERT INTO matrimony_refresh_tokens (matrimony_id, token, expires_at, is_valid)
            VALUES (%s, %s, %s, true)
            ON CONFLICT (matrimony_id) DO UPDATE SET
                token = EXCLUDED.token,
                expires_at = EXCLUDED.expires_at,
                is_valid = true
        """, (matrimony_id, new_refresh_token, datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)))
        conn.commit()

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }

    except HTTPException:
        raise  # Re-raise exact HTTP errors
    except Exception as e:
        logger.error("Unexpected error in /matrimony/refresh-token:\n%s", traceback.format_exc())
        raise HTTPException(status_code=500, detail="Unexpected server error")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.get("/matrimony/profiles", response_model=List[MatrimonyProfileResponse])
async def get_matrimony_profiles(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    language: Optional[str] = Query("en", description="Language for response (e.g., 'en', 'ta')")
):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    try:
        logger.info(f"Current user: {current_user}")
        logger.info(f"Requested language: {language}")

        query = "SELECT * FROM matrimony_profiles WHERE 1=1"
        params = []

        if current_user["user_type"] != "admin":
            user_gender = current_user.get("gender")
            if not user_gender:
                raise HTTPException(status_code=400, detail="User gender not found")
            opposite_gender = "Female" if user_gender.lower() == "male" else "Male"
            query += " AND gender ILIKE %s"
            params.append(opposite_gender)
            logger.info(f"Filtering opposite gender: {opposite_gender}")

        cur.execute(query, params)
        profiles = cur.fetchall()
        logger.info(f"Fetched profiles count: {len(profiles)}")

        if not profiles:
            return []

        translator = None
        if language and language.lower() != "en":
            try:
                from googletrans import Translator
                translator = Translator()
                translator.translate("test", src="en", dest=language)
                logger.info(f"Translator initialized for language: {language}")
            except Exception as e:
                logger.error(f"Translator failed to initialize: {e}")
                translator = None
        def process_s3_url(url, folder_name):
            """Process a single S3 URL"""
            if url and isinstance(url, str):
                if url.startswith("http"):
                    return url
                else:
                    return f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
            return None

        def process_s3_urls(value, folder_name):
            """Process a list of S3 URLs from the database array format"""
            if not value:
                return None
                
            # Handle both string representation of array and actual list
            if isinstance(value, str):
                # Remove curly braces and split by comma
                items = [item.strip().strip('"') for item in value.strip('{}').split(',') if item.strip()]
            elif isinstance(value, list):
                items = value
            else:
                return None
                
            if not items:
                return None
                
            return [
                item if item.startswith("http") else
                f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{item}"
                for item in items
            ]

        def translate_static_term(term: str, lang: str) -> str:
            key = term.strip().lower().replace(" ", "_")
            return ASTROLOGY_TERMS.get(key, {}).get(lang, term)

        result_profiles = []

        for profile in profiles:
            profile_dict = dict(profile)

            for key, value in profile_dict.items():
                if isinstance(value, str) and not value.strip():
                    profile_dict[key] = None

            # Process photo URL
            if profile_dict.get("photo_path"):
                profile_dict["photo"] = process_s3_url(profile_dict["photo_path"], "profile_photos")
            else:
                profile_dict["photo"] = None

            # Process photos array
            profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
            
            # Process horoscope documents array
            profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

            if isinstance(profile_dict.get("birth_time"), time):
                profile_dict["birth_time"] = profile_dict["birth_time"].strftime('%H:%M:%S')

            if isinstance(profile_dict.get("date_of_birth"), datetime):
                profile_dict["date_of_birth"] = profile_dict["date_of_birth"].strftime('%Y-%m-%d')

            if profile_dict.get("date_of_birth"):
                dob = datetime.strptime(profile_dict["date_of_birth"], '%Y-%m-%d')
                today = datetime.today()
                profile_dict["age"] = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

            profile_dict["is_translated"] = False
            if translator and language.lower() != "en":
                translatable_fields = [
                    "full_name", "occupation", "gender", "education", "mother_tongue", "dhosham", 
                    "work_type", "company", "work_location", "religion", "caste", "sub_caste"
                ]
                for field in translatable_fields:
                    if field in profile_dict and isinstance(profile_dict[field], str):
                        try:
                            translated = translator.translate(profile_dict[field], src="en", dest=language)
                            profile_dict[field] = translated.text
                            profile_dict["is_translated"] = True
                        except Exception as e:
                            logger.warning(f"Translation failed for {field}: {e}")

                for astro_field in ["nakshatra", "rashi", "dhosham"]:
                    if profile_dict.get(astro_field):
                        profile_dict[astro_field] = translate_static_term(profile_dict[astro_field], language)
                        profile_dict["is_translated"] = True

            try:
                result_profiles.append(MatrimonyProfileResponse(**profile_dict))
            except ValidationError as e:
                logger.error(f"Validation error for {profile_dict.get('matrimony_id')}: {e}")
                continue

        logger.info(f"Returning {len(result_profiles)} profiles")
        return result_profiles

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Server error while fetching profiles.")
    finally:
        cur.close()
        conn.close()

@app.get("/matrimony/preference", response_model=List[MatrimonyProfileResponse])
async def get_matrimony_preferences(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    try:
        # Get complete profile of current user
        cur.execute(
            """
            SELECT matrimony_id, gender, preferred_rashi, preferred_nakshatra, 
                   preferred_religion, rashi, nakshatra, religion
            FROM matrimony_profiles 
            WHERE matrimony_id = %s
            """, 
            [current_user.get("matrimony_id")]
        )
        user_profile = cur.fetchone()
        
        if not user_profile:
            logger.error(f"Profile not found for user: {current_user.get('matrimony_id')}")
            raise HTTPException(status_code=404, detail="User profile not found")

        logger.info(f"Current user exact values - ID: {user_profile['matrimony_id']}, "
                   f"Gender: '{user_profile['gender']}', "
                   f"Preferred Rashi: '{user_profile['preferred_rashi']}', "
                   f"Preferred Nakshatra: '{user_profile['preferred_nakshatra']}', "
                   f"Preferred Religion: '{user_profile['preferred_religion']}'")

        user_gender = user_profile['gender'].strip()
        opposite_gender = "Male" if user_gender.lower() == "female" else "Female"

        # Build query parts based on preferences
        query = """
            SELECT * FROM matrimony_profiles
            WHERE gender ILIKE %s
            AND matrimony_id != %s
        """
        params = [opposite_gender, user_profile['matrimony_id']]

        # Add rashi filter
        if user_profile['preferred_rashi']:
            preferred_rashi_list = [r.strip() for r in user_profile['preferred_rashi'].split(",") if r.strip()]
            if preferred_rashi_list:
                query += """
                    AND rashi IS NOT NULL
                    AND LOWER(rashi) = ANY(SELECT LOWER(UNNEST(%s)))
                """
                params.append(preferred_rashi_list)
                logger.info(f"Filtering by preferred rashi: {preferred_rashi_list}")

        # Add nakshatra filter
        if user_profile['preferred_nakshatra']:
            preferred_nakshatra_list = [n.strip() for n in user_profile['preferred_nakshatra'].split(",") if n.strip()]
            if preferred_nakshatra_list:
                query += """
                    AND nakshatra IS NOT NULL
                    AND LOWER(nakshatra) = ANY(SELECT LOWER(UNNEST(%s)))
                """
                params.append(preferred_nakshatra_list)
                logger.info(f"Filtering by preferred nakshatra: {preferred_nakshatra_list}")

        # Add religion filter
        if user_profile['preferred_religion']:
            preferred_religion_list = [r.strip() for r in user_profile['preferred_religion'].split(",") if r.strip()]
            if preferred_religion_list:
                query += """
                    AND religion IS NOT NULL
                    AND LOWER(religion) = ANY(SELECT LOWER(UNNEST(%s)))
                """
                params.append(preferred_religion_list)
                logger.info(f"Filtering by preferred religion: {preferred_religion_list}")

        logger.info(f"Executing query: {query}")
        logger.info(f"Query params: {params}")
        
        cur.execute(query, params)
        profiles = cur.fetchall()

        if not profiles:
            logger.info("No matching profiles found")
            return []

        compatible_profiles = []
        for profile in profiles:
            profile_dict = dict(zip([desc[0] for desc in cur.description], profile))
            
            if isinstance(profile_dict.get("birth_time"), time):
                profile_dict["birth_time"] = profile_dict["birth_time"].strftime("%H:%M:%S")
            
            logger.info(f"Found matching profile - ID: {profile_dict['matrimony_id']}, "
                       f"Gender: '{profile_dict['gender']}', "
                       f"Rashi: '{profile_dict.get('rashi')}', "
                       f"Nakshatra: '{profile_dict.get('nakshatra')}', "
                       f"Religion: '{profile_dict.get('religion')}'")
            
            compatible_profiles.append(MatrimonyProfileResponse(**profile_dict))

        return compatible_profiles

    except Exception as e:
        logger.error(f"Error in get_matrimony_preferences: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error retrieving profiles")

    finally:
        cur.close()
        conn.close()

@app.get("/rashi_compatibility/{rashi1}/{rashi2}")
def get_rashi_compatibility(rashi1: str, rashi2: str):
    rashi1, rashi2 = rashi1.lower(), rashi2.lower()
    compatibility = RASHI_COMPATIBILITY.get((rashi1, rashi2)) or RASHI_COMPATIBILITY.get((rashi2, rashi1))
    return {"rashi1": rashi1, "rashi2": rashi2, "compatibility": compatibility or "Unknown"}

@app.get("/nakshatra_compatibility/{nakshatra1}/{nakshatra2}")
def get_nakshatra_compatibility(nakshatra1: str, nakshatra2: str):
    nakshatra1, nakshatra2 = nakshatra1.lower(), nakshatra2.lower()
    compatibility = NAKSHATRA_COMPATIBILITY.get((nakshatra1, nakshatra2)) or NAKSHATRA_COMPATIBILITY.get((nakshatra2, nakshatra1))
    return {"nakshatra1": nakshatra1, "nakshatra2": nakshatra2, "compatibility": compatibility or "Unknown"}

@app.post("/check_compatibility/")
def check_full_compatibility(request: CompatibilityRequest):
    rashi_match = RASHI_COMPATIBILITY.get((request.groom_rashi.lower(), request.bride_rashi.lower()))
    nakshatra_match = NAKSHATRA_COMPATIBILITY.get((request.groom_nakshatra.lower(), request.bride_nakshatra.lower()))
    
    return {
        "groom_rashi": request.groom_rashi,
        "bride_rashi": request.bride_rashi,
        "rashi_compatibility": rashi_match or "Unknown",
        "groom_nakshatra": request.groom_nakshatra,
        "bride_nakshatra": request.bride_nakshatra,
        "nakshatra_compatibility": nakshatra_match or "Unknown"
    }


@app.post("/send-notification", response_model=Dict[str, Any])
async def send_notification(
    token: str = Query(..., description="Device token to send the notification to"),
    title: str = Query(..., description="Title of the notification"),
    body: str = Query(..., description="Body of the notification"),
):
    """
    Send a push notification to a specific device token.
    """
    return send_push_notification(token, title, body)

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000   
    )
