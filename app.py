import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import tempfile
import bcrypt
import re
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Query, Form, Body, Request
from typing import Optional, Literal
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
from collections import defaultdict


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
    allow_origins=["http://localhost:5173", "http://localhost:3000", "https://admin.newbrindha.com", "https://newbrindha.com", "http://admin.newbrindha.com", "http://newbrindha.com"],
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
    AWS_S3_BUCKET_NAME = "nbs-matrimonybucket2"  # Add this line
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

# is_user_blocked
def is_user_blocked(matrimony_id: str) -> bool:
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT 1 FROM blocked_users WHERE blocked_matrimony_id = %s
        """, (matrimony_id,))
        return cur.fetchone() is not None
    finally:
        cur.close()
        conn.close()

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
    message: str

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
    private_files_id: Optional[int]
    selected_urls: List[str]

class FileSelectionsRequest(BaseModel):
    user_id: int
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
    matrimony_id: str

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
    is_active: Optional[str]
    blood_group: Optional[str]
    is_verified:  Optional[str]
    verification_status: Optional[str] 
    verification_verification_comment: Optional[str] 

class MatrimonyProfilesWithMessage(BaseModel):
    message: str
    profiles: List[MatrimonyProfileResponse]


class AdminProfileVerificationSummary(BaseModel):
    message: str
    pending_count: int
    approved_count: int
    profiles: List[MatrimonyProfileResponse]

class ProfileVerificationUpdate(BaseModel):
    matrimony_id: str
    verification_status: Literal["approve", "pending"]
    verification_verification_comment: Optional[str] = None

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
    
class SpendAction(BaseModel):
    profile_matrimony_id: str = Field(..., alias="profile_matrimony_id")
    points: int

class SpendRequest(BaseModel):
    spend_requests: List[SpendAction]

class FavoriteProfilesRequest(BaseModel):
    favorite_profile_ids: List[str]
    unfavorite_profile_ids: Optional[List[str]] = []

class EmailVerificationRequest(BaseModel):
    email: EmailStr

class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)

class DeactivationReportRequest(BaseModel):
    matrimony_id: str
    reason: str

class ChatRequest(BaseModel):
    message: str
    sender_id: str
    receiver_id: str

class ChatUserRequest(BaseModel):
    message: str
    sender_id: str
    receiver_email: str

class AdminChatMessage(BaseModel):
    sender_id: str
    receiver_id: str
    message: str
    timestamp: datetime  

class ReportSchema(BaseModel):
    reported_matrimony_id: str
    reason: str

class BlockUserSchema(BaseModel):
    matrimony_id: str
    reason: str

class UnblockUserSchema(BaseModel):
    matrimony_id: List[str]

class ContactUsCreate(BaseModel):
    full_name: str
    email: EmailStr
    message: str

class ContactUsResponse(ContactUsCreate):
    matrimony_id: str
    created_at: datetime

class MarkViewedRequest(BaseModel):
    profile_matrimony_ids: List[str]


class ViewedProfilesResponse(BaseModel):
    success: bool
    viewer_id: str
    viewed_profiles: List[str]

# Define the NakshatraMatcher class 
class NakshatraMatcher:
    def __init__(self):
        # Define nakshatra compatibility rules (score 1-3, higher is better)
        self.compatibility_rules = {
            "Ashwini": {
                "Bharani": 3, "Krittika": 2, "Rohini": 1,
                "Mrigashira": 2, "Ardra": 1, "Punarvasu": 3
            },
            "Bharani": {
                "Krittika": 3, "Rohini": 2, "Mrigashira": 1,
                "Ardra": 2, "Punarvasu": 3, "Pushya": 1
            },
            "Krittika": {
                "Rohini": 3, "Mrigashira": 2, "Ardra": 1,
                "Punarvasu": 2, "Pushya": 3, "Ashlesha": 1
            },
            "Rohini": {
                "Mrigashira": 3, "Ardra": 2, "Punarvasu": 1,
                "Pushya": 2, "Ashlesha": 3, "Magha": 1
            },
            "Mrigashira": {
                "Ardra": 3, "Punarvasu": 2, "Pushya": 1,
                "Ashlesha": 2, "Magha": 3, "PurvaPhalguni": 1
            },
            "Ardra": {
                "Punarvasu": 3, "Pushya": 2, "Ashlesha": 1,
                "Magha": 2, "PurvaPhalguni": 3, "UttaraPhalguni": 1
            },
            "Punarvasu": {
                "Pushya": 3, "Ashlesha": 2, "Magha": 1,
                "PurvaPhalguni": 2, "UttaraPhalguni": 3, "Hasta": 1
            },
            "Pushya": {
                "Ashlesha": 3, "Magha": 2, "PurvaPhalguni": 1,
                "UttaraPhalguni": 2, "Hasta": 3, "Chitra": 1
            },
            "Ashlesha": {
                "Magha": 3, "PurvaPhalguni": 2, "UttaraPhalguni": 1,
                "Hasta": 2, "Chitra": 3, "Swati": 1
            },
            "Magha": {
                "PurvaPhalguni": 3, "UttaraPhalguni": 2, "Hasta": 1,
                "Chitra": 2, "Swati": 3, "Vishakha": 1
            },
            "PurvaPhalguni": {
                "UttaraPhalguni": 3, "Hasta": 2, "Chitra": 1,
                "Swati": 2, "Vishakha": 3, "Anuradha": 1
            },
            "UttaraPhalguni": {
                "Hasta": 3, "Chitra": 2, "Swati": 1,
                "Vishakha": 2, "Anuradha": 3, "Jyeshtha": 1
            },
            "Hasta": {
                "Chitra": 3, "Swati": 2, "Vishakha": 1,
                "Anuradha": 2, "Jyeshtha": 3, "Moola": 1
            },
            "Chitra": {
                "Swati": 3, "Vishakha": 2, "Anuradha": 1,
                "Jyeshtha": 2, "Moola": 3, "Purvashada": 1
            },
            "Swati": {
                "Vishakha": 3, "Anuradha": 2, "Jyeshtha": 1,
                "Moola": 2, "Purvashada": 3, "Uttarashada": 1
            },
            "Vishakha": {
                "Anuradha": 3, "Jyeshtha": 2, "Moola": 1,
                "Purvashada": 2, "Uttarashada": 3, "Shravana": 1
            },
            "Anuradha": {
                "Jyeshtha": 3, "Moola": 2, "Purvashada": 1,
                "Uttarashada": 2, "Shravana": 3, "Dhanishta": 1
            },
            "Jyeshtha": {
                "Moola": 3, "Purvashada": 2, "Uttarashada": 1,
                "Shravana": 2, "Dhanishta": 3, "Shatabhisha": 1
            },
            "Moola": {
                "Purvashada": 3, "Uttarashada": 2, "Shravana": 1,
                "Dhanishta": 2, "Shatabhisha": 3, "Purvabhadra": 1
            },
            "Purvashada": {
                "Uttarashada": 3, "Shravana": 2, "Dhanishta": 1,
                "Shatabhisha": 2, "Purvabhadra": 3, "Uttarabhadra": 1
            },
            "Uttarashada": {
                "Shravana": 3, "Dhanishta": 2, "Shatabhisha": 1,
                "Purvabhadra": 2, "Uttarabhadra": 3, "Revati": 1
            },
            "Shravana": {
                "Dhanishta": 3, "Shatabhisha": 2, "Purvabhadra": 1,
                "Uttarabhadra": 2, "Revati": 3, "Ashwini": 1
            },
            "Dhanishta": {
                "Shatabhisha": 3, "Purvabhadra": 2, "Uttarabhadra": 1,
                "Revati": 2, "Ashwini": 3, "Bharani": 1
            },
            "Shatabhisha": {
                "Purvabhadra": 3, "Uttarabhadra": 2, "Revati": 1,
                "Ashwini": 2, "Bharani": 3, "Krittika": 1
            },
            "Purvabhadra": {
                "Uttarabhadra": 3, "Revati": 2, "Ashwini": 1,
                "Bharani": 2, "Krittika": 3, "Rohini": 1
            },
            "Uttarabhadra": {
                "Revati": 3, "Ashwini": 2, "Bharani": 1,
                "Krittika": 2, "Rohini": 3, "Mrigashira": 1
            },
            "Revati": {
                "Ashwini": 3, "Bharani": 2, "Krittika": 1,
                "Rohini": 2, "Mrigashira": 3, "Ardra": 1
            }
        }
        
        # Define utthamam (excellent) matches - most compatible pairs
        self.utthamam_matches = {
            "Ashwini": ["Bharani", "Punarvasu", "Dhanishta"],
            "Bharani": ["Krittika", "Pushya", "Shatabhisha"],
            "Krittika": ["Rohini", "Ashlesha", "Purvabhadra"],
            "Rohini": ["Mrigashira", "Magha", "Uttarabhadra"],
            "Mrigashira": ["Ardra", "PurvaPhalguni", "Revati"],
            "Ardra": ["Punarvasu", "UttaraPhalguni", "Ashwini"],
            "Punarvasu": ["Pushya", "Hasta", "Bharani"],
            "Pushya": ["Ashlesha", "Chitra", "Krittika"],
            "Ashlesha": ["Magha", "Swati", "Rohini"],
            "Magha": ["PurvaPhalguni", "Vishakha", "Mrigashira"],
            "PurvaPhalguni": ["UttaraPhalguni", "Anuradha", "Ardra"],
            "UttaraPhalguni": ["Hasta", "Jyeshtha", "Punarvasu"],
            "Hasta": ["Chitra", "Moola", "Pushya"],
            "Chitra": ["Swati", "Purvashada", "Ashlesha"],
            "Swati": ["Vishakha", "Uttarashada", "Magha"],
            "Vishakha": ["Anuradha", "Shravana", "PurvaPhalguni"],
            "Anuradha": ["Jyeshtha", "Dhanishta", "UttaraPhalguni"],
            "Jyeshtha": ["Moola", "Shatabhisha", "Hasta"],
            "Moola": ["Purvashada", "Purvabhadra", "Chitra"],
            "Purvashada": ["Uttarashada", "Uttarabhadra", "Swati"],
            "Uttarashada": ["Shravana", "Revati", "Vishakha"],
            "Shravana": ["Dhanishta", "Ashwini", "Anuradha"],
            "Dhanishta": ["Shatabhisha", "Bharani", "Jyeshtha"],
            "Shatabhisha": ["Purvabhadra", "Krittika", "Moola"],
            "Purvabhadra": ["Uttarabhadra", "Rohini", "Purvashada"],
            "Uttarabhadra": ["Revati", "Mrigashira", "Uttarashada"],
            "Revati": ["Ashwini", "Ardra", "Shravana"]
        }
        
        # Define madhyamam (good) matches - secondary compatible pairs
        self.madhyamam_matches = {
            "Ashwini": ["Krittika", "Rohini", "Revati"],
            "Bharani": ["Rohini", "Mrigashira", "Purvabhadra"],
            "Krittika": ["Mrigashira", "Ardra", "Uttarabhadra"],
            "Rohini": ["Ardra", "Punarvasu", "Revati"],
            "Mrigashira": ["Punarvasu", "Pushya", "Ashwini"],
            "Ardra": ["Pushya", "Ashlesha", "Bharani"],
            "Punarvasu": ["Ashlesha", "Magha", "Krittika"],
            "Pushya": ["Magha", "PurvaPhalguni", "Rohini"],
            "Ashlesha": ["PurvaPhalguni", "UttaraPhalguni", "Mrigashira"],
            "Magha": ["UttaraPhalguni", "Hasta", "Ardra"],
            "PurvaPhalguni": ["Hasta", "Chitra", "Punarvasu"],
            "UttaraPhalguni": ["Chitra", "Swati", "Pushya"],
            "Hasta": ["Swati", "Vishakha", "Ashlesha"],
            "Chitra": ["Vishakha", "Anuradha", "Magha"],
            "Swati": ["Anuradha", "Jyeshtha", "PurvaPhalguni"],
            "Vishakha": ["Jyeshtha", "Moola", "UttaraPhalguni"],
            "Anuradha": ["Moola", "Purvashada", "Hasta"],
            "Jyeshtha": ["Purvashada", "Uttarashada", "Chitra"],
            "Moola": ["Uttarashada", "Shravana", "Swati"],
            "Purvashada": ["Shravana", "Dhanishta", "Vishakha"],
            "Uttarashada": ["Dhanishta", "Shatabhisha", "Anuradha"],
            "Shravana": ["Shatabhisha", "Purvabhadra", "Jyeshtha"],
            "Dhanishta": ["Purvabhadra", "Uttarabhadra", "Moola"],
            "Shatabhisha": ["Uttarabhadra", "Revati", "Purvashada"],
            "Purvabhadra": ["Revati", "Ashwini", "Uttarashada"],
            "Uttarabhadra": ["Ashwini", "Bharani", "Shravana"],
            "Revati": ["Bharani", "Krittika", "Dhanishta"]
        }

    def check_compatibility(self, Male_nakshatra: str, Female_nakshatra: str) -> Dict[str, Any]:
        Male_nakshatra = Male_nakshatra.strip().capitalize()
        Female_nakshatra = Female_nakshatra.strip().capitalize()
        
        # Check for utthamam match
        is_utthamam = Female_nakshatra in self.utthamam_matches.get(Male_nakshatra, [])
        
        # Check for madhyamam match if not utthamam
        is_madhyamam = False
        if not is_utthamam:
            is_madhyamam = Female_nakshatra in self.madhyamam_matches.get(Male_nakshatra, [])
        
        # Calculate combined score
        score = self.compatibility_rules.get(Male_nakshatra, {}).get(Female_nakshatra, 0)
        
        return {
            "is_utthamam": is_utthamam,
            "is_madhyamam": is_madhyamam,
            "combined_score": score,
            "Male_nakshatra": Male_nakshatra,
            "Female_nakshatra": Female_nakshatra
        }
nakshatra_matcher = NakshatraMatcher()

# Initialize the translator
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
            WHERE token = %s
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
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
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
    "image/jpg", "image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"
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

            # Debug individual token parts
            parts = token.split(".")
            if len(parts) != 3:
                raise HTTPException(status_code=401, detail="Malformed JWT token")

            # Try base64 decoding to see which part fails
            try:
                print("Header:", base64.urlsafe_b64decode(parts[0] + '=='))
                print("Payload:", base64.urlsafe_b64decode(parts[1] + '=='))
            except Exception as e:
                print("Base64 decode error:", e)
                raise HTTPException(status_code=401, detail="Malformed token content")


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
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "email": db_user[1],
            "user_type": db_user[3]  
        }
    except Exception as e:
        import traceback
        traceback.print_exc()  #
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

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
            "message": f"{event.name},{event.event_date},{event.event_time},{event.event_type} Event form submitted successfully",
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
    Retrieve all event forms with personalized success messages.
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
        columns = [desc[0] for desc in cur.description]

        event_forms = []
        for row in rows:
            event = dict(zip(columns, row))
            # Add personalized message to each event
            event["message"] = (
                f"{event['name']}, {event['event_date']}, "
                f"{event['event_time']}, {event['event_type']} Event form submitted successfully"
            )
            event_forms.append(event)

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
    limit: Optional[int] = Query(10, description="Number of files per page"),
    offset: Optional[int] = Query(0, description="Page offset"),
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
            "message": f"{frame_name}, {frame_id}, {frame_size}, Frame submitted successfully for {phone_number}",
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
    # limit: int = Query(10000, description="Number of frames per page"),
    # offset: int = Query(0, description="Page offset"),
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
            FROM product_frames;
            """,
            # (limit, offset)
        )
        frames = cur.fetchall()

        if not frames:
            raise HTTPException(status_code=404, detail="No product frames found")

        product_frames = [
            {
                "message": f"{frame[1]}, {frame[0]}, {frame[3]}, Frame submitted successfully for {frame[2]}",
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
        
        user_id = db_user[0] 

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
                user_id,
                datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            )
        )
        conn.commit()
        
        return {
            "message": "Login Successfully",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "data": {    
                "user_id": user_id,        
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
    user_id: int = Query(..., alias="user_id"),
    file_id: int = Query(None, alias="file_id")  # Optional query parameter for file_id
):
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
            (user_id,)
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
            "uploaded_by": user_id,
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
async def user_select_files(request: FileSelectionsRequest):
    user_id = request.user_id

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
            "uploaded_by": user_id,
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
async def user_get_all_selected_files(user_id: int = Query(...)):
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Step 1: Fetch file IDs and categories
        cur.execute("""
            SELECT private_files_id, category FROM private_files
            WHERE uploaded_by = %s
        """, (user_id,))
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
                "uploaded_by": user_id,
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

@app.get("/photostudio/admin/private/unselected-files", response_model=Dict[str, Any])
async def admin_get_unselected_files(user_id: int):
    # print("current_user:", current_user)
    # # Check if current user is admin
    # if current_user.get("user_type") != "admin":
    #     raise HTTPException(status_code=403, detail="Only admin can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # Join private_files and private_files_url, filter by user_id and unselected files
        cur.execute("""
            SELECT 
                pf.private_files_id,
                pf.category,
                pf.uploaded_by,
                pfu.id AS file_id,
                pfu.file_url,
                pfu.user_selected_files
            FROM private_files pf
            JOIN private_files_url pfu ON pf.private_files_id = pfu.private_files_id
            WHERE pf.uploaded_by = %s
              AND (
                  pfu.user_selected_files IS NULL
                  OR (pfu.user_selected_files::json ->> 'selected')::boolean = false
              )
        """, (user_id,))

        rows = cur.fetchall()

        result = [
            {
                "private_files_id": row["private_files_id"],
                "category": row["category"],
                "uploaded_by": row["uploaded_by"],
                "file_id": row["file_id"],
                "file_url": row["file_url"],
                "selected_status": (
                    row["user_selected_files"]
                    if isinstance(row["user_selected_files"], dict)
                    else json.loads(row["user_selected_files"]) if row["user_selected_files"]
                    else {"selected": False}
                )

            }
            for row in rows
        ]

        return {
            "uploaded_by": user_id,
            "unselected_files": result,
            "total_unselected": len(result)
        }

    except Exception as e:
        conn.rollback()
        print(f"Error fetching unselected files: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch unselected files")

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
    matrimony_id: Optional[str] = Form(None),
    blood_group: Optional[str] = Form(None)

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
            photo_url, photos_array, horoscope_array, dhosham, other_dhosham, quarter, marital_status, blood_group
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
            horoscope_documents, dhosham, other_dhosham, quarter, marital_status, blood_group
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

        # Check if user is blocked in the blocked_users table
        cur.execute(
            """
            SELECT * FROM blocked_users
            WHERE blocked_matrimony_id = %s AND is_blocked = true
            """,
            (request.matrimony_id,)
        )
        blocked_record = cur.fetchone()
        print("Blocked record found:", dict(blocked_record) if blocked_record else "None")

        if blocked_record:
            reason = blocked_record.get("reason") or "No reason specified"
            raise HTTPException(
                status_code=403,
                detail=f"Admin has blocked this profile. Reason: {reason}"
            )

        # Password and phone number from user profile
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
            matrimony_id=request.matrimony_id
        )

    except HTTPException as e:
        raise e  # Let FastAPI handle known HTTP errors

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
    VALUES (%s, %s, %s, TRUE)
    ON CONFLICT (matrimony_id) DO UPDATE SET
        token = EXCLUDED.token,
        expires_at = EXCLUDED.expires_at,
        is_valid = TRUE
""", (matrimony_id, new_refresh_token, datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)))


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
# Matrimony Profiles Endpoint
@app.get("/matrimony/profiles", response_model=Dict[str, List[MatrimonyProfileResponse]])
async def get_matrimony_profiles(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    language: Optional[str] = Query("en", description="Language for response (e.g., 'en', 'ta')"),
):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    try:
        logger.info(f"Current user: {current_user}")
        logger.info(f"Requested language: {language}")

        user_type = current_user["user_type"].lower()

        # Conditional base query depending on user type
        if user_type == "admin":
            query = "SELECT * FROM matrimony_profiles WHERE is_active = true"
        else:
            query = "SELECT * FROM matrimony_profiles WHERE is_active = true AND verification_status = 'approve'"

        params = []

        if user_type != "admin":
            # Users: show opposite gender and exclude globally blocked profiles
            user_gender = current_user.get("gender")
            if not user_gender:
                raise HTTPException(status_code=400, detail="User gender not found")

            opposite_gender = "Female" if user_gender.lower() == "male" else "Male"

            query += """
                AND gender ILIKE %s
                AND matrimony_id NOT IN (
                    SELECT blocked_matrimony_id
                    FROM blocked_users
                    WHERE is_blocked = true
                        AND is_verified = true
                        AND verification_status = 'approve'
                )
            """
            params.append(opposite_gender)
            logger.info(f"User view - Filtering opposite gender: {opposite_gender} and excluding globally blocked profiles")

        else:
            # Admins: exclude only profiles they themselves blocked
            admin_email = current_user["email"]
            query += """
                AND matrimony_id NOT IN (
                    SELECT blocked_matrimony_id 
                    FROM blocked_users 
                    WHERE admin_matrimony_id = %s AND is_blocked = true
                )
            """
            params.append(admin_email)
            logger.info(f"Admin {admin_email} view - excluding profiles they blocked")

        cur.execute(query, params)
        profiles = cur.fetchall()
        logger.info(f"Fetched profiles count: {len(profiles)}")

        if not profiles:
            return {"Profiles": []} if user_type == "admin" else {"New Profiles": [], "Default Profiles": []}

        # Optional translation
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

        # S3 helpers
        def process_s3_url(url, folder_name):
            if url and isinstance(url, str):
                return url if url.startswith("http") else f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
            return None

        def process_s3_urls(value, folder_name):
            if not value:
                return None
            if isinstance(value, str):
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

        new_profiles = []
        default_profiles = []
        all_profiles = []
        cutoff_date = datetime.now() - timedelta(days=30)


        for profile in profiles:
            profile_dict = dict(profile)

            for key, value in profile_dict.items():
                if isinstance(value, str) and not value.strip():
                    profile_dict[key] = None

            profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photos")
            profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
            profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

            if isinstance(profile_dict.get("birth_time"), time):
                profile_dict["birth_time"] = profile_dict["birth_time"].strftime('%H:%M:%S')

            if isinstance(profile_dict.get("date_of_birth"), (datetime, date)):
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
                profile_obj = MatrimonyProfileResponse(**profile_dict)
                updated_at = profile.get("updated_at")

                if user_type == "admin":
                    all_profiles.append(profile_obj)
                else:
                    if updated_at and isinstance(updated_at, datetime) and updated_at >= cutoff_date:
                        new_profiles.append(profile_obj)
                    else:
                        default_profiles.append(profile_obj)
            except ValidationError as e:
                logger.error(f"Validation error for {profile_dict.get('matrimony_id')}: {e}")
                logger.debug(f"Invalid profile data: {profile_dict}")
                continue

        return {"Profiles": all_profiles} if user_type == "admin" else {
            "New Profiles": new_profiles,
            "Default Profiles": default_profiles
        }

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        raise HTTPException(status_code=200, detail="Server error while fetching profiles.")
    finally:
        cur.close()
        conn.close()

        
# Endpoint to get matrimony preferences
@app.get("/matrimony/preference")
async def get_matrimony_preferences(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    case_sensitive: Optional[bool] = Query(default=False)
):
    if is_user_blocked(current_user.get("matrimony_id")):
        raise HTTPException(status_code=200, detail="Access denied. You have been blocked by admin.")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    def process_s3_url(url: Optional[str], folder_name: str) -> Optional[str]:
        if url and isinstance(url, str):
            if url.startswith("http"):
                return url
            return f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
        return None

    def process_s3_urls(value: Any, folder_name: str) -> Optional[List[str]]:
        if not value:
            return None
        if isinstance(value, str):
            items = [item.strip().strip('"') for item in value.strip('{}').split(',') if item.strip()]
        elif isinstance(value, list):
            items = value
        else:
            return None
        return [
            item if item.startswith("http") else
            f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{item}"
            for item in items
        ]

    try:
        cur.execute("""
            SELECT matrimony_id, full_name, gender, nakshatra, preferred_nakshatra
            FROM matrimony_profiles 
            WHERE matrimony_id = %s
        """, [current_user.get("matrimony_id")])
        user_profile = cur.fetchone()

        if not user_profile:
            raise HTTPException(status_code=404, detail="User profile not found")

        user_gender = user_profile['gender'].strip().lower()
        opposite_gender = "female" if user_gender == "male" else "male"
        Male_star = user_profile['nakshatra']

        query = """
            SELECT * FROM matrimony_profiles
            WHERE LOWER(gender) = %s
            AND matrimony_id != %s
            AND is_active = TRUE
            AND is_verified = true
            AND verification_status = 'approve'
            AND matrimony_id NOT IN (
                SELECT blocked_matrimony_id 
                FROM blocked_users 
                WHERE admin_matrimony_id = %s
            )
        """
        params = [opposite_gender, user_profile['matrimony_id'], current_user['matrimony_id']]

        if user_profile.get('preferred_nakshatra'):
            preferred_nakshatra_list = [n.strip() for n in user_profile['preferred_nakshatra'].split(",") if n.strip()]
            if preferred_nakshatra_list:
                if case_sensitive:
                    query += " AND (nakshatra IS NOT NULL AND nakshatra = ANY(%s))"
                    params.append(preferred_nakshatra_list)
                else:
                    query += " AND (nakshatra IS NOT NULL AND LOWER(nakshatra) = ANY(%s))"
                    params.append([n.lower() for n in preferred_nakshatra_list])

        cur.execute(query, params)
        profiles = cur.fetchall()

        matcher = NakshatraMatcher()
        compatible_profiles = []
        utthamam_matches = []

        for profile in profiles:
            profile_dict = dict(profile)
            profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photo")
            profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
            profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

            if isinstance(profile_dict.get("date_of_birth"), (datetime, date)):
                dob = profile_dict["date_of_birth"]
                today = datetime.today()
                profile_dict["age"] = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
                profile_dict["date_of_birth"] = dob.strftime('%Y-%m-%d')

            Female_star = profile_dict.get("nakshatra")
            if not Female_star:
                continue

            if user_gender == "male":
                result = matcher.check_compatibility(Male_star, Female_star)
            else:
                result = matcher.check_compatibility(Female_star, Male_star)

            profile_dict["nakshatra_match_score"] = result["combined_score"]
            profile_dict["nakshatra_match_type"] = (
                "Utthamam" if result["is_utthamam"] else
                "Madhyamam" if result["is_madhyamam"] else
                "Not Compatible"
            )

            compatible_profiles.append(profile_dict)
            if result["is_utthamam"]:
                utthamam_matches.append(profile_dict)

        if not compatible_profiles:
            # Fallback: Fetch all utthamam matches from full DB
            cur.execute("""
                SELECT * FROM matrimony_profiles
                WHERE LOWER(gender) = %s
                AND matrimony_id != %s
                AND is_active = TRUE
                AND is_verified = true
                AND verification_status = 'approve'
                AND matrimony_id NOT IN (
                    SELECT blocked_matrimony_id 
                    FROM blocked_users 
                    WHERE admin_matrimony_id = %s
                )
            """, [opposite_gender, user_profile['matrimony_id'], current_user['matrimony_id']])

            fallback_profiles = cur.fetchall()
            for profile in fallback_profiles:
                profile_dict = dict(profile)
                Female_star = profile_dict.get("nakshatra")
                if not Female_star:
                    continue

                if user_gender == "male":
                    result = matcher.check_compatibility(Male_star, Female_star)
                else:
                    result = matcher.check_compatibility(Female_star, Male_star)

                if result["is_utthamam"]:
                    profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photo")
                    profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
                    profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

                    if isinstance(profile_dict.get("date_of_birth"), (datetime, date)):
                        dob = profile_dict["date_of_birth"]
                        today = datetime.today()
                        profile_dict["age"] = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
                        profile_dict["date_of_birth"] = dob.strftime('%Y-%m-%d')

                    profile_dict["nakshatra_match_score"] = result["combined_score"]
                    profile_dict["nakshatra_match_type"] = "Utthamam"
                    utthamam_matches.append(profile_dict)

        if not compatible_profiles:
            message = f"No compatible profiles matched your preferences. Showing Utthamam matches instead."
        else:
            message = f"{user_profile['full_name']} ({user_profile['matrimony_id']}), you have {len(compatible_profiles)} compatible profiles found"

        return {
            "message": message,
            "profiles": compatible_profiles,
            "matching_profiles": utthamam_matches
        }


    except Exception as e:
        print(f"Exception occurred: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving profiles")
    finally:
        cur.close()
        conn.close()

# In Admin POV: get Method matrimony/preference updated -----------------
@app.get("/matrimony/admin/preference", response_model=List[Dict[str, Any]])
async def get_matrimony_preferences_admin(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    case_sensitive: Optional[bool] = Query(default=False),
    include_inactive: Optional[bool] = Query(default=False)
):
    """
    Admin view of all matrimony preferences and compatible profiles
    - Shows all users and their compatible matches
    - Can include inactive profiles (admin-only feature)
    - Shows nakshatra compatibility information
    """
    if is_user_blocked(current_user.get("matrimony_id")):
        raise HTTPException(status_code=403, detail="Access denied. You have been blocked by admin.")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    def process_s3_url(url, folder_name):
        if url and isinstance(url, str):
            if url.startswith("http"):
                return url
            return f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
        return None

    def process_s3_urls(value, folder_name):
        if not value:
            return None
        if isinstance(value, str):
            items = [item.strip().strip('"') for item in value.strip('{}').split(',') if item.strip()]
        elif isinstance(value, list):
            items = value
        else:
            return None
        return [
            item if item.startswith("http") else
            f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{item}"
            for item in items
        ]

    def get_compatible_profiles(user_profile):
        try:
            user_gender = user_profile['gender'].strip().lower()
            opposite_gender = "female" if user_gender == "male" else "male"

            query = """
                SELECT * FROM matrimony_profiles
                WHERE LOWER(gender) = %s
                AND matrimony_id != %s
                AND is_verified = true
                AND verification_status = 'approve'
                AND matrimony_id NOT IN (
                    SELECT blocked_matrimony_id 
                    FROM blocked_users 
                    WHERE admin_matrimony_id = %s
                )
            """
            params = [opposite_gender, user_profile['matrimony_id'], user_profile['matrimony_id']]

            # Add rashi filter if preferred_rashi exists
            if user_profile.get('preferred_rashi'):
                preferred_rashi_list = [r.strip() for r in user_profile['preferred_rashi'].split(",") if r.strip()]
                if preferred_rashi_list:
                    query += " AND rashi IS NOT NULL"
                    if case_sensitive:
                        query += " AND rashi = ANY(%s)"
                        params.append(preferred_rashi_list)
                    else:
                        query += " AND LOWER(rashi) = ANY(%s)"
                        params.append([r.lower() for r in preferred_rashi_list])

            # Add nakshatra filter if preferred_nakshatra exists
            if user_profile.get('preferred_nakshatra'):
                preferred_nakshatra_list = [n.strip() for n in user_profile['preferred_nakshatra'].split(",") if n.strip()]
                if preferred_nakshatra_list:
                    query += " AND nakshatra IS NOT NULL"
                    if case_sensitive:
                        query += " AND nakshatra = ANY(%s)"
                        params.append(preferred_nakshatra_list)
                    else:
                        query += " AND LOWER(nakshatra) = ANY(%s)"
                        params.append([n.lower() for n in preferred_nakshatra_list])

            cur.execute(query, params)
            results = cur.fetchall()

            compatible_profiles = []
            for profile in results:
                profile_dict = dict(profile)
                profile_dict.pop("password", None)
                
                # Process S3 URLs
                profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photos")
                profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
                profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

                # Format dates
                if isinstance(profile_dict.get("date_of_birth"), (datetime, date)):
                    profile_dict["date_of_birth"] = profile_dict["date_of_birth"].strftime('%Y-%m-%d')
                if isinstance(profile_dict.get("birth_time"), time):
                    profile_dict["birth_time"] = profile_dict["birth_time"].strftime('%H:%M:%S')

                # Calculate age
                if profile_dict.get("date_of_birth"):
                    dob = datetime.strptime(profile_dict["date_of_birth"], '%Y-%m-%d')
                    today = datetime.today()
                    profile_dict["age"] = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

                # Nakshatra compatibility check
                Male_star = user_profile.get('nakshatra')
                Female_star = profile_dict.get('nakshatra')

                match_result = None
                if Male_star and Female_star:
                    if user_gender == "male":
                        match_result = nakshatra_matcher.check_compatibility(Male_star, Female_star)
                    else:
                        match_result = nakshatra_matcher.check_compatibility(Female_star, Male_star)

                # Add compatibility info
                if match_result:
                    profile_dict['nakshatra_match_score'] = match_result.get('combined_score', 0)
                    profile_dict['nakshatra_match_type'] = (
                        'Utthamam' if match_result.get('is_utthamam') 
                        else 'Madhyamam' if match_result.get('is_madhyamam') 
                        else 'Not Compatible'
                    )
                else:
                    profile_dict['nakshatra_match_score'] = 0
                    profile_dict['nakshatra_match_type'] = 'Unknown'

                compatible_profiles.append(profile_dict)

            return compatible_profiles

        except Exception as e:
            print(f"Error processing compatible profiles for {user_profile.get('matrimony_id')}: {e}")
            return []

    try:
        # Fetch all active users (or all users if include_inactive is True)
        query = "SELECT * FROM matrimony_profiles"
        if not include_inactive:
            query += " WHERE is_active = TRUE"
        
        cur.execute(query)
        all_users = cur.fetchall()

        response_data = []
        for user in all_users:
            user_dict = dict(user)
            user_dict.pop("password", None)
            
            # Format user profile
            if isinstance(user_dict.get("date_of_birth"), (datetime, date)):
                user_dict["date_of_birth"] = user_dict["date_of_birth"].strftime('%Y-%m-%d')
            if isinstance(user_dict.get("birth_time"), time):
                user_dict["birth_time"] = user_dict["birth_time"].strftime('%H:%M:%S')
            
            # Calculate age for user
            if user_dict.get("date_of_birth"):
                dob = datetime.strptime(user_dict["date_of_birth"], '%Y-%m-%d')
                today = datetime.today()
                user_dict["age"] = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

            compatible_profiles = get_compatible_profiles(user)
            
            response_data.append({
                "user_profile": user_dict,
                "profile_details": compatible_profiles,
                "compatible_count": len(compatible_profiles),
                "last_updated": datetime.now().isoformat()
            })

        return response_data

    except Exception as e:
        print(f"Admin endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Error processing admin request")

    finally:
        cur.close()
        conn.close()

# Endpoint to get matrimony profiles based on location preference    
@app.get("/matrimony/location-preference", response_model=MatrimonyProfilesWithMessage)
async def get_matrimony_preferences(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    case_sensitive: Optional[bool] = Query(default=False)
):
    if is_user_blocked(current_user.get("matrimony_id")):
        raise HTTPException(status_code=200, detail="Access denied. You have been blocked by admin.")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    def process_s3_url(url, folder_name):
        if url and isinstance(url, str):
            if url.startswith("http"):
                return url
            return f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
        return None

    def process_s3_urls(value, folder_name):
        if not value:
            return None
        if isinstance(value, str):
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

    try:
        # Fetch current user's profile
        cur.execute("""
            SELECT matrimony_id, gender, preferred_location
            FROM matrimony_profiles 
            WHERE matrimony_id = %s
        """, [current_user.get("matrimony_id")])
        user_profile = cur.fetchone()

        if not user_profile:
            raise HTTPException(status_code=404, detail="User profile not found")

        user_gender = user_profile['gender'].strip()
        opposite_gender = "Male" if user_gender.lower() == "female" else "Female"

        # Base query with strict work_location filtering
        query = """
            SELECT * FROM matrimony_profiles
            WHERE gender ILIKE %s
            AND matrimony_id != %s
            AND TRIM(work_location) IS NOT NULL
            AND TRIM(work_location) != ''
            AND LOWER(TRIM(work_location)) != 'null'
            AND is_active = TRUE
            AND is_verified = TRUE
            AND verification_status = 'approve'
            AND matrimony_id NOT IN (
                SELECT blocked_matrimony_id 
                FROM blocked_users 
                WHERE admin_matrimony_id = %s
              )
        """
        params = [opposite_gender, user_profile['matrimony_id'], user_profile['matrimony_id']]

        # Apply location preference filtering
        if user_profile['preferred_location']:
            preferred_location_list = [l.strip() for l in user_profile['preferred_location'].split(",") if l.strip()]
            if preferred_location_list:
                if case_sensitive:
                    query += " AND work_location = ANY(%s)"
                    params.append(preferred_location_list)
                else:
                    query += " AND LOWER(work_location) = ANY(%s)"
                    params.append([loc.lower() for loc in preferred_location_list])

        cur.execute(query, params)
        profiles = cur.fetchall()

        compatible_profiles = []
        for profile in profiles:
            profile_dict = dict(profile)

            # Process media fields
            profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photos")
            profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
            profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

            # Format date_of_birth
            if isinstance(profile_dict.get("date_of_birth"), (datetime, date)):
                profile_dict["date_of_birth"] = profile_dict["date_of_birth"].strftime('%Y-%m-%d')

            # Format birth_time
            if isinstance(profile_dict.get("birth_time"), time):
                profile_dict["birth_time"] = profile_dict["birth_time"].strftime('%H:%M:%S')

            # Calculate age
            if profile_dict.get("date_of_birth"):
                dob = datetime.strptime(profile_dict["date_of_birth"], '%Y-%m-%d')
                today = datetime.today()
                profile_dict["age"] = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

            compatible_profiles.append(MatrimonyProfileResponse(**profile_dict))

        return MatrimonyProfilesWithMessage(
            message=f"{user_profile['matrimony_id']}, {len(compatible_profiles)} location-based profiles found.",
            profiles=compatible_profiles
        )


    except Exception as e:
        raise HTTPException(status_code=500, detail="Error retrieving profiles")

    finally:
        cur.close()
        conn.close()

# In Admin POV: get  /matrimony/admin/location-preference --
@app.get("/matrimony/admin/location-preference", response_model=List[Dict[str, Any]])
async def get_all_location_preferences(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    case_sensitive: Optional[bool] = Query(default=False)
):
    if is_user_blocked(current_user.get("matrimony_id")):
        raise HTTPException(status_code=403, detail="Access denied. You have been blocked by admin.")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    def process_s3_url(url, folder_name):
        if url and isinstance(url, str):
            if url.startswith("http"):
                return url
            return f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
        return None

    def process_s3_urls(value, folder_name):
        if not value:
            return None
        if isinstance(value, str):
            items = [item.strip().strip('"') for item in value.strip('{}').split(',') if item.strip()]
        elif isinstance(value, list):
            items = value
        else:
            return None
        return [
            item if item.startswith("http") else
            f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{item}"
            for item in items
        ]

    def fetch_location_matches(user_profile):
        try:
            gender = user_profile['gender'].strip()
            opposite_gender = "Male" if gender.lower() == "female" else "Female"

            query = """
                SELECT * FROM matrimony_profiles
                WHERE gender ILIKE %s
                AND matrimony_id != %s
                AND TRIM(work_location) IS NOT NULL
                AND TRIM(work_location) != ''
                AND LOWER(TRIM(work_location)) != 'null'
                AND is_active = TRUE
                AND is_verified = TRUE
                AND verification_status = 'approve'
                AND matrimony_id NOT IN (
                    SELECT blocked_matrimony_id 
                    FROM blocked_users 
                    WHERE admin_matrimony_id = %s
                  )
            """
            params = [opposite_gender, user_profile['matrimony_id'], user_profile['matrimony_id']]

            if user_profile.get('preferred_location'):
                preferred_locations = [loc.strip() for loc in user_profile['preferred_location'].split(",") if loc.strip()]
                if preferred_locations:
                    if case_sensitive:
                        query += " AND work_location = ANY(%s)"
                        params.append(preferred_locations)
                    else:
                        query += " AND LOWER(work_location) = ANY(%s)"
                        params.append([loc.lower() for loc in preferred_locations])

            cur.execute(query, params)
            results = cur.fetchall()

            compatible_profiles = []
            for profile in results:
                profile_dict = dict(profile)
                profile_dict.pop("password", None)
                profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photos")
                profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
                profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

                if isinstance(profile_dict.get("date_of_birth"), (datetime, date)):
                    profile_dict["date_of_birth"] = profile_dict["date_of_birth"].strftime('%Y-%m-%d')

                if isinstance(profile_dict.get("birth_time"), time):
                    profile_dict["birth_time"] = profile_dict["birth_time"].strftime('%H:%M:%S')

                if profile_dict.get("date_of_birth"):
                    dob = datetime.strptime(profile_dict["date_of_birth"], '%Y-%m-%d')
                    today = datetime.today()
                    profile_dict["age"] = str(today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day)))

                try:
                    profile_model = MatrimonyProfileResponse(**profile_dict)
                    compatible_profiles.append(profile_model.dict())
                except Exception as e:
                    print("Validation error:", e)
                    print("Bad profile:", profile_dict)

            # Format user profile
            formatted_user_profile = dict(user_profile)
            formatted_user_profile.pop("password", None)
            if isinstance(formatted_user_profile.get("date_of_birth"), (datetime, date)):
                formatted_user_profile["date_of_birth"] = formatted_user_profile["date_of_birth"].strftime('%Y-%m-%d')
            if isinstance(formatted_user_profile.get("birth_time"), time):
                formatted_user_profile["birth_time"] = formatted_user_profile["birth_time"].strftime('%H:%M:%S')

            return {
                "message": f"{user_profile['full_name']} ({user_profile['matrimony_id']}), {len(compatible_profiles)} location-based profiles found.",
                "user_profile": formatted_user_profile,
                "profile_details": compatible_profiles
            }

        except Exception as e:
            print(f"Error for user {user_profile.get('matrimony_id', 'UNKNOWN')}: {e}")
            return {
                "message": f"{user_profile.get('full_name', 'Unknown')} ({user_profile.get('matrimony_id', 'N/A')}), profile error occurred",
                "user_profile": user_profile,
                "profile_details": []
            }

    try:
        cur.execute("SELECT * FROM matrimony_profiles WHERE is_active = TRUE")
        all_users = cur.fetchall()

        response_data = []
        for user in all_users:
            try:
                print(f"Processing user: {user['matrimony_id']}")
                result = fetch_location_matches(user)
                response_data.append(result)
            except Exception as inner_e:
                print(f"Skipping user {user['matrimony_id']}: {inner_e}")
                continue

        return response_data

    except Exception as e:
        print("Top-level error:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Something went wrong")

    finally:
        cur.close()
        conn.close()


# User /matrimony/caste-preference
@app.get("/matrimony/caste-preference", response_model=MatrimonyProfilesWithMessage)
async def get_matrimony_caste_preferences(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    case_sensitive: Optional[bool] = Query(default=False)
):
    if is_user_blocked(current_user.get("matrimony_id")):
        raise HTTPException(status_code=200, detail="Access denied. You have been blocked by admin.")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    def process_s3_url(url, folder_name):
        if url and isinstance(url, str):
            if url.startswith("http"):
                return url
            return f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
        return None

    def process_s3_urls(value, folder_name):
        if not value:
            return None
        if isinstance(value, str):
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

    try:
        # Fetch current user's profile
        cur.execute("""
            SELECT matrimony_id, gender, preferred_caste
            FROM matrimony_profiles 
            WHERE matrimony_id = %s
        """, [current_user.get("matrimony_id")])
        user_profile = cur.fetchone()

        if not user_profile:
            raise HTTPException(status_code=404, detail="User profile not found")

        user_gender = user_profile['gender'].strip()
        opposite_gender = "Male" if user_gender.lower() == "female" else "Female"

        # Base query with caste filters
        query = """
            SELECT * FROM matrimony_profiles
            WHERE gender ILIKE %s
            AND matrimony_id != %s
            AND TRIM(caste) IS NOT NULL
            AND TRIM(caste) != ''
            AND LOWER(TRIM(caste)) NOT IN ('null', 'none', 'nan', 'nil', 'not specified')
            AND is_active = TRUE
            AND is_verified = TRUE
            AND verification_status = 'approve'
            AND matrimony_id NOT IN (
                SELECT blocked_matrimony_id 
                FROM blocked_users 
                WHERE admin_matrimony_id = %s
              )
        """
        params = [opposite_gender, user_profile['matrimony_id'], user_profile['matrimony_id']]

        # Filter by preferred_caste
        if user_profile.get('preferred_caste'):
            preferred_castes = [
                c.strip() for c in user_profile['preferred_caste'].split(',')
                if c.strip().lower() not in ['null', 'none', 'nan', 'nil', 'not specified']
            ]
            if preferred_castes:
                query += " AND caste IS NOT NULL"
                if case_sensitive:
                    query += " AND caste = ANY(%s)"
                    params.append(preferred_castes)
                else:
                    query += " AND LOWER(caste) = ANY(%s)"
                    params.append([c.lower() for c in preferred_castes])

        # Execute
        cur.execute(query, params)
        profiles = cur.fetchall()

        compatible_profiles = []
        for profile in profiles:
            profile_dict = dict(profile)

            profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photos")
            profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
            profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

            if isinstance(profile_dict.get("date_of_birth"), (datetime, date)):
                profile_dict["date_of_birth"] = profile_dict["date_of_birth"].strftime('%Y-%m-%d')

            if isinstance(profile_dict.get("birth_time"), time):
                profile_dict["birth_time"] = profile_dict["birth_time"].strftime('%H:%M:%S')

            if profile_dict.get("date_of_birth"):
                dob = datetime.strptime(profile_dict["date_of_birth"], '%Y-%m-%d')
                today = datetime.today()
                profile_dict["age"] = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

            compatible_profiles.append(MatrimonyProfileResponse(**profile_dict))

        return MatrimonyProfilesWithMessage(
            message=f"{user_profile['matrimony_id']}, {len(compatible_profiles)} caste-based profiles found.",
            profiles=compatible_profiles
        )

    except Exception as e:
        print("Error:", e)
        raise HTTPException(status_code=500, detail="Error retrieving caste preference profiles")

    finally:
        cur.close()
        conn.close()


# In Admin POV:  get /matrimony/admin/caste-preference --
@app.get("/matrimony/admin/caste-preference", response_model=List[Dict[str, Any]])
async def get_admin_caste_preferences(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    case_sensitive: Optional[bool] = Query(default=False)
):
    if is_user_blocked(current_user.get("matrimony_id")):
        raise HTTPException(status_code=403, detail="Access denied. You have been blocked by admin.")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    def process_s3_url(url, folder_name):
        if url and isinstance(url, str):
            if url.startswith("http"):
                return url
            return f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
        return None

    def process_s3_urls(value, folder_name):
        if not value:
            return None
        if isinstance(value, str):
            items = [item.strip().strip('"') for item in value.strip('{}').split(',') if item.strip()]
        elif isinstance(value, list):
            items = value
        else:
            return None
        return [
            item if item.startswith("http") else
            f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{item}"
            for item in items
        ]

    def fetch_compatible_profiles(user_profile):
        try:
            gender = user_profile['gender'].strip()
            opposite_gender = "Male" if gender.lower() == "female" else "Female"

            query = """
                SELECT * FROM matrimony_profiles
                WHERE gender ILIKE %s
                AND matrimony_id != %s
                AND TRIM(caste) IS NOT NULL
                AND TRIM(caste) != ''
                AND LOWER(TRIM(caste)) NOT IN ('null', 'none', 'nan', 'nil', 'not specified')
                AND is_active = TRUE
                AND is_verified = TRUE
                AND verification_status = 'approve'
                AND matrimony_id NOT IN (
                    SELECT blocked_matrimony_id 
                    FROM blocked_users 
                    WHERE admin_matrimony_id = %s
                )
            """
            params = [opposite_gender, user_profile['matrimony_id'], user_profile['matrimony_id']]

            if user_profile.get('preferred_caste'):
                preferred_castes = [
                    c.strip() for c in user_profile['preferred_caste'].split(',')
                    if c.strip().lower() not in ['null', 'none', 'nan', 'nil', 'not specified']
                ]
                if preferred_castes:
                    query += " AND caste IS NOT NULL"
                    if case_sensitive:
                        query += " AND caste = ANY(%s)"
                        params.append(preferred_castes)
                    else:
                        query += " AND LOWER(caste) = ANY(%s)"
                        params.append([c.lower() for c in preferred_castes])

            cur.execute(query, params)
            profiles = cur.fetchall()

            compatible_profiles = []
            for profile in profiles:
                profile_dict = dict(profile)
                profile_dict.pop("password", None)
                profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photos")
                profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
                profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

                if isinstance(profile_dict.get("date_of_birth"), (datetime, date)):
                    profile_dict["date_of_birth"] = profile_dict["date_of_birth"].strftime('%Y-%m-%d')

                if isinstance(profile_dict.get("birth_time"), time):
                    profile_dict["birth_time"] = profile_dict["birth_time"].strftime('%H:%M:%S')

                if profile_dict.get("date_of_birth"):
                    dob = datetime.strptime(profile_dict["date_of_birth"], '%Y-%m-%d')
                    today = datetime.today()
                    profile_dict["age"] = str(today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day)))

                profile_model = MatrimonyProfileResponse(**profile_dict)
                compatible_profiles.append(profile_model.dict())

            formatted_user_profile = dict(user_profile)
            formatted_user_profile.pop("password", None)
            return {
                "message": f"{user_profile.get('full_name', 'User')} ({user_profile['matrimony_id']}), you have {len(compatible_profiles)} caste-based compatible profiles.",
                "user_profile": formatted_user_profile,
                "profile_details": compatible_profiles
            }

        except Exception as e:
            print(f"Error processing {user_profile['matrimony_id']}: {e}")
            return {
                "message": f"{user_profile['matrimony_id']} - error occurred",
                "user_profile": user_profile,
                "profile_details": []
            }

    try:
        cur.execute("SELECT * FROM matrimony_profiles WHERE is_active = TRUE")
        users = cur.fetchall()

        response_data = []
        for user in users:
            try:
                result = fetch_compatible_profiles(user)
                response_data.append(result)
            except Exception as inner_e:
                print(f"Skipping user {user['matrimony_id']}: {inner_e}")
                continue

        return response_data

    except Exception as e:
        print("Top-level error:", e)
        raise HTTPException(status_code=500, detail="Failed to fetch caste preferences for all users")

    finally:
        cur.close()
        conn.close()

# overall admin view preference, location, caste preference

@app.get("/matrimony/admin/preference-overview")
async def get_combined_preferences(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony),
    case_sensitive: Optional[bool] = Query(default=False)
):
    if is_user_blocked(current_user.get("matrimony_id")):
        raise HTTPException(status_code=403, detail="Access denied. You have been blocked by admin.")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    def process_s3_url(url, folder_name):
        if url and isinstance(url, str):
            if url.startswith("http"):
                return url
            return f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
        return None

    def process_s3_urls(value, folder_name):
        if not value:
            return None
        if isinstance(value, str):
            items = [item.strip().strip('"') for item in value.strip('{}').split(',') if item.strip()]
        elif isinstance(value, list):
            items = value
        else:
            return None
        return [
            item if item.startswith("http") else
            f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{item}"
            for item in items
        ]

    def format_profile(profile):
        profile_dict = dict(profile)
        profile_dict.pop("password", None)
        profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photos")
        profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
        profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")
        if isinstance(profile_dict.get("date_of_birth"), (datetime, date)):
            profile_dict["date_of_birth"] = profile_dict["date_of_birth"].strftime('%Y-%m-%d')
        if isinstance(profile_dict.get("birth_time"), time):
            profile_dict["birth_time"] = profile_dict["birth_time"].strftime('%H:%M:%S')
        if profile_dict.get("date_of_birth"):
            dob = datetime.strptime(profile_dict["date_of_birth"], '%Y-%m-%d')
            today = datetime.today()
            profile_dict["age"] = str(today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day)))
        return profile_dict

    def get_opposite_gender(gender: str) -> str:
        return "Male" if gender.lower() == "female" else "Female"

    def fetch_matches(user_profile, preference_type):
        try:
            gender = user_profile["gender"].strip()
            opposite_gender = get_opposite_gender(gender)

            base_query = f"""
                SELECT * FROM matrimony_profiles
                WHERE gender ILIKE %s
                AND matrimony_id != %s
                AND is_active = TRUE
                AND matrimony_id NOT IN (
                    SELECT blocked_matrimony_id FROM blocked_users WHERE admin_matrimony_id = %s
                )
            """
            params = [opposite_gender, user_profile["matrimony_id"], user_profile["matrimony_id"]]

            if preference_type == "preference":
                if user_profile.get('preferred_rashi'):
                    preferred_rashi_list = [r.strip() for r in user_profile['preferred_rashi'].split(",") if r.strip()]
                    if preferred_rashi_list:
                        base_query += " AND rashi IS NOT NULL"
                        base_query += " AND " + ("rashi = ANY(%s)" if case_sensitive else "LOWER(rashi) = ANY(%s)")
                        params.append(preferred_rashi_list if case_sensitive else [r.lower() for r in preferred_rashi_list])
            elif preference_type == "location":
                base_query += " AND TRIM(work_location) IS NOT NULL AND TRIM(work_location) != ''"
                if user_profile.get('preferred_location'):
                    preferred_location_list = [l.strip() for l in user_profile['preferred_location'].split(",") if l.strip()]
                    base_query += " AND " + ("work_location = ANY(%s)" if case_sensitive else "LOWER(work_location) = ANY(%s)")
                    params.append(preferred_location_list if case_sensitive else [l.lower() for l in preferred_location_list])
            elif preference_type == "caste":
                base_query += " AND TRIM(caste) IS NOT NULL AND LOWER(TRIM(caste)) NOT IN ('null', 'none', 'nan', 'nil', 'not specified')"
                if user_profile.get('preferred_caste'):
                    preferred_castes = [
                        c.strip() for c in user_profile['preferred_caste'].split(",")
                        if c.strip().lower() not in ['null', 'none', 'nan', 'nil', 'not specified']
                    ]
                    base_query += " AND caste IS NOT NULL"
                    base_query += " AND " + ("caste = ANY(%s)" if case_sensitive else "LOWER(caste) = ANY(%s)")
                    params.append(preferred_castes if case_sensitive else [c.lower() for c in preferred_castes])

            cur.execute(base_query, params)
            profiles = cur.fetchall()
            return [format_profile(p) for p in profiles]

        except Exception as e:
            print(f"Error in fetch_matches for {preference_type}: {e}")
            return []

    try:
        cur.execute("SELECT * FROM matrimony_profiles WHERE is_active = TRUE")
        all_users = cur.fetchall()

        user_profiles = []
        preference_matches = []
        location_matches = []
        caste_matches = []

        for user in all_users:
            user_formatted = format_profile(user)
            user_profiles.append(user_formatted)

            preference_profiles = fetch_matches(user, "preference")
            preference_matches.append({
                "matrimony_id": user["matrimony_id"],
                "compatible_profiles": preference_profiles
            })

            location_profiles = fetch_matches(user, "location")
            location_matches.append({
                "matrimony_id": user["matrimony_id"],
                "compatible_profiles": location_profiles
            })

            caste_profiles = fetch_matches(user, "caste")
            caste_matches.append({
                "matrimony_id": user["matrimony_id"],
                "compatible_profiles": caste_profiles
            })

        return {
            "user_profiles": user_profiles,
            "preference": preference_matches,
            "location_preference": location_matches,
            "caste_preference": caste_matches
        }

    except Exception as e:
        print("Top-level error:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Failed to compile preference overview.")

    finally:
        cur.close()
        conn.close()

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

# Testing for the myprofiles endpoint
@app.get("/matrimony/my_profiles")
async def get_my_profiles(current_user: dict = Depends(get_current_user_matrimony)):
    email = current_user.get("email")
    matrimony_id = current_user.get("matrimony_id")

    if not email and not matrimony_id:
        raise HTTPException(status_code=400, detail="No valid identifier found in token")

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        query = """
        SELECT 
            mp.*, 
            COALESCE(SUM(sa.points), 0) AS points_spent
        FROM 
            matrimony_profiles mp
        LEFT JOIN 
            spend_actions sa 
        ON 
            mp.matrimony_id = sa.matrimony_id
        WHERE 
            (%(email)s IS NULL OR mp.email = %(email)s)
            AND (%(matrimony_id)s IS NULL OR mp.matrimony_id = %(matrimony_id)s)
                AND mp.is_active = TRUE
                AND mp.is_verified = TRUE
                AND mp.verification_status = 'approve'
        GROUP BY 
            mp.id
        LIMIT 1;
        """
        cur.execute(query, {"email": email, "matrimony_id": matrimony_id})
        profile = cur.fetchone()

        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")

        return {
            "status": "success",
            "profile": profile
        }

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

@app.put("/matrimony/my_profiles")
async def update_matrimony_profile(
    matrimony_id: Optional[str] = Form(None),
    full_name: Optional[str] = Form(None),
    age: Optional[str] = Form(None),
    gender: Optional[str] = Form(None),
    date_of_birth: Optional[str] = Form(None),
    email: Optional[EmailStr] = Form(None),
    password: Optional[str] = Form(None),
    phone_number: Optional[str] = Form(None),
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
    birth_time: Optional[str] = Form(None),
    birth_place: Optional[str] = Form(None),
    ascendent: Optional[str] = Form(None),
    # user_type: Optional[str] = Form(None),
    marital_status: Optional[str] = Form(None),
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
    blood_group: Optional[str] = Form(None),
    dhosham: Optional[str] = Form(None),
    other_dhosham: Optional[str] = Form(None),
    quarter: Optional[str] = Form(None),
    is_active: Optional[bool] = Form(None),
    is_verified: Optional[bool] = Form(None),
    verification_status: Optional[str] = Form(None),
    verification_comment: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user_matrimony)
):
    conn = psycopg2.connect(**settings.DB_CONFIG)
    cur = conn.cursor(cursor_factory=RealDictCursor)
    s3_handler = S3Handler()

    try:
        user_type = current_user.get("user_type", "").lower()

        if user_type == "admin":
            if not matrimony_id:
                raise HTTPException(
                    status_code=400,
                    detail="Admin must provide matrimony_id in form-data to update a profile"
                )
        elif user_type == "user":
            matrimony_id = current_user.get("matrimony_id")
            if not matrimony_id:
                raise HTTPException(status_code=403, detail="Unauthorized: No matrimony_id for user")
        else:
            raise HTTPException(status_code=403, detail="Unauthorized user type")


        update_fields = {
            k: v for k, v in {
                "matrimony_id": matrimony_id,
                "full_name": full_name,
                "age": age,
                "gender": gender,
                "date_of_birth": date_of_birth,
                "email": email,
                "password": pwd_context.hash(password) if password else None,
                "phone_number": phone_number,
                "height": height,
                "weight": weight,
                "occupation": occupation,
                "annual_income": annual_income,
                "education": education,
                "mother_tongue": mother_tongue,
                "profile_created_by": profile_created_by,
                "address": address,
                "work_type": work_type,
                "company": company,
                "work_location": work_location,
                "work_country": work_country,
                "mother_name": mother_name,
                "father_name": father_name,
                "sibling_count": sibling_count,
                "elder_brother": elder_brother,
                "elder_sister": elder_sister,
                "younger_sister": younger_sister,
                "younger_brother": younger_brother,
                "native": native,
                "mother_occupation": mother_occupation,
                "father_occupation": father_occupation,
                "religion": religion,
                "caste": caste,
                "sub_caste": sub_caste,
                "nakshatra": nakshatra,
                "rashi": rashi,
                "birth_time": birth_time,
                "birth_place": birth_place,
                "ascendent": ascendent,
                # "user_type": user_type,
                "marital_status": marital_status,
                "preferred_age_min": preferred_age_min,
                "preferred_age_max": preferred_age_max,
                "preferred_height_min": preferred_height_min,
                "preferred_height_max": preferred_height_max,
                "preferred_religion": preferred_religion,
                "preferred_caste": preferred_caste,
                "preferred_sub_caste": preferred_sub_caste,
                "preferred_nakshatra": preferred_nakshatra,
                "preferred_rashi": preferred_rashi,
                "preferred_location": preferred_location,
                "preferred_work_status": preferred_work_status,
                "blood_group": blood_group,
                "dhosham": dhosham,
                "other_dhosham": other_dhosham,
                "quarter": quarter,
                "is_active": is_active,
                "is_verified": is_verified,
                "verification_status": verification_status,
                "verification_comment": verification_comment
            }.items() if v is not None
        }

        if photo:
            photo_url = s3_handler.upload_to_s3(photo, "profile_photos")
            update_fields["photo_path"] = photo_url

        if photos:
            # Step 1: Get existing photo URLs from the DB
            cur.execute("SELECT photos FROM matrimony_profiles WHERE matrimony_id = %s", (matrimony_id,))
            existing_record = cur.fetchone()
            existing_photos_list = existing_record.get("photos", []) if existing_record else []

            # Step 2: Upload new photos
            new_photo_urls = [s3_handler.upload_to_s3(file, "photos") for file in photos]

            # Step 3: Merge and remove duplicates
            all_photos = list(dict.fromkeys(existing_photos_list + new_photo_urls))

            # Step 4: Update in Postgres array format (FastAPI will handle it correctly)
            update_fields["photos"] = "{" + ",".join(all_photos) + "}"



        if horoscope_documents:
            horoscope_urls = [s3_handler.upload_to_s3(file, "horoscopes") for file in horoscope_documents]
            update_fields["horoscope_documents"] = "{" + ",".join(horoscope_urls) + "}"

        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields provided for update")

        set_clause = ", ".join([f"{key} = %({key})s" for key in update_fields if key != "matrimony_id"])

        update_query = f"""
        UPDATE matrimony_profiles
        SET {set_clause}
        WHERE matrimony_id = %(matrimony_id)s
        RETURNING *;
        """

        cur.execute(update_query, update_fields)
        updated_profile = cur.fetchone()
        conn.commit()

        if not updated_profile:
            raise HTTPException(status_code=404, detail="Profile not found or not updated")

        return {
            "status": "success",
            "message": "Profile updated successfully",
            "profile": updated_profile
        }

    except psycopg2.Error as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error: {type(e).__name__}: {str(e)}")

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()


@app.delete("/matrimony/delete-my_profiles")
async def delete_profile_by_id(
    matrimony_id: str = Query(..., description="Matrimony ID of the profile to delete"),
    current_user: dict = Depends(get_current_user_matrimony)
):
    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        if matrimony_id != current_user.get("matrimony_id"):
            raise HTTPException(status_code=403, detail="You are not authorized to delete this profile")

        # Delete dependent refresh tokens first
        cur.execute(
            "DELETE FROM matrimony_refresh_tokens WHERE matrimony_id = %s;",
            (matrimony_id,)
        )

        # Now delete the profile
        cur.execute(
            "DELETE FROM matrimony_profiles WHERE matrimony_id = %s RETURNING *;",
            (matrimony_id,)
        )
        deleted_profile = cur.fetchone()

        if not deleted_profile:
            raise HTTPException(status_code=404, detail="Profile not found")

        conn.commit()
        return {"status": "success", "message": f"Profile with ID {matrimony_id} deleted"}

    except psycopg2.Error as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# active/ Inactive Status in the profiles 
@app.post("/matrimony/my_profiles/activate")
async def set_profile_active_status(
    is_active: bool = Body(..., embed=True, description="Set to true to activate, false to deactivate"),
    current_user: dict = Depends(get_current_user_matrimony)
):
    matrimony_id = current_user.get("matrimony_id")
    if not matrimony_id:
        raise HTTPException(status_code=400, detail="Matrimony ID missing")

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            UPDATE matrimony_profiles
            SET is_active = %s
            WHERE matrimony_id = %s
            RETURNING *;
        """, (is_active, matrimony_id))

        updated_profile = cur.fetchone()
        if not updated_profile:
            raise HTTPException(status_code=404, detail="Profile not found")

        conn.commit()
        return {
            "status": "success",
            "message": f"Profile {'activated' if is_active else 'deactivated'} successfully.",
            "profile": updated_profile
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

@app.get("/matrimony/my_profiles/activate")
async def get_profile_active_status(
    current_user: dict = Depends(get_current_user_matrimony)
):
    matrimony_id = current_user.get("matrimony_id")
    if not matrimony_id:
        raise HTTPException(status_code=400, detail="Matrimony ID missing")

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT matrimony_id, is_active
            FROM matrimony_profiles
            WHERE matrimony_id = %s;
        """, (matrimony_id,))
        result = cur.fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="Profile not found")

        return {
            "status": "success",
            "matrimony_id": result["matrimony_id"],
            "is_active": result["is_active"]
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# Admin can see the deleted profiles list
@app.delete("/matrimony/admin/delete-profiles")
async def delete_profiles_by_admin(
    matrimony_ids: List[str] = Body(..., embed=True, description="List of Matrimony IDs to delete"),
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admin can delete user profiles")

    deleted_profiles = []

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        for matrimony_id in matrimony_ids:
            # Step 1: Archive profile before deletion
            cur.execute("""
                INSERT INTO deleted_matrimony_profiles
                SELECT *, CURRENT_TIMESTAMP AS deleted_at
                FROM matrimony_profiles
                WHERE matrimony_id = %s;
            """, (matrimony_id,))

            # Step 2: Delete refresh tokens
            cur.execute(
                "DELETE FROM matrimony_refresh_tokens WHERE matrimony_id = %s;",
                (matrimony_id,)
            )

            # Step 3: Delete profile and store returned profile
            cur.execute(
                "DELETE FROM matrimony_profiles WHERE matrimony_id = %s RETURNING *;",
                (matrimony_id,)
            )
            deleted_profile = cur.fetchone()
            if deleted_profile:
                deleted_profiles.append(deleted_profile)

        conn.commit()

        if not deleted_profiles:
            raise HTTPException(status_code=404, detail="No matching profiles found to delete")

        return {
            "status": "success",
            "message": f"{len(deleted_profiles)} profile(s) archived and deleted by admin",
            "deleted_profiles": deleted_profiles
        }

    except psycopg2.Error as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

@app.get("/matrimony/admin/deleted-profiles-list")
async def get_deleted_profiles_by_admin(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view deleted profiles")
    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM deleted_matrimony_profiles ORDER BY deleted_at DESC;")
        deleted_profiles = cur.fetchall()

        return {
            "status": "success",
            "total_deleted": len(deleted_profiles),
            "deleted_profiles": deleted_profiles
        }

    except psycopg2.Error as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# Reporting the reasons for the user leaving the matrimony
@app.post("/matrimony/user/deactivate-report") 
async def report_deactivation(
    request: DeactivationReportRequest,
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "user":
        raise HTTPException(status_code=403, detail="Only users can access this endpoint")

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Get the authenticated user's matrimony_id from the token
        auth_matrimony_id = current_user.get("matrimony_id")
        
        # Verify the user is trying to deactivate their own profile
        if str(auth_matrimony_id) != str(request.matrimony_id):
            raise HTTPException(
                status_code=403,
                detail="You can only deactivate your own profile"
            )


        # Check if report already exists
        cur.execute("""
            SELECT id FROM deactivation_reports
            WHERE matrimony_id = %s
        """, (request.matrimony_id,))
        existing = cur.fetchone()

        if existing:
            raise HTTPException(
                status_code=200,
                detail="A deactivation report already exists for this user."
            )

        # Step 1: Deactivate user
        cur.execute("""
            UPDATE matrimony_profiles
            SET is_active = False
            WHERE matrimony_id = %s
            RETURNING *;
        """, (request.matrimony_id,))
        profile = cur.fetchone()

        if not profile:
            raise HTTPException(status_code=404, detail="Matrimony ID not found")

        # Step 2: Log reason
        cur.execute("""
            INSERT INTO deactivation_reports (matrimony_id, admin_email, reason)
            VALUES (%s, %s, %s)
            ON CONFLICT (matrimony_id)
            DO UPDATE SET reason = EXCLUDED.reason, admin_email = EXCLUDED.admin_email, created_at = CURRENT_TIMESTAMP
            RETURNING *;
        """, (
            request.matrimony_id,
            current_user.get("email"),
            request.reason
        ))

        conn.commit()

        return {
            "status": "success",
            "message": "Profile deactivated and reason logged.",
            "profile": profile
        }

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.get("/matrimony/admin/deactivate-report")
async def get_deactivation_reports(
    current_user: Dict = Depends(get_current_user_matrimony)
):
    # Strict admin check
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can access this endpoint")

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get all reports
        cur.execute("""
            SELECT 
                dr.*,
                mp.full_name
            FROM deactivation_reports dr
            LEFT JOIN matrimony_profiles mp ON dr.matrimony_id = mp.matrimony_id
            ORDER BY dr.created_at DESC
        """)
        reports = cur.fetchall()

        return {
            "status": "success",
            "count": len(reports),
            "reports": reports
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")
    
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# Points mechanism for recharge/ spend
@app.post("/wallet/recharge")
async def recharge_wallet(
    amount: float = Query(...),
    matrimony_id: Optional[str] = Query(None, description="Matrimony ID of the user to recharge"),
    current_user: dict = Depends(get_current_user_matrimony)
):
    if current_user["user_type"] not in ["user", "admin"]:
        raise HTTPException(status_code=403, detail="Only users and admins can access this endpoint")
    
    if current_user["user_type"] == "admin":
        if not matrimony_id:
            raise HTTPException(status_code=400, detail="Admin must specify matrimony_id to recharge")
    else:
        # 🚫 Prevent users from recharging other accounts
        if matrimony_id and matrimony_id != current_user.get("matrimony_id"):
            raise HTTPException(status_code=403, detail="Users are not allowed to recharge other accounts")
        matrimony_id = current_user.get("matrimony_id")
        
        if is_user_blocked(matrimony_id):
            raise HTTPException(status_code=403, detail="Access denied. You have been blocked by admin.")  
    if not matrimony_id:
        raise HTTPException(status_code=400, detail="Matrimony ID is required for recharge")
    
    rate_chart = {100: 500, 200: 1000, 500: 3000, 1000: 7000}
    if amount not in rate_chart:
        raise HTTPException(status_code=400, detail="Invalid recharge amount. Allowed: 100, 200, 500, 1000")

    points = rate_chart[amount]

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO wallets (matrimony_id, points_balance)
            VALUES (%s, %s)
            ON CONFLICT (matrimony_id) DO UPDATE
            SET points_balance = wallets.points_balance + %s, updated_at = now()
        """, (matrimony_id, points, points))

        cur.execute("""
            INSERT INTO point_transactions (matrimony_id, transaction_type, points, amount)
            VALUES (%s, 'recharge', %s, %s)
        """, (matrimony_id, points, amount))

        conn.commit()
        return {"status": "success", "points_added": points}

    except Exception as e:
        if 'conn' in locals(): conn.rollback()
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# Spending points from user wallet

@app.post("/wallet/spend")
async def spend_points_from_user_wallet(
    request: SpendRequest,
    current_user: dict = Depends(get_current_user_matrimony)
):
    results = []
    errors = []

    conn = psycopg2.connect(**settings.DB_CONFIG)
    cur = conn.cursor()

    try:
        user_matrimony_id = current_user["matrimony_id"]

        # Filter out already spent profiles
        valid_requests = []
        for req in request.spend_requests:
            cur.execute("""
                SELECT 1 FROM spend_actions 
                WHERE matrimony_id = %s AND target_matrimony_id = %s
            """, (user_matrimony_id, req.profile_matrimony_id))
            if cur.fetchone():
                errors.append({
                    "target_profile_id": req.profile_matrimony_id,
                    "error": "Points already spent on this profile."
                })
            else:
                valid_requests.append(req)

        total_points_needed = sum(req.points for req in valid_requests)

        # Check balance
        cur.execute("SELECT points_balance FROM wallets WHERE matrimony_id = %s", (user_matrimony_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Wallet not found")
        user_balance = row[0]

        if user_balance < total_points_needed:
            raise HTTPException(status_code=400, detail="Insufficient wallet balance")

        # Deduct points
        cur.execute("""
            UPDATE wallets
            SET points_balance = points_balance - %s, updated_at = now()
            WHERE matrimony_id = %s
        """, (total_points_needed, user_matrimony_id))

        # Record spending and update is_viewed
        for req in valid_requests:
            cur.execute("SELECT full_name FROM matrimony_profiles WHERE matrimony_id = %s", (req.profile_matrimony_id,))
            row = cur.fetchone()
            full_name = row[0] if row else "Unknown"

            # Insert spend action
            cur.execute("""
                INSERT INTO spend_actions (matrimony_id, target_matrimony_id, points)
                VALUES (%s, %s, %s)
            """, (user_matrimony_id, req.profile_matrimony_id, req.points))

            results.append({
                "target_profile_id": req.profile_matrimony_id,
                "target_profile_name": full_name,
                "points_spent": req.points
            })

        conn.commit()

        return {
            "status": "partial_success" if errors else "success",
            "message": "Points spent successfully on valid profiles",
            "results": results,
            "errors": errors
        }

    except Exception as e:
        if 'conn' in locals(): conn.rollback()
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# Fetching spend latest of the user
@app.get("/wallet/spend/latest")
async def get_latest_spends(current_user: dict = Depends(get_current_user_matrimony)):
    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()

        user_matrimony_id = current_user["matrimony_id"]

        # Fetch latest 10 spend actions
        cur.execute("""
            SELECT 
                sa.target_matrimony_id,
                mp.full_name,
                sa.points,
                sa.created_at
            FROM spend_actions sa
            LEFT JOIN matrimony_profiles mp 
            ON sa.target_matrimony_id = mp.matrimony_id
            WHERE sa.matrimony_id = %s
            ORDER BY sa.created_at DESC
            LIMIT 10
        """, (user_matrimony_id,))
        rows = cur.fetchall()

        results = [
            {
                "target_profile_id": row[0],
                "target_profile_name": row[1],
                "points_spent": row[2],
                "timestamp": row[3]
            }
            for row in rows
        ]

        # Count distinct target profiles spent on
        cur.execute("""
            SELECT COUNT(DISTINCT target_matrimony_id)
            FROM spend_actions
            WHERE matrimony_id = %s
        """, (user_matrimony_id,))
        count_row = cur.fetchone()
        distinct_profile_count = count_row[0] if count_row else 0

        return {
            "status": "success",
            "results": results,
            "distinct_profile_count": distinct_profile_count
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# Fetching spend history of the user
@app.get("/wallet/spend-history")
async def get_spend_history(current_user: dict = Depends(get_current_user_matrimony)):
    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()

        user_matrimony_id = current_user["matrimony_id"]

        # Fetch all spend transactions with target profile details
        cur.execute("""
            SELECT 
                mp.matrimony_id AS target_profile_id,
                mp.full_name AS target_profile_name,
                -pt.points AS points_spent,  -- Store as positive
                pt.created_at
            FROM point_transaction pt
            JOIN matrimony_profiles mp ON mp.matrimony_id != pt.matrimony_id
            WHERE pt.matrimony_id = %s AND pt.transaction_type = 'spend'
            ORDER BY pt.created_at DESC
        """, (user_matrimony_id,))
        rows = cur.fetchall()

        history = [
            {
                "target_profile_id": row[0],
                "target_profile_name": row[1],
                "points_spent": row[2],
                "timestamp": row[3]
            }
            for row in rows
        ]

        # Count distinct profiles spent on
        cur.execute("""
            SELECT COUNT(DISTINCT target_matrimony_id)
            FROM spend_actions
            WHERE matrimony_id = %s
        """, (user_matrimony_id,))
        count_row = cur.fetchone()
        distinct_profile_count = count_row[0] if count_row else 0

        return {
            "matrimony_id": user_matrimony_id,
            "distinct_profile_count": distinct_profile_count,
            "spend_history": history
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Failed to fetch spend history")
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()


@app.get("/wallet/balance")
async def get_wallet_balance(
    profile_matrimony_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user_matrimony)
):
    matrimony_id = profile_matrimony_id or current_user["matrimony_id"]

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()

        if profile_matrimony_id and profile_matrimony_id != current_user["matrimony_id"]:
            cur.execute("""
                SELECT 1 FROM profiles WHERE matrimony_id = %s AND owner_id = %s
            """, (profile_matrimony_id, current_user["matrimony_id"]))
            if not cur.fetchone():
                raise HTTPException(status_code=403, detail="Access denied for this profile")

        cur.execute("SELECT points_balance FROM wallets WHERE matrimony_id = %s", (matrimony_id,))
        row = cur.fetchone()

        return {
            "status": "success",
            "matrimony_id": matrimony_id,
            "points_balance": row[0] if row else 0
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if 'cur' in locals(): 
            cur.close()
        if 'conn' in locals(): 
            conn.close()
        

# Marking profiles as favorite or unfavorite
@app.post("/matrimony/favorite-profiles", response_model=Dict[str, Any])
async def mark_favorite_profiles(
    request: FavoriteProfilesRequest,
    current_user: dict = Depends(get_current_user_matrimony)
):
    if is_user_blocked(current_user.get("matrimony_id")):
        raise HTTPException(status_code=200, detail="Access denied. You have been blocked by admin.")

    matrimony_id = current_user["matrimony_id"]
    user_gender = current_user.get("gender")

    if not user_gender:
        raise HTTPException(status_code=400, detail="User gender not found")

    opposite_gender = "Female" if user_gender.lower() == "male" else "Male"

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        inserted = []
        removed = []

        # --- FAVORITE LOGIC ---
        for fav_id in request.favorite_profile_ids:
            cur.execute("SELECT gender FROM matrimony_profiles WHERE matrimony_id = %s", (fav_id,))
            result = cur.fetchone()

            if not result:
                raise HTTPException(status_code=404, detail=f"Profile {fav_id} not found")

            target_gender = result[0]
            if target_gender.lower() != opposite_gender.lower():
                raise HTTPException(
                    status_code=400,
                    detail=f"Cannot favorite profile {fav_id} with same gender: {target_gender}"
                )

            cur.execute("SELECT 1 FROM favorite_profiles WHERE matrimony_id = %s AND favorite_profile_id = %s", (matrimony_id, fav_id))
            if cur.fetchone():
                continue  
            cur.execute("""
                INSERT INTO favorite_profiles (matrimony_id, favorite_profile_id)
                VALUES (%s, %s) RETURNING favorite_profile_id
            """, (matrimony_id, fav_id))
            result = cur.fetchone()
            inserted.append(result[0])

        # --- UNFAVORITE LOGIC ---
        for unfav_id in request.unfavorite_profile_ids:
            cur.execute("""
                DELETE FROM favorite_profiles
                WHERE matrimony_id = %s AND favorite_profile_id = %s
                RETURNING favorite_profile_id
            """, (matrimony_id, unfav_id))
            result = cur.fetchone()
            if result:
                removed.append(result[0])

        conn.commit()

        return {
            "status": "success",
            "matrimony_id": matrimony_id,
            "favorited_profiles": inserted,
            "unfavorited_profiles": removed
        }

    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update favorites: {str(e)}")
    finally:
        cur.close()
        conn.close()

@app.get("/matrimony/get-favorite-profiles", response_model=Dict[str, Any])
async def get_favorite_profiles(
    current_user: dict = Depends(get_current_user_matrimony)
):
    if is_user_blocked(current_user.get("matrimony_id")):
        raise HTTPException(status_code=200, detail="Access denied. You have been blocked by admin.")

    matrimony_id = current_user["matrimony_id"]
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    def process_s3_url(url, folder_name):
        if url and isinstance(url, str):
            if url.startswith("http"):
                return url
            else:
                return f"https://{settings.AWS_S3_BUCKET_NAME}.s3.{settings.AWS_S3_REGION}.amazonaws.com/{folder_name}/{url}"
        return None

    def process_s3_urls(value, folder_name):
        if not value:
            return None
        if isinstance(value, str):
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

    try:
        base_query = """
            SELECT mp.*
            FROM favorite_profiles fp
            JOIN matrimony_profiles mp ON fp.favorite_profile_id = mp.matrimony_id
            WHERE fp.matrimony_id = %s
            AND is_active = TRUE

        """
        params = [matrimony_id]

        # Apply gender filter if user is not admin
        if current_user.get("user_type") != "admin":
            user_gender = current_user.get("gender")
            if not user_gender:
                raise HTTPException(status_code=400, detail="User gender not found")
            opposite_gender = "Female" if user_gender.lower() == "male" else "Male"
            base_query += " AND mp.gender ILIKE %s"
            params.append(opposite_gender)

        cur.execute(base_query, params)
        favorites = cur.fetchall()

        result_profiles = []

        for profile in favorites:
            profile_dict = dict(profile)

            for key, value in profile_dict.items():
                if isinstance(value, str) and not value.strip():
                    profile_dict[key] = None

            # Add processed photo URL
            profile_dict["photo"] = process_s3_url(profile_dict.get("photo_path"), "profile_photos")

            # Remove original photo_path field
            profile_dict.pop("photo_path", None)

            # Process other S3-based fields
            profile_dict["photos"] = process_s3_urls(profile_dict.get("photos"), "photos")
            profile_dict["horoscope_documents"] = process_s3_urls(profile_dict.get("horoscope_documents"), "horoscopes")

            result_profiles.append(profile_dict)

        return {
            "status": "success",
            "message": f"{current_user['matrimony_id']} is liked on your profile",
            "favorites": result_profiles
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving favorites: {str(e)}")

    finally:
        cur.close()

@app.post("/matrimony/verify-email")
async def verify_email(request: EmailVerificationRequest):
    try:
        # Connect to DB
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Query to check if email exists
        cur.execute("SELECT matrimony_id FROM matrimony_profiles WHERE email = %s", (request.email,))
        user = cur.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="Email not found")

        return {
            "message": "Email verified successfully",
            "matrimony_id": user["matrimony_id"]
        }

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

        conn.close()

@app.post("/matrimony/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    try:
        if request.new_password != request.confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")

        # Connect to DB
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()

        # Check if email exists
        cur.execute("SELECT matrimony_id FROM matrimony_profiles WHERE email = %s", (request.email,))
        user = cur.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="Email not found")

        # Hash and update the password
        hashed_password = pwd_context.hash(request.new_password)
        cur.execute(
            "UPDATE matrimony_profiles SET password = %s, updated_at = now() WHERE email = %s",
            (hashed_password, request.email)
        )
        conn.commit()

        return {"message": "Password has been reset successfully"}

    except psycopg2.Error as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error: {type(e).__name__}: {str(e)}")
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# ------------------- SEND MESSAGE (User → Admin) -------------------

@app.post("/matrimony/chat/user-to-admin")
async def user_to_admin_chat(
    request: ChatUserRequest,
    current_user: dict = Depends(get_current_user_matrimony)
):
    try:
        if current_user["user_type"] not in ["user", "admin"]:
            raise HTTPException(status_code=403, detail="Only users and admins can access this endpoint")

        sender_id = current_user["matrimony_id"]
        admin_email = request.receiver_email

        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()

        # Validate admin existence
        cur.execute("SELECT 1 FROM users WHERE email = %s AND user_type = 'admin'", (admin_email,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Admin not found with provided email")

        receiver_id = "admin"

        # Insert message
        cur.execute("""
            INSERT INTO matrimony_chats (sender_id, receiver_id, message) 
            VALUES (%s, %s, %s)
        """, (sender_id, receiver_id, request.message))
        conn.commit()

        return {
            "status": "success",
            "message": request.message,
            "sender_id": sender_id,
            "receiver_id": receiver_id
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

@app.post("/matrimony/chat/admin-to-user")
async def admin_to_user_chat(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user_matrimony)
):
    try:
        if current_user["user_type"] != "admin":
            raise HTTPException(status_code=403, detail="Only admin can access this endpoint")

        sender_id = "admin"
        user_id = request.receiver_id

        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()

        # Resolve user's matrimony_id
        cur.execute("SELECT matrimony_id FROM matrimony_profiles WHERE matrimony_id = %s AND user_type = 'user'", (request.receiver_id,))
        user_result = cur.fetchone()
        if not user_result:
            raise HTTPException(status_code=404, detail="User not found with provided email")

        receiver_id = user_result[0]


        # Insert message
        cur.execute("""
            INSERT INTO matrimony_chats (sender_id, receiver_id, message) 
            VALUES (%s, %s, %s)
        """, (sender_id, receiver_id, request.message))
        conn.commit()

        return {
            "status": "success",
            "message": request.message,
            "sender_id": sender_id,
            "receiver_id": receiver_id
        }

    except HTTPException as http_exc:
        raise http_exc  

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

@app.get("/matrimony/chat/admin/all-messages")
async def get_all_user_chats(current_user: dict = Depends(get_current_user_matrimony)):
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can access this endpoint")

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT * FROM matrimony_chats
            WHERE sender_id != 'admin' OR receiver_id != 'admin'
            ORDER BY timestamp ASC
        """)
        chats = cur.fetchall()

        return {"status": "success", "messages": chats}

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

@app.get("/matrimony/chat/admin/messages", response_model=List[AdminChatMessage])
async def get_chat_messages(
    matrimony_id: Optional[str] = Query(None),
    user_email: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user_matrimony)
):
    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Case 1: User - use their own matrimony_id
        if current_user["user_type"] == "user":
            matrimony_id = current_user["matrimony_id"]

        # Case 2: Admin - look up matrimony_id by user_email if provided
        elif current_user["user_type"] == "admin":
            if not matrimony_id:
                if not user_email:
                    raise HTTPException(status_code=400, detail="Provide either matrimony_id or user_email")

                cur.execute("SELECT matrimony_id FROM matrimony_profiles WHERE email = %s", (user_email,))
                user = cur.fetchone()
                if not user:
                    raise HTTPException(status_code=404, detail="User not found")
                matrimony_id = user["matrimony_id"]

        else:
            raise HTTPException(status_code=403, detail="Unauthorized access")

        # Fetch all messages between the user and admin
        cur.execute("""
            SELECT * FROM matrimony_chats
            WHERE (sender_id = %s AND receiver_id = 'admin')
               OR (sender_id = 'admin' AND receiver_id = %s)
            ORDER BY timestamp ASC
        """, (matrimony_id, matrimony_id))

        messages = cur.fetchall()
        return messages

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# Blocking Users Mechanism from Admin --> reporters are User , Admin can see the reported-profiles and Blocking 
@app.post("/matrimony/user/report")
async def report_user(report: ReportSchema, current_user: dict = Depends(get_current_user_matrimony)):

    conn = psycopg2.connect(**settings.DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO user_reports (reporter_matrimony_id, reported_matrimony_id, reason)
        VALUES (%s, %s, %s)
    """, (current_user["matrimony_id"], report.reported_matrimony_id, report.reason))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "User reported successfully"}


@app.get("/matrimony/admin/reported-profiles")
async def get_reported_profiles(current_user: dict = Depends(get_current_user_matrimony)):
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can access this endpoint")

    conn = psycopg2.connect(**settings.DB_CONFIG)
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # Step 1: Get admin's matrimony_id from users table
        cur.execute("SELECT email FROM users WHERE email = %s", (current_user["email"],))
        admin_result = cur.fetchone()
        if not admin_result:
            raise HTTPException(status_code=404, detail="Admin not found")
        admin_matrimony_id = admin_result["email"]

        # Step 2: Fetch all reported profiles and their details
        cur.execute("""
            SELECT 
                ur.reported_matrimony_id,
                COUNT(*) AS total_reports,
                ARRAY_AGG(ur.reason) AS reasons,
                ARRAY_AGG(ur.reporter_matrimony_id) AS reporters
            FROM user_reports ur
            GROUP BY ur.reported_matrimony_id
            ORDER BY total_reports DESC
        """)
        reported_profiles = cur.fetchall()

        # Step 3: Fetch all blocked matrimony_ids by this admin
        cur.execute("""
            SELECT blocked_matrimony_id 
            FROM blocked_users 
            WHERE admin_matrimony_id = %s
        """, (admin_matrimony_id,))
        blocked = cur.fetchall()
        blocked_ids = {row['blocked_matrimony_id'] for row in blocked}

        # Step 4: Annotate each report with is_blocked status
        for profile in reported_profiles:
            profile["is_blocked"] = profile["reported_matrimony_id"] in blocked_ids

        return reported_profiles

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get reported profiles: {str(e)}")

    finally:
        cur.close()
        conn.close()


@app.post("/matrimony/admin/block-user")
async def block_user(
    request: BlockUserSchema,
    current_user: dict = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admin can block users")

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()

        # Fetch admin's matrimony_id
        cur.execute("SELECT email FROM users WHERE email = %s", (current_user["email"],))
        result = cur.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Admin not found")
        admin_matrimony_id = result[0]

        # Check if the user is already blocked by this admin
        cur.execute("""
            SELECT 1 FROM blocked_users 
            WHERE blocked_matrimony_id = %s AND admin_matrimony_id = %s
        """, (request.matrimony_id, admin_matrimony_id))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="User is already blocked by this admin")

        # Insert block record
        cur.execute("""
            INSERT INTO blocked_users (blocked_matrimony_id, admin_matrimony_id, reason, is_blocked)
            VALUES (%s, %s, %s, %s)
        """, (request.matrimony_id, admin_matrimony_id, request.reason, True))
        conn.commit()

        return {
            "message": "User blocked successfully",
            "blocked_matrimony_id": request.matrimony_id,
            "admin_matrimony_id": admin_matrimony_id
        }

    finally:
        cur.close()
        conn.close()

@app.get("/matrimony/admin/blocked-users")
async def get_blocked_users(current_user: dict = Depends(get_current_user_matrimony)):
    if current_user["user_type"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can access this endpoint")

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT blocked_matrimony_id, admin_matrimony_id, reason, blocked_at
            FROM blocked_users
            ORDER BY blocked_at DESC
        """)
        blocked_users = cur.fetchall()

        return {"blocked_users": blocked_users}

    finally:
        cur.close()
        conn.close()

# Unblock-User 
@app.post("/matrimony/admin/unblock-user")
async def unblock_user(
    request: UnblockUserSchema,
    current_user: Dict = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admin can unblock users")

    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        cur = conn.cursor()

        # Get admin email (you could fetch matrimony_id too if needed)
        cur.execute("SELECT email FROM users WHERE email = %s", (current_user["email"],))
        result = cur.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Admin not found")
        admin_matrimony_id = result[0]

        # Delete all matching block records
        cur.execute("""
            DELETE FROM blocked_users 
            WHERE blocked_matrimony_id = ANY(%s) AND admin_matrimony_id = %s
        """, (request.matrimony_id, admin_matrimony_id))

        conn.commit()

        return {
            "message": "User(s) unblocked successfully",
            "unblocked_matrimony_ids": request.matrimony_id,
            "admin_matrimony_id": admin_matrimony_id
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to unblock user(s): {str(e)}")

    finally:
        cur.close()
        conn.close()

# Contact-us for User 

@app.post("/matrimony/contact-us", response_model=ContactUsResponse)
def submit_contact_form(
    data: ContactUsCreate,
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "user":
        raise HTTPException(status_code=403, detail="Only users can submit contact messages.")

    conn = None
    cur = None

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)

        # 👇 insert matrimony_id too
        cur.execute("""
            INSERT INTO contact_us (matrimony_id, full_name, email, message)
            VALUES (%s, %s, %s, %s)
            RETURNING matrimony_id, full_name, email, message, created_at
        """, (
            current_user["matrimony_id"],  # 👈 from user session
            data.full_name,
            data.email,
            data.message
        ))

        row = cur.fetchone()
        conn.commit()

        return dict(row)

    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


# Contact-us for admin
@app.get("/matrimony/admin/contact-us", response_model=List[ContactUsResponse])
def get_all_contacts(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admin can access contact messages.")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)

        cur.execute("""
            SELECT matrimony_id, full_name, email, message, created_at
            FROM contact_us
            ORDER BY created_at DESC
        """)
        rows = cur.fetchall()
        return [dict(row) for row in rows]  

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# Dashboard Creation

@app.get("/matrimony/admin/dashboards/overview")
def get_dashboard_overview(
    current_user: Dict[str, Any] = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admin can access this dashboard.")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)

        # Gender counts
        cur.execute("""
            SELECT LOWER(gender) AS gender, COUNT(*) 
            FROM matrimony_profiles 
            GROUP BY LOWER(gender)
        """)
        gender_data = cur.fetchall()
        gender_counts = {row['gender']: row['count'] for row in gender_data}

        # Active vs Inactive (Last 30 Days)
        cur.execute("""
            SELECT 
                DATE(updated_at) AS updated_date,
                is_active,
                COUNT(*) AS total
            FROM matrimony_profiles
            WHERE updated_at >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY DATE(updated_at), is_active
            ORDER BY updated_date;
        """)
        active_data = cur.fetchall()

        graph_data = defaultdict(lambda: {"date": None, "active": 0, "inactive": 0})
        for row in active_data:
            date_str = row["updated_date"].strftime('%Y-%m-%d')
            graph_data[date_str]["date"] = date_str
            if row["is_active"]:
                graph_data[date_str]["active"] = row["total"]
            else:
                graph_data[date_str]["inactive"] = row["total"]
        active_graph_points = list(sorted(graph_data.values(), key=lambda x: x["date"]))
        active_counts = {
            "active": sum(row["active"] for row in active_graph_points),
            "inactive": sum(row["inactive"] for row in active_graph_points),
        }

        # Blocked vs Unblocked
        cur.execute("SELECT COUNT(*) AS count FROM matrimony_profiles")
        total_users = cur.fetchone()["count"]

        cur.execute("SELECT COUNT(DISTINCT blocked_matrimony_id) AS count FROM blocked_users")
        blocked_count = cur.fetchone()["count"]
        blocked_counts = {
            "blocked": blocked_count,
            "unblocked": total_users - blocked_count
        }

        # 🔥 Top 5 Spenders
        cur.execute("""
            SELECT 
                pt.matrimony_id, 
                mp.full_name, 
                mp.photo_path,
                SUM(pt.amount) AS total_amount
            FROM point_transactions pt
            JOIN matrimony_profiles mp ON mp.matrimony_id = pt.matrimony_id
            WHERE pt.transaction_type = 'recharge'
            GROUP BY pt.matrimony_id, mp.full_name, mp.photo_path
            ORDER BY total_amount DESC
            LIMIT 5
        """)
        top_spenders = [
            {
                "matrimony_id": row["matrimony_id"],
                "full_name": row["full_name"],
                "photo": row["photo_path"],
                "total_amount": float(row["total_amount"])
            }
            for row in cur.fetchall()
        ]
        top_spenders_amount = sum(spender["total_amount"] for spender in top_spenders)

        # 💎 Top 5 Profiles by Points Consumed (Spent On)
        cur.execute("""
            SELECT 
                sa.target_matrimony_id AS matrimony_id,
                mp.full_name,
                mp.photo_path,
                SUM(sa.points) AS total_points_spent
            FROM spend_actions sa
            JOIN matrimony_profiles mp ON mp.matrimony_id = sa.target_matrimony_id
            GROUP BY sa.target_matrimony_id, mp.full_name, mp.photo_path
            ORDER BY total_points_spent DESC
            LIMIT 5
        """)
        top_profiles_by_points = [
            {
                "matrimony_id": row["matrimony_id"],
                "full_name": row["full_name"],
                "photo": row["photo_path"],
                "points_spent": int(row["total_points_spent"])
            }
            for row in cur.fetchall()
        ]

        return {
            "gender_counts": gender_counts,
            "active_status_counts": active_counts,
            "active_status_trend": active_graph_points,
            "blocked_status_counts": blocked_counts,
            "top_spenders": top_spenders,
            "top_spenders_count": len(top_spenders),
            "top_spenders_amount": top_spenders_amount,
            "top_profiles_by_points": top_profiles_by_points,
            "top_profiles_by_points_count": len(top_profiles_by_points),

            "message": "Dashboard overview fetched successfully"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()
    
# ------------------- Profile Verification/Approved/Pending -------------------   
@app.post("/admin/profile/verify")
async def verify_profile(
    matrimony_id: str = Form(...),
    verification_status: str = Form(...),  # values: "approve", "pending"
    verification_comment: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")

    if verification_status not in ["approve", "pending"]:
        raise HTTPException(status_code=400, detail="Invalid verification_status")

    conn = psycopg2.connect(**settings.DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        UPDATE matrimony_profiles
        SET is_verified = %s,
            verification_status = %s,
            verification_comment = %s
        WHERE matrimony_id = %s
    """, (
        True if verification_status == "approve" else False,
        verification_status,
        verification_comment,
        matrimony_id
    ))
    conn.commit()
    cur.close()
    conn.close()

    return {"message": f"Profile {'approved' if verification_status == 'approve' else 'pendinged'} successfully"}

# ------------------- Get Unverified Profiles ------------------- 
@app.get("/admin/profiles/unverified", response_model=AdminProfileVerificationSummary)
async def get_unverified_profiles(current_user: Dict = Depends(get_current_user_matrimony)):
    conn = psycopg2.connect(**settings.DB_CONFIG)
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        if current_user["user_type"] == "admin":
            # ✅ Admin: Fetch profiles with approve or pending status (case-insensitive)
            cur.execute("""
                SELECT * FROM matrimony_profiles
                WHERE LOWER(verification_status) IN ('approve', 'pending')
            """)
            profiles = cur.fetchall()

            # ✅ Count profiles by status
            cur.execute("""
                SELECT LOWER(verification_status) as verification_status, COUNT(*) as count
                FROM matrimony_profiles
                WHERE LOWER(verification_status) IN ('approve', 'pending')
                GROUP BY LOWER(verification_status)
            """)
            status_counts = cur.fetchall()

            # Extract counts
            pending_count = 0
            approved_count = 0
            for row in status_counts:
                if row["verification_status"] == "pending":
                    pending_count = row["count"]
                elif row["verification_status"] == "approve":
                    approved_count = row["count"]

            return {
                "message": "Fetched verification data successfully",
                "pending_count": pending_count,
                "approved_count": approved_count,
                "profiles": profiles
            }

        else:
            # ✅ User: Show only their own approved profile
            cur.execute("""
                SELECT * FROM matrimony_profiles
                WHERE matrimony_id = %s AND verification_status = 'approve'
            """, [current_user["matrimony_id"]])
            profile = cur.fetchone()
            profiles = [profile] if profile else []
            approved_count = 1 if profile else 0

            return {
                "message": "Fetched your approved profile successfully",
                "pending_count": 0,
                "approved_count": approved_count,
                "profiles": profiles
            }

    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Error fetching verification profiles")

    finally:
        cur.close()
        conn.close()


# ------------------- PUT Update Profile Verification Status -------------------

@app.put("/admin/profiles/verify")
async def verify_profile(
    matrimony_id: str = Form(...),
    verification_status: Literal["approve", "pending"] = Form(...),
    verification_comment: Optional[str] = Form(None),
    current_user: Dict = Depends(get_current_user_matrimony)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")

    # Normalize status to lowercase
    verification_status = verification_status.lower()

    conn = psycopg2.connect(**settings.DB_CONFIG)
    cur = conn.cursor()

    try:
        cur.execute("""
            UPDATE matrimony_profiles
            SET is_verified = %s,
                verification_status = %s,
                verification_comment = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE matrimony_id = %s
        """, (
            True if verification_status == "approve" else False,
            verification_status,
            verification_comment,
            matrimony_id
        ))

        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Matrimony ID not found")

        conn.commit()

        return {
            "message": f"Profile {'approved' if verification_status == 'approve' else 'marked as pending'} successfully",
            "matrimony_id": matrimony_id,
            "new_status": verification_status
        }

    except Exception as e:
        print(f"Error verifying profile: {e}")
        raise HTTPException(status_code=500, detail="Failed to update verification status")

    finally:
        cur.close()
        conn.close()

# marked -viewProfiles
@app.post("/matrimony/mark-viewed")
def mark_profile_viewed(
    payload: MarkViewedRequest,
    current_user=Depends(get_current_user_matrimony)
):
    viewer_id = current_user["matrimony_id"]
    profile_ids = payload.profile_matrimony_ids

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    try:
        for viewed_id in profile_ids:
            cur.execute("""
                INSERT INTO viewed_profiles (matrimony_id, viewed_matrimony_id)
                VALUES (%s, %s)
                ON CONFLICT (matrimony_id, viewed_matrimony_id) DO NOTHING
            """, (viewer_id, viewed_id))

        conn.commit()
        return {
            "success": True,
            "message": f"Marked {len(profile_ids)} profiles as viewed",
            "viewed_profiles": profile_ids
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        cur.close()
        conn.close()


# ------------------- Get Viewed Profiles -------------------
@app.get("/matrimony/viewed-profiles", response_model=ViewedProfilesResponse)
def get_viewed_profiles(current_user=Depends(get_current_user_matrimony)):
    viewer_id = current_user["matrimony_id"]

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)

    try:
        cur.execute("""
            SELECT viewed_matrimony_id
            FROM viewed_profiles
            WHERE matrimony_id = %s
        """, (viewer_id,))

        rows = cur.fetchall()

        # Extract valid profile IDs only
        viewed_ids = []
        for row in rows:
            value = row["viewed_matrimony_id"]
            if isinstance(value, str) and value.startswith("{"):
                # Handle case where value is a string representation of a list
                continue
            viewed_ids.append(value)

        return ViewedProfilesResponse(
            success=True,
            viewer_id=viewer_id,
            viewed_profiles=viewed_ids
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve viewed profiles: {str(e)}")

    finally:
        cur.close()
        conn.close()


# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000   
    )
