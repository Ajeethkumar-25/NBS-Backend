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
import logging
import urllib.parse
from app import (
    get_current_user, 
    create_access_token,
    create_refresh_token    
    )


# Twilio credentials (hardcoded)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
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
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
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

# # Set Firebase credentials path based on OS
# if platform.system() == "Windows":
#     firebase_cred_path = r"C:\Users\Premalatha\Desktop\NBS-Backend\myapp\cred\firebase.json"
# else:
#     firebase_cred_path = "/home/ubuntu/myapp/cred/firebase.json"

# # Initialize Firebase
# cred = credentials.Certificate(firebase_cred_path)
# firebase_admin.initialize_app(cred)


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
# Generate 16-digit password login link
@app.post("/photostudio/private/admin/generate-login-link", response_model=Dict[str, Any])
async def generate_login_link(email: str):
    logger.info(f"Generating login link for: {email}")
    
    if not email or not isinstance(email, str):
        logger.warning(f"Invalid email parameter received: {email}")
        return JSONResponse(
            status_code=400,
            content={"status": "error", "detail": "Invalid email format"}
        )
    
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        if not conn:
            logger.error("Failed to establish database connection")
            return JSONResponse(
                status_code=500,
                content={"status": "error", "detail": "Database connection error"}
            )
            
        cur = conn.cursor()
        
        # Check if user exists
        cur.execute("SELECT id, user_type FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        
        logger.debug(f"Database query result for email '{email}': {user}")

        if not user:
            logger.warning(f"User not found for email: {email}")
            return JSONResponse(
                status_code=404,
                content={"status": "error", "detail": "User not found"}
            )

        user_id, user_type = user

        # Generate a secure 16-digit numeric token
        secure_password = ''.join(random.choices('0123456789', k=16))
        hashed_password = pwd_context.hash(secure_password)
        expiry_time = datetime.utcnow() + timedelta(hours=24)

        # Insert or update the login link
        cur.execute("SELECT id FROM login_links WHERE user_id = %s", (user_id,))
        existing_link = cur.fetchone()

        if existing_link:
            cur.execute("""
                UPDATE login_links 
                SET token_hash = %s, expires_at = %s, updated_at = NOW() 
                WHERE user_id = %s
            """, (hashed_password, expiry_time, user_id))
            logger.debug(f"Updated existing login link for user ID {user_id}")
        else:
            cur.execute("""
                INSERT INTO login_links (user_id, token_hash, expires_at) 
                VALUES (%s, %s, %s)
            """, (user_id, hashed_password, expiry_time))
            logger.debug(f"Created new login link for user ID {user_id}")

        conn.commit()

        base_url = os.getenv("BASE_URL", "http://localhost:3000")
        login_link = f"{base_url}/photostudio/login-with-token?email={urllib.parse.quote(email)}&token={secure_password}"

        logger.info(f"Login link generated for {email}, expires at {expiry_time}")

        return {
            "status": "success",
            "login_link": login_link,
            "expires_at": expiry_time,
            "user_type": user_type
        }

    except psycopg2.Error as db_error:
        if conn:
            conn.rollback()
        logger.error(f"Database error generating login link: {str(db_error)}")
        return JSONResponse(
            status_code=500, 
            content={"status": "error", "detail": "Database error occurred"}
        )
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error generating login link: {str(e)}\n{traceback.format_exc()}")
        return JSONResponse(
            status_code=500, 
            content={"status": "error", "detail": "Internal server error"}
        )
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
        
# Login with token endpoint (public)
@app.post("/photostudio/public/login-with-token", response_model=Dict[str, Any])
async def login_with_token(email: str, token: str):
    logger.info(f"Login attempt with token for email: {email}")
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Get user ID from email
        cur.execute(
            "SELECT id, email, user_type FROM users WHERE email = %s",
            (email,)
        )
        user = cur.fetchone()
        
        if not user:
            logger.warning(f"Invalid login: User not found for email {email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user_id, user_email, user_type = user
        
        # Verify token exists and is valid
        cur.execute(
            """
            SELECT token_hash FROM login_links 
            WHERE user_id = %s AND expires_at > %s
            """,
            (user_id, datetime.utcnow())
        )
        
        token_record = cur.fetchone()
        
        if not token_record or not pwd_context.verify(token, token_record[0]):
            logger.warning(f"Invalid login: Token verification failed for {email}")
            raise HTTPException(status_code=401, detail="Invalid or expired login link")
        
        # Generate auth tokens
        access_token = create_access_token(
            {"sub": user_email, "user_type": user_type},
            timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        refresh_token = create_refresh_token(
            {"sub": user_email, "user_type": user_type},
            timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
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
        logger.info(f"Successful login with token for {email}")
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "data": {
                "email": user_email,
                "user_type": user_type
            }
        }
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error logging in with token: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    finally:
        cur.close()
