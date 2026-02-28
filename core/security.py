import os
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from core.config import settings
from db.session import get_db_connection
from psycopg2.extras import DictCursor

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def generate_otp(length=6):
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

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

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
        user_type = payload.get("user_type")
        
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        if user_type == "admin":
            cur.execute("SELECT id, email, user_type FROM users WHERE email = %s", (email,))
        else:
            cur.execute(
                "SELECT id, email, user_type FROM users WHERE email = %s UNION SELECT id, email, user_type FROM matrimony_profiles WHERE email = %s",
                (email, email)
            )
        
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return {"id": user[0], "email": user[1], "user_type": user[2]}
    except JWTError:
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
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()
