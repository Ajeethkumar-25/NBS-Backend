#Updated photosudio - Admin (register, login, post, get, put -upload), User(login, get -upload) 
import os
import  sys 
import logging
import uvicorn


import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError
from jose import jwt, JWTError, ExpiredSignatureError
from jose import JWTError

import psycopg2
from psycopg2.extras import DictCursor, RealDictCursor
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Query, Form, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional, Dict, Any, Union

from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, time, timedelta
from app import (
    UserCreate, 
    UserLogin, 
    Token,
    RefreshToken,
    get_current_user, 
    get_db_connection, 
    settings, 
    create_access_token, 
    create_refresh_token,
    S3Handler
        
    )

from dotenv import load_dotenv

load_dotenv()


app = FastAPI(title="Updated Photo Studio Endpoints")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# API Routes
# Register
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
                "is_active": is_active
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

# Photo_File_upload - post (Photo, video, pdf, File_size upto 100 MB)
@app.post("/photostudio/admin/private/fileupload", response_model=Dict[str, Any])
async def admin_upload_files(
    files: List[UploadFile] = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can access this endpoint")
    
    uploaded_files = []
    s3_handler = S3Handler()
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        print(f"Received {len(files)} files")

        for file in files:
            print(f"Processing file: {file.filename}")
            
            try:
                file_url = s3_handler.upload_to_s3(file, "admin_files")
                if not file_url:
                    print(f"Skipping {file.filename} - S3 upload failed")
                    continue
            except Exception as e:
                print(f"S3 Upload Error: {e}")
                continue

            file_type = file.content_type
            try:
                # Check if file already exists
                cur.execute(
                    """
                    SELECT private_files_id FROM private_files
                    WHERE filename = %s AND uploaded_by = %s
                    """,
                    (file.filename, current_user["id"])
                )
                existing = cur.fetchone()

                if existing:
                    cur.execute(
                        """
                        UPDATE private_files
                        SET file_type = %s,
                            file_url = array_append(file_url, %s),
                            uploaded_at = NOW()
                        WHERE private_files_id = %s
                        RETURNING private_files_id;
                        """,
                        (file_type, file_url, existing[0])
                    )
                    file_id = existing  # ✅ Already have ID
                else:
                    cur.execute(
                        """
                        INSERT INTO private_files (filename, file_type, file_url, uploaded_by, uploaded_at)
                        VALUES (%s, %s, ARRAY[%s], %s, NOW())
                        RETURNING private_files_id;
                        """,
                        (file.filename, file_type, file_url, current_user["id"])
                    )
                    file_id = cur.fetchone()


                if not file_id:
                    print(f"Skipping {file.filename} - Database insert failed")
                    continue

                uploaded_files.append({
                    "id": file_id[0],
                    "File Details": {
                        "filename": file.filename,
                        "file_type": file_type,
                        "uploaded_by": current_user["id"],
                        "file_url": file_url
                    }
                })

            except psycopg2.Error as e:
                conn.rollback()
                print(f"Database Error for {file.filename}: {str(e)}")
                continue

        conn.commit()

        if not uploaded_files:
            raise HTTPException(status_code=500, detail="No files were uploaded successfully")

        return {
            "message": "Files uploaded successfully by admin",
            "file_urls": [file["File Details"]["file_url"] for file in uploaded_files],
            "uploaded_files": uploaded_files
        }

    except Exception as e:
        conn.rollback()
        print(f"Unexpected Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    finally:
        cur.close()
        conn.close()

# Get Endpoint for file Upload
@app.get("/photostudio/admin/private/get_files", response_model=List[Dict[str, Any]])
def get_uploaded_files(
    file_id: Optional[int] = None,
    filename: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        query = """
            SELECT private_files_id, filename, file_type, file_url, uploaded_by, uploaded_at
            FROM private_files
            WHERE uploaded_by = %s
        """
        params = [current_user["id"]]

        if file_id:
            query += " AND private_files_id = %s"
            params.append(file_id)

        if filename:
            query += " AND filename = %s"
            params.append(filename)

        cur.execute(query, tuple(params))
        rows = cur.fetchall()

        if not rows:
            return []

        return [
            {
                "id": row[0],
                "filename": row[1],
                "file_type": row[2],
                "file_urls": row[3],
                "uploaded_by": row[4],
                "uploaded_at": row[5].isoformat()
            }
            for row in rows
        ]

    finally:
        cur.close()
        conn.close()

# Put for File_Upload
@app.put("/photostudio/admin/private/fileupdate/{file_id}", response_model=Dict[str, Any])
async def update_uploaded_file(
    file_id: int,
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()
    s3_handler = S3Handler()

    try:
        # Check ownership
        cur.execute(
            "SELECT uploaded_by FROM private_files WHERE private_files_id = %s",
            (file_id,)
        )
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="File record not found")
        if row[0] != current_user["id"]:
            raise HTTPException(status_code=403, detail="You cannot update files uploaded by others")

        # Upload new file to S3
        new_file_url = s3_handler.upload_to_s3(file, "admin_files")
        file_type = file.content_type

        # Replace last URL in array
        cur.execute(
            """
            UPDATE private_files
            SET file_type = %s,
                file_url = array_append(file_url, %s),
                uploaded_at = NOW()
            WHERE private_files_id = %s
            RETURNING filename, file_type, file_url;
            """,
            (file_type, new_file_url, file_id)
        )

        updated = cur.fetchone()
        conn.commit()

        return {
            "message": "File updated successfully",
            "updated_file": {
                "id": file_id,
                "filename": updated[0],
                "file_type": updated[1],
                "file_urls": updated[2]
            }
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")

    finally:
        cur.close()
        conn.close()

# Delete for File_Upload
@app.delete("/photostudio/admin/private/filedelete/{file_id}", response_model=Dict[str, Any])
async def delete_uploaded_file(
    file_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    if current_user.get("user_type") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can access this endpoint")

    conn = get_db_connection()
    cur = conn.cursor()
    s3_handler = S3Handler()

    try:
        # Check ownership and get file URLs
        cur.execute(
            "SELECT uploaded_by, file_url FROM private_files WHERE private_files_id = %s",
            (file_id,)
        )
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="File record not found")
        if row[0] != current_user["id"]:
            raise HTTPException(status_code=403, detail="You cannot delete files uploaded by others")

        file_urls = row[1]

        # Optionally delete files from S3
        for url in file_urls:
            s3_handler.delete_from_s3(url)  # You need to implement this method in S3Handler

        # Delete file record from DB
        cur.execute(
            "DELETE FROM private_files WHERE private_files_id = %s",
            (file_id,)
        )
        conn.commit()

        return {
            "message": "File deleted successfully",
            "file_id": file_id
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Deletion failed: {str(e)}")

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


if __name__ == "__main__":
    uvicorn.run("photostudio:app", host="0.0.0.0", port=8000, reload=True)
