import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from core.config import settings
from db.session import get_db_connection
from core.firebase import initialize_firebase
from api.photostudio import router as photostudio_router
from api.matrimony import router as matrimony_router
from db.init_db import init_db

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize Database Tables FIRST
    try:
        logger.info("Initializing database...")
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.critical(f"CRITICAL: Failed to initialize database: {str(e)}")
        # If DB fails, we can't really do much, but we try to continue
    
    # 2. Ensure all necessary directories exist
    try:
        logger.info("Setting up local directories...")
        settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        settings.PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
        settings.HOROSCOPES_DIR.mkdir(parents=True, exist_ok=True)
        (settings.UPLOAD_DIR / "admin_files").mkdir(parents=True, exist_ok=True)
        (settings.UPLOAD_DIR / "user_photos").mkdir(parents=True, exist_ok=True)
        (settings.UPLOAD_DIR / "frame_colors").mkdir(parents=True, exist_ok=True)
        (settings.UPLOAD_DIR / "profile_photos").mkdir(parents=True, exist_ok=True)
        logger.info("Local directories verified.")
    except Exception as e:
        logger.error(f"Error creating directories: {str(e)}")

    # 3. Initialize Firebase
    try:
        logger.info("Initializing Firebase...")
        initialize_firebase()
        logger.info("Firebase initialized.")
    except Exception as e:
        logger.error(f"Firebase initialization failed: {str(e)}")
    
    # 4. Startup Database cleanup
    conn = None
    cur = None
    try:
        logger.info("Performing startup cleanup...")
        conn = get_db_connection()
        cur = conn.cursor()
        # Delete expired refresh tokens (Photostudio)
        cur.execute("DELETE FROM refresh_tokens WHERE expires_at <= NOW()")
        # Delete expired refresh tokens (Matrimony)
        cur.execute("DELETE FROM matrimony_refresh_tokens WHERE expires_at <= NOW()")
        conn.commit()
        logger.info("Expired refresh tokens cleaned up.")
    except Exception as e:
        if conn: conn.rollback()
        logger.error(f"Error cleaning up expired refresh tokens: {str(e)}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
    
    yield
    # Shutdown
    logger.info("Application shutting down...")

app = FastAPI(
    lifespan=lifespan, 
    title=settings.PROJECT_NAME, 
    version=settings.VERSION, 
    debug=True
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static file routes
app.mount("/static", StaticFiles(directory=settings.UPLOAD_DIR), name="static")
app.mount("/static/photos", StaticFiles(directory=settings.PHOTOS_DIR), name="static_photos")
app.mount("/static/horoscopes", StaticFiles(directory=settings.HOROSCOPES_DIR), name="static_horoscopes")

# Include modularized routers
app.include_router(photostudio_router)
app.include_router(matrimony_router)

@app.get("/")
async def root():
    return {
        "message": f"Welcome to the {settings.PROJECT_NAME}",
        "version": settings.VERSION,
        "status": "online"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)