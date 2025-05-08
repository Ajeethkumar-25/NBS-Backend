from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app import (
    register, 
    login, 
    refresh_token, 
    admin_upload_files, 
    get_uploaded_files, 
    update_uploaded_file, 
    delete_uploaded_file, 
    create_admin_product_frame,
    create_event_form,
    create_product_frame,
    get_product_frames
    )

from matrimony import (
    send_otp, 
    verify_otp, 
    register_matrimony, 
    login_matrimony,
    get_last_matrimony_id,
    increment_matrimony_id,
    matrimony_refresh_token,
    get_matrimony_profiles,
    get_matrimony_preferences,
    get_rashi_compatibility,
    get_nakshatra_compatibility,
    check_full_compatibility,
    send_notification
)

app = FastAPI(
    title="Photo Studio & Matrimony API",
    version="1.0.0",
    description="API for managing file uploads, admin/user roles, and auth using JWT."
)

# CORS settings (update origins as needed)
origins = [
    "http://localhost:5173", "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allows frontends from these domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Route for Admin & User Module :
app.post("/photostudio/admin/register")(register)
app.post("/photostudio/admin/login")(login)
app.post("/photostudio/user/eventform")(create_event_form)
app.post("/photostudio/refresh-token")(refresh_token)
app.post("/photostudio/admin/fileupload")(admin_upload_files)
app.get("/photostudio/user/fileupload")(get_uploaded_files)
app.post("/photostudio/user/product_frame")(create_product_frame)
app.get("/photostudio/admin/product_frames")(get_product_frames)

# Route Includes for private module:
app.post("/photostudio/private/admin/register")(register)
app.post("/photostudio/private/admin/login")(login)
app.post("/photostudio/private/admin/refresh")(refresh_token)
app.post("/photostudio/admin/private/fileupload")(admin_upload_files)
app.get("/photostudio/admin/private/get_files")(get_uploaded_files)
app.put("/photostudio/admin/private/fileupdate/{file_id}")(update_uploaded_file)
app.delete("/photostudio/admin/private/filedelete/{file_id}")(delete_uploaded_file)
app.post("/photostudio/admin/product_frame")(create_admin_product_frame)

# Routes for matrimony
app.post("/matrimony/send-otp")(send_otp)
app.post("/matrimony/verify-otp")(verify_otp)
app.post("/matrimony/register")(register_matrimony)
app.post("/matrimony/login")(login_matrimony)
app.get("/matrimony/lastMatrimonyId")(get_last_matrimony_id)
app.put("/matrimony/incrementMatrimonyId")(increment_matrimony_id)
app.post("/matrimony/refresh-token")(matrimony_refresh_token)
app.get("/matrimony/profiles")(get_matrimony_profiles)
app.get("/matrimony/preference")(get_matrimony_preferences)
app.get("/rashi_compatibility/{rashi1}/{rashi2}")(get_rashi_compatibility)
app.get("/nakshatra_compatibility/{nakshatra1}/{nakshatra2}")(get_nakshatra_compatibility)
app.post("/check_compatibility/")(check_full_compatibility)
app.post("/send-notification")(send_notification)


@app.get("/", tags=["Health Check"])
async def root():
    return {"message": "Photo Studio & Matrimony API is running 🚀"}
