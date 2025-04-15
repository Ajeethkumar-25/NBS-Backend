from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from photostudio import (
    register, 
    login, 
    refresh_token, 
    admin_upload_files, 
    get_uploaded_files, 
    update_uploaded_file, 
    delete_uploaded_file, 
    create_admin_product_frame
    )

app = FastAPI(
    title="Photo Studio & Matrimony API",
    version="1.0.0",
    description="API for managing file uploads, admin/user roles, and auth using JWT."
)

# CORS settings (update origins as needed)
origins = [
    "http://localhost",
    "http://localhost:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allows frontends from these domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Route Includes
app.post("/photostudio/private/admin/register")(register)
app.post("/photostudio/private/admin/login")(login)
app.post("/photostudio/private/admin/refresh")(refresh_token)
app.post("/photostudio/admin/private/fileupload")(admin_upload_files)
app.get("/photostudio/admin/private/get_files")(get_uploaded_files)
app.put("/photostudio/admin/private/fileupdate/{file_id}")(update_uploaded_file)
app.delete("/photostudio/admin/private/filedelete/{file_id}")(delete_uploaded_file)
app.post("/photostudio/admin/product_frame")(create_admin_product_frame)

@app.get("/", tags=["Health Check"])
async def root():
    return {"message": "Photo Studio & Matrimony API is running 🚀"}
