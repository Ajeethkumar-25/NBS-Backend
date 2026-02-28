import os
import shutil
import logging
from fastapi import UploadFile, HTTPException
from core.config import settings

class FileHandler:
    def __init__(self):
        self.upload_base = str(settings.UPLOAD_DIR)

    def upload_file(self, file: UploadFile, folder: str) -> str:
        """Uploads a file to local storage and returns the static file URL."""
        try:
            filename = file.filename.strip().replace(" ", "_")
            folder_path = os.path.join(self.upload_base, folder)
            os.makedirs(folder_path, exist_ok=True)
            
            file_path = os.path.join(folder_path, filename)
            
            file.file.seek(0)
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # Return the static URL path
            file_url = f"/static/{folder}/{filename}"
            logging.info(f"File uploaded successfully: {file_url}")
            return file_url

        except Exception as e:
            logging.error(f"Failed to upload {file.filename}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to upload {file.filename}: {str(e)}")

    def list_files(self, folder: str):
        """Lists all files inside the specified local folder."""
        try:
            folder_path = os.path.join(self.upload_base, folder)
            if os.path.exists(folder_path):
                file_list = os.listdir(folder_path)
                logging.info(f"Files in {folder}: {file_list}")
                return file_list
            else:
                logging.info(f"No folder found at {folder}")
                return []
        except Exception as e:
            logging.error(f"Error listing files: {str(e)}")
            return []
        
    def process_url(self, value, folder_name):
        if value and isinstance(value, str) and value.strip():
            items = value.replace("{", "").replace("}", "").split(',')
            return [
                f"/static/{folder_name}/{item.strip()}"
                for item in items
                if item.strip()
            ]
        return None

    def delete_file(self, file_url: str):
        """Deletes a file from local storage given its static URL."""
        if not file_url.startswith("/static/"):
            logging.error(f"Invalid file URL for deletion: {file_url}")
            return

        relative_path = file_url.replace("/static/", "")
        file_path = os.path.join(self.upload_base, relative_path)

        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logging.info(f"Deleted {file_path}")
            else:
                logging.warning(f"File not found for deletion: {file_path}")
        except Exception as e:
            logging.error(f"Failed to delete {file_url}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to delete file: {str(e)}")

file_handler = FileHandler()
