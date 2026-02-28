import random
import psycopg2
import psycopg2.extras
from core.config import settings
import string
import logging
from fastapi import HTTPException
from firebase_admin import messaging
from db.session import get_db_connection

logger = logging.getLogger(__name__)

def generate_matrimony_id():
    """Generates a unique matrimony ID using a database sequence."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Create sequence if not exists (one-time setup)
        cur.execute("CREATE SEQUENCE IF NOT EXISTS matrimony_id_seq START 11111 INCREMENT 1;")
        cur.execute("SELECT nextval('matrimony_id_seq')")
        new_id = cur.fetchone()["nextval"]
        formatted_id = f"NBS{new_id:05d}"
        conn.commit()
        return formatted_id
    except Exception as e:
        conn.rollback()
        logger.error(f"Error generating matrimony ID: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate matrimony ID: {str(e)}")
    finally:
        cur.close()
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
