import psycopg2
import logging
import traceback
from psycopg2.extras import DictCursor
from core.config import settings

logger = logging.getLogger(__name__)

def get_db_connection():
    try:
        conn = psycopg2.connect(**settings.DB_CONFIG)
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise e
