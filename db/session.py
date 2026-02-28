import psycopg2
from psycopg2.extras import DictCursor
from core.config import settings

def get_db_connection():
    conn = psycopg2.connect(**settings.DB_CONFIG)
    return conn
