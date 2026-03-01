import logging
import psycopg2
from db.session import get_db_connection
from db.init_db import init_db

# Configure logging to console
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def debug():
    print("--- DB Diagnostic Start ---")
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        print("[✓] Connection successful.")
        
        # Check current tables
        cur.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public'")
        tables = cur.fetchall()
        print(f"Current tables: {[t[0] for t in tables]}")
        
        # Run init_db
        print("Running init_db()...")
        init_db()
        print("[✓] init_db() called successfully.")
        
        # Check tables again
        cur.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public'")
        tables = cur.fetchall()
        print(f"Tables after init: {[t[0] for t in tables]}")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[!] FAULT: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug()
