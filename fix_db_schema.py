import psycopg2
import sys
import os

# Add the current directory to sys.path to import from db.session
sys.path.append(os.getcwd())

from db.session import get_db_connection

def fix_schema():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        print("Checking for UNIQUE constraint on matrimony_refresh_tokens(matrimony_id)...")
        # Try to add it, if it fails because it already exists, we're good
        try:
            cur.execute("""
                ALTER TABLE matrimony_refresh_tokens
                ADD CONSTRAINT matrimony_refresh_tokens_matrimony_id_key UNIQUE (matrimony_id);
            """)
            conn.commit()
            print("[✓] UNIQUE constraint added successfully.")
        except psycopg2.errors.DuplicateTable:
            conn.rollback()
            print("[!] Constraint already exists.")
        except Exception as e:
            conn.rollback()
            if "already exists" in str(e).lower():
                print("[!] Constraint already exists.")
            else:
                raise e
    except Exception as e:
        print(f"Error fixing schema: {e}")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    fix_schema()
