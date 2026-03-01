import sys
import os
sys.path.append(os.getcwd())
from db.session import get_db_connection

def verify_constraint():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT conname, contype
            FROM pg_constraint
            WHERE conrelid = 'matrimony_refresh_tokens'::regclass;
        """)
        constraints = cur.fetchall()
        print("Constraints on matrimony_refresh_tokens:")
        for conname, contype in constraints:
            type_str = "UNIQUE" if contype == 'u' else "FOREIGN KEY" if contype == 'f' else "PRIMARY KEY" if contype == 'p' else contype
            print(f"- {conname}: {type_str}")
        
        has_unique = any(conname == 'matrimony_refresh_tokens_matrimony_id_key' for conname, contype in constraints)
        if has_unique:
            print("\n[✓] Verification successful: UNIQUE constraint exists on matrimony_id.")
        else:
            print("\n[X] Verification failed: UNIQUE constraint NOT found on matrimony_id.")
    except Exception as e:
        print(f"Error verifying: {e}")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    verify_constraint()
