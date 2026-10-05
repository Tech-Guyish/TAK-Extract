"""Connects to the live TAK Server database with the credentials in .env
and reports what it finds. The one suite here that needs a real database -
every other one runs against a temp sqlite file. Run from the checkout:
python tests/test_db.py
"""
import os
import psycopg2
from dotenv import load_dotenv

# This file lives in tests/; .env is in the checkout above it, so name that
# path rather than relying on where this was run from.
load_dotenv(os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

try:
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        connect_timeout=5,
    )
    cur = conn.cursor()

    cur.execute("SELECT count(*), min(servertime), max(servertime) FROM cot_router;")
    total, oldest, newest = cur.fetchone()

    print("Connected.")
    print(f"  Records : {total:,}")
    print(f"  Oldest  : {oldest}")
    print(f"  Newest  : {newest}")

    # Confirm the role really is read-only.
    try:
        cur.execute("CREATE TABLE should_not_work (x int);")
        print("  WARNING: this role can WRITE. It should be read-only.")
        conn.rollback()
    except psycopg2.errors.InsufficientPrivilege:
        conn.rollback()
        print("  Write access correctly denied.")

    cur.close()
    conn.close()

except Exception as e:
    print("Connection failed:")
    print(f"  {type(e).__name__}: {e}")