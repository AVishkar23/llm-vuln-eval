import sqlite3

def record_login(conn, username):
    # Stored with a parameterized query -- the write path is safe.
    conn.execute(
        "INSERT INTO login_audit (username) VALUES (?)", (username,)
    )
    conn.commit()

def recent_activity(conn):
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT username FROM login_audit ORDER BY id DESC LIMIT 1"
    ).fetchone()
    last_user = row[0]
    # Data read back from the database is still data, not SQL: bind it.
    return cursor.execute(
        "SELECT * FROM events WHERE username = ?", (last_user,)
    ).fetchall()
