"""Initialize test database for mcp-audit SQLite scanning target."""

import sqlite3

conn = sqlite3.connect("/data/test.db")
c = conn.cursor()

c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT)")
c.execute("INSERT INTO users VALUES (1, 'admin', 'admin@corp.com', 'administrator')")
c.execute("INSERT INTO users VALUES (2, 'jdoe', 'jdoe@corp.com', 'analyst')")
c.execute("INSERT INTO users VALUES (3, 'svc_account', 'svc@corp.com', 'service')")

c.execute("CREATE TABLE api_keys (id INTEGER PRIMARY KEY, owner TEXT, key_value TEXT, scope TEXT)")
c.execute("INSERT INTO api_keys VALUES (1, 'admin', 'sk-FAKE-1234567890abcdef', 'full')")
c.execute("INSERT INTO api_keys VALUES (2, 'jdoe', 'sk-FAKE-abcdef1234567890', 'readonly')")

c.execute(
    "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, timestamp TEXT, action TEXT, user_id INTEGER)"
)
c.execute("INSERT INTO audit_log VALUES (1, '2025-01-01T00:00:00', 'login', 1)")

conn.commit()
conn.close()
