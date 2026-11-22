import sqlite3
import time
import config

def get_connection():
    conn = sqlite3.connect(config.DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time REAL,
            rule TEXT,
            severity TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            message TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_alert(rule, severity, src_ip, dst_ip, message):
    conn = get_connection()
    conn.execute(
        "INSERT INTO alerts (time, rule, severity, src_ip, dst_ip, message) VALUES (?, ?, ?, ?, ?, ?)",
        (time.time(), rule, severity, src_ip, dst_ip, message),
    )
    conn.commit()
    conn.close()


def get_alerts(limit=50, severity=None):
    conn = get_connection()
    if severity:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE severity = ? ORDER BY time DESC LIMIT ?",
            (severity, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY time DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def count_by(column):
    if column not in ("rule", "severity"):
        raise ValueError("bad column")
    conn = get_connection()
    rows = conn.execute(
        f"SELECT {column}, COUNT(*) AS total FROM alerts GROUP BY {column}"
    ).fetchall()
    conn.close()
    return {row[column]: row["total"] for row in rows}


def top_attackers(limit=10):
    conn = get_connection()
    rows = conn.execute(
        """SELECT src_ip, COUNT(*) AS total FROM alerts
           WHERE src_ip IS NOT NULL
           GROUP BY src_ip ORDER BY total DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def timeline(minutes=60):
    # alerts per minute
    since = time.time() - minutes * 60
    conn = get_connection()
    rows = conn.execute(
        """SELECT CAST(time / 60 AS INTEGER) * 60 AS minute, COUNT(*) AS total
           FROM alerts WHERE time >= ? GROUP BY minute ORDER BY minute""",
        (since,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def attack_graph():
    # who attacked who
    conn = get_connection()
    rows = conn.execute(
        """SELECT src_ip, dst_ip, COUNT(*) AS total FROM alerts
           WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
           GROUP BY src_ip, dst_ip"""
    ).fetchall()
    conn.close()

    nodes = set()
    edges = []
    for row in rows:
        nodes.add(row["src_ip"])
        nodes.add(row["dst_ip"])
        edges.append({"from": row["src_ip"], "to": row["dst_ip"], "count": row["total"]})
    return {"nodes": sorted(nodes), "edges": edges}