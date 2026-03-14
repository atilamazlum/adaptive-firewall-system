from database import get_connection


def get_blocked_ips():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM blocked_ips")

    rows = cur.fetchall()

    conn.close()

    result = []

    for r in rows:
        result.append({
            "ip": r[1],
            "reason": r[2],
            "time": r[3]
        })

    return result
