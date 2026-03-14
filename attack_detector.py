from database import get_connection


def get_attack_logs():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM attack_logs")

    rows = cur.fetchall()

    conn.close()

    logs = []

    for r in rows:
        logs.append({
            "ip": r[1],
            "attack_type": r[2],
            "severity": r[3],
            "time": r[4]
        })

    return logs
