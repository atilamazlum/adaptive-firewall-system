import sqlite3

DB = "attacks.db"


def get_connection():
    return sqlite3.connect(DB)
