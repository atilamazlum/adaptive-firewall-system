from flask import Flask, jsonify
from flask_cors import CORS

from guard import check_system_status
from ip_guard import get_blocked_ips
from attack_detector import get_attack_logs

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return jsonify({"message": "Security Guard System Running"})


@app.route("/api/status")
def status():
    return jsonify(check_system_status())


@app.route("/api/blocked")
def blocked():
    return jsonify(get_blocked_ips())


@app.route("/api/attacks")
def attacks():
    return jsonify(get_attack_logs())


if __name__ == "__main__":
    app.run(debug=True)
