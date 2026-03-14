import datetime

def check_system_status():

    return {
        "system": "Security Guard",
        "status": "active",
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "layers": [
            "IP Monitoring",
            "Attack Detection",
            "Auto Blocking"
        ]
    }
