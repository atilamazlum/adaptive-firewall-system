**# adaptive-firewall-system
adaptive-firewall-system/
│
├── frontend/                # React
│   ├── src/
│   ├── public/
│   └── package.json
│
├── backend/                 # Flask
│   ├── app.py
│   ├── routes/
│   ├── models/
│   ├── services/
│   ├── tests/
│   └── requirements.txt
│
├── docs/
│   ├── er-diagram.md
│   ├── api-spec.md
│   └── project-notes.md
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── README.md
└── .gitignore
**# Security Guard System

Security Guard System is a multi-layer network security and monitoring project designed to detect suspicious activities, log potential attacks, and manage blocked IP addresses.

The goal of this project is to simulate a modular security monitoring architecture that can evolve into a more advanced defensive system capable of monitoring, analyzing, and reacting to potential network threats.

---

## Project Purpose

The purpose of this system is to:

- Monitor suspicious network activities
- Detect potential attack attempts
- Store and analyze security logs
- Manage blocked IP addresses
- Build a modular multi-layer security architecture
- Prepare infrastructure for automated firewall actions

---

## Current Features

The current prototype includes:

- Python Flask based backend
- REST API endpoints
- SQLite database integration
- Blocked IP list management
- Attack log storage
- Basic system monitoring structure
- Modular security architecture

---

## Planned / Upcoming Features

Future development plans include:

- nftables integration for automatic IP blocking
- Automated threat detection
- Brute force attack detection
- Port scan detection
- SQL injection attempt logging
- Real-time traffic monitoring
- Dynamic firewall rule management
- Security dashboard interface
- User authentication and session control
- Threat severity classification
- Blacklist / whitelist IP system
- Advanced log filtering and analysis
- IDS/IPS-like behavior simulation

---

## Technologies Used

Current and planned technologies:

- Python
- Flask
- Flask-CORS
- SQLite
- JavaScript
- React (planned)
- HTML
- CSS
- Linux networking tools
- nftables (planned)

---

## Project Structure
