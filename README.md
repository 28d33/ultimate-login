# Secure Local Login System 🛡️

A **defensive-by-design** authentication system built with Node.js, Express, and Docker. This project implements a full **Role-Based Access Control (RBAC)** system with "Defense-in-Depth" security principles, running entirely locally using DynamoDB Local and self-signed TLS.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Security](https://img.shields.io/badge/Security-High-green)
![Docker](https://img.shields.io/badge/Containerized-Docker-blue)

## 🚀 Key Features

* **Role-Based Access Control (RBAC):** Distinct flows for `User` (Dashboard) and `Admin` (User Management).
* **Transport Security:** Enforced **HTTPS/TLS 1.3** using self-signed certificates.
* **Session Security:** **HttpOnly, Secure, SameSite** Cookies preventing XSS token theft.
* **Brute Force Protection:** Rate limiting blocking IPs after 5 failed attempts.
* **Database Security:** DynamoDB Local with **NoSQL Injection** protection logic.
* **Password Hashing:** Industry-standard **bcrypt** with per-user salting.
* **CSRF Protection:** Synchronized Token Pattern via `csurf`.
* **Secure Headers:** Helmet.js implementation (CSP, HSTS, No-Sniff).

## 🛠️ Tech Stack

* **Backend:** Node.js, Express
* **Database:** Amazon DynamoDB Local
* **Infrastructure:** Docker, Docker Compose
* **Frontend:** Vanilla HTML/CSS/JS (No frameworks, strict CSP)
* **Security Libs:** `helmet`, `csurf`, `bcrypt`, `express-rate-limit`, `jsonwebtoken`

## 📂 Project Structure

```bash
secure-login-system/
├── backend/
│   ├── certs/          # Self-signed TLS keys (Not in repo)
│   ├── src/
│   │   └── server.js   # Core API & Security Middleware
│   ├── Dockerfile
│   └── package.json
├── frontend/           # Static UI assets
│   ├── index.html      # Login Page
│   ├── admin.html      # RBAC Admin Panel
│   ├── dashboard.html  # Standard User View
│   └── style.css       # Glassmorphism UI
├── docker-compose.yml  # Orchestration
└── .gitignore
```

## ⚡ Quick Start

### Prerequisites

* [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed.
* A terminal (Bash, PowerShell, or Zsh).

### 1. Clone the Repository

```bash
git clone https://github.com/28d33/ultimate-login.git
cd ultimate-login
```

### 2. Generate SSL Certificates

Since this project enforces HTTPS, you must generate a local key pair.

```bash
mkdir -p backend/certs
cd backend/certs

# Generate a self-signed cert valid for localhost
openssl req -x509 -new -nodes \
  -keyout server.key \
  -out server.cert \
  -sha256 -days 365 \
  -subj "/C=US/ST=State/L=City/O=LocalSecurity/OU=Dev/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

cd ../..
```

### 3. Build & Run

```bash
docker-compose up --build
```

*Wait until you see `Secure Server running on https://localhost:3000` in the terminal.*

### 4. Access the App

Open your browser to:
**[https://localhost:3001](https://localhost:3001)**

> **Note:** Your browser will warn you "Your connection is not private". This is normal because we signed the certificate ourselves. Click **Advanced -> Proceed to localhost**.

## 🧪 How to Test

### 1. Register an Admin

* Go to `Register`.
* Create a user named **`admin`** (This triggers the auto-admin role logic in the backend).
* Login. You will be redirected to the **Admin Panel** where you can manage other users.

### 2. Test Rate Limiting

* Try to login with wrong credentials **5+ times**.
* Result: `429 Too Many Requests`.

### 3. Test Security Headers

* Inspect the page (F12) -> Network Tab.
* You will see `Content-Security-Policy`, `X-Frame-Options: DENY`, and strictly scoped Cookies.

## 🛡️ Security Architecture

| Vector | Defense Mechanism |
| :--- | :--- |
| **MITM Attacks** | End-to-End HTTPS (TLS) enforced via Helmet. |
| **XSS (Scripting)** | Strict `Content-Security-Policy` & `HttpOnly` Cookies. |
| **SQL/NoSQL Injection** | Input Validation & ORM-like parameter binding. |
| **CSRF** | Double-submit cookie pattern with `csurf` tokens. |
| **Brute Force** | IP & Username-based exponential backoff/lockout. |

## ⚖️ Disclaimer

This project is for **educational purposes only**. The `JWT_SECRET` is hardcoded in the docker-compose file for demonstration. In a production environment, use environment variables and a real Certificate Authority.

---

*Built by [28d33](https://github.com/28d33)*
