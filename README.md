# User Management System (UMS)

A comprehensive, enterprise-grade User Management System built with modern technologies to handle user authentication, authorization, and role-based access control.

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [System Architecture](#system-architecture)
- [Documentation](#documentation)
- [Getting Help](#getting-help)

---

## 🎯 Project Overview

### Purpose

The User Management System (UMS) is a secure, scalable solution designed to manage user identities, authentication, and authorization across enterprise applications. It provides:

- **Centralized User Management**: Single source of truth for user data and access control
- **Secure Authentication**: JWT-based token authentication with OIDC signature verification
- **Fine-grained Authorization**: Role-Based Access Control (RBAC) with permission granularity
- **Token Management**: Dual-token system (Access + Refresh) with automatic rotation and blacklist mechanism
- **Audit Trail**: Complete logging and monitoring of user activities

### Business Use Case

The UMS enables organizations to:

- Control user access to multiple applications and services
- Enforce security policies and compliance requirements
- Implement least-privilege access principles
- Monitor and audit user activities
- Manage organizational hierarchy through roles and permissions

### Architecture Philosophy

The system follows **layered architecture** principles:

```
┌─────────────────────────────────────────────────────────┐
│                  Presentation Layer                      │
│                    (React.js Frontend)                   │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│              API Gateway / Middleware                    │
│          (JWT Validation, CORS, Error Handling)          │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│                   FastAPI Backend                        │
│          (Business Logic, RBAC, Services)                │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│               Data Access Layer                          │
│            (ORM, Database Queries, Caching)              │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│           MySQL Database / AWS RDS                       │
│          (Persistent Data Storage & ACID)                │
└─────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **JWT Authentication** | Secure token-based authentication with OIDC signature verification |
| **Refresh Token Mechanism** | Automatic token rotation with sliding session expiration |
| **Role-Based Access Control** | Hierarchical role and permission management |
| **Permission Groups** | Organize related permissions into groups for easier management |
| **Access Points** | Define protected resources and endpoints |
| **Token Blacklist** | Revoke compromised tokens in real-time |
| **CORS Support** | Secure cross-origin requests for frontend integration |
| **Audit Logging** | Complete audit trail of all user activities |
| **Error Handling** | Comprehensive exception handling and meaningful error responses |
| **API Rate Limiting** | Prevent abuse and ensure system stability |

---

## 🛠 Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React.js | UI and user interactions |
| **Backend** | FastAPI (Python) | REST API and business logic |
| **Database** | MySQL 8.0+ | Persistent data storage |
| **Authentication** | JWT + OIDC | Secure token management |
| **API Communication** | Axios + Interceptors | Frontend API calls with automatic token refresh |
| **Infrastructure** | AWS RDS | Managed database service |
| **Deployment** | Docker + CI/CD | Containerization and automated deployment |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Node.js 16+
- MySQL 8.0+
- Docker (optional)

### Backend Setup

```bash
# Navigate to backend directory
cd Backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your configuration

# Place RSA Keys
# 1. Go to Backend/Api_Layer/JWT/token_creation/keys
# 2. Place your private.pem and public.pem files

# Start FastAPI server
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

```bash
# Navigate to frontend directory (if exists)
cd Frontend

# Install dependencies
npm install

# Configure environment variables
cp .env.example .env
# Edit .env with API endpoint (http://localhost:8000)

# Start development server
npm start
```

### Database Setup

```bash
# Execute schema creation script
mysql -u root -p < "SQL for DB/Schema Creation.sql"

# Or run Python setup script
cd "SQL for DB"
python ums_script.py

# Update Backend/.env with MySQL credentials
# MYSQL_USER=your_username
# MYSQL_PASSWORD=your_password
# MYSQL_DB=ums_db
```

### Docker Setup

```bash
# Build and run with Docker Compose
docker-compose up -d

# Access the application
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Default Credentials

After initial database setup:
- **Username**: `admin` (or as per your database seed)
- **Password**: `Paves@123`
- **Test Users**: Available in users table with same password

### Quick Access

- **API Documentation**: http://localhost:8000/docs (Swagger UI)
- **Alternative API Docs**: http://localhost:8000/redoc (ReDoc)

---

## 🏗 System Architecture

### High-Level Flow

```
┌──────────────┐
│   User       │
│ (Browser)    │
└──────┬───────┘
       │
       │ HTTPS Request
       ↓
┌──────────────────────────────────┐
│     React Frontend               │
│  - Login Component               │
│  - Protected Routes              │
│  - Axios Interceptors            │
└──────┬───────────────────────────┘
       │
       │ POST /auth/login
       ↓
┌──────────────────────────────────┐
│   FastAPI Backend                │
│  - Auth Routes                   │
│  - JWT Validation                │
│  - RBAC Middleware               │
└──────┬───────────────────────────┘
       │
       │ Query/Verify
       ↓
┌──────────────────────────────────┐
│   MySQL Database                 │
│  - Users Table                   │
│  - Roles & Permissions           │
│  - Token Blacklist               │
└──────────────────────────────────┘
```

### Authentication Flow (High Level)

```
1. User Login
   ├─ Submit credentials
   ├─ Backend validates credentials
   ├─ Generate Access Token (15 min expiry)
   ├─ Generate Refresh Token (7 days expiry)
   └─ Return tokens to frontend

2. API Requests
   ├─ Frontend includes Access Token in headers
   ├─ Backend validates token signature (OIDC)
   ├─ Process request if valid
   └─ Return response

3. Token Expiration
   ├─ Access Token expires
   ├─ Frontend intercepts 401 response
   ├─ Automatically calls refresh endpoint
   ├─ Backend validates Refresh Token
   ├─ Issues new Access Token
   └─ Resume original request

4. Logout
   ├─ Frontend clears tokens
   ├─ Backend adds tokens to blacklist
   └─ Tokens no longer valid
```

For detailed flows, see [AUTHENTICATION_FLOW.md](AUTHENTICATION_FLOW.md)

---

## 📚 Documentation

Complete technical documentation is available in the following files:

| Document | Purpose |
|----------|---------|
| [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) | Architecture, design patterns, folder structure, and system components |
| [API_DOCUMENTATION.md](API_DOCUMENTATION.md) | Complete API endpoint documentation with request/response examples |
| [AUTHENTICATION_FLOW.md](AUTHENTICATION_FLOW.md) | Detailed authentication, authorization, and token management flows |
| [DATABASE_DESIGN.md](DATABASE_DESIGN.md) | Database schema, ER diagrams, table descriptions, and relationships |

---

## 🔐 Security

The UMS implements industry-standard security practices:

- **JWT Signing & Validation**: Asymmetric cryptography (RS256) with OIDC verification
- **Token Expiration**: Short-lived access tokens (15 minutes) and longer refresh tokens (7 days)
- **Token Revocation**: Immediate token blacklist for logout and compromised tokens
- **Password Security**: Bcrypt hashing with salt for all stored passwords
- **CORS Protection**: Configured for your specific frontend domain
- **Secure Headers**: HTTPS enforcement, secure cookie flags
- **SQL Injection Prevention**: Parameterized queries via ORM
- **Input Validation**: Comprehensive request validation and sanitization

For detailed security practices, see [AUTHENTICATION_FLOW.md](AUTHENTICATION_FLOW.md#-security-best-practices)

---

## 📁 Project Structure

```
User_Management_System/
├── Backend/                    # FastAPI Backend
│   ├── main.py                # Application entry point
│   ├── requirements.txt        # Python dependencies
│   ├── Api_Layer/             # API routes and controllers
│   ├── Business_Layer/        # Business logic and services
│   ├── Data_Access_Layer/     # Database models and repositories
│   └── config/                # Configuration management
├── Frontend/                   # React Frontend (optional)
│   ├── src/
│   ├── public/
│   └── package.json
├── SQL for DB/                # Database scripts
├── tests/                      # Unit and integration tests
├── docker-compose.yml         # Docker orchestration
├── Dockerfile                 # Container configuration
├── README.md                  # This file
├── SYSTEM_DESIGN.md          # Detailed architecture documentation
├── API_DOCUMENTATION.md       # API endpoint documentation
├── AUTHENTICATION_FLOW.md     # Authentication and authorization flows
└── DATABASE_DESIGN.md         # Database schema and design
```

For detailed folder structure explanations, see [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md#-folder-structure)

---

## 🧪 Testing

```bash
# Navigate to project root
cd Backend

# Run unit tests
pytest tests/unit/ -v

# Run integration tests
pytest tests/integration/ -v

# Generate coverage report
pytest --cov=. --cov-report=html

# View coverage report
open htmlcov/index.html
```

---

## 📊 Quality Assurance

The project includes automated quality checks:

```bash
# Run all quality checks
./scripts/quality_check.sh

# Run linting
flake8 Backend/

# Check security vulnerabilities
bandit -r Backend/

# Run type checking
mypy Backend/
```

Quality reports are available in the `quality_reports/` directory.

---

## 🚢 Deployment

### Development Environment

```bash
# Ensure .env is configured
# Start all services with Docker Compose
docker-compose up

# Backend: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Production Environment

```bash
# Build production images
docker build -t ums-backend:latest -f Dockerfile .

# Deploy to AWS or your infrastructure
# Update environment variables for production
# Configure AWS RDS connection
# Deploy using CI/CD pipeline
```

See [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md#-deployment-guide) for detailed deployment instructions.

---

## 📞 Getting Help

### Documentation

- **Architecture Questions**: See [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md)
- **API Usage**: See [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
- **Authentication Issues**: See [AUTHENTICATION_FLOW.md](AUTHENTICATION_FLOW.md)
- **Database Questions**: See [DATABASE_DESIGN.md](DATABASE_DESIGN.md)

### Common Issues

**Q: Token not refreshing automatically?**
A: Check if Axios interceptors are properly configured. See [AUTHENTICATION_FLOW.md](AUTHENTICATION_FLOW.md#-axios-interceptor-implementation)

**Q: Permission denied errors?**
A: Verify RBAC configuration and permission assignments. See [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md#-role-based-access-control)

**Q: Database connection failed?**
A: Check environment variables and database configuration. See [DATABASE_DESIGN.md](DATABASE_DESIGN.md)

**Q: Where to place RSA keys?**
A: Place private.pem and public.pem in `Backend/Api_Layer/JWT/token_creation/keys/`

---

## 📝 Contributing

1. Follow the folder structure and naming conventions
2. Write comprehensive tests for new features
3. Update documentation when adding new endpoints or features
4. Run quality checks before committing: `./scripts/quality_check.sh`
5. Follow PEP 8 style guide for Python code

---

## 📄 License

This project is proprietary and confidential. All rights reserved.

---

## 📞 Support & Contact

For questions or issues, contact the development team.

---

**Last Updated**: May 2026  
**Version**: 1.0.0
