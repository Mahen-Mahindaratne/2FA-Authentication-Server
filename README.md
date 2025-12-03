# 2FA Server with Key File Authentication

A secure Express.js server implementing two-factor authentication (2FA) using password and key file validation. Features real-time logging via Socket.IO, robust session management, and enhanced security measures.

## 🚀 Quick Start

### Prerequisites

- Node.js
- npm or yarn

### Installation

1. Clone the repository
2. Install dependencies: `npm install`
3. Generate environment file: `node create-env.js`
4. Start the server: `npm start` (or `npm run dev` for development)

## 📋 Project Structure

├── server.js # Main Express server with Socket.IO
├── package.json # Dependencies and scripts
├── create-env.js # Environment setup utility
├── public/
│ └── login.html # Authentication interface
├── private_key.pem # Example key file (not included)
└── .env # Environment variables (generated)

## 🔧 Configuration

### Environment Setup

Run the setup script:

````bash
node create-env.js

This generates a .env file with:

    Secure session secrets (64-byte random)

    Pre-configured test users

    Hashed passwords using bcrypt

    Key file SHA256 hashes

Default Test Users

    test/ test123 (password only)

    Admin / Admin123 (password + key file)

🔐 Authentication Flow
Login Process

    Client Access: User visits /login page

    Multi-Factor Input:

        Username & password

        Key file upload (.key, .pem, .txt)

    Server Validation:

        Password verification via bcrypt

        Key file SHA256 hash comparison

        Session regeneration for security

    Real-time Feedback: All steps logged via Socket.IO

    Access Grant: Successful login redirects to dashboard

Session Security

    New session ID generated on login (prevents fixation)

    24-hour session duration

    HTTPOnly cookies

    Key validation timestamp tracking

🌐 API Endpoints
Public Routes

    GET / - Root (redirects to login)

    GET /login - Login page

    POST /login - Authentication endpoint

    POST /logout - Logout and session cleanup

Protected Routes (Require Authentication)

    Accessible after successful login via client-side dashboard

Real-time Logging

    Socket.IO Connection: Real-time server logs streamed to client

    Log Levels: INFO, SUCCESS, WARN, ERROR, DEBUG, FATAL

    Sources: Server, Passport, Session, KeyValidation, etc.

🛡️ Security Features
Multi-Factor Authentication

    Password: bcrypt hashing (12 rounds)

    Key File: SHA256 hash validation

    Session: Regenerated on successful login

File Upload Security

    Allowed Types: .key, .pem, .txt files

    Size Limit: 10MB maximum

    Memory Storage: No temporary disk files

    MIME Validation: Whitelisted content types

Network Security

    Security Headers:

        X-Content-Type-Options: nosniff

        X-Frame-Options: DENY

    Session Protection: HTTPOnly cookies

📁 Key File Requirements
Supported Formats

    Extensions: .key, .pem, .txt

    MIME Types: application/octet-stream, text/plain

    Content: PEM encoded private keys, plain text tokens, binary keys

Generating Key Files

🔧 Technical Details
Core Technologies

    Backend: Express.js with Passport.js authentication

    Real-time: Socket.IO for live logging

    Security: bcryptjs, SHA256 hashing

    File Handling: Multer with memory storage

    Sessions: express-session with in-memory store

Server Startup

The server emits detailed startup logs including:

    Core technology stack

    Active middleware

    Security measures

    Configured users and their MFA status

🐛 Troubleshooting
Common Issues

    "Invalid file type" errors

        Verify file extension is .key, .pem, or .txt

        Check file isn't corrupted

    Authentication failures

        Ensure .env file exists and is properly formatted

        Verify password hashes match (use create-env.js)

        Check key file hash generation

    Socket.IO connection issues

        Verify client connects to correct port

        Check CORS settings match your environment

Debug Checklist

    .env file exists in project root

    All dependencies installed (npm install)

    Key file exists for users requiring MFA

    Server starts without errors

    Client can connect to Socket.IO

🚀 Deployment
Development

npm run dev  # Uses nodemon for auto-reload

npm start    # Standard Node.js execution

Production Considerations

    HTTPS: Set secure: true in session cookies

    Session Storage: Use Redis or database instead of memory

    Environment Variables: Use production-grade secrets

    Process Management: Use PM2 or similar

    Reverse Proxy: Nginx/Apache for SSL termination

📄 License

ISC License. For secure authentication implementations only.

Note: This implementation is for demonstration purposes. Always conduct security audits before production deployment.

Environment Setup: Run create-env.js in the root directory along with your key file to generate environment variables as a .env file. Passwords are encrypted using bcrypt, key files are hashed with SHA256, and a 64-byte random session secret is generated.