# 2FA Server with Key File Authentication

A secure Express.js server implementing two-factor authentication (2FA) using password and key file validation. Provides robust session management, file upload validation, and enhanced security features.

**2FA Server Demo | Featuring Agent 47**: 
[![2FA Server Demo | Featuring Agent 47](https://img.youtube.com/vi/MeD7AP4FIEQ/0.jpg)](https://www.youtube.com/watch?v=MeD7AP4FIEQ)

## 🌟 Features

- **Dual-Factor Authentication**: Password + Key File validation
- **Secure Session Management**: Session fixation protection with regeneration
- **File Upload Security**: Strict file type validation and size limits
- **Security Headers**: Built-in protection against common web vulnerabilities
- **Comprehensive Logging**: Detailed audit trails for all operations
- **Session Validation**: Time-based key file revalidation
- **Localhost Debug Endpoints**: Safe debugging capabilities

## 🚀 Quick Start

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Environment variables configured

### Installation

1. Clone the repository
2. Run `npm install`
3. Configure environment variables
4. Start with `npm start`

## 📁 File Upload Requirements

### Supported File Types

**MIME Types:**
- `application/octet-stream`
- `text/plain`
- `application/x-x509-ca-cert`
- `application/pkix-cert`

**Extensions:** `.key`, `.pem`, `.txt`

**Maximum Size:** 10MB

### Key File Format

Key files should be in one of these formats:
- PEM encoded private keys
- Plain text token files
- Binary key files
- Certificate files

## 🔐 Authentication Flow

1. **Initial Request**: User accesses protected resource
2. **Redirect to Login**: Unauthenticated users are redirected to `/login`
3. **Credential Submission**: User provides username, password, and key file
4. **Validation Process**:
   - Password verification using bcrypt
   - Key file SHA256 hash comparison
   - Session regeneration for security
5. **Session Establishment**: Successful login creates validated session
6. **Access Grant**: User redirected to `/dashboard`

## 🛡️ Security Features

### Session Security

- **Session Regeneration**: New session ID on login to prevent fixation
- **HTTPOnly Cookies**: Prevents client-side script access
- **Secure Validation**: Key file validation tied to session
- **Time-based Expiry**: 24-hour key validation limit

### File Upload Security

- **Strict Type Checking**: Whitelisted MIME types and extensions
- **Size Limits**: Prevents resource exhaustion attacks
- **Memory Storage**: No temporary files on disk
- **Hash Verification**: Cryptographic validation of key files

### Network Security

- **Security Headers**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
- **Localhost Restrictions**: Debug endpoints limited to localhost

## 📊 API Endpoints

### Public Endpoints

- `GET /` - Root redirect (to login or dashboard)
- `GET /login` - Login page
- `POST /login` - Authentication processing
- `GET /logout` - Logout redirect

### Protected Endpoints (Require Authentication)

- `GET /dashboard` - User dashboard
- `GET /api/user` - Current user information
- `POST /logout` - Logout processing

### Debug Endpoints (Localhost Only)

- `GET /debug` - Session and validation state information

## 🔍 Monitoring and Logging

The server provides comprehensive logging for all operations and security events.

## 🚨 Error Handling

### Common Error Scenarios

- **Invalid Credentials**: Redirect to `/login?error=1`
- **Missing Key File**: Clear error message
- **Invalid File Type**: Specific rejection reasons
- **Session Timeout**: Automatic redirect to login
- **Key Validation Expired**: Requires re-authentication

## 👥 User Management

### Adding New Users

1. Increment the user counter in environment variables
2. Generate password hash using bcrypt
3. Generate key file SHA256 hash
4. Restart server

### Customization Points

- File size limits in multer configuration
- Session duration in cookie settings
- Allowed file types in upload filter
- Key validation timeout period

## 📝 Troubleshooting

### Common Issues

**"Invalid file type" errors:**
- Verify file extension is in allowed list
- Check file MIME type
- Ensure file isn't corrupted

**Authentication failures:**
- Verify password hashing matches
- Check key file hash generation
- Confirm environment variables are loaded

**Session issues:**
- Check SESSION_SECRET is set
- Verify cookie settings match deployment
- Clear browser cookies if needed

### Debug Checklist

- [ ] Environment variables loaded
- [ ] User credentials properly hashed
- [ ] Key files generate correct SHA256 hashes
- [ ] File uploads meet type/size requirements
- [ ] Session secret is sufficiently random

## 🔒 Production Considerations

### Security Hardening

- Use HTTPS in production
- Set `secure: true` in session cookies
- Implement rate limiting
- Add CSRF protection
- Use environment-specific configuration

### Performance

- Implement session storage (Redis, etc.)
- Add file upload streaming for large files
- Consider CDN for static assets
- Implement clustering for high availability

### Monitoring

- Log aggregation and analysis
- Session metrics tracking
- Failed authentication alerts
- File upload statistics

## 📄 License

This project is for secure authentication implementations. Ensure compliance with your organization's security policies and applicable regulations.

> **Note**: This server implements security best practices but should be thoroughly tested in your specific environment before production deployment.

---

**Key File Generation**: Learn how to generate key files by checking out my [Hashnode blog](https://the-ghost-protocol.hashnode.space/the-ghost-protocol/rsa-key-generation-instructions).

**Environment Setup**: Run `create-env.js` in the root directory along with your key file to generate environment variables as a `.env` file. Passwords are encrypted using bcrypt, key files are hashed with SHA256, and a 64-byte random session secret is generated.
