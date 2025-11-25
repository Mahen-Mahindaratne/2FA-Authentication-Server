const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const http = require('http'); 
const { Server } = require('socket.io'); 

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000; 

// =========================================================
// CENTRALIZED LOGGER & SOCKET.IO INTEGRATION
// =========================================================
let ioInstance = null;

/**
 * Central logging function that logs to console and broadcasts to connected Socket.IO clients.
 * @param {string} level - Log level (INFO, SUCCESS, WARN, ERROR, DEBUG, FATAL)
 * @param {string} source - Source component (Server, Passport, SocketIO, etc.)
 * @param {string} message - The log message.
 * @param {object} data - Optional context data.
 */
const log = (level, source, message, data = {}) => {
  const logObject = {
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    source: source,
    message: message,
    data: data
  };

  // 1. Log to the server console (structured)
  const consoleMessage = `[${logObject.level}][${logObject.source}] ${logObject.message}` + (Object.keys(data).length > 0 ? ` - ${JSON.stringify(data)}` : '');
  
  if (level === 'ERROR' || level === 'FATAL') {
    console.error(consoleMessage);
  } else if (level === 'WARN') {
    console.warn(consoleMessage);
  } else {
    console.log(consoleMessage);
  }

  // 2. Emit the log object to all connected clients
  if (ioInstance) {
    ioInstance.emit('serverLog', logObject);
  }
};
// =========================================================


// Enhanced multer configuration with logging
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    log('INFO', 'Multer', 'File upload attempt', {
      originalname: file.originalname,
      mimetype: file.mimetype,
      size: file.size
    });
    
    // Simplified allowed types for demo
    const allowedMimeTypes = ['application/octet-stream', 'text/plain'];
    const allowedExtensions = ['.key', '.pem', '.txt'];
    const fileExtension = path.extname(file.originalname).toLowerCase();
    
    if (allowedMimeTypes.includes(file.mimetype) || allowedExtensions.includes(fileExtension)) {
      log('DEBUG', 'Multer', 'File accepted');
      cb(null, true);
    } else {
      log('WARN', 'Multer', 'File rejected - invalid type');
      cb(new Error('Invalid file type. Only .key, .pem, and .txt files are allowed.'));
    }
  }
});

// Parse users with debug info
const parseUsers = () => {
  const users = {};
  let i = 1;
  while (process.env[`USER_${i}_USERNAME`]) {
    const username = process.env[`USER_${i}_USERNAME`];
    const hashedPassword = process.env[`USER_${i}_PASSWORD`];
    const keyFileHash = process.env[`USER_${i}_KEY_HASH`];
    
    log('DEBUG', 'UserConfig', `Found user ${i}`, {
      username,
      passwordSet: !!hashedPassword,
      keyHashSet: !!keyFileHash
    });
    
    users[username] = { 
      username, 
      password: hashedPassword,
      keyFileHash: keyFileHash 
    };
    i++;
  }
  return users;
};

const users = parseUsers();

// Utility function to generate SHA256 hash
const generateHash = (data) => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Key file validation
const validateKeyFile = (username, fileBuffer) => {
  const user = users[username];
  if (!user || !user.keyFileHash) {
    log('WARN', 'KeyValidation', `Key validation failed: User ${username} not found or no key hash set`);
    return false;
  }
  
  const fileHash = generateHash(fileBuffer);
  const isValid = fileHash === user.keyFileHash;
  
  log('DEBUG', 'KeyValidation', `Key file hash comparison`, {
    expectedHash: user.keyFileHash.substring(0, 10) + '...',
    isValid: isValid
  });
  
  return isValid;
};

// Store active sessions (using Map for simplicity in this demo)
const sessionKeyValidation = new Map();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Basic security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'a_secret_key_123',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true if using HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

// Passport Local Strategy
passport.use(new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
  passReqToCallback: true
}, async (req, username, password, done) => {
  try {
    log('INFO', 'Passport', 'Authentication attempt initiated', { username });

    const user = users[username];
    if (!user) {
      log('WARN', 'Passport', 'User not found in memory database', { username });
      return done(null, false, { message: 'Invalid credentials.' });
    }
    
    // Validate password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      log('WARN', 'Passport', 'Invalid password provided', { username });
      return done(null, false, { message: 'Invalid credentials.' });
    }
    
    // Validate key file if required
    if (user.keyFileHash) {
      log('INFO', 'KeyValidation', '2FA Key File check required', { username });
      const keyFile = req.file;
      if (!keyFile) {
        log('WARN', 'KeyValidation', 'Key file missing from request', { username });
        return done(null, false, { message: 'Key file required.' });
      }
      
      const isKeyFileValid = validateKeyFile(username, keyFile.buffer);
      if (!isKeyFileValid) {
        log('ERROR', 'KeyValidation', 'Key file validation failed (Hash Mismatch)', { username });
        return done(null, false, { message: 'Invalid key file.' });
      }
      
      req.keyFileValidated = true;
      log('SUCCESS', 'KeyValidation', 'Key file validation passed', { username });
    }
    
    log('SUCCESS', 'Passport', 'Authentication successful', { username });
    return done(null, user);
  } catch (error) {
    log('FATAL', 'Passport', 'Internal authentication error', { message: error.message });
    return done(error);
  }
}));

// Login route now returns JSON for client-side success panel
app.post('/login', upload.single('keyFile'), (req, res, next) => {
  log('INFO', 'LoginRoute', 'Login POST request received', {
    username: req.body.username
  });

  passport.authenticate('local', (err, user, info) => {
    if (err) {
      log('FATAL', 'LoginRoute', 'Passport authentication error', { message: err.message });
      return res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
    
    if (!user) {
      log('WARN', 'LoginRoute', 'Authentication failed', { username: req.body.username });
      // Return JSON error response
      return res.status(401).json({ success: false, message: info.message || 'Invalid credentials or missing key file.' });
    }
    
    // Session regeneration to prevent fixation
    req.session.regenerate((err) => {
      if (err) {
        log('FATAL', 'LoginRoute', 'Session regeneration error', { message: err.message });
        return res.status(500).json({ success: false, error: 'Session error' });
      }
      
      req.logIn(user, (err) => {
        if (err) {
          log('FATAL', 'LoginRoute', 'Login error during logIn', { message: err.message });
          return res.status(500).json({ success: false, error: 'Login error' });
        }

        if (req.keyFileValidated) {
          sessionKeyValidation.set(req.sessionID, {
            username: user.username,
            keyValidated: true,
            timestamp: Date.now()
          });
          log('SUCCESS', 'LoginRoute', 'Key file validation stored with final session', { sessionId: req.sessionID.substring(0, 10) + '...' });
        }
        
        log('SUCCESS', 'LoginRoute', 'Login successful', { username: user.username });
        // Return JSON success response with user details
        return res.json({ 
            success: true, 
            message: 'Access granted.', 
            user: { username: user.username, sessionId: req.sessionID.substring(0, 10) + '...' } 
        });
      });
    });
  })(req, res, next);
});

// Serialize user for session
passport.serializeUser((user, done) => {
  log('DEBUG', 'Session', 'Serializing user', { username: user.username });
  done(null, user.username);
});

// Deserialize user from session
passport.deserializeUser((username, done) => {
  log('DEBUG', 'Session', 'Deserializing user', { username });
  const user = users[username];
  done(null, user);
});


// Routes
app.get('/', (req, res) => {
  log('INFO', 'RouteAccess', 'Root route accessed, serving login page');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login', (req, res) => {
  log('INFO', 'RouteAccess', 'Login page accessed');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


// Logout routes
app.post('/logout', (req, res) => {
  log('INFO', 'LogoutRoute', 'Logout request received', { username: req.user?.username });
  
  const sessionId = req.sessionID;
  
  if (sessionId) {
    sessionKeyValidation.delete(sessionId);
    log('INFO', 'Session', 'Session validation cleared', { sessionId: sessionId.substring(0, 10) + '...' });
  }
  
  req.logout((err) => {
    if (err) {
      log('ERROR', 'LogoutRoute', 'Logout error', { message: err.message });
      return res.status(500).json({ error: 'Logout failed' });
    }
    
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        log('ERROR', 'LogoutRoute', 'Session destruction error', { message: destroyErr.message });
        return res.status(500).json({ error: 'Session destruction failed' });
      }
      
      log('SUCCESS', 'LogoutRoute', 'Logout successful');
      res.redirect('/login');
    });
  });
});

// Basic error handling
app.use((err, req, res, next) => {
  log('FATAL', 'GlobalError', 'Unhandled Request Error', { message: err.message, path: req.path });
  if (!res.headersSent) {
    res.status(500).send('System Failure: Check server logs.');
  }
});


// =========================================================
// SOCKET.IO AND HTTP SERVER STARTUP (Detailed Log)
// =========================================================

const httpServer = http.createServer(app);

const io = new Server(httpServer, {
    cors: {
        origin: `http://localhost:${PORT}`, 
        methods: ["GET", "POST"]
    }
});

ioInstance = io;

io.on('connection', (socket) => {
    log('INFO', 'SocketIO', `Client connected: ${socket.id}`);

    // Initial message to the client
    socket.emit('serverLog', { 
        level: 'INFO', 
        source: 'System', 
        message: 'Real-time log stream established. Awaiting server startup details.',
        timestamp: new Date().toISOString()
    });

    socket.on('disconnect', () => {
        log('INFO', 'SocketIO', `Client disconnected: ${socket.id}`);
    });
});

httpServer.listen(PORT, () => {
    // DETAILED STARTUP LOG: Emitted via the `log` function
    log('SUCCESS', 'Server', `🚀 System Access Terminal Online. Port: ${PORT}`);
    
    log('INFO', 'Startup', '--- CORE TECH STACK ---');
    log('INFO', 'Startup', 'Backend Framework: Express.js (HTTP/Routing)');
    log('INFO', 'Startup', 'Real-Time Comms: Socket.IO (WebSockets)');
    log('INFO', 'Startup', 'Authentication: Passport.js (LocalStrategy)');
    log('INFO', 'Startup', 'Password Hashing: bcryptjs (Asynchronous, 10 rounds)');
    log('INFO', 'Startup', 'File Handling: Multer (Memory Storage)');
    
    log('INFO', 'Startup', '--- ACTIVE MIDDLEWARE ---');
    log('INFO', 'Startup', 'Body Parsing: express.urlencoded / express.json');
    log('INFO', 'Startup', 'Session Management: express-session (In-memory store, non-persistent)');
    log('INFO', 'Startup', 'Authentication Init: passport.initialize / passport.session');
    
    log('INFO', 'Startup', '--- SECURITY MEASURES ---');
    log('INFO', 'Startup', 'HTTP Headers: X-Content-Type-Options: nosniff, X-Frame-Options: DENY');
    log('INFO', 'Startup', 'Session Security: session.regenerate on successful login (Fixation Prevention)');
    log('INFO', 'Startup', 'Password Storage: bcrypt Hashing');
    log('INFO', 'Startup', 'MFA Check: Custom Key File Validation (SHA256 Hash Check)');
    
    log('INFO', 'Startup', `--- ACCESS DETAILS ---`);
    Object.keys(users).forEach(username => {
        const user = users[username];
        const mfaStatus = user.keyFileHash ? 'REQUIRED' : 'DISABLED';
        log('INFO', 'Startup', `User: ${username} | MFA: ${mfaStatus}`);
    });

    console.log(`\n\n[SYSTEM ACCESS ONLINE] Listening on http://localhost:${PORT}\n\n`);
});