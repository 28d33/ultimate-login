const fs = require('fs');
const https = require('https');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const AWS = require('aws-sdk');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const morgan = require('morgan');

const app = express();

// --- 1. Database Setup (Step 3) ---
const dynamoDB = new AWS.DynamoDB.DocumentClient({
    region: 'localhost',
    endpoint: process.env.DYNAMO_ENDPOINT,
    accessKeyId: 'fake',  // DynamoDB Local doesn't need real creds
    secretAccessKey: 'fake'
});

const TABLE_NAME = "Users";

// Initial DB Setup function (Run once)
const initDb = async () => {
    const dynamodbRaw = new AWS.DynamoDB({
        region: 'localhost',
        endpoint: process.env.DYNAMO_ENDPOINT,
        accessKeyId: 'fake', 
        secretAccessKey: 'fake'
    });
    
    try {
        await dynamodbRaw.createTable({
            TableName: TABLE_NAME,
            KeySchema: [{ AttributeName: "username", KeyType: "HASH" }],
            AttributeDefinitions: [{ AttributeName: "username", AttributeType: "S" }],
            ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
        }).promise();
        console.log("Users table created.");
    } catch (e) {
        if (e.code !== 'ResourceInUseException') console.error("DB Init Error:", e);
    }
};

// --- 2. Security Middleware (Steps 2 & 6) ---

// HTTPS Enforcement (Helmet HSTS + CSP)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"], // Strict: No inline scripts
            styleSrc: ["'self'"], 
            upgradeInsecureRequests: null // Disable auto-upgrade for localhost self-signed
        }
    }
}));

// Rate Limiting (Brute Force Protection)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit to 5 attempts
    message: "Too many login attempts, please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(express.json({ limit: '10kb' })); // Body limit prevents DoS
app.use(cookieParser());
app.use(morgan('combined')); // Logging

// CSRF Protection
// Note: We ignore CSRF for the initial /init-db or non-browser APIs, 
// strictly applied to state-changing requests.
const csrfProtection = csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'Strict' } });

// Serve Frontend Static Files
app.use(express.static(path.join(__dirname, '../frontend')));

// --- 3. Routes & Logic (Steps 4 & 5) ---

// Endpoint to get CSRF token for the frontend
app.get('/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// ... (Keep existing imports and setup up to the Routes) ...

// --- Middleware: Verify JWT & Check Role ---
const authenticateToken = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ error: "Access denied" });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(403).json({ error: "Invalid token" });
    }
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Admin access required" });
    }
    next();
};

// --- Routes ---

// 1. GET /me (Used by frontend to decide where to redirect)
app.get('/me', authenticateToken, (req, res) => {
    res.json({ username: req.user.username, role: req.user.role });
});

// 2. Register (Updated for Roles)
app.post('/register', 
    [
        body('username').isAlphanumeric().trim().escape(),
        body('password').isLength({ min: 12 })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { username, password } = req.body;
        
        // AUTO-ADMIN TRICK: If username is 'admin', give them admin role.
        // In production, you would seed this manually.
        const role = (username.toLowerCase() === 'admin') ? 'admin' : 'user';

        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);

        const params = {
            TableName: "Users",
            Item: {
                username,
                password_hash,
                role, // <--- Storing Role
                created_at: new Date().toISOString(),
                failed_login_attempts: 0
            },
            ConditionExpression: 'attribute_not_exists(username)'
        };

        try {
            await dynamoDB.put(params).promise();
            res.status(201).json({ message: "User registered", role });
        } catch (err) {
            res.status(400).json({ error: "User already exists" });
        }
    }
);

// 3. Login (Updated to return Role)
app.post('/login', 
    loginLimiter, csrfProtection, 
    [ body('username').trim().escape(), body('password').notEmpty() ],
    async (req, res) => {
        const { username, password } = req.body;
        
        const params = { TableName: "Users", Key: { username } };
        const result = await dynamoDB.get(params).promise();
        const user = result.Item;

        if (!user) {
            await bcrypt.compare(password, '$2b$10$FakeHash...'); 
            return res.status(401).json({ error: "Invalid credentials" });
        }

        if (user.failed_login_attempts >= 5) return res.status(429).json({ error: "Locked" });

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            // ... (keep your existing failed attempt logic here) ...
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Reset failures
        await dynamoDB.update({
            TableName: "Users", Key: { username },
            UpdateExpression: "set failed_login_attempts = :val",
            ExpressionAttributeValues: { ":val": 0 }
        }).promise();

        // Sign Token with Role
        const token = jwt.sign({ username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });

        res.cookie('auth_token', token, {
            httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 900000
        });

        // Return role so frontend knows where to go
        res.json({ message: "Login successful", role: user.role });
    }
);

// 4. Logout (Fix: Pass options to ensure cookie is cleared)
app.post('/logout', (req, res) => {
    res.clearCookie('auth_token', {
        httpOnly: true,
        secure: true,     // Must match the creation option
        sameSite: 'Strict' // Must match the creation option
    });
    res.json({ message: "Logged out" });
});

// 5. Admin: Get All Users
app.get('/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        // Warning: scan is expensive in Prod, okay for Dev
        const data = await dynamoDB.scan({ 
            TableName: "Users", 
            ProjectionExpression: "username, #r, created_at, failed_login_attempts",
            ExpressionAttributeNames: { "#r": "role" }
        }).promise();
        res.json(data.Items);
    } catch (err) {
        res.status(500).json({ error: "Db Error" });
    }
});

// 6. Admin: Delete User
app.delete('/admin/users/:username', authenticateToken, requireAdmin, csrfProtection, async (req, res) => {
    const { username } = req.params;
    if (username === req.user.username) return res.status(400).json({ error: "Cannot delete yourself" });

    await dynamoDB.delete({ TableName: "Users", Key: { username } }).promise();
    res.json({ message: "User deleted" });
});

// ... (Keep server listen logic) ...
// --- 4. Start Server (Step 8: HTTPS) ---
const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, '../certs/server.key')),
    cert: fs.readFileSync(path.join(__dirname, '../certs/server.cert'))
};

// Delay DB init slightly to ensure container is ready
setTimeout(initDb, 5000); 

https.createServer(sslOptions, app).listen(3000, () => {
    console.log('Secure Server running on https://localhost:3000');
});
