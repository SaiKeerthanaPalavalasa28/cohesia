const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, 'users.json');

// Middleware
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());

// SESSION MIDDLEWARE
app.use(session({
    secret: 'cohesia-secret-key-change-this-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// AUTHENTICATION MIDDLEWARE
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }
    next();
}

// Role-based middleware
function requireRole(role) {
    return (req, res, next) => {
        if (!req.session.userId) {
            return res.redirect('/login.html');
        }
        if (req.session.userRole !== role) {
            return res.status(403).send('Access denied - insufficient permissions');
        }
        next();
    };
}

// PROTECTED ROUTES - Must come BEFORE static file serving
app.get('/emp_dashboard.html', requireRole('employee'), (req, res) => {
    res.sendFile(path.join(__dirname, 'emp_dashboard.html'));
});

app.get('/hr_dashboard.html', requireRole('HR'), (req, res) => {
    res.sendFile(path.join(__dirname, 'hr_dashboard.html'));
});

// Custom middleware to block direct access to dashboard files
app.use((req, res, next) => {
    const protectedFiles = ['emp_dashboard.html', 'hr_dashboard.html'];
    const requestedFile = path.basename(req.path);
    
    // If requesting a protected file directly, it's already handled by routes above
    if (protectedFiles.includes(requestedFile)) {
        return next();
    }
    
    // Otherwise, serve static files
    express.static(__dirname, { index: false })(req, res, next);
});

// Helper function to read users from JSON file
async function readUsers() {
    try {
        const data = await fs.readFile(USERS_FILE, 'utf8');
        const jsonData = JSON.parse(data);
        
        if (jsonData.users && Array.isArray(jsonData.users)) {
            return jsonData.users;
        } else {
            return [];
        }
    } catch (error) {
        console.error('Error reading users.json:', error);
        return [];
    }
}

// Helper function to write users to JSON file
async function writeUsers(users) {
    try {
        const jsonData = { users: users };
        await fs.writeFile(USERS_FILE, JSON.stringify(jsonData, null, 2));
        return true;
    } catch (error) {
        console.error('Error writing to users.json:', error);
        return false;
    }
}

// Route to serve your main HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// API endpoint to check if user is logged in
app.get('/api/check-auth', (req, res) => {
    if (req.session.userId) {
        res.json({
            authenticated: true,
            user: {
                name: req.session.userName,
                employeeId: req.session.userId,
                role: req.session.userRole
            }
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    try {
        const { employeeId, password } = req.body;
        
        if (!employeeId || !password) {
            return res.status(400).json({
                success: false,
                message: 'Employee ID and password are required'
            });
        }

        const users = await readUsers();
        const user = users.find(u => u.employeeId === employeeId);
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid employee ID or password'
            });
        }

        if (user.password !== password) {
            return res.status(401).json({
                success: false,
                message: 'Invalid employee ID or password'
            });
        }

        // CREATE SESSION
        req.session.userId = user.employeeId;
        req.session.userRole = user.role;
        req.session.userName = user.name;

        // Successful login
        res.json({
            success: true,
            role: user.role,
            name: user.name,
            employeeId: user.employeeId
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Logout endpoint
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: 'Error logging out'
            });
        }
        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    });
});

// Registration endpoint
app.post('/register', async (req, res) => {
    try {
        const { name, employeeId, phoneNumber, password, role } = req.body;
        
        if (!name || !employeeId || !phoneNumber || !password || !role) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        const users = await readUsers();
        
        const existingUser = users.find(u => u.employeeId === employeeId);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'Employee ID already exists'
            });
        }

        const newUser = {
            name,
            employeeId,
            phoneNumber,
            password,
            role,
            createdAt: new Date().toISOString()
        };

        users.push(newUser);

        const writeSuccess = await writeUsers(users);
        
        if (!writeSuccess) {
            return res.status(500).json({
                success: false,
                message: 'Failed to save user data'
            });
        }

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: {
                name: newUser.name,
                employeeId: newUser.employeeId,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Route to get all users (for admin purposes)
app.get('/users', async (req, res) => {
    try {
        const users = await readUsers();
        const safeUsers = users.map(user => ({
            name: user.name,
            employeeId: user.employeeId,
            phoneNumber: user.phoneNumber,
            role: user.role,
            createdAt: user.createdAt
        }));
        res.json(safeUsers);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Verify user exists and get role (for OTP generation)
app.post('/verify-user', async (req, res) => {
    try {
        const { employeeId } = req.body;
        
        if (!employeeId) {
            return res.status(400).json({
                success: false,
                message: 'Employee ID is required'
            });
        }

        const users = await readUsers();
        const user = users.find(u => u.employeeId === employeeId);
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Employee ID not found'
            });
        }

        // Return user info without password
        res.json({
            success: true,
            user: {
                name: user.name,
                employeeId: user.employeeId,
                role: user.role,
                phoneNumber: user.phoneNumber
            }
        });

    } catch (error) {
        console.error('Verify user error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// OTP Login endpoint (no password required)
app.post('/otp-login', async (req, res) => {
    try {
        const { employeeId } = req.body;
        
        if (!employeeId) {
            return res.status(400).json({
                success: false,
                message: 'Employee ID is required'
            });
        }

        const users = await readUsers();
        const user = users.find(u => u.employeeId === employeeId);
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid employee ID'
            });
        }

        // CREATE SESSION
        req.session.userId = user.employeeId;
        req.session.userRole = user.role;
        req.session.userName = user.name;

        console.log('OTP Login successful for:', user.employeeId, 'Role:', user.role);

        // Successful login
        res.json({
            success: true,
            role: user.role,
            name: user.name,
            employeeId: user.employeeId
        });

    } catch (error) {
        console.error('OTP Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Frontend files served from: ${__dirname}`);
    console.log(`Users data file: ${USERS_FILE}`);
});