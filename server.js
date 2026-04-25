const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');
const app = express();

app.use(bodyParser.json());
app.use(express.static(__dirname));

// Database Connection
const db = mysql.createConnection({
    host: process.env.MYSQLHOST || 'localhost',
    user: process.env.MYSQLUSER || 'root',
    password: process.env.MYSQLPASSWORD || '', 
    database: process.env.MYSQLDATABASE || 'industry_monitor',
    port: process.env.MYSQLPORT || 3306
});

db.connect(err => {
    if (err) console.error('Database connection failed:', err);
    else console.log('Connected to XAMPP MySQL Database');
});

// Serve the login page at http://localhost:3000
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// REGISTRATION: Saves new users to the MySQL database
const bcrypt = require('bcryptjs');

app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    try {
        // Hash the password (10 is the security "salt" level)
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const sql = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
        db.query(sql, [username, hashedPassword, role], (err, result) => {
            if (err) return res.status(500).json({ success: false, message: "User already exists" });
            res.json({ success: true, message: "Account secured and created!" });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: "Security error" });
    }
});

// LOGIN: Checks the MySQL database for the user
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM users WHERE username = ? AND password = ?";
    
    db.query(sql, [username, password], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: "Database error" });
        
        if (results.length > 0) {
            // User found in database!
            res.json({ success: true, role: results[0].role });
        } else {
            res.status(401).json({ success: false, message: "Invalid credentials" });
        }
    });
});

   const PORT = process.env.PORT || 3000; // Uses the cloud's port or 3000 locally
app.listen(PORT, () => {
    console.log(`Server is live on port ${PORT}`);
    });

// Route for Admins to update inventory and log the action
app.post('/api/update-inventory', (req, res) => {
    const { username, role, itemName, newQuantity } = req.body;

    // Check for administrative privileges
    if (role !== 'admin') {
        return res.status(403).json({ success: false, message: "Access denied. Admins only." });
    }

    // 1. Record the action in the activity_logs table
    const logSql = "INSERT INTO activity_logs (admin_username, action_performed, item_affected) VALUES (?, ?, ?)";
    const actionDesc = `Updated quantity to ${newQuantity}`;

    db.query(logSql, [username, actionDesc, itemName], (err, result) => {
        if (err) {
            console.error("Logging failed:", err);
            return res.status(500).json({ success: false, message: "Failed to log action" });
        }
        
        // 2. Here you would also update your goods_inventory table
        res.json({ success: true, message: "Inventory updated and logged successfully!" });
    });
});

// Fetch the latest 10 activity logs
app.get('/api/logs', (req, res) => {
    const sql = "SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 10";
    
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ success: false, message: "Error fetching logs" });
        res.json(results);
    });
});