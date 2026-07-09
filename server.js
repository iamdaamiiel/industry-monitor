const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');

// Import initializeApp and cert directly using standard CommonJS destructured syntax
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const app = express();

app.use(bodyParser.json());
app.use(express.static(__dirname));

// Load your credentials key file
const serviceAccount = require('./serviceAccountKey.json');

// Initialize the application using the direct functions
initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();
console.log('Connected to Firebase Firestore Database');

// Serve the login page at http://localhost:3000
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// REGISTRATION: Saves new users to the Firestore 'users' collection
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    try {
        // Reference to the specific user document using the username as the ID
        const userRef = db.collection('users').doc(username);
        const doc = await userRef.get();

        // Enforce unique user constraint
        if (doc.exists) {
            return res.status(500).json({ success: false, message: "User already exists" });
        }

        // Hash the password (10 is the security "salt" level)
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save the new user
        await userRef.set({
            username,
            password: hashedPassword,
            role,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ success: true, message: "Account secured and created!" });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ success: false, message: "Security error" });
    }
});

// LOGIN: Checks the Firestore 'users' collection for the user
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userRef = db.collection('users').doc(username);
        const doc = await userRef.get();

        if (!doc.exists) {
            // User not found
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const userData = doc.data();

        // Compare the typed password with the hashed password from Firestore
        const isMatch = await bcrypt.compare(password, userData.password);

        if (isMatch) {
            res.json({ 
                message: "Login successful", 
                role: userData.role, 
                username: userData.username 
            });
        } else {
            // Password didn't match the hash
            res.status(401).json({ message: "Invalid credentials" });
        }
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Database error" });
    }
});

// Route for Admins to update inventory and log the action
app.post('/api/update-inventory', async (req, res) => {
    const { username, role, itemName, newQuantity } = req.body;

    // Check for administrative privileges
    if (role !== 'admin') {
        return res.status(403).json({ success: false, message: "Access denied. Admins only." });
    }

    try {
        const actionDesc = `Updated quantity to ${newQuantity}`;

        // 1. Record the action in the 'activity_logs' collection
        await db.collection('activity_logs').add({
            admin_username: username,
            action_performed: actionDesc,
            item_affected: itemName,
            timestamp: admin.firestore.FieldValue.serverTimestamp() // Automatically adds the current time
        });
        
        // 2. Here you would also update your goods_inventory collection if needed
        res.json({ success: true, message: "Inventory updated and logged successfully!" });
    } catch (error) {
        console.error("Logging failed:", error);
        return res.status(500).json({ success: false, message: "Failed to log action" });
    }
});

// Fetch the latest 10 activity logs
app.get('/api/logs', async (req, res) => {
    try {
        const logsSnapshot = await db.collection('activity_logs')
            .orderBy('timestamp', 'desc')
            .limit(10)
            .get();

        const results = [];
        logsSnapshot.forEach(doc => {
            results.push({ id: doc.id, ...doc.data() });
        });

        res.json(results);
    } catch (error) {
        console.error("Error fetching logs:", error);
        return res.status(500).json({ success: false, message: "Error fetching logs" });
    }
});

const PORT = process.env.PORT || 3000; 
app.listen(PORT, () => {
    console.log(`Server is live on port ${PORT}`);
});