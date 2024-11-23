const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");

const app = express();
const PORT = 3000;

// Database setup: Connect to the existing database 'diehlDB.sqlite'
const db = new sqlite3.Database("diehlDB.sqlite", (err) => {
    if (err) {
        console.error("Error opening database: ", err.message);
        process.exit(1);  // Exit if the database can't be opened
    } else {
        console.log("Connected to the existing database 'diehlDB.sqlite'");
    }
});

// Middleware
app.use(bodyParser.json());
app.use(express.static("public"));

// Serve the index page (default home page)
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

// Ensure the users table exists (if not, you can create it)
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);
});

// Hash password with SHA-256 (using the crypto module)
function hashPassword(password) {
    return crypto.createHash("sha256").update(password).digest("hex");
}

app.post("/register", (req, res) => {
    const { username, password } = req.body;

    // Insecure string concatenation (SQL Injection Vulnerable)
    db.get("SELECT * FROM users WHERE username = '" + username + "'", (err, row) => {
        if (err) {
            return res.status(500).json({ message: "Error checking username" });
        }
        if (row) {
            return res.status(400).json({ message: "Username already exists" });
        }

        // Hash the password with SHA-256 (No encryption here, but SQL injection could still happen)
        const hashedPassword = hashPassword(password);

        // Vulnerable insert statement using string concatenation
        db.run("INSERT INTO users (username, password) VALUES ('" + username + "', '" + hashedPassword + "')", function (err) {
            if (err) {
                return res.status(500).json({ message: "Error registering user" });
            }
            res.json({ message: "User registered successfully" });
        });
    });
});

// Login endpoint vulnerable to SQL Injection
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    // Log inputs for debugging
    console.log("Received Username: ", username);
    console.log("Received Password: ", password);

    // Hash the password for comparison
    const hashedPassword = hashPassword(password);

    // Construct the vulnerable query
    const query = `
        SELECT * FROM users 
        WHERE username = '${username}' AND password = '${hashedPassword}'`;

    // Log the SQL query
    console.log("Executing Query: ", query);

    // Use .all to fetch results for SELECT queries
    db.all(query, (err, rows) => {
        if (err) {
            console.error("Database Error: ", err.message);
            return res.status(500).json({ message: "Database error" });
        }

        // Check if any rows were returned
        if (rows.length > 0) {
            // Check if the login was valid (correct username and hashed password)
            const validUser = rows.find(
                (row) => row.username === username && row.password === hashedPassword
            );

            if (validUser) {
                console.log("Login successful for username:", username);
                return res.json({ message: "Login successful" });
            }

            // Otherwise, it's likely an injection-based success
            db.exec(query);
            console.log("Login successful via SQL injection, rows returned: ", rows);
            return res.json({ message: "Login successful via SQL injection", data: rows });
        }

        // If no rows, invalid login
        console.log("Invalid username or password");
        return res.status(400).json({ message: "Invalid username or password" });
    });
});





// Start server
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
