const request = require('supertest');
const express = require('express');
const bodyParser = require('body-parser');
const pg = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const db = new pg.Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
db.connect();

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});


function verifyToken(req, res, callback) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).send("Token is required");
    console.log(authHeader)

    const token = authHeader.split(' ')[1]; // Extract the token from the Bearer scheme
    if (!token) return res.status(403).send("Token is required");
    console.log(token)

    jwt.verify(token, process.env.SECRET, (err, decoded) => {
        if (err) return res.status(401).send("Invalid Token");
        req.user = decoded;
        callback();
    });
}


app.post("/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (username && email && password) {
            const data = await db.query("SELECT * FROM customer WHERE username = $1 OR email = $2", [username, email]);
            if (data.rows.length > 0) {
                return res.status(400).send("User already exists");
            } else {
                const hashedPassword = await bcrypt.hash(password, saltRounds);
                await db.query("INSERT INTO customer (username, email, password) VALUES ($1, $2, $3) RETURNING *", [username, email, hashedPassword]);
                return res.status(200).send("Registration successful");
            }
        } else {
            return res.status(400).send("Fill all the fields to proceed");
        }
    } catch (err) {
        console.error(err);
        return res.status(500).send("Internal Server Error");
    }
});


app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (username && password) {
            const data = await db.query("SELECT * FROM customer WHERE username = $1", [username]);
            if (data.rows.length == 0) {
                return res.status(400).send("User does not exist");
            }
            else{
            const user = data.rows[0];
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(400).send("Invalid password");
            }
            else{
            const token = jwt.sign(
                { id: user.username, email: user.email },
                process.env.SECRET,
                { expiresIn: "2h" }
            );

            return res.status(200).json({ message: "Login successful", token });
            }}
        } else {
            return res.status(400).send("Fill all the fields to proceed");
        }
    } catch (err) {
        console.error(err);
        return res.status(500).send("Internal Server Error");
    }
});


app.get("/protected", (req, res) => {
    verifyToken(req, res, () => {
        return res.status(200).json({ message: "This is a protected route email of user", email: req.user.email });
    });
});

  
module.exports = {
    verifyToken
    
};

