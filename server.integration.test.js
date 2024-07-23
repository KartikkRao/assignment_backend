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
            const user = data.rows[0];
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(400).send("Invalid password");
            }
            const token = jwt.sign(
                { id: user.username, email: user.email },
                process.env.SECRET,
                { expiresIn: "2h" }
            );

            return res.status(200).json({ message: "Login successful", token });
        } else {
            return res.status(400).send("Fill all the fields to proceed");
        }
    } catch (err) {
        console.error(err);
        return res.status(500).send("Internal Server Error");
    }
});

function verifyToken(req, res, callback) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).send("Token is required");

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(403).send("Token is required");

    jwt.verify(token, process.env.SECRET, (err, decoded) => {
        if (err) return res.status(401).send("Invalid Token");
        req.user = decoded;
        callback();
    });
}

app.get("/protected", (req, res) => {
    verifyToken(req, res, () => {
        return res.status(200).json({ message: "This is a protected route", email: req.user.email });
    });
});

describe('Authentication Integration Tests', () => {
    let server;

    beforeAll(() => {
        server = app.listen(4000, () => {
            console.log(`Test server running on port 4000`);
        });
    });

    afterAll(done => {
        server.close(done);
    });

    test('User registration', async () => {
        const response = await request(server)
            .post('/register')
            .send({ username: 'testuser', email: 'testuser@example.com', password: 'password123' });

        expect(response.status).toBe(200);
        expect(response.text).toBe('Registration successful');
    });

    test('User login', async () => {
        const response = await request(server)
            .post('/login')
            .send({ username: 'testuser', password: 'password123' });

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('token');
    });

    test('Protected route access with token', async () => {
        const loginResponse = await request(server)
            .post('/login')
            .send({ username: 'testuser', password: 'password123' });

        const token = loginResponse.body.token;

        const protectedResponse = await request(server)
            .get('/protected')
            .set('Authorization', `Bearer ${token}`);

        expect(protectedResponse.status).toBe(200);
        expect(protectedResponse.body).toHaveProperty('email', 'testuser@example.com');
    });
});
