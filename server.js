// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ===================== CONFIG =====================
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123"; // Change this!
const PASSWORD_HASH = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest('hex');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Simple Admin Auth Middleware
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString();
        const [username, password] = credentials.split(':');

        if (!password) {
            return res.status(401).json({ error: 'Invalid credentials format' });
        }

        const inputHash = crypto.createHash('sha256').update(password).digest('hex');

        if (inputHash !== PASSWORD_HASH) {
            return res.status(401).json({ error: 'Invalid password' });
        }
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid authorization header' });
    }
};

// Database
const db = new sqlite3.Database('./agents.db', (err) => {
    if (err) console.error(err);
    else console.log('✅ Connected to SQLite');
});

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            llm TEXT,
            rag TEXT,
            description TEXT,
            capabilities TEXT,
            tags TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
});

// ==================== PUBLIC ROUTES ====================
app.get('/api/agents', (req, res) => {
    const search = req.query.search?.trim();
    let query = `SELECT * FROM agents ORDER BY created_at DESC`;
    const params = [];

    if (search) {
        query = `SELECT * FROM agents WHERE name LIKE ? OR llm LIKE ? OR rag LIKE ? OR description LIKE ? OR tags LIKE ? ORDER BY created_at DESC`;
        const term = `%${search}%`;
        params.push(term, term, term, term, term);
    }

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/agents/:id', (req, res) => {
    db.get('SELECT * FROM agents WHERE id = ?', [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Not found' });
        res.json(row);
    });
});

// ==================== PROTECTED ROUTES ====================
app.post('/api/agents', authenticateAdmin, (req, res) => {
    const { name, llm, rag, description, capabilities, tags } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });

    db.run(`INSERT INTO agents (name, llm, rag, description, capabilities, tags) VALUES (?, ?, ?, ?, ?, ?)`,
        [name, llm, rag, description, capabilities, tags], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, ...req.body });
    });
});

app.put('/api/agents/:id', authenticateAdmin, (req, res) => {
    const { name, llm, rag, description, capabilities, tags } = req.body;
    db.run(`UPDATE agents SET name=?, llm=?, rag=?, description=?, capabilities=?, tags=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
        [name, llm, rag, description, capabilities, tags, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
        res.json({ message: 'Updated' });
    });
});

app.delete('/api/agents/:id', authenticateAdmin, (req, res) => {
    db.run('DELETE FROM agents WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
        res.json({ message: 'Deleted' });
    });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`🔐 Admin password protection enabled`);
});
