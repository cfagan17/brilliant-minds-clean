const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// SQLite database
const dbPath = path.join(__dirname, '..', 'brilliant_minds.db');
const db = new sqlite3.Database(dbPath);

function initializeDatabase() {
    // Create users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_pro BOOLEAN DEFAULT FALSE,
            discussions_used INTEGER DEFAULT 0,
            last_reset_date DATE DEFAULT CURRENT_DATE,
            stripe_customer_id TEXT,
            subscription_id TEXT,
            subscription_status TEXT
        )
    `);
    
    // Add last_checkout_session column if it doesn't exist
    db.run(`ALTER TABLE users ADD COLUMN last_checkout_session TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.log('Column last_checkout_session might already exist');
        }
    });
    
    // Add admin columns
    db.run(`ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0`, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.log('Column is_admin might already exist');
        }
    });
    
    db.run(`ALTER TABLE users ADD COLUMN is_test_account BOOLEAN DEFAULT 0`, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.log('Column is_test_account might already exist');
        }
    });
    
    // Add analytics table
    db.run(`
        CREATE TABLE IF NOT EXISTS analytics_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            session_id TEXT,
            event_type TEXT,
            event_data TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Create table for anonymous users
    db.run(`
        CREATE TABLE IF NOT EXISTS anonymous_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            discussions_used INTEGER DEFAULT 0,
            last_discussion_date DATE DEFAULT CURRENT_DATE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Create saved conversations table
    db.run(`
        CREATE TABLE IF NOT EXISTS saved_conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            topic TEXT,
            format TEXT,
            participants TEXT,
            conversation_data TEXT,
            is_shared INTEGER DEFAULT 0,
            view_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `);
    
    // Add missing columns if they don't exist (for existing databases)
    db.run(`ALTER TABLE saved_conversations ADD COLUMN is_shared INTEGER DEFAULT 0`, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.log('is_shared column may already exist');
        }
    });
    
    db.run(`ALTER TABLE saved_conversations ADD COLUMN view_count INTEGER DEFAULT 0`, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.log('view_count column may already exist');
        }
    });
    
    // Create shared conversations table
    db.run(`
        CREATE TABLE IF NOT EXISTS shared_conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            share_id TEXT UNIQUE NOT NULL,
            topic TEXT,
            format TEXT,
            participants TEXT,
            conversation_html TEXT,
            metadata TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL
        )
    `);
    
    console.log('SQLite database initialized');
}

module.exports = { db, initializeDatabase };