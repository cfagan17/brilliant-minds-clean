const { Pool } = require('pg');

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Initialize database schema
async function initializeDatabase() {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_pro BOOLEAN DEFAULT false,
        discussions_used INTEGER DEFAULT 0,
        last_reset_date DATE DEFAULT CURRENT_DATE,
        stripe_customer_id VARCHAR(255),
        subscription_id VARCHAR(255),
        subscription_status VARCHAR(50),
        last_checkout_session VARCHAR(255),
        is_admin BOOLEAN DEFAULT false,
        is_test_account BOOLEAN DEFAULT false
      )
    `);

    // Create indexes for performance
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id)`);

    // Create anonymous_users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS anonymous_users (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255) UNIQUE NOT NULL,
        discussions_used INTEGER DEFAULT 0,
        last_discussion_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_anon_users_id ON anonymous_users(user_id)`);

    // Create analytics_events table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS analytics_events (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255),
        session_id VARCHAR(255),
        event_type VARCHAR(100),
        event_data JSONB,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics_events(timestamp)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_analytics_user ON analytics_events(user_id)`);

    // Create saved_conversations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS saved_conversations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        title VARCHAR(500),
        topic VARCHAR(255),
        format VARCHAR(50),
        participants JSONB,
        conversation_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_conversations_user ON saved_conversations(user_id)`);

    console.log('PostgreSQL database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
}

// Helper functions to match SQLite interface
const db = {
  get: (query, params, callback) => {
    // Convert SQLite-style placeholders
    let pgQuery = query;
    let paramIndex = 1;
    while (pgQuery.includes('?')) {
      pgQuery = pgQuery.replace('?', '$' + paramIndex);
      paramIndex++;
    }
    
    pool.query(pgQuery, params)
      .then(result => callback(null, result.rows[0]))
      .catch(err => callback(err));
  },
  
  all: (query, params, callback) => {
    // Convert SQLite-style placeholders
    let pgQuery = query;
    let paramIndex = 1;
    while (pgQuery.includes('?')) {
      pgQuery = pgQuery.replace('?', '$' + paramIndex);
      paramIndex++;
    }
    
    pool.query(pgQuery, params)
      .then(result => callback(null, result.rows))
      .catch(err => callback(err));
  },
  
  run: function(query, params, callback) {
    // Convert SQLite-style placeholders (?) to PostgreSQL style ($1, $2, etc)
    let pgQuery = query;
    let paramIndex = 1;
    while (pgQuery.includes('?')) {
      pgQuery = pgQuery.replace('?', '$' + paramIndex);
      paramIndex++;
    }
    
    // Handle INSERT queries to return ID
    if (pgQuery.toLowerCase().includes('insert into')) {
      pgQuery = pgQuery.trim();
      if (!pgQuery.toLowerCase().includes('returning')) {
        pgQuery += ' RETURNING id';
      }
    }
    
    pool.query(pgQuery, params)
      .then(result => {
        if (callback) {
          const lastID = result.rows[0]?.id || result.lastInsertRowid;
          callback.call({ lastID, changes: result.rowCount }, null);
        }
      })
      .catch(err => {
        if (callback) callback(err);
      });
  }
};

module.exports = { db, initializeDatabase, pool };