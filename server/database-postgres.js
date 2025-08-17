const { Pool } = require('pg');

// Check if DATABASE_URL is provided
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL is not set in environment variables');
  throw new Error('DATABASE_URL is required for PostgreSQL connection');
}

console.log('📊 DATABASE_URL is set, length:', process.env.DATABASE_URL.length);
console.log('📊 NODE_ENV:', process.env.NODE_ENV);

// Create pool with explicit error handling
let pool;
try {
  // Try to parse the DATABASE_URL to ensure it's valid
  const dbUrl = process.env.DATABASE_URL;
  
  // Create pool without using connectionString to avoid parsing issues
  if (dbUrl.startsWith('postgresql://') || dbUrl.startsWith('postgres://')) {
    // Parse URL manually to avoid pg-connection-string issues
    const url = new URL(dbUrl);
    
    // Log parsed components for debugging
    console.log('📊 Parsed connection details:');
    console.log('  - Host:', url.hostname);
    console.log('  - Port:', url.port || 5432);
    console.log('  - Database:', url.pathname.slice(1));
    console.log('  - User:', url.username);
    console.log('  - Password length:', url.password ? url.password.length : 0);
    
    pool = new Pool({
      user: url.username,
      password: decodeURIComponent(url.password),
      host: url.hostname,
      port: url.port || 5432,
      database: url.pathname.slice(1),
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      max: 1, // Serverless should use minimal connections
      idleTimeoutMillis: 0, // Close connections immediately after use
      connectionTimeoutMillis: 10000, // Give more time to connect in serverless
      allowExitOnIdle: true, // Allow process to exit when idle
      keepAlive: false, // Disable keep-alive for serverless
      keepAliveInitialDelayMillis: 0 // No keep-alive delay
    });
    
    console.log('✅ PostgreSQL pool created with parsed connection');
  } else {
    throw new Error('DATABASE_URL must start with postgresql:// or postgres://');
  }
} catch (error) {
  console.error('❌ Error creating PostgreSQL pool:', error);
  console.error('DATABASE_URL format issue - ensure it starts with postgresql:// or postgres://');
  throw error;
}

// Initialize database schema
async function initializeDatabase() {
  try {
    // First test DNS resolution
    console.log('🔄 Testing DNS resolution...');
    const dns = require('dns').promises;
    try {
      const addresses = await dns.resolve4('db.uzjqstwlvbjalrrydlzf.supabase.co');
      console.log('✅ DNS resolved to:', addresses);
    } catch (dnsError) {
      console.error('❌ DNS resolution failed:', dnsError);
      // Try alternative connection method
      console.log('🔄 Trying alternative connection...');
    }
    
    // Test the connection with retry
    console.log('🔄 Testing PostgreSQL connection...');
    await executeWithRetry(() => pool.query('SELECT NOW()'));
    console.log('✅ PostgreSQL connection successful');
    
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
        is_test_account BOOLEAN DEFAULT false,
        subscription_end_date TIMESTAMP
      )
    `);
    
    // Add subscription_end_date column if it doesn't exist
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_end_date TIMESTAMP`).catch(() => {});

    // Create indexes for performance
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id)`);

    // Create anonymous_users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS anonymous_users (
        id SERIAL PRIMARY KEY,
        session_id VARCHAR(255) UNIQUE NOT NULL,
        discussions_used INTEGER DEFAULT 0,
        total_messages INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_anon_users_session ON anonymous_users(session_id)`);

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

    // Create password_resets table for password reset functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_email VARCHAR(255) NOT NULL,
        token VARCHAR(255) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT false
      )
    `);
    
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(user_email)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at)`);

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
        is_shared BOOLEAN DEFAULT false,
        view_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_conversations_user ON saved_conversations(user_id)`);
    
    // Add missing columns if they don't exist (for existing databases)
    await pool.query(`ALTER TABLE saved_conversations ADD COLUMN IF NOT EXISTS is_shared BOOLEAN DEFAULT false`).catch(() => {});
    await pool.query(`ALTER TABLE saved_conversations ADD COLUMN IF NOT EXISTS view_count INTEGER DEFAULT 0`).catch(() => {});
    
    // Create shared_conversations table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS shared_conversations (
        id SERIAL PRIMARY KEY,
        share_id VARCHAR(100) UNIQUE NOT NULL,
        topic VARCHAR(255),
        format VARCHAR(50),
        participants JSONB,
        conversation_html TEXT,
        metadata JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_shared_conversations_share_id ON shared_conversations(share_id)`);

    console.log('PostgreSQL database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
}

// Retry logic for serverless connections
async function executeWithRetry(queryFn, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await queryFn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      
      // Retry on connection errors
      if (error.code === 'ECONNRESET' || 
          error.code === 'ETIMEDOUT' || 
          error.message.includes('connection timeout') ||
          error.message.includes('Connection terminated')) {
        console.log(`Retrying database query (attempt ${i + 2}/${maxRetries})...`);
        await new Promise(resolve => setTimeout(resolve, 100 * (i + 1))); // Exponential backoff
        continue;
      }
      throw error;
    }
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
    
    executeWithRetry(() => pool.query(pgQuery, params))
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
    
    executeWithRetry(() => pool.query(pgQuery, params))
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
    
    executeWithRetry(() => pool.query(pgQuery, params))
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

// Cleanup function for serverless environments
async function cleanup() {
  if (pool) {
    try {
      await pool.end();
      console.log('✅ PostgreSQL pool closed');
    } catch (error) {
      console.error('Error closing pool:', error);
    }
  }
}

// Handle process termination in serverless
if (process.env.NODE_ENV === 'production') {
  process.on('SIGTERM', cleanup);
  process.on('SIGINT', cleanup);
}

module.exports = { db, initializeDatabase, pool, cleanup };