// Initialize Supabase database tables
// Run this locally with: node init-database.js

const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ Please set DATABASE_URL environment variable');
  console.log('Example: DATABASE_URL="postgresql://..." node init-database.js');
  process.exit(1);
}

console.log('📋 Using database URL:', DATABASE_URL.substring(0, 30) + '...');

async function initDatabase() {
  let pool;
  
  try {
    pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });
  } catch (error) {
    console.error('❌ Failed to create pool. Make sure your DATABASE_URL is correct.');
    console.error('Error:', error.message);
    process.exit(1);
  }

  try {
    console.log('🔄 Connecting to database...');
    
    // Test connection
    await pool.query('SELECT NOW()');
    console.log('✅ Connected to database');

    // Run the same initialization as in database-postgres.js
    console.log('🔄 Creating tables...');

    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        is_pro BOOLEAN DEFAULT FALSE,
        discussions_used INTEGER DEFAULT 0,
        total_messages INTEGER DEFAULT 0,
        stripe_customer_id VARCHAR(255),
        subscription_status VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_reset_date DATE DEFAULT CURRENT_DATE,
        is_admin BOOLEAN DEFAULT FALSE
      )
    `);
    console.log('✅ Created users table');

    // Analytics events table
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
    console.log('✅ Created analytics_events table');

    // Anonymous users table
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
    console.log('✅ Created anonymous_users table');

    // Saved conversations table
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
    console.log('✅ Created saved_conversations table');

    // Create indexes
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics_events(timestamp)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_analytics_user ON analytics_events(user_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_saved_conversations_user ON saved_conversations(user_id)`);
    console.log('✅ Created indexes');

    console.log('\n🎉 Database initialization complete!');
    console.log('Your Supabase database is ready to use.');
    
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

initDatabase();