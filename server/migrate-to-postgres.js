// Migration script from SQLite to PostgreSQL
require('dotenv').config();
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');
const path = require('path');

async function migrate() {
    console.log('Starting migration from SQLite to PostgreSQL...');
    
    // SQLite connection
    const sqliteDb = new sqlite3.Database(path.join(__dirname, '..', 'brilliant_minds.db'));
    
    // PostgreSQL connection
    const pgPool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });
    
    try {
        // Migrate users
        console.log('Migrating users...');
        const users = await new Promise((resolve, reject) => {
            sqliteDb.all('SELECT * FROM users', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        for (const user of users) {
            await pgPool.query(`
                INSERT INTO users (email, password_hash, created_at, is_pro, discussions_used, 
                    last_reset_date, stripe_customer_id, subscription_id, subscription_status, last_checkout_session)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (email) DO NOTHING
            `, [
                user.email, user.password_hash, user.created_at, user.is_pro || false,
                user.discussions_used || 0, user.last_reset_date, user.stripe_customer_id,
                user.subscription_id, user.subscription_status, user.last_checkout_session
            ]);
        }
        console.log(`Migrated ${users.length} users`);
        
        // Migrate anonymous users
        console.log('Migrating anonymous users...');
        const anonUsers = await new Promise((resolve, reject) => {
            sqliteDb.all('SELECT * FROM anonymous_users', (err, rows) => {
                if (err) resolve([]); // Table might not exist
                else resolve(rows);
            });
        });
        
        for (const anonUser of anonUsers) {
            await pgPool.query(`
                INSERT INTO anonymous_users (user_id, discussions_used, last_discussion_date, created_at)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id) DO NOTHING
            `, [
                anonUser.user_id, anonUser.discussions_used || 0,
                anonUser.last_discussion_date, anonUser.created_at
            ]);
        }
        console.log(`Migrated ${anonUsers.length} anonymous users`);
        
        // Migrate analytics events (last 30 days only to save space)
        console.log('Migrating analytics events...');
        const events = await new Promise((resolve, reject) => {
            sqliteDb.all(
                "SELECT * FROM analytics_events WHERE created_at > datetime('now', '-30 days')",
                (err, rows) => {
                    if (err) resolve([]);
                    else resolve(rows);
                }
            );
        });
        
        for (const event of events) {
            await pgPool.query(`
                INSERT INTO analytics_events (user_id, session_id, event_type, event_data, timestamp)
                VALUES ($1, $2, $3, $4, $5)
            `, [
                event.user_id, event.session_id, event.event_type,
                event.event_data, event.created_at || event.timestamp
            ]);
        }
        console.log(`Migrated ${events.length} analytics events`);
        
        // Migrate saved conversations
        console.log('Migrating saved conversations...');
        const conversations = await new Promise((resolve, reject) => {
            sqliteDb.all('SELECT * FROM saved_conversations', (err, rows) => {
                if (err) resolve([]);
                else resolve(rows);
            });
        });
        
        for (const conv of conversations) {
            // Get the user's new PostgreSQL ID
            const userResult = await pgPool.query(
                'SELECT id FROM users WHERE email = (SELECT email FROM users WHERE id = $1 LIMIT 1)',
                [conv.user_id]
            );
            
            if (userResult.rows[0]) {
                await pgPool.query(`
                    INSERT INTO saved_conversations (user_id, title, topic, format, participants, conversation_data, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                `, [
                    userResult.rows[0].id, conv.title, conv.topic, conv.format,
                    conv.participants, conv.conversation_data, conv.created_at
                ]);
            }
        }
        console.log(`Migrated ${conversations.length} saved conversations`);
        
        console.log('Migration completed successfully!');
    } catch (error) {
        console.error('Migration failed:', error);
        process.exit(1);
    } finally {
        await pgPool.end();
        sqliteDb.close();
    }
}

if (require.main === module) {
    migrate();
}