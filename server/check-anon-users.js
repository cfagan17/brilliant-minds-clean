require('dotenv').config();
const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error('DATABASE_URL not found in environment');
    process.exit(1);
}

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function checkAnonymousUsers() {
    try {
        // Check if anonymous_users table exists and its structure
        const tableCheck = await pool.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'anonymous_users'
            ORDER BY ordinal_position
        `);
        
        if (tableCheck.rows.length === 0) {
            console.log('❌ anonymous_users table does not exist in production!');
            
            // Check what tables do exist
            const tables = await pool.query(`
                SELECT tablename 
                FROM pg_tables 
                WHERE schemaname = 'public'
                ORDER BY tablename
            `);
            
            console.log('\nExisting tables in production:');
            tables.rows.forEach(t => console.log('  -', t.tablename));
            return;
        }
        
        console.log('✓ anonymous_users table exists with columns:');
        tableCheck.rows.forEach(col => {
            console.log('  -', col.column_name, ':', col.data_type);
        });
        
        // Get anonymous user data
        const users = await pool.query('SELECT * FROM anonymous_users ORDER BY created_at DESC');
        
        console.log('\n=== Anonymous Users in Production ===');
        console.log('Total count:', users.rows.length);
        
        if (users.rows.length > 0) {
            console.log('\nDetailed records:');
            users.rows.forEach(user => {
                console.log('\n---');
                console.log('ID:', user.id);
                console.log('Session ID:', user.session_id || 'NULL');
                console.log('IP:', user.ip_address || 'NULL');
                console.log('Discussions Used:', user.discussions_used);
                console.log('Created:', user.created_at);
                console.log('Last Active:', user.last_active || 'NULL');
            });
            
            // Summary statistics
            const stats = await pool.query(`
                SELECT 
                    COUNT(DISTINCT COALESCE(session_id, ip_address, CAST(id AS TEXT))) as unique_sessions,
                    SUM(discussions_used) as total_discussions
                FROM anonymous_users
            `);
            
            console.log('\n=== Summary Statistics ===');
            console.log('Unique Sessions/Users:', stats.rows[0].unique_sessions);
            console.log('Total Discussions:', stats.rows[0].total_discussions || 0);
        }
        
    } catch (error) {
        console.error('Error:', error.message);
    } finally {
        await pool.end();
    }
}

checkAnonymousUsers();