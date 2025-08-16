// One-time script to create admin user in production database
// Run this locally with your production DATABASE_URL to set up the admin user

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

async function setupAdminUser() {
    // Check for required environment variables
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
    const DATABASE_URL = process.env.DATABASE_URL;
    
    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
        console.error('❌ ADMIN_EMAIL and ADMIN_PASSWORD must be set in environment variables');
        process.exit(1);
    }
    
    if (!DATABASE_URL) {
        console.error('❌ DATABASE_URL must be set to your Supabase connection string');
        process.exit(1);
    }
    
    console.log('📧 Admin email:', ADMIN_EMAIL);
    console.log('🔗 Connecting to database...');
    
    const pool = new Pool({
        connectionString: DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });
    
    try {
        // Check if admin user already exists
        const checkResult = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [ADMIN_EMAIL]
        );
        
        if (checkResult.rows.length > 0) {
            console.log('✅ Admin user already exists. Updating password and permissions...');
            
            // Hash the new password
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
            
            // Update existing user
            await pool.query(
                `UPDATE users 
                 SET password_hash = $1, 
                     is_admin = true, 
                     is_pro = true 
                 WHERE email = $2`,
                [hashedPassword, ADMIN_EMAIL]
            );
            
            console.log('✅ Admin user updated successfully!');
        } else {
            console.log('Creating new admin user...');
            
            // Hash the password
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
            
            // Create new admin user
            await pool.query(
                `INSERT INTO users (
                    email, 
                    password_hash, 
                    is_admin, 
                    is_pro, 
                    discussions_used,
                    total_messages,
                    created_at,
                    is_test_account
                ) VALUES ($1, $2, true, true, 0, 0, NOW(), false)`,
                [ADMIN_EMAIL, hashedPassword]
            );
            
            console.log('✅ Admin user created successfully!');
        }
        
        console.log('\n🎉 Setup complete! You can now login with:');
        console.log('   Email:', ADMIN_EMAIL);
        console.log('   Password: [Your ADMIN_PASSWORD from environment]');
        console.log('\n📊 Access analytics at: https://www.iconoclash.ai/analytics-dashboard-v2.html');
        
    } catch (error) {
        console.error('❌ Error setting up admin user:', error);
        process.exit(1);
    } finally {
        await pool.end();
    }
}

// Run the setup
setupAdminUser();