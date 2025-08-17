// Script to fix paid user issues
// Run this locally with your production DATABASE_URL

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

async function fixPaidUser() {
    const USER_EMAIL = process.argv[2];
    const NEW_PASSWORD = process.argv[3];
    
    if (!USER_EMAIL) {
        console.log('Usage: node fix-paid-user.js <email> [new-password]');
        console.log('Example: node fix-paid-user.js user@example.com newpassword123');
        process.exit(1);
    }
    
    const DATABASE_URL = process.env.DATABASE_URL;
    
    if (!DATABASE_URL) {
        console.error('❌ DATABASE_URL must be set in environment');
        process.exit(1);
    }
    
    const pool = new Pool({
        connectionString: DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });
    
    try {
        // First, check the user's current status
        const checkResult = await pool.query(
            'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
            [USER_EMAIL]
        );
        
        if (checkResult.rows.length === 0) {
            console.log('❌ User not found:', USER_EMAIL);
            
            // Check for similar emails
            const similarResult = await pool.query(
                "SELECT email FROM users WHERE LOWER(email) LIKE LOWER($1)",
                [`%${USER_EMAIL.split('@')[0]}%`]
            );
            
            if (similarResult.rows.length > 0) {
                console.log('\nSimilar emails found:');
                similarResult.rows.forEach(row => console.log(' -', row.email));
            }
            
            process.exit(1);
        }
        
        const user = checkResult.rows[0];
        console.log('\n✅ User found:');
        console.log('   ID:', user.id);
        console.log('   Email:', user.email);
        console.log('   Is Pro:', user.is_pro);
        console.log('   Subscription Status:', user.subscription_status);
        console.log('   Stripe Customer ID:', user.stripe_customer_id);
        console.log('   Created:', user.created_at);
        console.log('   Has Password:', !!user.password_hash);
        
        // Check Stripe for their actual subscription status
        if (user.stripe_customer_id && process.env.STRIPE_SECRET_KEY) {
            console.log('\n🔍 Checking Stripe subscription status...');
            const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
            
            try {
                const subscriptions = await stripe.subscriptions.list({
                    customer: user.stripe_customer_id,
                    status: 'active'
                });
                
                if (subscriptions.data.length > 0) {
                    console.log('✅ Active Stripe subscription found!');
                    const sub = subscriptions.data[0];
                    console.log('   Status:', sub.status);
                    console.log('   Current period ends:', new Date(sub.current_period_end * 1000));
                } else {
                    console.log('⚠️  No active Stripe subscription found');
                }
            } catch (stripeError) {
                console.log('⚠️  Could not check Stripe:', stripeError.message);
            }
        }
        
        // Fix the user's pro status if needed
        if (!user.is_pro || user.subscription_status !== 'active') {
            console.log('\n🔧 Fixing user pro status...');
            await pool.query(
                `UPDATE users 
                 SET is_pro = true, 
                     subscription_status = 'active'
                 WHERE id = $1`,
                [user.id]
            );
            console.log('✅ User pro status updated');
        }
        
        // Update password if provided
        if (NEW_PASSWORD) {
            console.log('\n🔐 Updating password...');
            const hashedPassword = await bcrypt.hash(NEW_PASSWORD, 10);
            await pool.query(
                'UPDATE users SET password_hash = $1 WHERE id = $2',
                [hashedPassword, user.id]
            );
            console.log('✅ Password updated successfully');
            console.log('\nUser can now login with:');
            console.log('   Email:', user.email);
            console.log('   Password:', NEW_PASSWORD);
        }
        
        console.log('\n✅ User account fixed!');
        console.log('They should now be able to login as a Pro user.');
        
    } catch (error) {
        console.error('❌ Error:', error);
    } finally {
        await pool.end();
    }
}

fixPaidUser();