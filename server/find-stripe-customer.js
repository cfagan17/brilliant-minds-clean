// Find a customer in Stripe and check if they exist in database
require('dotenv').config();
const { Pool } = require('pg');

async function findStripeCustomer() {
    const CUSTOMER_EMAIL = process.argv[2];
    
    if (!CUSTOMER_EMAIL) {
        console.log('Usage: node find-stripe-customer.js <email>');
        console.log('Example: node find-stripe-customer.js user@example.com');
        process.exit(1);
    }
    
    const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
    const DATABASE_URL = process.env.DATABASE_URL;
    
    if (!STRIPE_SECRET_KEY) {
        console.error('❌ STRIPE_SECRET_KEY not found in environment');
        process.exit(1);
    }
    
    const stripe = require('stripe')(STRIPE_SECRET_KEY);
    
    try {
        console.log('🔍 Searching Stripe for customer:', CUSTOMER_EMAIL);
        
        // Search Stripe for this customer
        const customers = await stripe.customers.list({
            email: CUSTOMER_EMAIL,
            limit: 10
        });
        
        if (customers.data.length === 0) {
            console.log('❌ No customer found in Stripe with email:', CUSTOMER_EMAIL);
            
            // Try searching for all recent customers
            console.log('\n📋 Recent Stripe customers (last 20):');
            const recentCustomers = await stripe.customers.list({
                limit: 20
            });
            
            recentCustomers.data.forEach(customer => {
                console.log(`  - ${customer.email} (${customer.id}) - Created: ${new Date(customer.created * 1000).toLocaleDateString()}`);
            });
            
            return;
        }
        
        console.log(`\n✅ Found ${customers.data.length} customer(s) in Stripe:`);
        
        for (const customer of customers.data) {
            console.log('\n📧 Customer:', customer.email);
            console.log('   Stripe ID:', customer.id);
            console.log('   Created:', new Date(customer.created * 1000));
            console.log('   Name:', customer.name || 'Not provided');
            
            // Check for active subscriptions
            const subscriptions = await stripe.subscriptions.list({
                customer: customer.id,
                status: 'all'
            });
            
            if (subscriptions.data.length > 0) {
                console.log('\n   📊 Subscriptions:');
                subscriptions.data.forEach(sub => {
                    console.log(`      - Status: ${sub.status}`);
                    console.log(`        Amount: $${(sub.items.data[0].price.unit_amount / 100).toFixed(2)}/${sub.items.data[0].price.recurring.interval}`);
                    console.log(`        Created: ${new Date(sub.created * 1000).toLocaleDateString()}`);
                    if (sub.status === 'active') {
                        console.log(`        Current period ends: ${new Date(sub.current_period_end * 1000).toLocaleDateString()}`);
                    }
                });
            } else {
                console.log('   ⚠️  No subscriptions found');
            }
            
            // Check if this customer exists in the database
            if (DATABASE_URL) {
                const pool = new Pool({
                    connectionString: DATABASE_URL,
                    ssl: { rejectUnauthorized: false }
                });
                
                try {
                    // Check by email
                    let result = await pool.query(
                        'SELECT id, email, is_pro, subscription_status FROM users WHERE LOWER(email) = LOWER($1)',
                        [customer.email]
                    );
                    
                    if (result.rows.length > 0) {
                        console.log('\n   ✅ Found in database:');
                        console.log('      User ID:', result.rows[0].id);
                        console.log('      Is Pro:', result.rows[0].is_pro);
                        console.log('      Subscription Status:', result.rows[0].subscription_status);
                    } else {
                        // Check by stripe_customer_id
                        result = await pool.query(
                            'SELECT id, email, is_pro, subscription_status FROM users WHERE stripe_customer_id = $1',
                            [customer.id]
                        );
                        
                        if (result.rows.length > 0) {
                            console.log('\n   ⚠️  Found in database with different email:');
                            console.log('      Database Email:', result.rows[0].email);
                            console.log('      User ID:', result.rows[0].id);
                            console.log('      Is Pro:', result.rows[0].is_pro);
                        } else {
                            console.log('\n   ❌ NOT FOUND in database!');
                            console.log('      This customer paid but has no account!');
                            
                            // Suggest creating the account
                            console.log('\n   🔧 To create account for this customer, they need to:');
                            console.log('      1. Sign up at https://iconoclash.ai with email:', customer.email);
                            console.log('      2. Then we can link their Stripe customer ID');
                        }
                    }
                } catch (dbError) {
                    console.log('   ⚠️  Could not check database:', dbError.message);
                } finally {
                    await pool.end();
                }
            }
        }
        
        // Check for recent payments
        console.log('\n💳 Checking recent payments...');
        const charges = await stripe.charges.list({
            limit: 5,
            customer: customers.data[0].id
        });
        
        if (charges.data.length > 0) {
            console.log('Recent payments:');
            charges.data.forEach(charge => {
                console.log(`  - $${(charge.amount / 100).toFixed(2)} on ${new Date(charge.created * 1000).toLocaleDateString()} - ${charge.status}`);
            });
        }
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

findStripeCustomer();