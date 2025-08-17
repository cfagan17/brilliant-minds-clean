-- Recovery script for Stripe customers without database accounts
-- Run this in Supabase SQL editor

-- 1. First, check how many Pro users exist vs Stripe customers
SELECT 
    COUNT(*) as pro_users_count,
    COUNT(DISTINCT stripe_customer_id) as unique_stripe_customers
FROM users 
WHERE is_pro = true;

-- 2. Create account for the missing paid customer
-- Replace with actual values from Stripe dashboard
INSERT INTO users (
    email,
    password_hash,
    is_pro,
    subscription_status,
    stripe_customer_id,
    created_at,
    discussions_used,
    total_messages,
    last_reset_date
) VALUES (
    'customer@example.com',  -- Their email from Stripe
    '$2b$10$TEMP.NEEDS.RESET',  -- Temporary password hash
    true,
    'active',
    'cus_xxxxx',  -- Their Stripe customer ID
    NOW(),
    0,
    0,
    CURRENT_DATE
) ON CONFLICT (email) DO UPDATE SET
    is_pro = true,
    subscription_status = 'active',
    stripe_customer_id = EXCLUDED.stripe_customer_id;

-- 3. Verify the account was created
SELECT * FROM users WHERE email = 'customer@example.com';

-- 4. Optional: Set a specific password for them
-- First generate the hash using: node set-user-password.js TheirPassword
-- Then update with the generated hash