-- Complete setup for Nancy's account
-- Run this entire script in Supabase SQL Editor

-- Step 1: Create Nancy's account
-- ⚠️ IMPORTANT: Replace 'cus_XXXXX' with her actual Customer ID from Stripe Dashboard
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
    'nancymagnussondurham@gmail.com',
    '$2b$10$AgACu7pCiUBR4pH6tQnyeudE4KClGdXQzWwcwn71ozjAX5KkvIrpG',  -- Password: NancyPro2025!
    true,
    'active',
    'cus_XXXXX',  -- ⚠️ REPLACE with her actual Customer ID from Stripe
    '2025-08-13 12:17:48',  -- When she actually subscribed
    0,
    0,
    CURRENT_DATE
) ON CONFLICT (email) DO UPDATE SET
    password_hash = '$2b$10$AgACu7pCiUBR4pH6tQnyeudE4KClGdXQzWwcwn71ozjAX5KkvIrpG',
    is_pro = true,
    subscription_status = 'active',
    stripe_customer_id = EXCLUDED.stripe_customer_id;

-- Step 2: Verify the account was created successfully
SELECT 
    id,
    email,
    is_pro,
    subscription_status,
    stripe_customer_id,
    created_at,
    CASE 
        WHEN password_hash = '$2b$10$AgACu7pCiUBR4pH6tQnyeudE4KClGdXQzWwcwn71ozjAX5KkvIrpG' 
        THEN 'Password set correctly' 
        ELSE 'Password issue - needs reset' 
    END as password_status
FROM users 
WHERE email = 'nancymagnussondurham@gmail.com';

-- Nancy can now login with:
-- Email: nancymagnussondurham@gmail.com
-- Password: NancyPro2025!