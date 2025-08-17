-- Create account for Nancy who paid on Aug 13 but has no account due to webhook failure
-- Run this in Supabase SQL editor

-- First, get Nancy's Stripe Customer ID from Stripe Dashboard
-- Go to stripe.com/dashboard and search for: nancymagnussondurham@gmail.com
-- Copy her customer ID (starts with cus_)

-- Then run this SQL with her actual customer ID:
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
    '$2b$10$TEMP.NEEDS.RESET.INVALID',  -- Temporary hash - she needs to reset password
    true,
    'active',
    'cus_XXXXX',  -- ⚠️ REPLACE with her actual Customer ID from Stripe
    '2025-08-13 12:17:48',  -- When she actually subscribed
    0,
    0,
    CURRENT_DATE
) ON CONFLICT (email) DO UPDATE SET
    is_pro = true,
    subscription_status = 'active',
    stripe_customer_id = EXCLUDED.stripe_customer_id;

-- Verify the account was created successfully
SELECT 
    id,
    email,
    is_pro,
    subscription_status,
    stripe_customer_id,
    created_at
FROM users 
WHERE email = 'nancymagnussondurham@gmail.com';

-- After running this, Nancy needs to:
-- 1. Go to your app
-- 2. Click "Forgot Password" (if you have this feature)
-- OR
-- 3. You manually set a password for her using the set-user-password.js script