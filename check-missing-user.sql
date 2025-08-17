-- Run these queries in Supabase SQL editor

-- 1. Search for the user by partial email (in case of typos)
-- Replace 'partoftheiremail' with part of their email before the @
SELECT 
    id, 
    email, 
    is_pro, 
    subscription_status,
    stripe_customer_id,
    created_at
FROM users
WHERE LOWER(email) LIKE LOWER('%partoftheiremail%');

-- 2. Check if they exist with the Stripe customer ID
-- Replace 'cus_xxxxx' with the customer ID from Stripe
SELECT 
    id, 
    email, 
    is_pro, 
    subscription_status,
    created_at
FROM users
WHERE stripe_customer_id = 'cus_xxxxx';

-- 3. See all Pro users to check if they're there with different email
SELECT 
    email,
    stripe_customer_id,
    subscription_status,
    created_at
FROM users
WHERE is_pro = true
ORDER BY created_at DESC;

-- 4. If they don't exist at all, create their account
-- Replace values with their actual information
INSERT INTO users (
    email,
    password_hash,
    is_pro,
    subscription_status,
    stripe_customer_id,
    created_at,
    discussions_used,
    total_messages
) VALUES (
    'their-email@example.com',
    '$2b$10$TEMPORARY_HASH', -- They'll need to reset password
    true,
    'active',
    'cus_xxxxx', -- Their Stripe customer ID
    NOW(),
    0,
    0
);