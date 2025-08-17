-- Debug paid user login issues
-- Run these in Supabase SQL editor with the user's email

-- REPLACE 'user@example.com' with the actual user's email
DECLARE
    user_email TEXT := 'user@example.com';  -- <-- CHANGE THIS TO THE USER'S EMAIL

-- 1. Check if user exists and their current status
SELECT 
    id,
    email,
    is_pro,
    subscription_status,
    stripe_customer_id,
    discussions_used,
    last_reset_date,
    created_at,
    subscription_end_date,
    CASE 
        WHEN password_hash IS NULL THEN 'NO PASSWORD'
        WHEN LENGTH(password_hash) < 10 THEN 'INVALID HASH'
        ELSE 'HAS PASSWORD'
    END as password_status
FROM users
WHERE LOWER(email) = LOWER('user@example.com');  -- <-- CHANGE THIS TOO

-- 2. Check for duplicate accounts (different case, spaces, etc)
SELECT 
    id,
    email,
    is_pro,
    subscription_status,
    created_at
FROM users
WHERE LOWER(email) LIKE LOWER('%user@example%');  -- <-- CHANGE THIS TO MATCH

-- 3. Check recent login attempts (if we're tracking them in analytics)
SELECT 
    event_type,
    timestamp,
    event_data
FROM analytics_events
WHERE user_id IN (SELECT id FROM users WHERE LOWER(email) = LOWER('user@example.com'))  -- <-- CHANGE THIS
ORDER BY timestamp DESC
LIMIT 10;

-- 4. Check ALL pro users to see the pattern
SELECT 
    COUNT(*) as total_users,
    COUNT(CASE WHEN is_pro = true THEN 1 END) as pro_users,
    COUNT(CASE WHEN is_pro = true AND subscription_status = 'active' THEN 1 END) as active_pro,
    COUNT(CASE WHEN is_pro = true AND subscription_status != 'active' THEN 1 END) as inactive_pro,
    COUNT(CASE WHEN is_pro = false AND subscription_status = 'active' THEN 1 END) as mismatch_cases
FROM users;

-- 5. If you find the user, you can manually fix their status with:
-- UPDATE users 
-- SET is_pro = true, 
--     subscription_status = 'active'
-- WHERE LOWER(email) = LOWER('user@example.com');