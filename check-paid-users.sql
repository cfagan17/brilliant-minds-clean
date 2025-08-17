-- Check paid users in your database
-- Run this in Supabase SQL editor

-- 1. Count of users by subscription status
SELECT 
    subscription_status,
    COUNT(*) as user_count
FROM users
WHERE subscription_status IS NOT NULL
GROUP BY subscription_status
ORDER BY user_count DESC;

-- 2. Active Pro users (paid)
SELECT 
    COUNT(*) as total_paid_users
FROM users
WHERE is_pro = true 
    AND subscription_status = 'active';

-- 3. List of paid users with details
SELECT 
    id,
    email,
    subscription_status,
    stripe_customer_id,
    created_at,
    subscription_end_date
FROM users
WHERE is_pro = true
ORDER BY created_at DESC;

-- 4. Revenue summary (if subscription_end_date indicates payment)
SELECT 
    COUNT(CASE WHEN is_pro = true AND subscription_status = 'active' THEN 1 END) as active_subscriptions,
    COUNT(CASE WHEN is_pro = true AND subscription_status = 'canceled' THEN 1 END) as canceled_subscriptions,
    COUNT(CASE WHEN is_pro = true THEN 1 END) as total_pro_users_ever
FROM users;