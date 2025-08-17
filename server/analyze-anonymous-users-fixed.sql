-- SQL queries to analyze anonymous users in production
-- Run these in Supabase SQL editor to understand the discrepancy

-- 1. Check table structure (RUN THIS FIRST)
SELECT 
    column_name, 
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'anonymous_users'
ORDER BY ordinal_position;

-- 2. View all anonymous users with details (adjusted for actual columns)
SELECT 
    id,
    session_id,
    discussions_used,
    created_at,
    last_active
FROM anonymous_users
ORDER BY created_at DESC;

-- 3. Summary statistics (adjusted to not use ip_address)
SELECT 
    COUNT(*) as total_records,
    COUNT(DISTINCT COALESCE(session_id, id::text)) as unique_users,
    SUM(discussions_used) as total_discussions,
    COUNT(CASE WHEN discussions_used > 0 THEN 1 END) as users_with_discussions,
    COUNT(CASE WHEN discussions_used = 0 THEN 1 END) as users_without_discussions,
    MIN(created_at) as first_user,
    MAX(created_at) as latest_user
FROM anonymous_users;

-- 4. Group by discussions used to see distribution
SELECT 
    discussions_used,
    COUNT(*) as user_count
FROM anonymous_users
GROUP BY discussions_used
ORDER BY discussions_used;

-- 5. Check for duplicate or NULL session IDs
SELECT 
    COALESCE(session_id, 'NO_SESSION_ID') as session_identifier,
    COUNT(*) as record_count,
    SUM(discussions_used) as total_discussions,
    MIN(created_at) as first_seen,
    MAX(last_active) as last_seen
FROM anonymous_users
GROUP BY session_identifier
ORDER BY record_count DESC;

-- 6. Recent activity
SELECT 
    id,
    session_id,
    discussions_used,
    created_at,
    last_active,
    CASE 
        WHEN last_active IS NOT NULL THEN 
            EXTRACT(EPOCH FROM (last_active - created_at))/60 
        ELSE 0 
    END as session_duration_minutes
FROM anonymous_users
WHERE created_at > NOW() - INTERVAL '7 days'
ORDER BY created_at DESC;

-- 7. Check if session_id is NULL for any records (this might explain the discrepancy)
SELECT 
    CASE 
        WHEN session_id IS NULL THEN 'No Session ID'
        WHEN session_id = '' THEN 'Empty Session ID'
        ELSE 'Has Session ID'
    END as session_status,
    COUNT(*) as count,
    SUM(discussions_used) as total_discussions
FROM anonymous_users
GROUP BY session_status;