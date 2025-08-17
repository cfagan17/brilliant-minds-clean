-- Verify anonymous_users table in production

-- 1. Check the structure
SELECT 
    column_name, 
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'anonymous_users'
ORDER BY ordinal_position;

-- 2. Check current data
SELECT 
    COUNT(*) as total_records,
    COUNT(DISTINCT session_id) as unique_sessions,
    SUM(discussions_used) as total_discussions
FROM anonymous_users;

-- 3. View any existing records
SELECT * FROM anonymous_users ORDER BY created_at DESC LIMIT 10;