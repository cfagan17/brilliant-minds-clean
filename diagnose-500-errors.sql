-- Diagnose 500 errors in Supabase
-- Run each section to identify the issue

-- 1. Check analytics_events table structure
SELECT 
    column_name, 
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'analytics_events'
ORDER BY ordinal_position;

-- 2. Check if password_resets table exists
SELECT EXISTS (
    SELECT 1 
    FROM information_schema.tables 
    WHERE table_name = 'password_resets'
) as password_resets_exists;

-- 3. Check anonymous_users table structure
SELECT 
    column_name, 
    data_type,
    is_nullable
FROM information_schema.columns 
WHERE table_name = 'anonymous_users'
ORDER BY ordinal_position;

-- 4. Test if we can insert into analytics_events
-- This will help identify any permission or structure issues
INSERT INTO analytics_events (user_id, session_id, event_type, event_data, timestamp)
VALUES ('test_user', 'test_session', 'test_event', '{"test": true}'::jsonb, NOW())
RETURNING id;

-- 5. Clean up test data
DELETE FROM analytics_events 
WHERE user_id = 'test_user' AND event_type = 'test_event';

-- 6. Check for any recent errors in analytics_events
SELECT * FROM analytics_events 
WHERE timestamp > NOW() - INTERVAL '10 minutes'
ORDER BY timestamp DESC
LIMIT 5;