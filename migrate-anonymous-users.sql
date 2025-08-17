-- Migration script to ensure anonymous_users table has all required columns
-- Run this in Supabase SQL editor

-- Check if session_id column exists, add if missing
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'anonymous_users' 
        AND column_name = 'session_id'
    ) THEN
        ALTER TABLE anonymous_users ADD COLUMN session_id TEXT;
        -- Create index for faster lookups
        CREATE INDEX idx_anonymous_users_session_id ON anonymous_users(session_id);
    END IF;
END $$;

-- Check if last_active column exists, add if missing
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'anonymous_users' 
        AND column_name = 'last_active'
    ) THEN
        ALTER TABLE anonymous_users ADD COLUMN last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    END IF;
END $$;

-- Update any NULL session_ids with a generated value based on existing data
UPDATE anonymous_users 
SET session_id = CONCAT('anon_legacy_', id::text, '_', EXTRACT(EPOCH FROM created_at)::text)
WHERE session_id IS NULL;

-- Add constraint to ensure session_id is unique going forward
ALTER TABLE anonymous_users 
ADD CONSTRAINT unique_session_id UNIQUE (session_id);

-- Query to check the current state
SELECT 
    COUNT(*) as total_users,
    COUNT(DISTINCT session_id) as unique_sessions,
    SUM(discussions_used) as total_discussions,
    COUNT(CASE WHEN discussions_used > 0 THEN 1 END) as users_with_discussions
FROM anonymous_users;