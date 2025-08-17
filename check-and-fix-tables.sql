-- Check which tables exist in your Supabase database
-- Run this in Supabase SQL editor

-- 1. Check what tables exist
SELECT tablename 
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY tablename;

-- 2. Create missing tables if needed

-- Create analytics_events table if missing
CREATE TABLE IF NOT EXISTS analytics_events (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255),
    session_id VARCHAR(255),
    event_type VARCHAR(100),
    event_data JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_analytics_user ON analytics_events(user_id);

-- Create password_resets table if missing
CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);
CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(user_email);
CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at);

-- 3. Verify all required tables exist
SELECT 
    'users' as required_table,
    EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'users' AND schemaname = 'public') as exists
UNION ALL
SELECT 
    'anonymous_users',
    EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'anonymous_users' AND schemaname = 'public')
UNION ALL
SELECT 
    'analytics_events',
    EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'analytics_events' AND schemaname = 'public')
UNION ALL
SELECT 
    'password_resets',
    EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'password_resets' AND schemaname = 'public')
UNION ALL
SELECT 
    'saved_conversations',
    EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'saved_conversations' AND schemaname = 'public')
UNION ALL
SELECT 
    'shared_conversations',
    EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'shared_conversations' AND schemaname = 'public');