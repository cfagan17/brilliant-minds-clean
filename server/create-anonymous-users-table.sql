-- Create anonymous_users table in production (Supabase)
-- Run this in Supabase SQL editor

-- Create the anonymous_users table
CREATE TABLE IF NOT EXISTS anonymous_users (
    id SERIAL PRIMARY KEY,
    session_id TEXT UNIQUE NOT NULL,
    discussions_used INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_anonymous_users_session_id ON anonymous_users(session_id);
CREATE INDEX IF NOT EXISTS idx_anonymous_users_created_at ON anonymous_users(created_at);
CREATE INDEX IF NOT EXISTS idx_anonymous_users_last_active ON anonymous_users(last_active);

-- Enable Row Level Security
ALTER TABLE anonymous_users ENABLE ROW LEVEL SECURITY;

-- Create a policy to allow the backend to manage anonymous users
-- This allows all operations from authenticated services
CREATE POLICY "Service role can manage anonymous users" ON anonymous_users
    FOR ALL
    USING (true)
    WITH CHECK (true);

-- Verify the table was created
SELECT 
    'anonymous_users table created successfully' as status,
    COUNT(*) as initial_record_count
FROM anonymous_users;

-- Check the structure
SELECT 
    column_name, 
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'anonymous_users'
ORDER BY ordinal_position;