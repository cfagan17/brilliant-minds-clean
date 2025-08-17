-- Create password_resets table in production (Supabase)
-- Run this in Supabase SQL editor NOW to fix the 500 errors

CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT false
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);
CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(user_email);
CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at);

-- Verify table was created
SELECT 
    column_name, 
    data_type,
    is_nullable
FROM information_schema.columns 
WHERE table_name = 'password_resets'
ORDER BY ordinal_position;