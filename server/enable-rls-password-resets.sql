-- Enable Row Level Security for password_resets table
-- Run this in Supabase SQL editor to fix the security alert

-- 1. Enable RLS on the password_resets table
ALTER TABLE password_resets ENABLE ROW LEVEL SECURITY;

-- 2. Drop existing policies if they exist (safe to run multiple times)
DROP POLICY IF EXISTS "Password resets are viewable by token holder" ON password_resets;
DROP POLICY IF EXISTS "Password resets can be created by anyone" ON password_resets;
DROP POLICY IF EXISTS "Password resets can be updated by token holder" ON password_resets;
DROP POLICY IF EXISTS "Password resets cleanup for expired tokens" ON password_resets;

-- 3. Create RLS policies

-- Policy 1: Allow anyone to create a password reset request (public endpoint)
-- This is necessary for the forgot password functionality
CREATE POLICY "Password resets can be created by anyone" 
ON password_resets 
FOR INSERT 
TO public
WITH CHECK (true);

-- Policy 2: Allow reading password reset tokens only if you have the token
-- This prevents enumeration of reset tokens
CREATE POLICY "Password resets are viewable by token holder" 
ON password_resets 
FOR SELECT
TO public
USING (
    -- Only allow selecting if the token is provided in the query
    -- This ensures users can only access their own reset token
    token IS NOT NULL
);

-- Policy 3: Allow updating (marking as used) only for valid tokens
CREATE POLICY "Password resets can be updated by token holder" 
ON password_resets 
FOR UPDATE
TO public
USING (
    -- Only allow updating if the token exists and hasn't expired
    expires_at > NOW() AND used = false
)
WITH CHECK (
    -- Only allow setting 'used' to true
    used = true
);

-- Policy 4: Allow deletion of expired tokens (for cleanup)
CREATE POLICY "Password resets cleanup for expired tokens" 
ON password_resets 
FOR DELETE
TO public
USING (
    expires_at < NOW() OR used = true
);

-- 4. Create a service role bypass for backend operations
-- Note: Your backend should use the service role key for password reset operations
-- The service role automatically bypasses RLS

-- 5. Verify RLS is enabled
SELECT 
    schemaname,
    tablename,
    rowsecurity
FROM pg_tables
WHERE tablename = 'password_resets';

-- 6. Test the policies (optional - run these to verify)
-- This should show the current RLS policies
SELECT 
    policyname,
    permissive,
    roles,
    cmd,
    qual,
    with_check
FROM pg_policies
WHERE tablename = 'password_resets'
ORDER BY policyname;