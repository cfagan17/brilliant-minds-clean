-- Fix Supabase Row Level Security (RLS) Issues
-- Run these commands in your Supabase SQL Editor

-- ============================================================================
-- 1. ENABLE RLS ON ALL PUBLIC TABLES
-- ============================================================================

-- Enable RLS on users table
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Enable RLS on saved_conversations table
ALTER TABLE public.saved_conversations ENABLE ROW LEVEL SECURITY;

-- Enable RLS on shared_conversations table
ALTER TABLE public.shared_conversations ENABLE ROW LEVEL SECURITY;

-- Enable RLS on analytics_events table
ALTER TABLE public.analytics_events ENABLE ROW LEVEL SECURITY;

-- Enable RLS on anonymous_users table
ALTER TABLE public.anonymous_users ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 2. CREATE POLICIES FOR users table
-- ============================================================================

-- Users can read their own profile
CREATE POLICY "Users can view own profile" 
ON public.users 
FOR SELECT 
TO authenticated 
USING (auth.uid()::text = id OR auth.uid()::text = user_id);

-- Users can update their own profile
CREATE POLICY "Users can update own profile" 
ON public.users 
FOR UPDATE 
TO authenticated 
USING (auth.uid()::text = id OR auth.uid()::text = user_id);

-- Service role can manage all users (for admin operations)
CREATE POLICY "Service role can manage all users" 
ON public.users 
FOR ALL 
TO service_role 
USING (true);

-- Allow new user registration (insert only with matching auth.uid)
CREATE POLICY "Users can insert their own profile on signup" 
ON public.users 
FOR INSERT 
TO authenticated 
WITH CHECK (auth.uid()::text = id OR auth.uid()::text = user_id);

-- ============================================================================
-- 3. CREATE POLICIES FOR saved_conversations table
-- ============================================================================

-- Users can view their own saved conversations
CREATE POLICY "Users can view own saved conversations" 
ON public.saved_conversations 
FOR SELECT 
TO authenticated 
USING (auth.uid()::text = user_id);

-- Users can create their own saved conversations
CREATE POLICY "Users can create own saved conversations" 
ON public.saved_conversations 
FOR INSERT 
TO authenticated 
WITH CHECK (auth.uid()::text = user_id);

-- Users can update their own saved conversations
CREATE POLICY "Users can update own saved conversations" 
ON public.saved_conversations 
FOR UPDATE 
TO authenticated 
USING (auth.uid()::text = user_id);

-- Users can delete their own saved conversations
CREATE POLICY "Users can delete own saved conversations" 
ON public.saved_conversations 
FOR DELETE 
TO authenticated 
USING (auth.uid()::text = user_id);

-- ============================================================================
-- 4. CREATE POLICIES FOR shared_conversations
-- ============================================================================

-- Allow authenticated users to create their own shared conversations
CREATE POLICY "Users can create their own shared conversations" 
ON public.shared_conversations 
FOR INSERT 
TO authenticated 
WITH CHECK (auth.uid()::text = user_id);

-- Allow anyone to read shared conversations (they're meant to be shared)
CREATE POLICY "Anyone can read shared conversations" 
ON public.shared_conversations 
FOR SELECT 
TO public 
USING (true);

-- Allow users to update their own shared conversations
CREATE POLICY "Users can update their own shared conversations" 
ON public.shared_conversations 
FOR UPDATE 
TO authenticated 
USING (auth.uid()::text = user_id);

-- Allow users to delete their own shared conversations
CREATE POLICY "Users can delete their own shared conversations" 
ON public.shared_conversations 
FOR DELETE 
TO authenticated 
USING (auth.uid()::text = user_id);

-- ============================================================================
-- 5. CREATE POLICIES FOR analytics_events
-- ============================================================================

-- Only allow service role to insert analytics events (server-side only)
CREATE POLICY "Service role can insert analytics events" 
ON public.analytics_events 
FOR INSERT 
TO service_role 
WITH CHECK (true);

-- Only allow service role to read analytics events (admin only)
CREATE POLICY "Service role can read analytics events" 
ON public.analytics_events 
FOR SELECT 
TO service_role 
USING (true);

-- ============================================================================
-- 6. CREATE POLICIES FOR anonymous_users
-- ============================================================================

-- Allow service role to manage anonymous users (server-side only)
CREATE POLICY "Service role can manage anonymous users" 
ON public.anonymous_users 
FOR ALL 
TO service_role 
USING (true);

-- ============================================================================
-- 7. VERIFY RLS IS ENABLED
-- ============================================================================

-- Run this query to verify RLS is enabled on all tables
SELECT 
    schemaname,
    tablename,
    rowsecurity
FROM 
    pg_tables
WHERE 
    schemaname = 'public'
    AND tablename IN ('users', 'saved_conversations', 'shared_conversations', 'analytics_events', 'anonymous_users');

-- Expected result: rowsecurity should be 'true' for all five tables