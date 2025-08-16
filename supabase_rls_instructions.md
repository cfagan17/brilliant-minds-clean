# Fixing Supabase Row Level Security (RLS) Issues

## Immediate Actions Required

### 1. Apply the RLS Fix
1. Go to your Supabase Dashboard
2. Navigate to SQL Editor
3. Copy the entire contents of `supabase_rls_fix.sql`
4. Paste and run it in the SQL Editor
5. This will enable RLS and create appropriate policies

### 2. Update Your Application Code

Since your app currently uses SQLite locally and doesn't appear to be using Supabase directly, you might need to check:

1. **If you're using Supabase Auth**: The policies assume `auth.uid()` for user identification
2. **If you're using direct database access**: You'll need to use the service_role key for server-side operations

### 3. Test Your Application

After enabling RLS:
1. Test user registration and login
2. Test sharing conversations
3. Test analytics tracking
4. Verify that existing functionality still works

## Understanding the Policies

### users Table
- **Self Access Only**: Users can only view/update their own profile
- **Service Role**: Backend server has full access for admin operations
- **Registration**: New users can insert their own profile during signup

### saved_conversations Table
- **Private to User**: Users can only see/manage their own saved conversations
- **Full CRUD**: Users have complete control over their own saved conversations
- **No Public Access**: Saved conversations are completely private

### shared_conversations Table
- **Public Read**: Anyone can view shared conversations (they're meant to be shared)
- **Authenticated Write**: Only logged-in users can create/update/delete their own conversations

### analytics_events Table
- **Service Role Only**: Only your backend server can read/write analytics
- **No Public Access**: Protects sensitive analytics data

### anonymous_users Table
- **Service Role Only**: Only your backend server can manage anonymous users
- **No Public Access**: Protects user tracking data

## If You Need Different Policies

Modify the policies based on your actual use case:

### Example: If you want to make analytics read-only for authenticated users:
```sql
CREATE POLICY "Authenticated users can read analytics" 
ON public.analytics_events 
FOR SELECT 
TO authenticated 
USING (true);
```

### Example: If you want to restrict shared conversations by visibility:
```sql
CREATE POLICY "Read public or own shared conversations" 
ON public.shared_conversations 
FOR SELECT 
TO public 
USING (is_public = true OR auth.uid()::text = user_id);
```

## Important Notes

1. **Service Role Key**: Keep your `service_role` key secret and only use it server-side
2. **Anon Key**: Use the `anon` key for client-side operations
3. **Test Thoroughly**: RLS can break existing functionality if not configured correctly
4. **Monitor Logs**: Check Supabase logs for any permission errors after enabling RLS

## Verification

After applying the fixes, the security advisor should show:
- ✅ RLS enabled on all public tables
- ✅ Appropriate policies in place
- ✅ No unauthorized access possible