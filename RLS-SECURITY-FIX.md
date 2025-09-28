# Password Resets Table - Row Level Security Fix

## Issue
Supabase security alert: Table `public.password_resets` is public but RLS has not been enabled.

## Solution
Run the SQL script `/server/enable-rls-password-resets.sql` in your Supabase SQL editor.

## What the RLS policies do:

1. **INSERT Policy**: Allows anyone to create password reset requests (needed for forgot password flow)
2. **SELECT Policy**: Only allows reading if you have the exact token (prevents enumeration attacks)
3. **UPDATE Policy**: Only allows marking tokens as "used" if they haven't expired
4. **DELETE Policy**: Allows cleanup of expired or used tokens

## Important Notes:

- Your backend server should use the **service role key** (not anon key) to bypass RLS when needed
- The anon key will be restricted by these policies
- These policies prevent:
  - Token enumeration attacks
  - Unauthorized access to other users' reset tokens
  - Modification of reset records by unauthorized users

## To Apply:

1. Go to Supabase Dashboard → SQL Editor
2. Copy the contents of `/server/enable-rls-password-resets.sql`
3. Run the SQL script
4. Verify in Table Editor that RLS is now enabled (lock icon should appear)

## Testing:

After applying, test that:
- Password reset requests still work
- Reset tokens can only be used once
- Expired tokens cannot be used