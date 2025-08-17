# Password Reset Implementation Plan

## Option A: Quick Fix (Temporary)
Create a simple admin tool to manually reset passwords:
1. Admin enters user email and new password
2. System updates password_hash in database
3. Admin emails user their new password

## Option B: Proper Implementation
1. Add "Forgot Password" link to login form
2. User enters email
3. Generate reset token and save to database
4. Email user a reset link
5. User clicks link and sets new password

## Database Changes Needed
```sql
-- Add password reset tokens table
CREATE TABLE password_resets (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used BOOLEAN DEFAULT false
);

-- Tokens expire after 1 hour
CREATE INDEX idx_password_resets_token ON password_resets(token);
```

## Email Service Options
1. SendGrid (easy, reliable)
2. AWS SES (cheap at scale)
3. Resend (modern, developer-friendly)
4. Postmark (great deliverability)

## Required Environment Variables
- EMAIL_API_KEY
- EMAIL_FROM_ADDRESS
- APP_URL (for reset links)