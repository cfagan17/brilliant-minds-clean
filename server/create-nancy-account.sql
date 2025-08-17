-- Create account for Nancy who paid on Aug 13
-- Her payment went through but webhook failed to create account

INSERT INTO users (
    email,
    password_hash,
    is_pro,
    subscription_status,
    stripe_customer_id,
    created_at,
    discussions_used,
    total_messages,
    last_reset_date
) VALUES (
    'nancymagnussondurham@gmail.com',
    '$2b$10$TEMP.NEEDS.RESET',  -- She'll need to reset password
    true,
    'active',
    -- We need to get her customer ID from Stripe dashboard
    -- Look for nancymagnussondurham@gmail.com in Stripe
    (SELECT 'cus_' || 'REPLACE_WITH_ID'),  -- Replace with actual ID from Stripe
    '2025-08-13 12:17:48',  -- When she actually subscribed
    0,
    0,
    CURRENT_DATE
) ON CONFLICT (email) DO UPDATE SET
    is_pro = true,
    subscription_status = 'active',
    stripe_customer_id = EXCLUDED.stripe_customer_id;

-- Verify the account was created
SELECT * FROM users WHERE email = 'nancymagnussondurham@gmail.com';