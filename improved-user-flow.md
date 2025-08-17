# Improved User Flow

## Current Problems
1. Users can pay without having an account
2. Paid users can't set passwords
3. No communication with users after payment

## Recommended Flow

### Option 1: Require Account Before Payment (Best)
```
User Journey:
1. User clicks "Upgrade to Pro"
2. Check if logged in:
   - Yes → Go to Stripe checkout
   - No → Show "Create account to continue"
3. User creates account with password
4. Redirect to Stripe checkout
5. After payment, update existing account to Pro
```

### Option 2: Create Account During Checkout (Good)
```
User Journey:
1. User clicks "Upgrade to Pro"
2. Stripe checkout collects email
3. After payment webhook:
   - Check if account exists
   - If not, create with temporary password
   - Send welcome email with password reset link
4. User sets password via email link
```

### Option 3: Magic Link Login (Modern)
```
User Journey:
1. Remove passwords entirely
2. User enters email to login/signup
3. Send magic link to email
4. User clicks link to login
5. No password management needed
```

## Implementation Priority
1. **Immediate**: Add password reset for Nancy and future users
2. **This Week**: Require login before Stripe checkout
3. **Later**: Add email service for better communication