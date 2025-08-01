# 🚀 Launch Checklist for Iconoclash

## Pre-Launch Setup (Do This First!)

### 1. Set Admin Credentials
Add these to your `.env` file:
```bash
ADMIN_EMAIL=your-email@gmail.com
ADMIN_PASSWORD=generate-a-secure-password-here
```

Generate a secure password:
```bash
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
```

### 2. Test Locally One More Time
```bash
npm run dev
# Visit http://localhost:3000
# Login with your admin credentials
# Test all features
```

## Launch Steps

### ✅ Step 1: Push to GitHub
```bash
git add .
git commit -m "Launch ready - added admin features and analytics"
git push origin main
```

### ✅ Step 2: Deploy to Vercel
```bash
vercel --prod
```

### ✅ Step 3: Set Environment Variables on Vercel
Go to your Vercel project → Settings → Environment Variables

**Required:**
```
CLAUDE_API_KEY=your-claude-api-key
DATABASE_URL=your-postgres-url (from Vercel Storage)
JWT_SECRET=generate-random-32-chars
STRIPE_SECRET_KEY=sk_live_xxx (switch to LIVE key!)
STRIPE_WEBHOOK_SECRET=whsec_xxx
ADMIN_EMAIL=your-email@gmail.com
ADMIN_PASSWORD=your-secure-password
NODE_ENV=production
```

**Optional but Recommended:**
```
REDIS_URL=your-redis-url (from Upstash)
SENTRY_DSN=your-sentry-dsn
```

### ✅ Step 4: Set Up Database
1. Go to Vercel Dashboard → Storage
2. Create PostgreSQL database
3. Copy the DATABASE_URL to environment variables

### ✅ Step 5: Configure Stripe Webhook
1. Go to Stripe Dashboard → Webhooks
2. Add endpoint: `https://your-domain.vercel.app/api/stripe/webhook`
3. Select events:
   - checkout.session.completed
   - customer.subscription.updated
   - customer.subscription.deleted
4. Copy webhook secret to STRIPE_WEBHOOK_SECRET

### ✅ Step 6: Buy & Connect Domain
1. Buy domain on Namecheap (e.g., iconoclash.com)
2. In Vercel: Settings → Domains → Add Domain
3. Follow Vercel's instructions to update Namecheap DNS
4. Wait 10-30 minutes for DNS propagation

### ✅ Step 7: Switch Stripe to Live Mode
1. Get your LIVE API keys from Stripe
2. Update STRIPE_SECRET_KEY in Vercel
3. Update webhook with live endpoint

## Post-Launch Verification

### 🔍 Test Everything
1. **Visit your domain** (not the vercel.app URL)
2. **Test signup flow** with a real email
3. **Test payment** with real card (you can refund yourself)
4. **Check analytics** at `/analytics-dashboard.html`

### 📊 Access Your Analytics
1. Login with your admin account
2. Navigate to `/analytics-dashboard.html`
3. Or run locally: `node view-analytics.js`

### 🛡️ Admin Features
- Your admin account has unlimited usage
- It won't affect analytics (marked as test account)
- You can view all analytics dashboards
- Regular users cannot access analytics

## First Week Monitoring

### Daily Checks
- [ ] Check error logs in Vercel dashboard
- [ ] Review analytics for user signups
- [ ] Monitor Claude API costs
- [ ] Check Stripe for successful payments

### Metrics to Watch
- **Signup rate**: Should be >5% of visitors
- **Activation rate**: Should be >50% of signups
- **Error rate**: Should be <1%
- **Page load time**: Should be <3 seconds

## If Something Goes Wrong

### "Site not working"
1. Check Vercel dashboard for errors
2. Verify all environment variables are set
3. Check database connection

### "Payments not working"
1. Verify Stripe is in LIVE mode
2. Check webhook is configured
3. Look for errors in Vercel logs

### "Can't see analytics"
1. Make sure you're logged in as admin
2. Check browser console for errors
3. Verify DATABASE_URL is set

### Emergency Rollback
```bash
vercel rollback
```

## You're Ready! 🎉

Remember:
- **You're the admin** - only you can see analytics
- **Test mode enabled** - your usage won't affect metrics
- **Everything is tracked** - you'll see exactly how users behave
- **It's normal to be nervous** - but you've built something amazing!

## Support Contacts
- **Vercel Issues**: support@vercel.com
- **Stripe Issues**: support.stripe.com
- **Domain Issues**: Namecheap live chat

Good luck with your launch! You've got this! 🚀