# Deployment Guide for Iconoclash

## Prerequisites

1. Vercel account
2. PostgreSQL database (Vercel Postgres recommended)
3. Stripe account (for payments)
4. Claude API key from Anthropic

## Step 1: Set up PostgreSQL on Vercel

1. Go to your Vercel dashboard
2. Navigate to "Storage" → "Create Database" → "Postgres"
3. Create a new PostgreSQL database
4. Copy the connection string (starts with `postgres://`)

## Step 2: Deploy to Vercel

```bash
# Install Vercel CLI if you haven't
npm i -g vercel

# Deploy
vercel

# Follow the prompts, then set environment variables
```

## Step 3: Set Environment Variables on Vercel

Go to your project settings on Vercel and add these environment variables:

```
# Required
CLAUDE_API_KEY=sk-ant-api03-xxxxx
DATABASE_URL=postgres://xxxxx (from Step 1)
JWT_SECRET=generate-a-32-character-random-string
STRIPE_SECRET_KEY=sk_live_xxxxx
STRIPE_WEBHOOK_SECRET=whsec_xxxxx

# Optional but recommended
NODE_ENV=production
```

## Step 4: Set up Stripe Webhook

1. Go to Stripe Dashboard → Developers → Webhooks
2. Add endpoint: `https://your-app.vercel.app/api/stripe/webhook`
3. Select events: 
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
4. Copy the webhook secret to `STRIPE_WEBHOOK_SECRET`

## Step 5: Initialize Database

The database will auto-initialize on first run, but if you have existing data:

```bash
# Set DATABASE_URL environment variable locally
export DATABASE_URL="your-postgres-connection-string"

# Run migration (if you have existing SQLite data)
node server/migrate-to-postgres.js
```

## Step 6: Test Your Deployment

1. Visit your Vercel URL
2. Create a test account
3. Test the payment flow with Stripe test card: 4242 4242 4242 4242
4. Monitor logs in Vercel dashboard

## Production Checklist

- [ ] PostgreSQL database connected
- [ ] All environment variables set
- [ ] Stripe webhook configured
- [ ] Test payment flow works
- [ ] Error monitoring set up (optional)
- [ ] Custom domain configured (optional)

## Monitoring

- **Vercel Dashboard**: Monitor function logs and errors
- **Database**: Check Vercel Postgres dashboard for connection pool usage
- **Stripe**: Monitor payment success rate

## Scaling Tips

1. **Database Connections**: Default pool size is 20, increase if needed
2. **Function Timeout**: Currently 30s, can increase to 60s if needed
3. **Rate Limiting**: Implemented per IP, consider Redis for per-user limits
4. **Caching**: Add Redis for session caching as you scale

## Troubleshooting

**"Database connection failed"**
- Check DATABASE_URL is set correctly
- Ensure SSL is enabled for production

**"Stripe webhook failed"**
- Verify webhook secret matches
- Check webhook URL includes `/api/stripe/webhook`

**"Users not upgrading to Pro after payment"**
- Check webhook events in Stripe dashboard
- Verify customer email matches user email

## Cost Estimates

At 2,000 active users:
- Vercel Pro: $20/month
- Vercel Postgres: $15/month (up to 60 connections)
- Claude API: $200-1000/month (depending on usage)
- Total: ~$235-1035/month