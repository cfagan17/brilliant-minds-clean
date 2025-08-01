# Production Setup Guide

## What's Been Implemented

### 1. ✅ PostgreSQL Support
- Automatic switching between SQLite (dev) and PostgreSQL (prod)
- Connection pooling with 20 connections
- Proper indexes on all foreign keys
- Migration script for existing data

### 2. ✅ Redis-Based Rate Limiting
- **Free users**: 10 Claude requests/hour
- **Pro users**: 100 Claude requests/hour  
- **Anonymous**: 5 Claude requests/hour
- **Auth endpoints**: 5 attempts/15 minutes (prevents brute force)
- Falls back to in-memory if Redis unavailable

### 3. ✅ Error Monitoring (Sentry)
- Automatic error capture with stack traces
- Performance monitoring for slow operations
- Claude API usage tracking with cost estimates
- Sensitive data filtering (passwords, tokens)

### 4. ✅ Performance Tracking
- Claude API response times
- Cost estimation per request
- Usage analytics in Redis
- Slow operation alerts (>1 second)

## Environment Variables Needed

```bash
# Required for production
DATABASE_URL=postgres://user:pass@host:5432/dbname
REDIS_URL=redis://default:pass@host:6379
SENTRY_DSN=https://xxx@sentry.io/xxx
NODE_ENV=production

# Already configured
CLAUDE_API_KEY=sk-ant-api03-xxx
STRIPE_SECRET_KEY=sk_live_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
JWT_SECRET=your-secret-key
```

## Setting Up Services

### 1. Vercel Postgres (Recommended)
- Go to Vercel Dashboard → Storage → Create Database
- Choose PostgreSQL
- Copy the `DATABASE_URL` from the dashboard

### 2. Upstash Redis (Recommended)
- Create account at upstash.com
- Create new Redis database
- Choose closest region to your users
- Copy the `REDIS_URL`

### 3. Sentry
- Create account at sentry.io
- Create new project → Node.js
- Copy the DSN from project settings

## Rate Limits Explained

### Claude API Limits
| User Type | Requests/Hour | Cost/Month* |
|-----------|--------------|-------------|
| Anonymous | 5            | Free        |
| Free User | 10           | Free        |
| Pro User  | 100          | ~$30-50     |

*Cost estimates based on average message length

### Why These Limits?
- Claude API costs $3/million tokens
- Average conversation = 2,000 tokens = $0.006
- 100 requests/hour × 24 hours = 2,400/day = $14.40/day max
- Most users won't hit limits, keeping costs reasonable

## Monitoring Your App

### 1. Real-time Errors (Sentry)
- View all errors at sentry.io
- Get email alerts for new errors
- See which users are affected

### 2. Usage Analytics (Redis)
```javascript
// View in Redis:
HGETALL usage:daily:2024-01-15  // Daily usage
HGETALL usage:user:123          // User's total usage
```

### 3. Performance Metrics
- Slow Claude API calls (>1s) logged
- High-cost requests (>$0.50) alerted
- Database query times tracked

## Scaling Considerations

### Current Capacity
- **Database**: 20 concurrent connections = ~200-500 active users
- **Redis**: 10,000 connections = ~10,000 active users
- **Rate Limits**: Prevent any single user from overloading

### When to Scale
- Database connections >80% utilized → Increase pool size
- Redis memory >80% → Upgrade plan
- Claude costs >$500/month → Review rate limits

### Next Steps for 10,000+ Users
1. Add caching layer (Redis cache for common queries)
2. Implement Claude response caching
3. Add read replicas for database
4. Consider CDN for static assets

## Cost Breakdown at Scale

### 100 Active Users
- Vercel: $20/month
- Database: $15/month
- Redis: Free tier
- Claude API: ~$50/month
- **Total: ~$85/month**

### 1,000 Active Users
- Vercel: $20/month
- Database: $25/month
- Redis: $10/month
- Claude API: ~$200-500/month
- Sentry: $26/month
- **Total: ~$281-561/month**

### 5,000 Active Users
- Vercel Pro: $150/month
- Database: $50/month
- Redis: $50/month
- Claude API: ~$1,000-2,500/month
- Sentry: $80/month
- **Total: ~$1,330-2,830/month**

## Quick Deployment Checklist

- [ ] Set up Vercel Postgres
- [ ] Set up Upstash Redis
- [ ] Set up Sentry account
- [ ] Add all environment variables to Vercel
- [ ] Deploy with `vercel --prod`
- [ ] Test rate limiting works
- [ ] Verify error tracking in Sentry
- [ ] Monitor first 24 hours closely