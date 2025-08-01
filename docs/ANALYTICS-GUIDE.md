# Analytics Implementation Guide

## Overview

Your app now has comprehensive analytics tracking that gives you the data needed to optimize for profitability. The system tracks the entire user journey from landing to payment, with detailed cost analysis.

## What's Tracked

### 1. Conversion Funnel
- **Landing Page Views** → First Interaction → Signup → Active User → Paying Customer
- Conversion rates at each stage
- Drop-off analysis

### 2. User Behavior
- Session duration and engagement
- Feature usage patterns
- Discussion formats popularity
- Message frequency
- Time on site milestones (30s, 60s, 3m)

### 3. Revenue Metrics
- Daily/monthly revenue
- Average order value
- Customer lifetime value
- Payment success/failure rates

### 4. Cost Analysis
- Claude API usage per user
- Cost per conversation
- Token usage patterns
- Profit margins

### 5. Retention Metrics
- Daily/weekly/monthly active users
- Cohort retention curves
- Churn risk indicators

## Accessing Analytics

### Dashboard API Endpoints

```bash
# Main dashboard (requires auth)
GET /api/analytics/dashboard

# Conversion funnel
GET /api/analytics/funnel?startDate=2024-01-01&endDate=2024-01-31

# Revenue metrics
GET /api/analytics/revenue?startDate=2024-01-01&endDate=2024-01-31

# Cohort retention
GET /api/analytics/retention/2024-01-15?days=30
```

### Dashboard Response Example

```json
{
  "overview": {
    "today": {
      "visitors": 150,
      "signups": 12,
      "active_users": 45,
      "discussions": 230,
      "paying_users": 3
    },
    "change": {
      "visitors": 15.3,  // % change from yesterday
      "signups": -8.3,
      "active_users": 22.1
    }
  },
  "conversion": {
    "funnel": {
      "visitor_to_engaged": 32.5,
      "engaged_to_signup": 18.2,
      "signup_to_active": 75.3,
      "active_to_paying": 6.8,
      "overall": 2.8
    }
  },
  "revenue": {
    "total": 156.00,
    "byDate": [...]
  },
  "costs": {
    "total": 48.32,
    "byDate": [...]
  },
  "profitability": {
    "revenue": 156.00,
    "costs": 48.32,
    "profit": 107.68,
    "margin": 69.0
  }
}
```

## Key Metrics to Watch

### For Growth
1. **Visitor → Signup Rate** (Target: >10%)
2. **Signup → Active Rate** (Target: >60%)
3. **Daily Active Users** growth rate

### For Profitability
1. **Cost per Active User** (Claude API / Active Users)
2. **Revenue per User** (Total Revenue / Active Users)
3. **Conversion to Pro** (Target: >5% of active users)
4. **Profit Margin** (Should be >50%)

### Red Flags
- Cost per user > $0.50/day
- Signup → Active < 40%
- Session duration < 2 minutes
- Pro conversion < 2%

## Using Data to Optimize

### 1. Improve Conversion
- If signup rate is low → A/B test landing page
- If activation is low → Improve onboarding
- If Pro conversion is low → Test pricing/features

### 2. Reduce Costs
- Track high-usage users
- Implement response caching
- Consider cheaper models for some responses

### 3. Increase Engagement
- Track popular discussion formats
- See when users drop off
- Identify power users

## Privacy & Compliance

The analytics system:
- Doesn't store full email addresses (only domains)
- Uses anonymous IDs for non-logged users
- Respects user privacy
- Can be extended for GDPR compliance

## Integrating with External Tools

While the built-in analytics are comprehensive, you can also send data to:

### Mixpanel/Amplitude
```javascript
// In analytics-client.js
if (window.mixpanel) {
    mixpanel.track(eventName, data);
}
```

### Google Analytics
```javascript
if (window.gtag) {
    gtag('event', eventName, data);
}
```

### Custom Webhooks
Add to server/analytics.js to forward events to external services.

## SQL Queries for Deep Analysis

### Find your most valuable users
```sql
SELECT 
    user_id,
    COUNT(CASE WHEN event_type = 'discussion_started' THEN 1 END) as discussions,
    SUM(CAST(json_extract(event_data, '$.cost') AS REAL)) as total_cost,
    MAX(CASE WHEN event_type = 'payment_completed' THEN 1 ELSE 0 END) as is_paying
FROM analytics_events
GROUP BY user_id
ORDER BY discussions DESC
LIMIT 100;
```

### Conversion funnel by day
```sql
SELECT 
    DATE(timestamp) as date,
    COUNT(DISTINCT CASE WHEN event_type = 'landing_page_view' THEN user_id END) as visitors,
    COUNT(DISTINCT CASE WHEN event_type = 'signup_completed' THEN user_id END) as signups,
    CAST(COUNT(DISTINCT CASE WHEN event_type = 'signup_completed' THEN user_id END) AS FLOAT) / 
    COUNT(DISTINCT CASE WHEN event_type = 'landing_page_view' THEN user_id END) * 100 as conversion_rate
FROM analytics_events
WHERE timestamp > datetime('now', '-30 days')
GROUP BY DATE(timestamp)
ORDER BY date DESC;
```

## Next Steps

1. **Set up monitoring alerts** for key metrics
2. **Create a weekly analytics review** process
3. **A/B test** based on funnel drop-offs
4. **Optimize costs** based on usage patterns
5. **Build retention** features for engaged users

Your analytics are now as sophisticated as companies with dedicated data teams!