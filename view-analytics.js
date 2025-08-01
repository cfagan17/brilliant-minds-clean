#!/usr/bin/env node

// Quick analytics viewer - run with: node view-analytics.js
require('dotenv').config();
const { db } = require('./server/database');

const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m'
};

console.log(`\n${colors.bright}${colors.blue}📊 ICONOCLASH ANALYTICS SUMMARY${colors.reset}\n`);

// Today's stats
const today = new Date().toISOString().split('T')[0];
const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
const lastWeek = new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0];

// Get key metrics
async function getAnalytics() {
    try {
        // Today's activity
        const todayStats = await new Promise((resolve, reject) => {
            db.get(`
                SELECT 
                    COUNT(DISTINCT CASE WHEN event_type = 'landing_page_view' THEN user_id END) as visitors,
                    COUNT(DISTINCT CASE WHEN event_type = 'signup_completed' THEN user_id END) as signups,
                    COUNT(DISTINCT CASE WHEN event_type = 'discussion_started' THEN user_id END) as active_users,
                    COUNT(CASE WHEN event_type = 'discussion_started' THEN 1 END) as discussions,
                    COUNT(DISTINCT CASE WHEN event_type = 'payment_completed' THEN user_id END) as new_customers
                FROM analytics_events
                WHERE DATE(timestamp) = ?
            `, [today], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        // Revenue stats
        const revenueStats = await new Promise((resolve, reject) => {
            db.get(`
                SELECT 
                    COALESCE(SUM(CAST(json_extract(event_data, '$.amount') AS REAL)), 0) as revenue_today
                FROM analytics_events
                WHERE event_type = 'payment_completed' 
                AND DATE(timestamp) = ?
            `, [today], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        // Cost stats
        const costStats = await new Promise((resolve, reject) => {
            db.get(`
                SELECT 
                    COUNT(*) as api_calls,
                    COALESCE(SUM(CAST(json_extract(event_data, '$.cost') AS REAL)), 0) as total_cost
                FROM analytics_events
                WHERE event_type = 'claude_api_cost'
                AND DATE(timestamp) = ?
            `, [today], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        // Weekly trends
        const weeklyTrends = await new Promise((resolve, reject) => {
            db.all(`
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(DISTINCT CASE WHEN event_type = 'discussion_started' THEN user_id END) as active_users,
                    COUNT(DISTINCT CASE WHEN event_type = 'signup_completed' THEN user_id END) as signups
                FROM analytics_events
                WHERE DATE(timestamp) >= ?
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            `, [lastWeek], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });

        // Total users
        const totalUsers = await new Promise((resolve, reject) => {
            db.get(`
                SELECT 
                    COUNT(DISTINCT CASE WHEN event_type = 'signup_completed' THEN user_id END) as total_signups,
                    COUNT(DISTINCT CASE WHEN event_type = 'payment_completed' THEN user_id END) as total_paying
                FROM analytics_events
            `, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        // Display results
        console.log(`${colors.bright}📅 TODAY (${today})${colors.reset}`);
        console.log(`├─ Visitors: ${colors.cyan}${todayStats.visitors || 0}${colors.reset}`);
        console.log(`├─ Signups: ${colors.green}${todayStats.signups || 0}${colors.reset}`);
        console.log(`├─ Active Users: ${colors.blue}${todayStats.active_users || 0}${colors.reset}`);
        console.log(`├─ Discussions: ${colors.yellow}${todayStats.discussions || 0}${colors.reset}`);
        console.log(`└─ New Customers: ${colors.bright}${colors.green}${todayStats.new_customers || 0}${colors.reset}\n`);

        console.log(`${colors.bright}💰 FINANCIALS${colors.reset}`);
        const revenue = revenueStats.revenue_today || 0;
        const costs = costStats.total_cost || 0;
        const profit = revenue - costs;
        const margin = revenue > 0 ? (profit / revenue * 100) : 0;
        
        console.log(`├─ Revenue Today: ${colors.green}$${revenue.toFixed(2)}${colors.reset}`);
        console.log(`├─ Costs Today: ${colors.red}$${costs.toFixed(2)}${colors.reset} (${costStats.api_calls} API calls)`);
        console.log(`├─ Profit Today: ${profit >= 0 ? colors.green : colors.red}$${profit.toFixed(2)}${colors.reset}`);
        console.log(`└─ Margin: ${margin >= 50 ? colors.green : colors.yellow}${margin.toFixed(1)}%${colors.reset}\n`);

        console.log(`${colors.bright}📈 TOTALS${colors.reset}`);
        console.log(`├─ Total Signups: ${colors.blue}${totalUsers.total_signups || 0}${colors.reset}`);
        console.log(`├─ Total Paying: ${colors.green}${totalUsers.total_paying || 0}${colors.reset}`);
        console.log(`└─ Conversion Rate: ${colors.cyan}${((totalUsers.total_paying / totalUsers.total_signups) * 100).toFixed(1)}%${colors.reset}\n`);

        console.log(`${colors.bright}📊 LAST 7 DAYS${colors.reset}`);
        weeklyTrends.forEach(day => {
            const isToday = day.date === today;
            console.log(`${isToday ? colors.bright : ''}${day.date}: ${day.active_users} active, ${day.signups} signups${colors.reset}`);
        });

        // Conversion funnel
        const funnelData = await new Promise((resolve, reject) => {
            db.get(`
                SELECT 
                    COUNT(DISTINCT CASE WHEN event_type = 'landing_page_view' THEN user_id END) as visitors,
                    COUNT(DISTINCT CASE WHEN event_type = 'first_interaction' THEN user_id END) as engaged,
                    COUNT(DISTINCT CASE WHEN event_type = 'signup_completed' THEN user_id END) as signups,
                    COUNT(DISTINCT CASE WHEN event_type = 'discussion_started' THEN user_id END) as active,
                    COUNT(DISTINCT CASE WHEN event_type = 'payment_completed' THEN user_id END) as paying
                FROM analytics_events
                WHERE DATE(timestamp) >= ?
            `, [lastWeek], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        console.log(`\n${colors.bright}🎯 CONVERSION FUNNEL (Last 7 Days)${colors.reset}`);
        console.log(`├─ Visitors: ${funnelData.visitors}`);
        console.log(`├─ Engaged: ${funnelData.engaged} (${((funnelData.engaged/funnelData.visitors)*100).toFixed(1)}%)`);
        console.log(`├─ Signups: ${funnelData.signups} (${((funnelData.signups/funnelData.engaged)*100).toFixed(1)}%)`);
        console.log(`├─ Active: ${funnelData.active} (${((funnelData.active/funnelData.signups)*100).toFixed(1)}%)`);
        console.log(`└─ Paying: ${funnelData.paying} (${((funnelData.paying/funnelData.active)*100).toFixed(1)}%)`);

        console.log(`\n${colors.bright}💡 INSIGHTS${colors.reset}`);
        
        // Provide insights
        if (margin < 50) {
            console.log(`${colors.yellow}⚠️  Low profit margin (${margin.toFixed(1)}%). Consider raising prices or reducing API usage.${colors.reset}`);
        }
        
        if (todayStats.signups > 0 && todayStats.active_users / todayStats.signups < 0.5) {
            console.log(`${colors.yellow}⚠️  Low activation rate. Improve onboarding experience.${colors.reset}`);
        }
        
        if (funnelData.paying / funnelData.active < 0.05) {
            console.log(`${colors.yellow}⚠️  Low pro conversion (${((funnelData.paying/funnelData.active)*100).toFixed(1)}%). A/B test pricing or features.${colors.reset}`);
        }

        console.log(`\n${colors.cyan}View full dashboard at: /analytics-dashboard.html${colors.reset}`);
        console.log(`${colors.cyan}API endpoints: /api/analytics/dashboard, /api/analytics/funnel, /api/analytics/revenue${colors.reset}\n`);

    } catch (error) {
        console.error(`${colors.red}Error loading analytics:${colors.reset}`, error);
    } finally {
        process.exit(0);
    }
}

getAnalytics();