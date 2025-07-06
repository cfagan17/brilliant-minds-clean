require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;
// ADD THIS LINE - Initialize Stripe
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());
app.use(express.static('.')); // Serve static files from current directory

// API endpoint to proxy Claude requests
app.post('/api/claude', async (req, res) => {
    try {
        const { message, figure } = req.body;
        // Remove apiKey from req.body - we'll use our own
        
        console.log('Received request for figure:', figure);
        
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': CLAUDE_API_KEY,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 1200,
                messages: [{
                    role: 'user',
                    content: message
                }]
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Claude API Error:', response.status, errorText);
            return res.status(response.status).json({ error: errorText });
        }
        
        const data = await response.json();
        res.json(data);
        
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { priceId } = req.body;
        
        console.log('Creating checkout session for price:', priceId);
        
        // DEBUG: Log all the header info
        console.log('🔍 Request headers:', {
            origin: req.headers.origin,
            referer: req.headers.referer,
            host: req.headers.host
        });
        
        // Try multiple ways to get the correct URL
        let baseUrl;
        if (req.headers.origin) {
            baseUrl = req.headers.origin;
        } else if (req.headers.referer) {
            baseUrl = req.headers.referer.replace(/\/$/, ''); // Remove trailing slash
        } else {
            baseUrl = 'https://brilliant-minds-clean.vercel.app/';
        }
        
        console.log('🎯 Using baseUrl:', baseUrl);
        console.log('🎯 Success URL will be:', `${baseUrl}?success=true`);
        
        const session = await stripe.checkout.sessions.create({
            mode: 'subscription',
            payment_method_types: ['card'],
            line_items: [
                {
                    price: priceId,
                    quantity: 1,
                },
            ],
            success_url: `${baseUrl}?success=true`,
            cancel_url: `${baseUrl}?canceled=true`,
        });

        res.json({ sessionId: session.id });
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

// Enhanced analytics endpoint with storage
app.post('/api/analytics', async (req, res) => {
    try {
        const event = req.body;
        
        // Log the analytics event
        console.log('📊 Analytics Event:', {
            eventType: event.eventType,
            userId: event.userId,
            timestamp: event.timestamp,
            data: event.data
        });
        
        // Store analytics in memory (simple aggregation)
        if (!global.analyticsData) {
            global.analyticsData = {
                totalEvents: 0,
                dailyStats: {},
                formatPopularity: {},
                userSessions: {},
                conversions: {
                    totalUpgrades: 0,
                    upgradesByDay: {}
                }
            };
        }
        
        const analytics = global.analyticsData;
        const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
        
        // Update global counters
        analytics.totalEvents++;
        
        // Initialize today's stats if needed
        if (!analytics.dailyStats[today]) {
            analytics.dailyStats[today] = {
                sessions: new Set(),
                discussions: 0,
                formatUsage: {},
                upgrades: 0
            };
        }
        
        // Process different event types
        switch (event.eventType) {
            case 'session_start':
                analytics.dailyStats[today].sessions.add(event.userId);
                if (!analytics.userSessions[event.userId]) {
                    analytics.userSessions[event.userId] = {
                        firstSession: event.timestamp,
                        totalSessions: 0,
                        totalDiscussions: 0,
                        isProUser: false
                    };
                }
                analytics.userSessions[event.userId].totalSessions++;
                break;
                
            case 'discussion_start':
                analytics.dailyStats[today].discussions++;
                const format = event.data.format;
                analytics.dailyStats[today].formatUsage[format] = 
                    (analytics.dailyStats[today].formatUsage[format] || 0) + 1;
                analytics.formatPopularity[format] = 
                    (analytics.formatPopularity[format] || 0) + 1;
                    
                if (analytics.userSessions[event.userId]) {
                    analytics.userSessions[event.userId].totalDiscussions++;
                }
                break;
                
            case 'user_upgraded':
                analytics.conversions.totalUpgrades++;
                analytics.conversions.upgradesByDay[today] = 
                    (analytics.conversions.upgradesByDay[today] || 0) + 1;
                analytics.dailyStats[today].upgrades++;
                
                if (analytics.userSessions[event.userId]) {
                    analytics.userSessions[event.userId].isProUser = true;
                }
                break;
        }
        
        res.json({ success: true, received: event.eventType });
        
    } catch (error) {
        console.error('Analytics error:', error);
        res.status(500).json({ error: 'Failed to process analytics' });
    }
});

// Add analytics dashboard endpoint
app.get('/api/analytics/dashboard', (req, res) => {
    try {
        if (!global.analyticsData) {
            return res.json({ message: 'No analytics data yet' });
        }
        
        const analytics = global.analyticsData;
        const today = new Date().toISOString().split('T')[0];
        
        // Convert Sets to counts for JSON response
        const processedDailyStats = {};
        Object.keys(analytics.dailyStats).forEach(date => {
            processedDailyStats[date] = {
                ...analytics.dailyStats[date],
                sessions: analytics.dailyStats[date].sessions.size
            };
        });
        
        const dashboard = {
            overview: {
                totalEvents: analytics.totalEvents,
                totalUpgrades: analytics.conversions.totalUpgrades,
                totalUsers: Object.keys(analytics.userSessions).length,
                todaysSessions: analytics.dailyStats[today]?.sessions.size || 0,
                todaysDiscussions: analytics.dailyStats[today]?.discussions || 0
            },
            formatPopularity: analytics.formatPopularity,
            dailyStats: processedDailyStats,
            recentUpgrades: analytics.conversions.upgradesByDay
        };
        
        res.json(dashboard);
        
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to get dashboard data' });
    }
});


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/chat.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'chat.html'));
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        hasApiKey: !!CLAUDE_API_KEY
    });
});

// Export the app for Vercel (remove the app.listen for serverless)
module.exports = app;

// Only listen when running locally (not on Vercel)
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Open your app at: http://localhost:${PORT}`);
    });
}