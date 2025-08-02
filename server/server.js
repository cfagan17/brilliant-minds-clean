// Only load dotenv in development
if (process.env.NODE_ENV !== 'production') {
    try {
        require('dotenv').config();
    } catch (e) {
        // dotenv not available, that's OK in production
    }
}
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { db, initializeDatabase, USE_POSTGRES } = require('./database');
const { initializeSentry, errorHandler, logEvent, trackPerformance, trackClaudeUsage } = require('./monitoring');
// Redis rate limiting removed - using database-based discussion tracking instead
const { analytics, ANALYTICS_EVENTS } = require('./analytics');
const { createAdminUser, requireAdmin, isTestAccount } = require('./admin');

const app = express();

// Trust proxy for Vercel deployment
app.set('trust proxy', true);

// Initialize Sentry error monitoring
initializeSentry(app);

const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// Initialize Stripe
let stripe;
try {
  if (process.env.STRIPE_SECRET_KEY) {
    stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  } else {
    console.log('⚠️  Stripe not configured - payment features disabled');
  }
} catch (error) {
  console.log('⚠️  Stripe initialization failed:', error.message);
}

// Claude API function
async function makeClaudeRequest(message, userId = null) {
    console.log('Claude API key present:', !!CLAUDE_API_KEY);
    if (!CLAUDE_API_KEY) {
        console.error('CLAUDE_API_KEY environment variable is not set');
        throw new Error('Claude API key not configured - please set CLAUDE_API_KEY environment variable');
    }

    const startTime = Date.now();
    
    try {
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': CLAUDE_API_KEY,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 12000,
                temperature: 0.7,
                system: "You are helping facilitate intellectual discussions between historical figures in Iconoclash. Respond authentically to the character you're embodying while being helpful and engaging.",
                messages: [
                    {
                        role: 'user',
                        content: message
                    }
                ]
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Claude API Error:', response.status, errorText);
            
            if (response.status === 529) {
                throw new Error('Claude API is temporarily overloaded. Please try again in a moment.');
            }
            
            throw new Error(`Claude API error: ${response.status} - ${errorText}`);
        }

        const result = await response.json();
        
        // Track performance and usage
        const duration = Date.now() - startTime;
        trackPerformance('claude_api_call', duration, { userId });
        
        // Estimate cost (rough estimate based on input/output tokens)
        const estimatedTokens = (message.length + (result.content?.[0]?.text?.length || 0)) / 4;
        const estimatedCost = (estimatedTokens / 1000000) * 3; // $3 per million tokens
        
        if (userId) {
            trackClaudeUsage(userId, 'claude-sonnet-4', estimatedTokens, estimatedCost);
            // Usage tracking handled by database discussions_used counter
            
            // Track for analytics
            await analytics.trackEvent(ANALYTICS_EVENTS.CLAUDE_API_COST, userId, {
                tokens: estimatedTokens,
                cost: estimatedCost,
                model: 'claude-sonnet-4',
                messageLength: message.length,
                responseLength: result.content?.[0]?.text?.length || 0
            });
        }
        
        return result;
    } catch (error) {
        console.error('Claude request failed:', error);
        
        // Track failed requests
        const duration = Date.now() - startTime;
        trackPerformance('claude_api_error', duration, { userId, error: error.message });
        
        throw error;
    }
}

// IMPORTANT: Add webhook before express.json() middleware
app.use('/api/stripe/webhook', express.raw({type: 'application/json'}));
// IMPORTANT: Add webhook before express.json() middleware
app.use('/api/stripe/webhook', express.raw({type: 'application/json'}));

// Initialize database with proper async handling
let dbInitialized = false;
let dbInitPromise = null;

async function ensureDbInitialized() {
    if (dbInitialized) return;
    
    if (!dbInitPromise) {
        dbInitPromise = initializeDatabase()
            .then(() => {
                dbInitialized = true;
                console.log('✅ Database initialized successfully');
            })
            .catch(error => {
                console.error('❌ Database initialization error:', error);
                // In serverless, we might need to retry on next request
                dbInitPromise = null;
                throw error;
            });
    }
    
    return dbInitPromise;
}

// Initialize on startup (best effort)
ensureDbInitialized().catch(err => {
    console.error('Initial database setup failed:', err);
    // Don't crash the server, will retry on first request
});

// Create admin user on startup (only if database is available)
if (typeof createAdminUser === 'function') {
    setTimeout(() => {
        createAdminUser().catch(err => console.error('Admin setup error:', err));
    }, 1000);
}

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..'))); // Serve static files from current directory

// Favicon route
app.get('/favicon.ico', (req, res) => {
    res.status(204).end();
});

// Auth middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Optional auth middleware (allows both authenticated and guest users)
function optionalAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (!err) {
                req.user = user;
            }
        });
    }
    next();
}

// Helper function to reset daily discussions if new day
function resetDailyDiscussions(userId, callback) {
    db.run(`
        UPDATE users 
        SET discussions_used = CASE 
            WHEN last_reset_date != CURRENT_DATE THEN 0
            ELSE discussions_used 
        END,
        last_reset_date = CURRENT_DATE
        WHERE id = ?
    `, [userId], callback);
}

// ============================================================================
// STRIPE WEBHOOK (MUST BE BEFORE OTHER ROUTES)
// ============================================================================

app.post('/api/stripe/webhook', (req, res) => {
    if (!stripe) {
    return res.status(503).json({ error: 'Stripe not configured' });
  }
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.log(`⚠️  Webhook signature verification failed.`, err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the checkout.session.completed event
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        console.log('🎉 Payment successful for session:', session.id);
        
        // Get customer email from session
        const customerEmail = session.customer_details?.email;
        
        if (customerEmail) {
            // Update user to pro status
            db.run(`
                UPDATE users 
                SET is_pro = TRUE, 
                    stripe_customer_id = ?, 
                    subscription_status = 'active'
                WHERE email = ?
            `, [session.customer, customerEmail], function(err) {
                if (err) {
                    console.error('Error updating user to pro:', err);
                } else {
                    console.log(`✅ User ${customerEmail} upgraded to Pro`);
                    
                    // Track payment conversion
                    db.get('SELECT id FROM users WHERE email = ?', [customerEmail], (err, user) => {
                        if (!err && user) {
                            analytics.trackEvent(ANALYTICS_EVENTS.PAYMENT_COMPLETED, user.id, {
                                amount: session.amount_total / 100, // Convert from cents
                                currency: session.currency,
                                customerId: session.customer,
                                subscriptionId: session.subscription
                            }).catch(err => console.error('Analytics error:', err));
                        }
                    });
                }
            });
        }
    }

    // Handle subscription updates
    if (event.type === 'customer.subscription.updated') {
        const subscription = event.data.object;
        
        db.run(`
            UPDATE users 
            SET subscription_id = ?, 
                subscription_status = ?
            WHERE stripe_customer_id = ?
        `, [subscription.id, subscription.status, subscription.customer]);
    }

    // Handle subscription cancellations
    if (event.type === 'customer.subscription.deleted') {
        const subscription = event.data.object;
        
        db.run(`
            UPDATE users 
            SET is_pro = FALSE, 
                subscription_status = 'canceled'
            WHERE stripe_customer_id = ?
        `, [subscription.customer]);
    }

    res.json({received: true});
});

// ============================================================================
// AUTH ROUTES
// ============================================================================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok',
        environment: process.env.NODE_ENV || 'development',
        hasClaudeKey: !!process.env.CLAUDE_API_KEY,
        hasJwtSecret: !!process.env.JWT_SECRET,
        hasStripeKey: !!process.env.STRIPE_SECRET_KEY
    });
});

// Register new user (10 daily discussions for free tier)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Create user
        db.run('INSERT INTO users (email, password_hash) VALUES (?, ?)', 
               [email, passwordHash], function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    return res.status(400).json({ error: 'Email already exists' });
                }
                return res.status(500).json({ error: 'Failed to create user' });
            }

            // Create token
            const token = jwt.sign({ userId: this.lastID }, JWT_SECRET, { expiresIn: '30d' });
            
            // Track signup conversion
            analytics.trackEvent(ANALYTICS_EVENTS.SIGNUP_COMPLETED, this.lastID, {
                email,
                source: req.body.utm_source,
                campaign: req.body.utm_campaign,
                referrer: req.headers.referer
            }).catch(err => console.error('Analytics error:', err));
            
            res.json({
                token,
                user: {
                    id: this.lastID,
                    email,
                    isProUser: false,
                    discussionsUsed: 0,
                    dailyLimit: 10,
                    remaining: 10
                }
            });
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Server error' });
            }

            if (!user || !await bcrypt.compare(password, user.password_hash)) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
            
            res.json({
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    isProUser: false,
                    discussionsUsed: user.discussions_used
                }
            });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get current user info
app.get('/api/auth/me', authenticateToken, (req, res) => {
    db.get('SELECT * FROM users WHERE id = ?', [req.user.userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Only reset for Pro users (they get unlimited daily)
        // Free users keep their total count
        if (user.is_pro) {
            resetDailyDiscussions(user.id, () => {
                // Get updated user data
                db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, updatedUser) => {
                    res.json({
                        id: updatedUser.id,
                        email: updatedUser.email,
                        isProUser: true,
                        discussionsUsed: updatedUser.discussions_used,
                        dailyLimit: 'unlimited',
                        remaining: 'unlimited'
                    });
                });
            });
        } else {
            // Free user - return daily usage (resets each day)
            res.json({
                id: user.id,
                email: user.email,
                isProUser: user.is_pro,
                discussionsUsed: user.discussions_used,
                dailyLimit: 10,
                remaining: Math.max(0, 10 - user.discussions_used)
            });
        }
    });
});

// ============================================================================
// CLAUDE API (FIXED WITH CONSISTENT LIMITS)
// ============================================================================

// Enhanced rate limiting for guests (10 daily)
const guestRateLimit = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours (daily reset)
    max: 10,
    message: { 
        error: 'You\'ve used your 10 free discussions for today! Upgrade to Pro for unlimited access.',
        signupRequired: true,
        limit: true,
        guestLimitReached: true
    },
    skip: (req) => {
        // Skip rate limiting for authenticated users
        return !!req.user;
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Trust proxy is already set, use a simple key generator
    keyGenerator: (req) => {
        return req.ip || req.connection.remoteAddress || 'unknown';
    }
});

// Apply rate limiting to Claude endpoint for guests only
app.use('/api/claude', guestRateLimit);

// Endpoint for speaker suggestions - doesn't count against usage
app.post('/api/suggest-speakers', async (req, res) => {
    try {
        console.log('Speaker suggestion endpoint called - NO AUTH, NO LIMITS');
        const { message } = req.body;
        
        if (!message || typeof message !== 'string') {
            return res.status(400).json({ error: 'Message is required' });
        }
        
        // Make request without ANY tracking or limits
        console.log('Making Claude request for speaker suggestions');
        const claudeResponse = await makeClaudeRequest(message, null);
        console.log('Speaker suggestion successful');
        
        res.json({
            ...claudeResponse,
            usage: {
                isSuggestion: true,
                counted: false
            }
        });
    } catch (error) {
        console.error('Speaker suggestion error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({ 
            error: 'Failed to get speaker suggestions',
            details: error.message,
            hint: error.message.includes('Claude API key') ? 'Please ensure CLAUDE_API_KEY is set in Vercel environment variables' : undefined
        });
    }
});

// API endpoint to proxy Claude requests (UPDATED MODEL)
app.post('/api/claude', optionalAuth, async (req, res) => {
    try {
        const { message, figure, format, sessionId } = req.body;
        
        // Validate input
        if (!message || typeof message !== 'string' || message.trim().length === 0) {
            return res.status(400).json({ error: 'Message is required' });
        }
        
        // Check usage limits for authenticated users (NO DAILY RESET)
        if (req.user) {
            // Get user data and check limits - NO daily reset for free users
            db.get('SELECT * FROM users WHERE id = ?', [req.user.userId], async (err, user) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                
                if (!user) {
                    return res.status(404).json({ error: 'User not found' });
                }
                
                // Reset daily discussions for ALL users (free get 10/day, pro get unlimited)
                resetDailyDiscussions(user.id, async () => {
                    await processAuthenticatedRequest(req, res, user.id, message);
                });
            });
        } else {
            // Guest user - limited to 10 per day (handled by rate limiting middleware)
            try {
                console.log('Making Claude API request for guest user:', req.ip);
                const claudeResponse = await makeClaudeRequest(message, `anon_${req.ip}`);
                console.log('Claude API response received for guest');
                
                // Get current usage from rate limit headers
                const remaining = res.getHeader('X-RateLimit-Remaining') || 0;
                const used = 10 - remaining;
                
                res.json({
                    ...claudeResponse,
                    usage: {
                        used: used,
                        limit: 10,
                        remaining: remaining,
                        isProUser: false,
                        userType: 'anonymous'
                    },
                    message: remaining <= 1 
                        ? 'Sign up for 10 total discussions and advanced features!' 
                        : `${remaining} anonymous discussions remaining. Sign up for 10 total discussions!`
                });
            } catch (error) {
                console.error('Claude API error for guest:', error);
                res.status(500).json({ 
                    error: 'Failed to get AI response',
                    details: error.message 
                });
            }
        }
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

// Helper function to process authenticated requests
async function processAuthenticatedRequest(req, res, userId, message) {
    // Track discussion start (only for non-test accounts)
    const isTest = await isTestAccount(userId);
    if (!isTest) {
        analytics.trackEvent(ANALYTICS_EVENTS.DISCUSSION_STARTED, userId, {
            format: req.body.format || 'chat',
            sessionId: req.body.sessionId,
            userAgent: req.headers['user-agent']
        }).catch(err => console.error('Analytics error:', err));
    }
    
    db.get('SELECT * FROM users WHERE id = ?', [userId], async (err, user) => {
        if (err) {
            console.error('Database error getting user:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        // Free registered users get 10 per day (same as anonymous)
        if (!user.is_pro && user.discussions_used >= 10) {
            return res.status(429).json({ 
                error: 'You\'ve used your 10 free discussions for today. Upgrade to Pro for unlimited access!',
                limit: true,
                remaining: 0,
                dailyLimit: 10,
                isProUser: false,
                authLimitReached: true
            });
        }
        
        try {
            // Make Claude API call
            console.log('Making Claude API request for user:', user.id);
            const claudeResponse = await makeClaudeRequest(message, user.id);
            console.log('Claude API response received');
            
            // Increment usage counter
            db.run('UPDATE users SET discussions_used = discussions_used + 1 WHERE id = ?', 
                   [userId], (err) => {
                if (err) {
                    console.error('Error updating usage counter:', err);
                }
            });
            
            // Return response with daily usage info
            res.json({
                ...claudeResponse,
                usage: {
                    used: user.discussions_used + 1,
                    limit: user.is_pro ? 'unlimited' : 10,
                    remaining: user.is_pro ? 'unlimited' : Math.max(0, 10 - (user.discussions_used + 1)),
                    isProUser: user.is_pro,
                    userType: 'authenticated',
                    dailyUsage: true // Both free and pro reset daily
                }
            });
        } catch (claudeError) {
            console.error('Claude API error:', claudeError);
            console.error('Full error details:', claudeError.stack);
            res.status(500).json({ 
                error: 'Failed to get AI response',
                details: claudeError.message 
            });
        }
    });
}

// ============================================================================
// STRIPE CHECKOUT (ENHANCED)
// ============================================================================

// Manual payment verification for development (when webhooks aren't available)
app.post('/api/verify-payment', authenticateToken, async (req, res) => {
    try {
        if (!stripe) {
            return res.status(503).json({ error: 'Payment system not configured' });
        }
        
        const { sessionId } = req.body;
        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID required' });
        }
        
        // Retrieve the session from Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        
        if (session.payment_status === 'paid' && session.customer_details?.email) {
            // Update user to pro status
            db.run(`
                UPDATE users 
                SET is_pro = TRUE, 
                    stripe_customer_id = ?, 
                    subscription_status = 'active'
                WHERE email = ?
            `, [session.customer, session.customer_details.email], function(err) {
                if (err) {
                    console.error('Error updating user to pro:', err);
                    return res.status(500).json({ error: 'Failed to update user status' });
                }
                
                console.log(`✅ User ${session.customer_details.email} manually verified and upgraded to Pro`);
                res.json({ 
                    success: true, 
                    message: 'Successfully upgraded to Pro!',
                    isProUser: true 
                });
            });
        } else {
            res.status(400).json({ error: 'Payment not completed or email not found' });
        }
    } catch (error) {
        console.error('Error verifying payment:', error);
        res.status(500).json({ error: 'Failed to verify payment' });
    }
});

app.post('/api/create-checkout-session', optionalAuth, async (req, res) => {
    try {
        // Check if Stripe is configured
        if (!stripe) {
            console.error('Stripe is not configured');
            return res.status(503).json({ error: 'Payment system is not configured. Please contact support.' });
        }
        
        const { priceId } = req.body;
        
        console.log('Creating checkout session for price:', priceId);
        
        // Get base URL
        let baseUrl;
        if (req.headers.origin) {
            baseUrl = req.headers.origin;
        } else if (req.headers.referer) {
            baseUrl = req.headers.referer.replace(/\/$/, '');
        } else {
            baseUrl = 'http://localhost:3000'; // Fallback for development
        }
        
        const sessionConfig = {
            mode: 'subscription',
            payment_method_types: ['card'],
            line_items: [
                {
                    price: priceId,
                    quantity: 1,
                },
            ],
            success_url: `${baseUrl}/?success=true`,
            cancel_url: `${baseUrl}/?canceled=true`,
        };
        
        // If user is authenticated, prefill their email
        if (req.user) {
            db.get('SELECT email FROM users WHERE id = ?', [req.user.userId], async (err, user) => {
                if (!err && user) {
                    sessionConfig.customer_email = user.email;
                }
                
                const session = await stripe.checkout.sessions.create(sessionConfig);
                
                // Store session ID for manual verification (development)
                db.run('UPDATE users SET last_checkout_session = ? WHERE id = ?', 
                    [session.id, req.user.userId]);
                
                res.json({ sessionId: session.id });
            });
        } else {
            const session = await stripe.checkout.sessions.create(sessionConfig);
            
            // Store session ID for manual verification (development)
            if (req.user) {
                db.run('UPDATE users SET last_checkout_session = ? WHERE id = ?', 
                    [session.id, req.user.userId]);
            }
            
            res.json({ sessionId: session.id });
        }

    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

// ============================================================================
// ANALYTICS (ENHANCED)
// ============================================================================

// Initialize analytics data structure
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

// Store analytics in database
app.post('/api/analytics', async (req, res) => {
    try {
        const event = req.body;
        
        // Log the analytics event
        console.log('📊 Analytics Event:', {
            eventType: event.eventType,
            userId: event.userId,
            timestamp: event.timestamp
        });
        
        // Ensure analytics data is initialized
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
        
        // Update in-memory analytics
        const analytics = global.analyticsData;
        const today = new Date().toISOString().split('T')[0];
        
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
                const format = event.data?.format;
                if (format) {
                    analytics.dailyStats[today].formatUsage[format] = 
                        (analytics.dailyStats[today].formatUsage[format] || 0) + 1;
                    analytics.formatPopularity[format] = 
                        (analytics.formatPopularity[format] || 0) + 1;
                }
                
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
        
        // Store in database
        // For PostgreSQL, pass the object directly (it handles JSONB conversion)
        // For SQLite, stringify the object
        const eventData = USE_POSTGRES ? (event.data || {}) : JSON.stringify(event.data || {});
        
        db.run(`
            INSERT INTO analytics_events (user_id, session_id, event_type, event_data)
            VALUES (?, ?, ?, ?)
        `, [
            event.userId,
            event.sessionId,
            event.eventType,
            eventData
        ], function(err) {
            if (err) {
                console.error('Analytics storage error:', err);
                return res.status(500).json({ error: 'Failed to store analytics' });
            }
            
            res.json({ success: true, received: event.eventType });
        });
        
    } catch (error) {
        console.error('Analytics error:', error);
        res.status(500).json({ error: 'Failed to process analytics' });
    }
});

// Comprehensive analytics dashboard endpoint (admin only)
app.get('/api/analytics/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        // Check if user is admin (you might want to add an is_admin field to users table)
        const userId = req.user.userId;
        
        // Get comprehensive dashboard data
        const dashboardData = await analytics.getDashboardData();
        
        // Add legacy in-memory data if available
        if (global.analyticsData) {
            dashboardData.legacy = {
                totalEvents: global.analyticsData.totalEvents,
                formatPopularity: global.analyticsData.formatPopularity
            };
        }
        
        res.json(dashboardData);
        
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to get dashboard data' });
    }
});

// Additional analytics endpoints
app.get('/api/analytics/funnel', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        const start = startDate || new Date(Date.now() - 30 * 86400000).toISOString();
        const end = endDate || new Date().toISOString();
        
        const funnelData = await analytics.getConversionMetrics(start, end);
        res.json(funnelData);
    } catch (error) {
        console.error('Funnel analytics error:', error);
        res.status(500).json({ error: 'Failed to get funnel data' });
    }
});

app.get('/api/analytics/revenue', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        const start = startDate || new Date(Date.now() - 30 * 86400000).toISOString();
        const end = endDate || new Date().toISOString();
        
        const revenueData = await analytics.getRevenueMetrics(start, end);
        res.json(revenueData);
    } catch (error) {
        console.error('Revenue analytics error:', error);
        res.status(500).json({ error: 'Failed to get revenue data' });
    }
});

app.get('/api/analytics/retention/:cohortDate', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { cohortDate } = req.params;
        const { days = 30 } = req.query;
        
        const retentionData = await analytics.getCohortRetention(cohortDate, parseInt(days));
        res.json(retentionData);
    } catch (error) {
        console.error('Retention analytics error:', error);
        res.status(500).json({ error: 'Failed to get retention data' });
    }
});

// Save conversation endpoint
app.post('/api/conversations/save', authenticateToken, (req, res) => {
    try {
        const { topic, format, participants, conversationData } = req.body;
        
        if (!topic || !format || !participants || !conversationData) {
            return res.status(400).json({ error: 'Missing required conversation data' });
        }
        
        // Auto-generate title
        const title = generateConversationTitle(participants, topic, format);
        
        db.run(`
            INSERT INTO saved_conversations 
            (user_id, title, topic, format, participants, conversation_data)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [
            req.user.userId,
            title,
            topic,
            format,
            JSON.stringify(participants),
            JSON.stringify(conversationData)
        ], function(err) {
            if (err) {
                console.error('Error saving conversation:', err);
                return res.status(500).json({ error: 'Failed to save conversation' });
            }
            
            res.json({
                success: true,
                conversationId: this.lastID,
                title: title,
                message: 'Conversation saved successfully!'
            });
        });
        
    } catch (error) {
        console.error('Save conversation error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get user's saved conversations
app.get('/api/conversations', authenticateToken, (req, res) => {
    try {
        db.all(`
            SELECT id, title, topic, format, participants, created_at, is_shared, view_count
            FROM saved_conversations 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        `, [req.user.userId], (err, conversations) => {
            if (err) {
                console.error('Error fetching conversations:', err);
                return res.status(500).json({ error: 'Failed to fetch conversations' });
            }
            
            // Parse participants JSON
            const formattedConversations = conversations.map(conv => ({
                ...conv,
                participants: JSON.parse(conv.participants)
            }));
            
            res.json(formattedConversations);
        });
        
    } catch (error) {
        console.error('Fetch conversations error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get specific conversation (for viewing/sharing)
app.get('/api/conversations/:id', optionalAuth, (req, res) => {
    try {
        const conversationId = req.params.id;
        
        db.get(`
            SELECT * FROM saved_conversations 
            WHERE id = ?
        `, [conversationId], (err, conversation) => {
            if (err) {
                console.error('Error fetching conversation:', err);
                return res.status(500).json({ error: 'Failed to fetch conversation' });
            }
            
            if (!conversation) {
                return res.status(404).json({ error: 'Conversation not found' });
            }
            
            // Check if user owns this conversation or if it's shared
            if (conversation.user_id !== req.user?.userId && !conversation.is_shared) {
                return res.status(403).json({ error: 'Access denied' });
            }
            
            // Parse JSON fields
            const formattedConversation = {
                ...conversation,
                participants: JSON.parse(conversation.participants),
                conversation_data: JSON.parse(conversation.conversation_data)
            };
            
            res.json(formattedConversation);
        });
        
    } catch (error) {
        console.error('Get conversation error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete conversation
app.delete('/api/conversations/:id', authenticateToken, (req, res) => {
    try {
        const conversationId = req.params.id;
        
        db.run(`
            DELETE FROM saved_conversations 
            WHERE id = ? AND user_id = ?
        `, [conversationId, req.user.userId], function(err) {
            if (err) {
                console.error('Error deleting conversation:', err);
                return res.status(500).json({ error: 'Failed to delete conversation' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Conversation not found or access denied' });
            }
            
            res.json({ success: true, message: 'Conversation deleted successfully' });
        });
        
    } catch (error) {
        console.error('Delete conversation error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Helper function to auto-generate conversation titles
function generateConversationTitle(participants, topic, format) {
    const formatNames = {
        arena: 'Discussion',
        panel: 'Panel',
        symposium: 'Symposium', 
        debate: 'Debate',
        roundtable: 'Roundtable',
        chat: 'Chat'
    };
    
    const formatName = formatNames[format] || 'Discussion';
    
    if (participants.length === 1) {
        // Personal chat
        return `${participants[0]} Chat: ${truncateTitle(topic)}`;
    } else if (participants.length === 2) {
        // Two-person discussion
        return `${participants[0]} vs ${participants[1]}: ${truncateTitle(topic)}`;
    } else {
        // Multi-person
        return `${formatName}: ${truncateTitle(topic)}`;
    }
}

function truncateTitle(topic, maxLength = 50) {
    if (topic.length <= maxLength) return topic;
    return topic.substring(0, maxLength).trim() + '...';
}


// ============================================================================
// EXISTING ROUTES
// ============================================================================

app.get('/', (req, res) => {
    const filePath = path.join(__dirname, '..', 'index.html');
    console.log('🔍 Serving index.html from:', filePath);
    res.sendFile(filePath);
});

app.get('/chat.html', (req, res) => {
    const filePath = path.join(__dirname, '..', 'chat.html');
    console.log('🔍 Serving chat.html from:', filePath);
    res.sendFile(filePath);
});

app.get('/conversations.html', (req, res) => {
    const filePath = path.join(__dirname, '..', 'conversations.html');
    console.log('🔍 Serving conversations.html from:', filePath);
    res.sendFile(filePath);
});

app.get('/conversation.html', (req, res) => {
    const filePath = path.join(__dirname, '..', 'conversation.html');
    console.log('🔍 Serving conversation.html from:', filePath);
    res.sendFile(filePath);
});

app.get('/test-auth.html', (req, res) => {
    const filePath = path.join(__dirname, '..', 'test-auth.html');
    console.log('🔍 Serving test-auth.html from:', filePath);
    res.sendFile(filePath);
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        hasApiKey: !!CLAUDE_API_KEY,
        hasStripeKey: !!process.env.STRIPE_SECRET_KEY,
        hasWebhookSecret: !!STRIPE_WEBHOOK_SECRET
    });
});

// Test Claude API endpoint
app.get('/api/test-claude', async (req, res) => {
    try {
        console.log('Testing Claude API...');
        const response = await makeClaudeRequest('Say "API is working!" in exactly 3 words.');
        res.json({ 
            success: true, 
            response: response,
            message: 'Claude API is working correctly!'
        });
    } catch (error) {
        console.error('Claude API test failed:', error.message);
        res.status(500).json({ 
            success: false, 
            error: error.message,
            message: 'Claude API test failed. Check server logs for details.'
        });
    }
});

// ============================================================================
// CONVERSATION SHARING ENDPOINTS
// ============================================================================

// Share conversation anonymously (temporary link)
app.post('/api/conversations/share-anonymous', async (req, res) => {
    try {
        const { topic, format, participants, conversationHtml, metadata } = req.body;
        
        // Generate a unique share ID
        const shareId = 'share_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        
        // Store in database with expiration
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30); // 30 days
        
        // Store in database
        db.run(`
            INSERT INTO shared_conversations (
                share_id, topic, format, participants, conversation_html, metadata, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            shareId,
            topic,
            format,
            JSON.stringify(participants),
            conversationHtml,
            JSON.stringify(metadata || {}),
            expiresAt.toISOString()
        ], (err) => {
            if (err) {
                console.error('Database error storing shared conversation:', err);
                return res.status(500).json({ error: 'Failed to create share link' });
            }
        
            res.json({
                shareId: shareId,
                message: 'Share link created',
                expiresAt: expiresAt.toISOString()
            });
        });
        
    } catch (error) {
        console.error('Share anonymous error:', error);
        res.status(500).json({ error: 'Failed to create share link' });
    }
});

// Get shared conversation
app.get('/api/conversations/shared/:shareId', async (req, res) => {
    try {
        const { shareId } = req.params;
        
        // Get shared conversation from database
        // Use SQLite-style placeholders - they'll be converted for PostgreSQL
        const query = `SELECT * FROM shared_conversations WHERE share_id = ? AND expires_at > ${USE_POSTGRES ? 'NOW()' : "datetime('now')"}`;
        
        console.log('Fetching shared conversation:', shareId);
        console.log('Query:', query);
        console.log('USE_POSTGRES:', USE_POSTGRES);
        
        db.get(query, [shareId], (err, shared) => {
            if (err) {
                console.error('Database error getting shared conversation:', err);
                console.error('Error details:', err.message, err.code);
                return res.status(500).json({ 
                    error: 'Failed to load shared conversation',
                    details: err.message,
                    code: err.code 
                });
            }
            
            if (!shared) {
                console.log('No shared conversation found for shareId:', shareId);
                return res.status(404).json({ error: 'Share link not found or expired' });
            }
            
            console.log('Found shared conversation:', shared);
            
            try {
                // Parse JSON fields - PostgreSQL JSONB returns objects, SQLite returns strings
                const conversation = {
                    topic: shared.topic,
                    format: shared.format,
                    participants: typeof shared.participants === 'string' ? JSON.parse(shared.participants) : shared.participants,
                    conversationHtml: shared.conversation_html,
                    metadata: typeof shared.metadata === 'string' ? JSON.parse(shared.metadata) : shared.metadata,
                    createdAt: shared.created_at,
                    expiresAt: shared.expires_at
                };
                
                res.json(conversation);
            } catch (parseError) {
                console.error('Error parsing shared conversation data:', parseError);
                console.error('Raw data:', shared);
                console.error('Participants type:', typeof shared.participants);
                console.error('Metadata type:', typeof shared.metadata);
                res.status(500).json({ 
                    error: 'Failed to parse conversation data',
                    details: parseError.message 
                });
            }
        });
        
    } catch (error) {
        console.error('Get shared conversation error:', error);
        res.status(500).json({ error: 'Failed to load shared conversation' });
    }
});

// Global error handler (must be last)
app.use(errorHandler);

// Export the app for Vercel
module.exports = app;

// Only listen when running locally (not on Vercel)
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Open your app at: http://localhost:${PORT}`);
        console.log('Environment check:');
        console.log('- Claude API Key:', !!CLAUDE_API_KEY);
        console.log('- Stripe Secret Key:', !!process.env.STRIPE_SECRET_KEY);
        console.log('- Stripe Webhook Secret:', !!STRIPE_WEBHOOK_SECRET);
        console.log('- Database:', USE_POSTGRES ? 'PostgreSQL' : 'SQLite');
        console.log('- Redis:', !!process.env.REDIS_URL);
        console.log('- Sentry:', !!process.env.SENTRY_DSN);
        
        // Log initial event
        logEvent('server_started', {
            port: PORT,
            environment: process.env.NODE_ENV || 'development',
            database: USE_POSTGRES ? 'postgres' : 'sqlite'
        });
    });
}