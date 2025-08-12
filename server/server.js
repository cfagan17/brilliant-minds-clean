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
    console.log('✅ Stripe initialized successfully');
  } else {
    console.log('⚠️  Stripe not configured - STRIPE_SECRET_KEY not found in environment variables');
    console.log('Available env vars:', Object.keys(process.env).filter(k => k.includes('STRIPE')));
  }
} catch (error) {
  console.log('⚠️  Stripe initialization failed:', error.message);
  console.log('Full error:', error);
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
// Both endpoints needed - Stripe is configured for /api/stripe-webhook (with hyphen)
app.use('/api/stripe/webhook', express.raw({type: 'application/json'}));
app.use('/api/stripe-webhook', express.raw({type: 'application/json'}));

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
    console.log('[OptionalAuth] Starting auth check for', req.path);
    console.log('[OptionalAuth] Headers:', Object.keys(req.headers).filter(h => h.toLowerCase().includes('auth')));
    
    // Headers in Express are case-insensitive, but let's be explicit
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    console.log('[OptionalAuth] Auth header value:', authHeader ? authHeader.substring(0, 30) + '...' : 'NONE');
    
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        console.log('[OptionalAuth] Token found, attempting verification...');
        try {
            // Use synchronous verify to ensure req.user is set before next middleware
            const user = jwt.verify(token, JWT_SECRET);
            req.user = user;
            console.log('[OptionalAuth] ✅ SUCCESS: User authenticated -', user.userId);
        } catch (err) {
            console.log('[OptionalAuth] ❌ FAILED: Token invalid -', err.message);
            // Token is invalid or expired - treat as anonymous
        }
    } else {
        console.log('[OptionalAuth] No token found in request');
        if (authHeader) {
            console.log('[OptionalAuth] Invalid auth header format:', authHeader);
        }
    }
    
    console.log('[OptionalAuth] Final req.user state:', req.user ? 'SET' : 'NOT SET');
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

// Handler function for Stripe webhooks
const handleStripeWebhook = (req, res) => {
    if (!stripe) {
        console.error('Stripe webhook called but Stripe not configured');
        return res.status(503).json({ error: 'Stripe not configured' });
    }
    
    const sig = req.headers['stripe-signature'];
    
    // If no webhook secret is configured, log warning but still process (for testing)
    if (!STRIPE_WEBHOOK_SECRET) {
        console.warn('⚠️  No STRIPE_WEBHOOK_SECRET configured - webhook signature verification skipped');
        // In production, you should return an error here
        // return res.status(500).json({ error: 'Webhook secret not configured' });
    }
    
    let event;

    try {
        if (STRIPE_WEBHOOK_SECRET) {
            // Verify signature if secret is configured
            event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
        } else {
            // Parse without verification (development/testing only)
            event = JSON.parse(req.body.toString());
        }
    } catch (err) {
        console.error(`❌ Webhook error:`, err.message);
        console.error('Signature header:', sig ? 'present' : 'missing');
        console.error('Webhook secret configured:', !!STRIPE_WEBHOOK_SECRET);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Log all webhook events for debugging
    console.log(`📨 Received webhook: ${event.type} (ID: ${event.id})`);
    
    // Handle the checkout.session.completed event
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        console.log('🎉 Payment successful for session:', session.id);
        
        // Get customer email from session
        const customerEmail = session.customer_details?.email;
        
        if (customerEmail) {
            // First check if user exists
            db.get('SELECT id FROM users WHERE email = ?', [customerEmail], (err, existingUser) => {
                if (err) {
                    console.error('Error checking user existence:', err);
                    return;
                }
                
                if (existingUser) {
                    // User exists, update to pro status
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
                            console.log(`✅ Existing user ${customerEmail} upgraded to Pro`);
                            
                            // Track payment conversion
                            analytics.trackEvent(ANALYTICS_EVENTS.PAYMENT_COMPLETED, existingUser.id, {
                                amount: session.amount_total / 100, // Convert from cents
                                currency: session.currency,
                                customerId: session.customer,
                                subscriptionId: session.subscription
                            }).catch(err => console.error('Analytics error:', err));
                        }
                    });
                } else {
                    // User doesn't exist, create new pro user (without password)
                    db.run(`
                        INSERT INTO users (email, is_pro, stripe_customer_id, subscription_status)
                        VALUES (?, TRUE, ?, 'active')
                    `, [customerEmail, session.customer], function(err) {
                        if (err) {
                            console.error('Error creating pro user:', err);
                        } else {
                            console.log(`✅ New Pro user ${customerEmail} created from payment`);
                            
                            // Track payment conversion for new user
                            analytics.trackEvent(ANALYTICS_EVENTS.PAYMENT_COMPLETED, this.lastID, {
                                amount: session.amount_total / 100, // Convert from cents
                                currency: session.currency,
                                customerId: session.customer,
                                subscriptionId: session.subscription,
                                newUser: true
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

    // Always return 200 to acknowledge receipt
    res.status(200).json({received: true});
};

// Register both webhook endpoints (Stripe is configured for /api/stripe-webhook)
app.post('/api/stripe/webhook', handleStripeWebhook);
app.post('/api/stripe-webhook', handleStripeWebhook);

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

// Test auth endpoint
app.get('/api/test-auth', optionalAuth, (req, res) => {
    console.log('[TEST-AUTH] req.user:', req.user);
    res.json({
        authenticated: !!req.user,
        userId: req.user?.userId,
        headers: {
            authorization: req.headers.authorization ? 'present' : 'missing'
        }
    });
});

// Rate limit status endpoint will be defined after guestRateLimit

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
                    isProUser: user.is_pro || false,
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

        // Reset daily discussions for ALL users (both free and pro reset daily)
        resetDailyDiscussions(user.id, () => {
            // Get updated user data after reset
            db.get('SELECT * FROM users WHERE id = ?', [user.id], (err, updatedUser) => {
                if (err) {
                    return res.status(500).json({ error: 'Database error' });
                }
                
                res.json({
                    id: updatedUser.id,
                    email: updatedUser.email,
                    isProUser: updatedUser.is_pro,
                    discussionsUsed: updatedUser.discussions_used,
                    dailyLimit: updatedUser.is_pro ? 'unlimited' : 10,
                    remaining: updatedUser.is_pro ? 'unlimited' : Math.max(0, 10 - updatedUser.discussions_used)
                });
            });
        });
    });
});

// Claim Pro account endpoint (for users who paid but don't have password)
app.post('/api/auth/claim-pro', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        // Check if user exists and is Pro but has no password
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Server error' });
            }

            if (!user) {
                return res.status(404).json({ error: 'No Pro account found with this email. Please check your payment email.' });
            }

            if (user.password_hash) {
                return res.status(400).json({ error: 'Account already has a password. Please sign in instead.' });
            }

            if (!user.is_pro) {
                return res.status(400).json({ error: 'This email is not associated with a Pro account.' });
            }

            // Hash password and update user
            const passwordHash = await bcrypt.hash(password, 10);
            
            db.run('UPDATE users SET password_hash = ? WHERE id = ?', 
                   [passwordHash, user.id], function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to set password' });
                }

                // Create token
                const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
                
                res.json({
                    token,
                    user: {
                        id: user.id,
                        email: user.email,
                        isProUser: true,
                        message: 'Password set successfully! You can now sign in from any device.'
                    }
                });
            });
        });
    } catch (error) {
        console.error('Claim Pro error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================================================
// CLAUDE API (FIXED WITH CONSISTENT LIMITS)
// ============================================================================

// Enhanced rate limiting for guests (10 daily)
// NOTE: Using standard memory store with 24-hour window
// Server restart will reset counts
const guestRateLimit = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    max: 10,
    skipSuccessfulRequests: false,
    skipFailedRequests: true,
    message: { 
        error: 'You\'ve reached your free discussion limit! Upgrade to Pro for unlimited access.',
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
    },
    handler: (req, res) => {
        // This handler will be called when rate limit is exceeded
        console.log('Rate limit exceeded for IP:', req.ip);
        res.status(429).json({ 
            error: 'You\'ve reached your free discussion limit! Upgrade to Pro for unlimited access.',
            limit: true,
            guestLimitReached: true,
            remaining: 0,
            dailyLimit: 10,
            isProUser: false,
            userType: 'anonymous'
        });
    }
});

// Note: Rate limiting is now applied directly in the route after auth check

// Check rate limit status endpoint
app.get('/api/rate-limit-status', optionalAuth, guestRateLimit, (req, res) => {
    res.json({
        authenticated: !!req.user,
        ip: req.ip,
        rateLimit: {
            limit: res.getHeader('X-RateLimit-Limit'),
            remaining: res.getHeader('X-RateLimit-Remaining'),
            reset: res.getHeader('X-RateLimit-Reset'),
            resetDate: res.getHeader('X-RateLimit-Reset') ? 
                new Date(parseInt(res.getHeader('X-RateLimit-Reset'))).toISOString() : null
        }
    });
});

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
app.post('/api/claude', optionalAuth, guestRateLimit, async (req, res) => {
    console.log('\n=== CLAUDE ENDPOINT DEBUG ===');
    console.log('1. User authenticated?', !!req.user);
    console.log('2. User ID:', req.user?.userId);
    console.log('3. Auth header received:', req.headers.authorization ? 'YES' : 'NO');
    console.log('4. Rate limit headers:', {
        remaining: res.getHeader('X-RateLimit-Remaining'),
        limit: res.getHeader('X-RateLimit-Limit')
    });
    
    try {
        const { message, figure, format, sessionId } = req.body;
        
        // Validate input
        if (!message || typeof message !== 'string' || message.trim().length === 0) {
            return res.status(400).json({ error: 'Message is required' });
        }
        
        // Check usage limits for authenticated users (NO DAILY RESET)
        if (req.user) {
            console.log('Processing authenticated request for user ID:', req.user.userId);
            // Get user data and check limits - NO daily reset for free users
            db.get('SELECT * FROM users WHERE id = ?', [req.user.userId], async (err, user) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                
                if (!user) {
                    return res.status(404).json({ error: 'User not found' });
                }
                
                // Process the authenticated request (daily reset handled inside)
                await processAuthenticatedRequest(req, res, user.id, message);
            });
        } else {
            // Guest user - limited to 10 per day (handled by rate limiting middleware)
            // Check if rate limit has been exceeded
            const limit = res.getHeader('X-RateLimit-Limit');
            const remaining = res.getHeader('X-RateLimit-Remaining');
            const reset = res.getHeader('X-RateLimit-Reset');
            
            console.log('Anonymous user rate limit info:', {
                limit: limit,
                remaining: remaining,
                reset: reset ? new Date(parseInt(reset)).toISOString() : 'not set',
                ip: req.ip,
                parsedRemaining: parseInt(remaining)
            });
            
            // Only block if we explicitly have a remaining count of 0
            // If header is missing, allow the request (rate limiter will handle it)
            if (remaining !== undefined && parseInt(remaining) <= 0) {
                // Rate limit exceeded - return error immediately
                console.log('Rate limit exceeded for anonymous user');
                return res.status(429).json({ 
                    error: 'You\'ve reached your free discussion limit! Upgrade to Pro for unlimited access.',
                    limit: true,
                    guestLimitReached: true,
                    remaining: 0,
                    limit: 10,
                    isProUser: false,
                    userType: 'anonymous'
                });
            }
            
            try {
                console.log('Making Claude API request for guest user:', req.ip);
                const claudeResponse = await makeClaudeRequest(message, `anon_${req.ip}`);
                console.log('Claude API response received for guest');
                
                // Get current usage from rate limit headers
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
    
    // First reset daily discussions if needed
    resetDailyDiscussions(userId, (resetErr) => {
        if (resetErr) {
            console.error('Error resetting daily discussions:', resetErr);
        }
        
        // Now get the updated user data
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
        console.log('=== Create checkout session request ===');
        console.log('Stripe initialized:', !!stripe);
        console.log('Environment:', process.env.NODE_ENV);
        
        // Check if Stripe is configured
        if (!stripe) {
            console.error('Stripe is not configured');
            console.error('STRIPE_SECRET_KEY present:', !!process.env.STRIPE_SECRET_KEY);
            return res.status(503).json({ error: 'Payment system is not configured. Please contact support.' });
        }
        
        const { priceId } = req.body;
        
        console.log('Creating checkout session for price:', priceId);
        console.log('Stripe mode:', process.env.STRIPE_SECRET_KEY?.startsWith('sk_test_') ? 'TEST' : 'LIVE');
        
        if (!priceId) {
            return res.status(400).json({ error: 'Price ID is required' });
        }
        
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
        console.error('Error type:', error.type);
        console.error('Error code:', error.code);
        console.error('Error message:', error.message);
        
        // Return more specific error message
        if (error.type === 'StripeInvalidRequestError') {
            res.status(400).json({ error: error.message || 'Invalid payment configuration' });
        } else {
            res.status(500).json({ error: error.message || 'Failed to create checkout session' });
        }
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
        
        console.log('Saving conversation - received data:', {
            topic,
            format,
            participants,
            conversationDataKeys: conversationData ? Object.keys(conversationData) : null,
            messagesCount: conversationData?.messages?.length
        });
        
        if (!topic || !format || !participants || !conversationData) {
            return res.status(400).json({ error: 'Missing required conversation data' });
        }
        
        // Ensure participants is an array
        const participantsArray = Array.isArray(participants) ? participants : [participants];
        
        // Auto-generate title
        const title = generateConversationTitle(participantsArray, topic, format);
        
        const conversationDataString = JSON.stringify(conversationData);
        console.log('Stringified conversation data length:', conversationDataString.length);
        
        db.run(`
            INSERT INTO saved_conversations 
            (user_id, title, topic, format, participants, conversation_data)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [
            req.user.userId,
            title,
            topic,
            format,
            JSON.stringify(participantsArray),
            conversationDataString
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
        console.log('Fetching conversations for user:', req.user.userId);
        
        db.all(`
            SELECT id, title, topic, format, participants, created_at, is_shared, view_count
            FROM saved_conversations 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        `, [req.user.userId], (err, conversations) => {
            if (err) {
                console.error('Database error fetching conversations:', err);
                console.error('Error details:', err.message, err.code);
                return res.status(500).json({ 
                    error: 'Failed to fetch conversations',
                    details: err.message 
                });
            }
            
            console.log('Found conversations:', conversations ? conversations.length : 0);
            
            // Handle empty result set
            if (!conversations || conversations.length === 0) {
                return res.json([]);
            }
            
            try {
                // Parse participants JSON - handle both array and string formats
                const formattedConversations = conversations.map(conv => {
                    let participants = [];
                    
                    if (conv.participants) {
                        try {
                            // Try parsing as JSON first
                            participants = JSON.parse(conv.participants);
                            // If it parsed but isn't an array, wrap it
                            if (!Array.isArray(participants)) {
                                participants = [participants];
                            }
                        } catch (e) {
                            // If JSON parse fails, treat it as a plain string
                            // This handles cases like "Kurt Gödel" stored as a string
                            participants = [conv.participants];
                        }
                    }
                    
                    return {
                        ...conv,
                        participants: participants
                    };
                });
                
                res.json(formattedConversations);
            } catch (parseError) {
                console.error('Error parsing conversation data:', parseError);
                console.error('Problematic conversation:', conversations);
                res.status(500).json({ 
                    error: 'Failed to parse conversation data',
                    details: parseError.message 
                });
            }
        });
        
    } catch (error) {
        console.error('Unexpected error in /api/conversations:', error);
        res.status(500).json({ error: 'Server error', details: error.message });
    }
});

// Get specific conversation (for viewing/sharing)
app.get('/api/conversations/:id', optionalAuth, (req, res) => {
    try {
        const conversationId = req.params.id;
        console.log('Fetching conversation with ID:', conversationId);
        console.log('User ID from auth:', req.user?.userId || 'not authenticated');
        
        db.get(`
            SELECT * FROM saved_conversations 
            WHERE id = ?
        `, [conversationId], (err, conversation) => {
            if (err) {
                console.error('Database error fetching conversation:', err);
                console.error('Error details:', err.message, err.code);
                return res.status(500).json({ 
                    error: 'Failed to fetch conversation',
                    details: err.message 
                });
            }
            
            if (!conversation) {
                return res.status(404).json({ error: 'Conversation not found' });
            }
            
            // Allow access if:
            // 1. User owns the conversation
            // 2. Conversation is marked as shared
            // 3. Anyone with the direct link (for simplicity)
            // Note: Having the conversation ID acts as the "share key"
            // If you want more security, keep the original check:
            // if (conversation.user_id !== req.user?.userId && !conversation.is_shared) {
            //     return res.status(403).json({ error: 'Access denied' });
            // }
            
            // Parse JSON fields with error handling
            try {
                // Parse participants - handle both array and string formats
                let participants = [];
                if (conversation.participants) {
                    try {
                        participants = JSON.parse(conversation.participants);
                        if (!Array.isArray(participants)) {
                            participants = [participants];
                        }
                    } catch (e) {
                        // If JSON parse fails, treat as plain string
                        participants = [conversation.participants];
                    }
                }
                
                // Parse conversation data
                let conversationData = {};
                console.log('Raw conversation_data from DB:', conversation.conversation_data);
                console.log('Type of conversation_data:', typeof conversation.conversation_data);
                
                if (conversation.conversation_data) {
                    try {
                        conversationData = JSON.parse(conversation.conversation_data);
                        console.log('Parsed conversation_data:', conversationData);
                    } catch (e) {
                        console.error('Error parsing conversation_data:', e);
                        console.error('Failed to parse:', conversation.conversation_data);
                        conversationData = {};
                    }
                } else {
                    console.log('conversation_data is null or undefined');
                }
                
                const formattedConversation = {
                    ...conversation,
                    participants: participants,
                    conversation_data: conversationData
                };
                
                res.json(formattedConversation);
            } catch (parseError) {
                console.error('Error parsing conversation:', parseError);
                console.error('Raw conversation data:', conversation);
                res.status(500).json({ error: 'Failed to parse conversation data' });
            }
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

// Toggle share status for a conversation
app.put('/api/conversations/:id/share', authenticateToken, (req, res) => {
    try {
        const conversationId = req.params.id;
        const { shared } = req.body;
        
        db.run(`
            UPDATE saved_conversations 
            SET is_shared = ?
            WHERE id = ? AND user_id = ?
        `, [shared ? 1 : 0, conversationId, req.user.userId], function(err) {
            if (err) {
                console.error('Error updating share status:', err);
                return res.status(500).json({ error: 'Failed to update share status' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Conversation not found or access denied' });
            }
            
            res.json({ 
                success: true, 
                message: shared ? 'Conversation shared' : 'Conversation unshared',
                shareUrl: shared ? `${req.protocol}://${req.get('host')}/conversation.html?id=${conversationId}` : null
            });
        });
        
    } catch (error) {
        console.error('Update share status error:', error);
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

// Cancel subscription endpoint
app.post('/api/cancel-subscription', authenticateToken, async (req, res) => {
    console.log('Cancel subscription endpoint called');
    console.log('User:', req.user);
    console.log('Stripe initialized:', !!stripe);
    
    try {
        if (!stripe) {
            console.error('Stripe not initialized - STRIPE_SECRET_KEY may not be set');
            // For now, just mark as cancelled in the database without Stripe API call
            db.run(`
                UPDATE users 
                SET is_pro = false,
                    subscription_status = 'cancelled'
                WHERE id = ?
            `, [req.user.userId], (err) => {
                if (err) {
                    console.error('Error updating subscription status:', err);
                    return res.status(500).json({ error: 'Failed to cancel subscription' });
                }
                
                return res.json({ 
                    success: true,
                    message: 'Subscription cancelled successfully',
                    note: 'Please contact support if you have any billing concerns'
                });
            });
            return;
        }
        
        // Get user's subscription info
        db.get('SELECT * FROM users WHERE id = ?', [req.user.userId], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (!user || !user.stripe_customer_id) {
                return res.status(400).json({ error: 'No active subscription found' });
            }
            
            try {
                // List customer's subscriptions
                const subscriptions = await stripe.subscriptions.list({
                    customer: user.stripe_customer_id,
                    status: 'active'
                });
                
                if (subscriptions.data.length === 0) {
                    return res.status(400).json({ error: 'No active subscription found' });
                }
                
                // Cancel the subscription at period end
                const subscription = await stripe.subscriptions.update(
                    subscriptions.data[0].id,
                    { cancel_at_period_end: true }
                );
                
                // Calculate end date safely
                let endDate = null;
                if (subscription.current_period_end) {
                    try {
                        endDate = new Date(subscription.current_period_end * 1000).toISOString();
                    } catch (e) {
                        console.error('Error parsing subscription end date:', e);
                        endDate = null;
                    }
                }
                
                // Update database
                db.run(`
                    UPDATE users 
                    SET subscription_status = 'cancelled',
                        subscription_end_date = ?
                    WHERE id = ?
                `, [endDate, user.id], (err) => {
                    if (err) {
                        console.error('Error updating subscription status:', err);
                        return res.status(500).json({ error: 'Failed to update subscription status' });
                    }
                    
                    console.log(`✅ Subscription cancelled for user ${user.email}`);
                    res.json({ 
                        success: true,
                        message: 'Subscription cancelled successfully',
                        endsAt: endDate
                    });
                });
                
            } catch (stripeError) {
                console.error('Stripe cancellation error:', stripeError);
                res.status(500).json({ error: 'Failed to cancel subscription with payment provider' });
            }
        });
    } catch (error) {
        console.error('Cancel subscription error:', error);
        res.status(500).json({ error: 'Failed to cancel subscription' });
    }
});

// Test Stripe configuration
app.get('/api/test-stripe', async (req, res) => {
    res.json({
        configured: !!stripe,
        hasSecretKey: !!process.env.STRIPE_SECRET_KEY,
        keyPrefix: process.env.STRIPE_SECRET_KEY ? process.env.STRIPE_SECRET_KEY.substring(0, 7) + '...' : null,
        mode: process.env.STRIPE_SECRET_KEY?.startsWith('sk_test_') ? 'test' : 'live'
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
        
        console.log('Fetching shared conversation:', shareId);
        console.log('USE_POSTGRES:', USE_POSTGRES);
        
        // First check if the share exists at all
        db.get('SELECT * FROM shared_conversations WHERE share_id = ?', [shareId], (err, shared) => {
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
                return res.status(404).json({ error: 'Share link not found' });
            }
            
            // Check if expired
            const now = new Date();
            const expiresAt = new Date(shared.expires_at);
            
            console.log('Current time:', now.toISOString());
            console.log('Expires at:', expiresAt.toISOString());
            console.log('Is expired?', now > expiresAt);
            
            if (now > expiresAt) {
                return res.status(404).json({ error: 'Share link has expired' });
            }
            
            console.log('Found shared conversation:', shared);
            
            try {
                // Parse participants - handle both array and string formats
                let participants = [];
                if (shared.participants) {
                    if (typeof shared.participants === 'object' && !Array.isArray(shared.participants)) {
                        // PostgreSQL JSONB returns as object
                        participants = shared.participants;
                    } else if (typeof shared.participants === 'string') {
                        try {
                            // Try parsing as JSON
                            participants = JSON.parse(shared.participants);
                            if (!Array.isArray(participants)) {
                                participants = [participants];
                            }
                        } catch (e) {
                            // If JSON parse fails, treat as plain string
                            participants = [shared.participants];
                        }
                    } else if (Array.isArray(shared.participants)) {
                        participants = shared.participants;
                    }
                }
                
                // Parse metadata
                let metadata = {};
                if (shared.metadata) {
                    if (typeof shared.metadata === 'string') {
                        try {
                            metadata = JSON.parse(shared.metadata);
                        } catch (e) {
                            console.error('Error parsing metadata:', e);
                            metadata = {};
                        }
                    } else {
                        metadata = shared.metadata;
                    }
                }
                
                const conversation = {
                    topic: shared.topic,
                    format: shared.format,
                    participants: participants,
                    conversationHtml: shared.conversation_html,
                    metadata: metadata,
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