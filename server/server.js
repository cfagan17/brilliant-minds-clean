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
// Removed express-rate-limit - using session-based tracking instead
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
const RESEND_API_KEY = process.env.RESEND_API_KEY;

// Initialize Resend for email sending
let resend;
try {
    if (RESEND_API_KEY) {
        const { Resend } = require('resend');
        resend = new Resend(RESEND_API_KEY);
        console.log('✅ Resend email service initialized');
    } else {
        console.log('⚠️  Resend not configured - password reset emails will not be sent');
    }
} catch (resendError) {
    console.log('⚠️  Resend initialization error:', resendError.message);
    resend = null;
}

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

// IMPORTANT: Webhook endpoints MUST be registered before express.json() middleware
// to preserve the raw body for signature verification

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

// ============================================================================
// STRIPE WEBHOOK HANDLER (MUST BE DEFINED BEFORE USE)
// ============================================================================

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
                    // User doesn't exist, create new pro user with temporary password
                    // They'll need to use "forgot password" to set their password
                    const tempPasswordHash = '$2b$10$TEMP.NEEDS.RESET.HASH'; // Invalid hash that can't be logged into
                    
                    db.run(`
                        INSERT INTO users (
                            email, 
                            password_hash,
                            is_pro, 
                            stripe_customer_id, 
                            subscription_status,
                            discussions_used,
                            total_messages,
                            created_at
                        )
                        VALUES (?, ?, TRUE, ?, 'active', 0, 0, CURRENT_TIMESTAMP)
                    `, [customerEmail, tempPasswordHash, session.customer], function(err) {
                        if (err) {
                            console.error('❌ CRITICAL: Failed to create user after payment:', err);
                            console.error('Customer email:', customerEmail);
                            console.error('Stripe customer:', session.customer);
                            
                            // TODO: Send alert to admin or create a recovery mechanism
                            // This is a paying customer who can't access their account!
                        } else {
                            console.log(`✅ New Pro user ${customerEmail} created from payment`);
                            console.log(`⚠️  User needs to set password via forgot password flow`);
                            
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
        console.log('Subscription updated:', {
            id: subscription.id,
            status: subscription.status,
            cancel_at_period_end: subscription.cancel_at_period_end,
            current_period_end: subscription.current_period_end
        });
        
        // Determine the effective status
        let effectiveStatus = subscription.status;
        if (subscription.cancel_at_period_end) {
            effectiveStatus = 'canceling'; // Will cancel at period end
        }
        
        // Calculate cancellation date if applicable
        let cancelAt = null;
        if (subscription.cancel_at_period_end && subscription.current_period_end) {
            cancelAt = new Date(subscription.current_period_end * 1000).toISOString();
        }
        
        // User remains Pro until the period ends
        const isPro = subscription.status === 'active' || subscription.status === 'trialing';
        
        db.run(`
            UPDATE users 
            SET subscription_id = ?, 
                subscription_status = ?,
                is_pro = ?,
                subscription_end_date = ?
            WHERE stripe_customer_id = ?
        `, [subscription.id, effectiveStatus, isPro, cancelAt, subscription.customer], (err) => {
            if (err) {
                console.error('Error updating subscription:', err);
            } else {
                console.log(`Updated subscription for customer ${subscription.customer}: status=${effectiveStatus}, cancelAt=${cancelAt}`);
            }
        });
    }

    // Handle subscription cancellations (when period actually ends)
    if (event.type === 'customer.subscription.deleted') {
        const subscription = event.data.object;
        console.log('Subscription deleted/expired for customer:', subscription.customer);
        
        db.run(`
            UPDATE users 
            SET is_pro = FALSE, 
                subscription_status = 'canceled',
                subscription_end_date = NULL
            WHERE stripe_customer_id = ?
        `, [subscription.customer], (err) => {
            if (err) {
                console.error('Error canceling subscription:', err);
            } else {
                console.log(`Subscription ended for customer ${subscription.customer} - reverted to free tier`);
            }
        });
    }

    // Always return 200 to acknowledge receipt
    res.status(200).json({received: true});
};

// Enable CORS first
app.use(cors());

// IMPORTANT: Register webhook routes BEFORE express.json() middleware
// Webhook endpoints need raw body for signature verification
app.post('/api/stripe-webhook', express.raw({type: 'application/json'}), handleStripeWebhook);
app.post('/api/stripe/webhook', express.raw({type: 'application/json'}), handleStripeWebhook);

// Now add JSON parsing for all other routes
app.use(express.json());
app.use(express.static(path.join(__dirname, '..'))); // Serve static files from current directory

// Favicon route
app.get('/favicon.ico', (req, res) => {
    res.status(204).end();
});

// Auth middleware
// AUTH DISABLED - All endpoints open
function authenticateToken(req, res, next) {
    // Authentication disabled - return 404 for auth-required endpoints
    return res.status(404).json({ error: 'Feature temporarily unavailable' });

    /* Original auth code - disabled
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
    */
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

// Admin setup endpoint has been disabled for security
// To re-enable, uncomment the code below
/*
app.post('/api/setup-admin-user', async (req, res) => {
    return res.status(404).json({ error: 'This endpoint has been disabled for security' });
});
*/

// Test auth endpoint
app.get('/api/test-auth', optionalAuth, (req, res) => {
    console.log('[TEST-AUTH] req.user:', req.user);
    
    if (req.user && req.user.userId) {
        // Check if user is admin
        db.get('SELECT id, email, is_admin, is_pro FROM users WHERE id = ?', [req.user.userId], (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            res.json({
                authenticated: true,
                userId: req.user.userId,
                userDetails: user,
                isAdmin: user?.is_admin,
                headers: {
                    authorization: req.headers.authorization ? 'present' : 'missing'
                }
            });
        });
    } else {
        res.json({
            authenticated: false,
            userId: null,
            headers: {
                authorization: req.headers.authorization ? 'present' : 'missing'
            }
        });
    }
});

// AUTH ENDPOINTS DISABLED - App now runs fully anonymous
/*
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
*/

// AUTH ENDPOINTS DISABLED
/*
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
                    isAdmin: user.is_admin || false,
                    isTestAccount: user.is_test_account || false,
                    discussionsUsed: user.discussions_used
                }
            });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});
*/

// Password reset request - DISABLED
/*
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        // Check if user exists
        db.get('SELECT id, email FROM users WHERE email = ?', [email.toLowerCase()], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Server error' });
            }
            
            // Always return success to prevent email enumeration
            if (!user) {
                console.log('Password reset requested for non-existent email:', email);
                return res.json({ message: 'If that email exists, a reset link has been sent.' });
            }
            
            // Generate reset token
            const crypto = require('crypto');
            const resetToken = crypto.randomBytes(32).toString('hex');
            const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
            
            // Store token in database (expires in 1 hour)
            const expiresAt = new Date(Date.now() + 3600000); // 1 hour from now
            
            // Use proper boolean for PostgreSQL
            const usedValue = USE_POSTGRES ? false : 0;
            
            db.run(`
                INSERT INTO password_resets (user_email, token, expires_at, used)
                VALUES (?, ?, ?, ?)
            `, [user.email, hashedToken, expiresAt.toISOString(), usedValue], async (insertErr) => {
                if (insertErr) {
                    console.error('Failed to store reset token:', insertErr);
                    return res.status(500).json({ error: 'Failed to create reset token' });
                }
                
                // Create reset URL
                const baseUrl = req.headers.origin || 'https://iconoclash.ai';
                const resetUrl = `${baseUrl}/reset-password.html?token=${resetToken}`;
                
                console.log('Password reset requested for:', user.email);
                console.log('Reset URL:', resetUrl);
                
                // Send email with Resend
                if (resend) {
                    try {
                        const emailHtml = `
                            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
                                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; text-align: center; border-radius: 12px 12px 0 0;">
                                    <h1 style="color: white; margin: 0;">Iconoclash</h1>
                                </div>
                                <div style="background: white; padding: 40px; border: 1px solid #e5e5e5; border-radius: 0 0 12px 12px;">
                                    <h2 style="color: #333; margin-top: 0;">Reset Your Password</h2>
                                    <p style="color: #666; line-height: 1.6;">
                                        We received a request to reset your password. Click the button below to create a new password:
                                    </p>
                                    <div style="text-align: center; margin: 30px 0;">
                                        <a href="${resetUrl}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 14px 30px; text-decoration: none; border-radius: 8px; font-weight: 600;">
                                            Reset Password
                                        </a>
                                    </div>
                                    <p style="color: #999; font-size: 14px;">
                                        This link will expire in 1 hour. If you didn't request this, you can safely ignore this email.
                                    </p>
                                    <hr style="border: none; border-top: 1px solid #e5e5e5; margin: 30px 0;">
                                    <p style="color: #999; font-size: 12px; text-align: center;">
                                        If the button doesn't work, copy and paste this link into your browser:<br>
                                        <a href="${resetUrl}" style="color: #667eea; word-break: break-all;">${resetUrl}</a>
                                    </p>
                                </div>
                            </div>
                        `;
                        
                        const { data, error } = await resend.emails.send({
                            from: 'Iconoclash <onboarding@resend.dev>', // Use Resend's domain until yours is verified
                            // from: 'Iconoclash <noreply@iconoclash.ai>', // Use this after domain verification
                            to: [user.email],
                            subject: 'Reset Your Iconoclash Password',
                            html: emailHtml
                        });
                        
                        if (error) {
                            console.error('Failed to send reset email:', error);
                            // Still log for manual sending as backup
                            console.log('=== PASSWORD RESET LINK (Email failed) ===');
                            console.log('Email to:', user.email);
                            console.log('Reset link:', resetUrl);
                            console.log('========================');
                        } else {
                            console.log('Reset email sent successfully:', data.id);
                        }
                    } catch (emailError) {
                        console.error('Error sending email:', emailError);
                        // Log for manual sending as backup
                        console.log('=== PASSWORD RESET LINK (Email error) ===');
                        console.log('Email to:', user.email);
                        console.log('Reset link:', resetUrl);
                        console.log('========================');
                    }
                } else {
                    // No email service configured, log for manual sending
                    console.log('=== PASSWORD RESET LINK (No email service) ===');
                    console.log('Email to:', user.email);
                    console.log('Reset link:', resetUrl);
                    console.log('Expires in 1 hour');
                    console.log('========================');
                }
                
                res.json({ 
                    message: 'If that email exists, a reset link has been sent.',
                    // In development, include the link in response
                    ...(process.env.NODE_ENV !== 'production' && { resetUrl })
                });
            });
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});
*/

// Reset password with token - DISABLED
/*
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token and new password are required' });
        }
        
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        // Hash the token to match stored version
        const crypto = require('crypto');
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        
        // Find valid reset token (PostgreSQL compatible)
        const resetQuery = USE_POSTGRES ? `
            SELECT * FROM password_resets 
            WHERE token = ? 
            AND expires_at > NOW()
            AND used = false
        ` : `
            SELECT * FROM password_resets 
            WHERE token = ? 
            AND expires_at > datetime('now')
            AND used = 0
        `;
        
        db.get(resetQuery, [hashedToken], async (err, resetRecord) => {
            if (err || !resetRecord) {
                return res.status(400).json({ error: 'Invalid or expired reset token' });
            }
            
            // Hash new password
            const passwordHash = await bcrypt.hash(newPassword, 10);
            
            // Update user's password
            db.run(`
                UPDATE users 
                SET password_hash = ?
                WHERE email = ?
            `, [passwordHash, resetRecord.user_email], (updateErr) => {
                if (updateErr) {
                    console.error('Failed to update password:', updateErr);
                    return res.status(500).json({ error: 'Failed to update password' });
                }
                
                // Mark token as used
                const usedUpdateValue = USE_POSTGRES ? true : 1;
                db.run(`
                    UPDATE password_resets 
                    SET used = ? 
                    WHERE id = ?
                `, [usedUpdateValue, resetRecord.id]);
                
                console.log('Password reset successful for:', resetRecord.user_email);
                res.json({ message: 'Password has been reset successfully' });
            });
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});
*/

// Get current user info - DISABLED
/*
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
*/

// Claim Pro account endpoint - DISABLED
/*
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
*/

// ============================================================================
// CLAUDE API (FIXED WITH CONSISTENT LIMITS)
// ============================================================================

// Session-based discussion tracking for anonymous users
// Use global object that persists across requests
global.anonymousUsage = global.anonymousUsage || new Map();
const anonymousUsage = global.anonymousUsage;

// Helper function to get or create anonymous user in database
async function getOrCreateAnonymousUser(sessionId, ip) {
    return new Promise((resolve, reject) => {
        // First check if this session exists
        db.get('SELECT * FROM anonymous_users WHERE session_id = ?', [sessionId], (err, user) => {
            if (err) {
                console.error('Error checking anonymous user:', err);
                return reject(err);
            }
            
            if (user) {
                // Update last_active timestamp
                db.run('UPDATE anonymous_users SET last_active = CURRENT_TIMESTAMP WHERE session_id = ?', 
                    [sessionId], (err) => {
                    if (err) console.error('Error updating anonymous user:', err);
                });
                resolve(user);
            } else {
                // Create new anonymous user
                db.run(`
                    INSERT INTO anonymous_users (session_id, ip_address, discussions_used, created_at, last_active)
                    VALUES (?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                `, [sessionId, ip || '0.0.0.0'], function(err) {
                    if (err) {
                        console.error('Error creating anonymous user:', err);
                        return reject(err);
                    }
                    resolve({
                        id: this.lastID,
                        session_id: sessionId,
                        discussions_used: 0
                    });
                });
            }
        });
    });
}

// Check usage status endpoint for both authenticated and anonymous users
app.get('/api/rate-limit-status', optionalAuth, async (req, res) => {
    // For authenticated users, return their database usage
    if (req.user) {
        db.get('SELECT * FROM users WHERE id = ?', [req.user.userId], (err, user) => {
            if (err || !user) {
                return res.json({
                    authenticated: true,
                    rateLimit: {
                        limit: 10,
                        remaining: 10,
                        isProUser: false
                    }
                });
            }
            
            res.json({
                authenticated: true,
                rateLimit: {
                    limit: user.is_pro ? 'unlimited' : 10,
                    remaining: user.is_pro ? 'unlimited' : Math.max(0, 10 - user.discussions_used),
                    isProUser: user.is_pro
                }
            });
        });
    } else {
        // For anonymous users, check database using session ID
        const sessionId = req.headers['x-session-id'] || req.query.sessionId || `anon_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        
        // Save to database for tracking
        getOrCreateAnonymousUser(sessionId, ip).then(anonUser => {
            const remaining = Math.max(0, 10 - (anonUser.discussions_used || 0));
            res.json({
                authenticated: false,
                sessionId: sessionId,
                ip: req.ip,
                rateLimit: {
                    limit: 10,
                    remaining: remaining
                }
            });
        }).catch(error => {
            console.error('Error with anonymous user:', error);
            // Fallback response
            res.json({
                authenticated: false,
                sessionId: sessionId,
                ip: req.ip,
                rateLimit: {
                    limit: 10,
                    remaining: 10
                }
            });
        });
    }
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
app.post('/api/claude', optionalAuth, async (req, res) => {
    console.log('\n=== CLAUDE ENDPOINT DEBUG ===');
    console.log('1. User authenticated?', !!req.user);
    console.log('2. User ID:', req.user?.userId);
    console.log('3. Session ID:', req.body?.sessionId);
    
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
            // Guest user - limited to 10 discussions per day
            const ip = req.ip || req.connection.remoteAddress || 'unknown';
            const discussionSessionId = req.body?.sessionId;
            const anonSessionId = req.headers['x-session-id'] || `anon_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            
            // Track in database
            try {
                const anonUser = await getOrCreateAnonymousUser(anonSessionId, ip);
                
                // Check if this is a new discussion session
                let isNewDiscussion = false;
                if (discussionSessionId && discussionSessionId.startsWith('disc_')) {
                    // Track in memory for backward compatibility
                    const today = new Date().toDateString();
                    const usageKey = `${ip}_${today}`;
                    let usage = anonymousUsage.get(usageKey);
                    if (!usage) {
                        usage = { discussions: new Set(), count: 0, date: today };
                        anonymousUsage.set(usageKey, usage);
                    }
                    
                    if (!usage.discussions.has(discussionSessionId)) {
                        usage.discussions.add(discussionSessionId);
                        usage.count++;
                        isNewDiscussion = true;
                        
                        // Update database
                        db.run('UPDATE anonymous_users SET discussions_used = discussions_used + 1, last_active = CURRENT_TIMESTAMP WHERE session_id = ?',
                            [anonSessionId], (err) => {
                            if (err) console.error('Error updating anonymous discussion count:', err);
                        });
                        
                        console.log(`New discussion ${discussionSessionId} for anonymous session ${anonSessionId}. Count: ${anonUser.discussions_used + 1}/10`);
                    }
                }
                
                const currentCount = anonUser.discussions_used + (isNewDiscussion ? 1 : 0);
                const remaining = Math.max(0, 10 - currentCount);
                
                // Check if limit exceeded
                if (isNewDiscussion && currentCount > 10) {
                    console.log('Discussion limit exceeded for anonymous user');
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
                
                console.log('Making Claude API request for anonymous user:', anonSessionId);
                const claudeResponse = await makeClaudeRequest(message, `anon_${req.ip}`);
                console.log('Claude API response received for anonymous');
                
                res.json({
                    ...claudeResponse,
                    sessionId: anonSessionId,
                    usage: {
                        used: currentCount,
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
                console.error('Error handling anonymous request:', error);
                res.status(500).json({ 
                    error: 'Failed to process request',
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

app.post('/api/create-checkout-session', authenticateToken, async (req, res) => {
    try {
        console.log('=== Create checkout session request ===');
        console.log('User ID:', req.user.userId); // Now guaranteed to exist
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
        
        // Get user's email to prefill in Stripe (user is now guaranteed to be authenticated)
        db.get('SELECT email FROM users WHERE id = ?', [req.user.userId], async (err, user) => {
            if (!err && user) {
                sessionConfig.customer_email = user.email;
                console.log('Prefilling email for checkout:', user.email);
            }
            
            try {
                const session = await stripe.checkout.sessions.create(sessionConfig);
                
                // Store session ID for tracking
                db.run('UPDATE users SET last_checkout_session = ? WHERE id = ?', 
                    [session.id, req.user.userId], (updateErr) => {
                        if (updateErr) {
                            console.error('Failed to store checkout session:', updateErr);
                        }
                    });
                
                console.log('Checkout session created:', session.id);
                res.json({ sessionId: session.id });
            } catch (stripeError) {
                console.error('Stripe session creation failed:', stripeError);
                res.status(500).json({ error: 'Failed to create checkout session' });
            }
        });

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
app.get('/api/analytics/dashboard', authenticateToken, async (req, res) => {
    try {
        // Temporarily bypass admin check for debugging
        const userId = req.user.userId;
        console.log('[Analytics Dashboard] User ID:', userId);
        
        // For now, return simplified data that works with PostgreSQL
        const simplifiedData = await new Promise((resolve, reject) => {
            const data = {
                totalUsers: 0,
                proUsers: 0,
                totalDiscussions: 0,
                activeUsers7d: 0,
                totalRevenue: 0,
                mrr: 0,
                totalApiCosts: 0,
                userGrowth: 0,
                avgDiscussionsPerUser: 0,
                dailyStats: [],
                revenueByDay: [],
                formatPopularity: {},
                userGrowthData: [],
                recentUsers: [],
                topUsers: []
            };
            
            // Get basic user stats
            db.get(`
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN is_pro = true THEN 1 ELSE 0 END) as pro_users,
                    SUM(discussions_used) as total_discussions
                FROM users
            `, [], (err, stats) => {
                if (err) {
                    console.error('Stats query error:', err);
                    return reject(err);
                }
                
                data.totalUsers = stats?.total || 0;
                data.proUsers = stats?.pro_users || 0;
                data.totalDiscussions = stats?.total_discussions || 0;
                data.avgDiscussionsPerUser = data.totalUsers > 0 ? data.totalDiscussions / data.totalUsers : 0;
                data.mrr = data.proUsers * 2; // $2 per pro user
                data.totalRevenue = data.mrr * 3; // Estimate 3 months average
                
                // Get recent users
                db.all(`
                    SELECT email, is_pro, discussions_used, created_at
                    FROM users
                    ORDER BY created_at DESC
                    LIMIT 10
                `, [], (err, users) => {
                    if (err) {
                        console.error('Recent users error:', err);
                    }
                    data.recentUsers = users || [];
                    
                    // Get format popularity from in-memory data
                    if (global.analyticsData) {
                        data.formatPopularity = global.analyticsData.formatPopularity || {};
                    }
                    
                    resolve(data);
                });
            });
        });
        
        res.json(simplifiedData);
        
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

// Real-time analytics endpoint
app.get('/api/analytics/realtime', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const now = new Date();
        const fiveMinutesAgo = new Date(now - 5 * 60 * 1000);
        const todayStart = new Date(now.setHours(0, 0, 0, 0));
        
        // Get real-time metrics
        const realtimeData = await analytics.getRealtimeMetrics(fiveMinutesAgo, todayStart);
        res.json(realtimeData);
    } catch (error) {
        console.error('Realtime analytics error:', error);
        res.status(500).json({ error: 'Failed to get realtime data' });
    }
});

// Anonymous users analytics endpoint
app.get('/api/analytics/anonymous', authenticateToken, async (req, res) => {
    try {
        const anonData = await new Promise((resolve, reject) => {
            const data = {
                totalAnonymous: 0,
                totalDiscussions: 0,
                conversionRate: 0,
                recentSessions: [],
                dailyActivity: []
            };
            
            // Get anonymous user stats
            db.get(`
                SELECT 
                    COUNT(*) as total,
                    SUM(discussions_used) as total_discussions
                FROM anonymous_users
            `, [], (err, stats) => {
                if (err) {
                    console.error('Anonymous stats error:', err);
                    return reject(err);
                }
                
                data.totalAnonymous = stats?.total || 0;
                data.totalDiscussions = stats?.total_discussions || 0;
                
                // Get recent anonymous sessions
                db.all(`
                    SELECT session_id, discussions_used, created_at, last_active
                    FROM anonymous_users
                    ORDER BY last_active DESC
                    LIMIT 20
                `, [], (err, sessions) => {
                    if (err) {
                        console.error('Anonymous sessions error:', err);
                    }
                    data.recentSessions = sessions || [];
                    
                    // Calculate conversion rate (anonymous users who became registered)
                    db.get(`
                        SELECT COUNT(DISTINCT u.id) as converted
                        FROM users u
                        WHERE u.created_at > (SELECT MIN(created_at) FROM anonymous_users)
                    `, [], (err, converted) => {
                        if (!err && converted && data.totalAnonymous > 0) {
                            data.conversionRate = (converted.converted / data.totalAnonymous) * 100;
                        }
                        
                        resolve(data);
                    });
                });
            });
        });
        
        res.json(anonData);
    } catch (error) {
        console.error('Anonymous analytics error:', error);
        res.status(500).json({ error: 'Failed to get anonymous user data' });
    }
});

// Engagement analytics endpoint
app.get('/api/analytics/engagement', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        const start = startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
        const end = endDate || new Date().toISOString();
        
        const engagementData = await analytics.getEngagementMetrics(start, end);
        res.json(engagementData);
    } catch (error) {
        console.error('Engagement analytics error:', error);
        res.status(500).json({ error: 'Failed to get engagement data' });
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
                    if (typeof conversation.participants === 'object') {
                        // PostgreSQL JSONB returns as object/array
                        participants = Array.isArray(conversation.participants) 
                            ? conversation.participants 
                            : [conversation.participants];
                    } else if (typeof conversation.participants === 'string') {
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
                }
                
                // Parse conversation data - handle both string and object formats
                let conversationData = {};
                console.log('Raw conversation_data from DB:', conversation.conversation_data);
                console.log('Type of conversation_data:', typeof conversation.conversation_data);
                
                if (conversation.conversation_data) {
                    if (typeof conversation.conversation_data === 'object') {
                        // PostgreSQL JSONB returns as object
                        conversationData = conversation.conversation_data;
                        console.log('Using conversation_data as object (PostgreSQL JSONB):', conversationData);
                    } else if (typeof conversation.conversation_data === 'string') {
                        // SQLite returns as string
                        try {
                            conversationData = JSON.parse(conversation.conversation_data);
                            console.log('Parsed conversation_data from string:', conversationData);
                        } catch (e) {
                            console.error('Error parsing conversation_data:', e);
                            console.error('Failed to parse:', conversation.conversation_data);
                            conversationData = {};
                        }
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