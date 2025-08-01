const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');
const RedisStore = require('rate-limit-redis').default;
const { redis, redisAvailable } = require('./redis');

// Different rate limits for different endpoints
const rateLimits = {
    // Claude API - most expensive, strict limits
    claude: {
        windowMs: 60 * 60 * 1000, // 1 hour
        free: 10, // 10 requests per hour for free users
        pro: 100, // 100 requests per hour for pro users
        anonymous: 5, // 5 requests per hour for anonymous
        message: 'Too many requests. Please upgrade to Pro for higher limits.'
    },
    
    // Auth endpoints - prevent brute force
    auth: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5, // 5 attempts per 15 minutes
        message: 'Too many login attempts. Please try again later.',
        skipSuccessfulRequests: true
    },
    
    // General API endpoints
    general: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // 100 requests per 15 minutes
        message: 'Too many requests. Please try again later.'
    }
};

// Create rate limiter with Redis store if available
function createRateLimiter(config, keyGenerator) {
    const options = {
        windowMs: config.windowMs,
        max: config.max || config.free,
        message: config.message,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: keyGenerator || ipKeyGenerator,
        handler: (req, res) => {
            res.status(429).json({
                error: config.message,
                retryAfter: res.getHeader('Retry-After')
            });
        }
    };

    // Use Redis store if available
    if (redis && redisAvailable()) {
        options.store = new RedisStore({
            client: redis,
            prefix: 'rl:',
        });
    } else {
        console.log('Using in-memory rate limiting (not suitable for production)');
    }

    return rateLimit(options);
}

// Claude API rate limiter - different limits based on user type
const claudeRateLimiter = (req, res, next) => {
    let limit = rateLimits.claude.anonymous;
    let keyPrefix = 'anon';
    
    if (req.user) {
        // Authenticated user
        keyPrefix = 'user';
        limit = req.user.isProUser ? rateLimits.claude.pro : rateLimits.claude.free;
    }
    
    const limiter = createRateLimiter(
        { ...rateLimits.claude, max: limit },
        (req) => `claude:${keyPrefix}:${req.user?.userId || ipKeyGenerator(req)}`
    );
    
    return limiter(req, res, next);
};

// Auth rate limiter
const authRateLimiter = createRateLimiter(
    rateLimits.auth,
    (req) => `auth:${req.body?.email || ipKeyGenerator(req)}`
);

// General API rate limiter
const generalRateLimiter = createRateLimiter(
    rateLimits.general,
    (req) => `api:${req.user?.userId || ipKeyGenerator(req)}`
);

// Usage tracking with Redis (for analytics)
async function trackUsage(userId, eventType) {
    if (!redis || !redisAvailable()) return;
    
    try {
        const today = new Date().toISOString().split('T')[0];
        const hourly = new Date().toISOString().split(':')[0];
        
        // Track daily usage
        await redis.hincrby(`usage:daily:${today}`, `${eventType}:${userId}`, 1);
        await redis.expire(`usage:daily:${today}`, 7 * 24 * 60 * 60); // Keep for 7 days
        
        // Track hourly usage
        await redis.hincrby(`usage:hourly:${hourly}`, `${eventType}:${userId}`, 1);
        await redis.expire(`usage:hourly:${hourly}`, 24 * 60 * 60); // Keep for 24 hours
        
        // Track user's total usage
        await redis.hincrby(`usage:user:${userId}`, eventType, 1);
    } catch (err) {
        console.error('Usage tracking error:', err);
    }
}

// Get usage statistics
async function getUsageStats(userId) {
    if (!redis || !redisAvailable()) return null;
    
    try {
        const today = new Date().toISOString().split('T')[0];
        const stats = {
            daily: await redis.hget(`usage:daily:${today}`, `claude:${userId}`) || 0,
            total: await redis.hget(`usage:user:${userId}`, 'claude') || 0
        };
        return stats;
    } catch (err) {
        console.error('Get usage stats error:', err);
        return null;
    }
}

module.exports = {
    claudeRateLimiter,
    authRateLimiter,
    generalRateLimiter,
    trackUsage,
    getUsageStats,
    rateLimits
};