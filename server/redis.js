const Redis = require('ioredis');

let redis = null;
let redisAvailable = false;

// Initialize Redis connection
if (process.env.REDIS_URL) {
    try {
        redis = new Redis(process.env.REDIS_URL, {
            maxRetriesPerRequest: 3,
            retryStrategy: (times) => {
                if (times > 3) {
                    console.error('Redis connection failed after 3 retries');
                    return null;
                }
                return Math.min(times * 100, 3000);
            },
            reconnectOnError: (err) => {
                console.error('Redis reconnect error:', err.message);
                return true;
            }
        });

        redis.on('connect', () => {
            console.log('✅ Redis connected successfully');
            redisAvailable = true;
        });

        redis.on('error', (err) => {
            console.error('❌ Redis error:', err.message);
            redisAvailable = false;
        });

        redis.on('close', () => {
            console.log('Redis connection closed');
            redisAvailable = false;
        });

        // Test the connection
        redis.ping().catch(err => {
            console.error('Redis ping failed:', err.message);
            redisAvailable = false;
        });
    } catch (error) {
        console.error('Failed to initialize Redis:', error.message);
        redis = null;
    }
} else {
    console.log('⚠️  Redis not configured - using in-memory rate limiting');
}

// Helper function to safely use Redis with fallback
async function redisGet(key) {
    if (!redisAvailable || !redis) return null;
    try {
        return await redis.get(key);
    } catch (err) {
        console.error('Redis get error:', err.message);
        return null;
    }
}

async function redisSet(key, value, expirySeconds) {
    if (!redisAvailable || !redis) return false;
    try {
        if (expirySeconds) {
            await redis.setex(key, expirySeconds, value);
        } else {
            await redis.set(key, value);
        }
        return true;
    } catch (err) {
        console.error('Redis set error:', err.message);
        return false;
    }
}

async function redisIncr(key) {
    if (!redisAvailable || !redis) return null;
    try {
        return await redis.incr(key);
    } catch (err) {
        console.error('Redis incr error:', err.message);
        return null;
    }
}

async function redisExpire(key, seconds) {
    if (!redisAvailable || !redis) return false;
    try {
        await redis.expire(key, seconds);
        return true;
    } catch (err) {
        console.error('Redis expire error:', err.message);
        return false;
    }
}

module.exports = {
    redis,
    redisAvailable: () => redisAvailable,
    redisGet,
    redisSet,
    redisIncr,
    redisExpire
};