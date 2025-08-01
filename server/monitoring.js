const Sentry = require('@sentry/node');

// Initialize Sentry for error tracking
function initializeSentry(app) {
    if (process.env.SENTRY_DSN) {
        Sentry.init({
            dsn: process.env.SENTRY_DSN,
            environment: process.env.NODE_ENV || 'development',
            integrations: [
                // Automatically instrument Node.js libraries and frameworks
                ...Sentry.autoDiscoverNodePerformanceMonitoringIntegrations(),
            ],
            // Performance monitoring
            tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
            
            // Set sample rate for profiling
            profilesSampleRate: 0.1,
            
            beforeSend(event, hint) {
                // Filter out sensitive data
                if (event.request) {
                    // Remove auth headers
                    if (event.request.headers) {
                        delete event.request.headers.authorization;
                        delete event.request.headers.cookie;
                    }
                    // Remove sensitive body data
                    if (event.request.data) {
                        delete event.request.data.password;
                        delete event.request.data.creditCard;
                        delete event.request.data.stripeToken;
                    }
                }
                
                // Don't send events in development
                if (process.env.NODE_ENV === 'development') {
                    return null;
                }
                
                return event;
            }
        });
        
        console.log('✅ Sentry error monitoring initialized');
    } else {
        console.log('⚠️  Sentry not configured - error monitoring disabled');
    }
}

// Custom error handler middleware
function errorHandler(err, req, res, next) {
    // Log the error
    console.error('Error:', err);
    
    // Capture in Sentry
    if (process.env.SENTRY_DSN) {
        Sentry.captureException(err, {
            extra: {
                url: req.url,
                method: req.method,
                ip: req.ip,
                userId: req.user?.userId,
                userType: req.user ? 'authenticated' : 'anonymous'
            }
        });
    }
    
    // Send appropriate error response
    const status = err.status || 500;
    const message = process.env.NODE_ENV === 'production' 
        ? 'An error occurred processing your request'
        : err.message;
    
    res.status(status).json({
        error: message,
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
}

// Log important events
function logEvent(eventName, data = {}) {
    const event = {
        timestamp: new Date().toISOString(),
        event: eventName,
        ...data
    };
    
    // Console log
    console.log(`📊 Event: ${eventName}`, data);
    
    // Send to Sentry as breadcrumb
    if (process.env.SENTRY_DSN) {
        Sentry.addBreadcrumb({
            category: 'app.event',
            message: eventName,
            level: 'info',
            data
        });
    }
}

// Track performance metrics
function trackPerformance(operation, duration, metadata = {}) {
    const metric = {
        operation,
        duration,
        timestamp: new Date().toISOString(),
        ...metadata
    };
    
    // Log slow operations
    if (duration > 1000) {
        console.warn(`⚠️  Slow operation: ${operation} took ${duration}ms`, metadata);
        
        // Report to Sentry
        if (process.env.SENTRY_DSN) {
            Sentry.captureMessage(`Slow operation: ${operation}`, {
                level: 'warning',
                extra: metric
            });
        }
    }
}

// Monitor Claude API usage and costs
function trackClaudeUsage(userId, model, tokens, cost) {
    const usage = {
        userId,
        model,
        tokens,
        estimatedCost: cost,
        timestamp: new Date().toISOString()
    };
    
    logEvent('claude_api_usage', usage);
    
    // Alert on high usage
    if (cost > 0.5) {
        console.warn(`⚠️  High Claude API cost: $${cost} for user ${userId}`);
        if (process.env.SENTRY_DSN) {
            Sentry.captureMessage('High Claude API cost detected', {
                level: 'warning',
                extra: usage
            });
        }
    }
}

module.exports = {
    initializeSentry,
    errorHandler,
    logEvent,
    trackPerformance,
    trackClaudeUsage,
    Sentry
};