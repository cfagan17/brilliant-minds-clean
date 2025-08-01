// Client-side analytics tracking
class AnalyticsTracker {
    constructor() {
        this.sessionId = this.getOrCreateSessionId();
        this.userId = this.getUserId();
        this.startTime = Date.now();
        this.events = [];
        
        // Track page view on load
        this.trackPageView();
        
        // Track session duration on unload
        window.addEventListener('beforeunload', () => this.trackSessionEnd());
        
        // Track user interactions
        this.setupEventListeners();
    }
    
    // Get or create session ID
    getOrCreateSessionId() {
        let sessionId = sessionStorage.getItem('sessionId');
        if (!sessionId) {
            sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            sessionStorage.setItem('sessionId', sessionId);
        }
        return sessionId;
    }
    
    // Get user ID from auth or anonymous ID
    getUserId() {
        const user = JSON.parse(localStorage.getItem('currentUser') || '{}');
        if (user.id) return `user_${user.id}`;
        
        let anonId = localStorage.getItem('anonymousId');
        if (!anonId) {
            anonId = `anon_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            localStorage.setItem('anonymousId', anonId);
        }
        return anonId;
    }
    
    // Track any event
    async track(eventName, data = {}) {
        const event = {
            eventType: eventName,
            userId: this.getUserId(),
            sessionId: this.sessionId,
            timestamp: new Date().toISOString(),
            data: {
                ...data,
                // Add automatic context
                url: window.location.pathname,
                referrer: document.referrer,
                userAgent: navigator.userAgent,
                screenResolution: `${window.screen.width}x${window.screen.height}`,
                // UTM parameters
                utm_source: new URLSearchParams(window.location.search).get('utm_source'),
                utm_campaign: new URLSearchParams(window.location.search).get('utm_campaign'),
                utm_medium: new URLSearchParams(window.location.search).get('utm_medium')
            }
        };
        
        // Store locally
        this.events.push(event);
        
        // Send to server
        try {
            await fetch('/api/analytics', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(event)
            });
        } catch (error) {
            console.error('Analytics tracking error:', error);
            // Store failed events for retry
            this.storeFailedEvent(event);
        }
    }
    
    // Track page view
    trackPageView() {
        this.track('landing_page_view', {
            page: document.title,
            path: window.location.pathname
        });
    }
    
    // Track session end
    trackSessionEnd() {
        const duration = Date.now() - this.startTime;
        this.track('session_duration', {
            duration: Math.round(duration / 1000), // seconds
            pageViews: this.events.filter(e => e.eventType === 'page_view').length,
            interactions: this.events.length
        });
    }
    
    // Track signup funnel
    trackSignupStarted(source = 'modal') {
        this.track('signup_started', { source });
    }
    
    trackSignupCompleted(email) {
        this.track('signup_completed', { 
            email: email.split('@')[1] // Only domain for privacy
        });
    }
    
    // Track engagement
    trackDiscussionStarted(format, topic, participants) {
        this.track('discussion_started', {
            format,
            topic,
            participantCount: participants.length,
            participants: participants.map(p => p.name)
        });
    }
    
    trackMessageSent(messageLength, isFirstMessage = false) {
        this.track('message_sent', {
            messageLength,
            isFirstMessage
        });
        
        if (isFirstMessage) {
            this.track('first_interaction');
        }
    }
    
    trackFeatureUsed(feature, metadata = {}) {
        this.track('feature_used', {
            feature,
            ...metadata
        });
    }
    
    // Track conversion
    trackUpgradeModalShown(trigger) {
        this.track('upgrade_modal_shown', { trigger });
    }
    
    trackUpgradeClicked(plan = 'pro') {
        this.track('upgrade_clicked', { plan });
    }
    
    trackCheckoutStarted() {
        this.track('checkout_started');
    }
    
    trackPaymentCompleted() {
        this.track('payment_completed');
    }
    
    // Track errors and issues
    trackError(error, context = {}) {
        this.track('client_error', {
            error: error.message || error,
            stack: error.stack,
            ...context
        });
    }
    
    // Setup automatic event listeners
    setupEventListeners() {
        // Track clicks on key CTAs
        document.addEventListener('click', (e) => {
            const target = e.target.closest('[data-track]');
            if (target) {
                const eventName = target.dataset.track;
                const eventData = JSON.parse(target.dataset.trackData || '{}');
                this.track(eventName, eventData);
            }
        });
        
        // Track form submissions
        document.addEventListener('submit', (e) => {
            const form = e.target;
            if (form.dataset.trackSubmit) {
                this.track(form.dataset.trackSubmit, {
                    formId: form.id,
                    formAction: form.action
                });
            }
        });
        
        // Track time on page
        let timeOnPage = 0;
        setInterval(() => {
            timeOnPage += 10;
            // Track milestones
            if (timeOnPage === 30) {
                this.track('engaged_30s');
            } else if (timeOnPage === 60) {
                this.track('engaged_60s');
            } else if (timeOnPage === 180) {
                this.track('engaged_3m');
            }
        }, 10000); // Every 10 seconds
    }
    
    // Store failed events for retry
    storeFailedEvent(event) {
        const failed = JSON.parse(localStorage.getItem('failedAnalytics') || '[]');
        failed.push(event);
        // Keep only last 100 events
        if (failed.length > 100) failed.shift();
        localStorage.setItem('failedAnalytics', JSON.stringify(failed));
    }
    
    // Retry failed events
    async retryFailedEvents() {
        const failed = JSON.parse(localStorage.getItem('failedAnalytics') || '[]');
        if (failed.length === 0) return;
        
        const successful = [];
        for (const event of failed) {
            try {
                await fetch('/api/analytics', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(event)
                });
                successful.push(event);
            } catch (error) {
                // Keep failed events
            }
        }
        
        // Remove successful events
        const remaining = failed.filter(e => !successful.includes(e));
        localStorage.setItem('failedAnalytics', JSON.stringify(remaining));
    }
}

// Initialize analytics
const analytics = new AnalyticsTracker();

// Retry failed events every minute
setInterval(() => analytics.retryFailedEvents(), 60000);

// Export for use in other scripts
window.analytics = analytics;