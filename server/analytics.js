const { db } = require('./database');

// Core metrics to track for business intelligence
const ANALYTICS_EVENTS = {
    // User Journey Events
    LANDING_PAGE_VIEW: 'landing_page_view',
    FIRST_INTERACTION: 'first_interaction',
    SIGNUP_STARTED: 'signup_started',
    SIGNUP_COMPLETED: 'signup_completed',
    LOGIN: 'login',
    
    // Engagement Events
    DISCUSSION_STARTED: 'discussion_started',
    DISCUSSION_COMPLETED: 'discussion_completed',
    MESSAGE_SENT: 'message_sent',
    FEATURE_USED: 'feature_used',
    CONVERSATION_SAVED: 'conversation_saved',
    CONVERSATION_SHARED: 'conversation_shared',
    
    // Conversion Events
    UPGRADE_MODAL_SHOWN: 'upgrade_modal_shown',
    UPGRADE_CLICKED: 'upgrade_clicked',
    CHECKOUT_STARTED: 'checkout_started',
    PAYMENT_COMPLETED: 'payment_completed',
    PAYMENT_FAILED: 'payment_failed',
    
    // Retention Events
    DAILY_ACTIVE: 'daily_active',
    WEEKLY_ACTIVE: 'weekly_active',
    SESSION_DURATION: 'session_duration',
    CHURN_RISK: 'churn_risk',
    
    // Cost Events
    CLAUDE_API_CALL: 'claude_api_call',
    CLAUDE_API_COST: 'claude_api_cost'
};

// Conversion funnel stages
const FUNNEL_STAGES = {
    VISITOR: 'visitor',
    ENGAGED: 'engaged',
    REGISTERED: 'registered',
    ACTIVE_USER: 'active_user',
    PAYING_USER: 'paying_user'
};

class Analytics {
    constructor() {
        this.sessionData = new Map();
    }
    
    // Track any event with metadata
    async trackEvent(eventName, userId, data = {}) {
        const timestamp = new Date();
        const event = {
            event_type: eventName,
            user_id: userId,
            session_id: data.sessionId || this.getSessionId(userId),
            timestamp,
            data: {
                ...data,
                // Add automatic metadata
                hour: timestamp.getHours(),
                dayOfWeek: timestamp.getDay(),
                userAgent: data.userAgent,
                referrer: data.referrer,
                utm_source: data.utm_source,
                utm_campaign: data.utm_campaign
            }
        };
        
        // Store in database
        try {
            await this.storeEvent(event);
            
            // Real-time metrics disabled (Redis removed)
            
        } catch (error) {
            console.error('Analytics tracking error:', error);
        }
        
        return event;
    }
    
    // Store event in database
    async storeEvent(event) {
        return new Promise((resolve, reject) => {
            db.run(`
                INSERT INTO analytics_events (user_id, session_id, event_type, event_data, timestamp)
                VALUES (?, ?, ?, ?, ?)
            `, [
                event.user_id,
                event.session_id,
                event.event_type,
                JSON.stringify(event.data),
                event.timestamp.toISOString()
            ], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }
    
    // Real-time metrics disabled (Redis removed)
    async updateRealtimeMetrics(event) {
        // Disabled after Redis removal
    }
    
    // User journey tracking disabled (Redis removed)
    async updateUserJourney(userId, eventName) {
        // Disabled after Redis removal
    }
    
    // Check if event is part of conversion funnel
    isFunnelEvent(eventType) {
        return [
            ANALYTICS_EVENTS.LANDING_PAGE_VIEW,
            ANALYTICS_EVENTS.FIRST_INTERACTION,
            ANALYTICS_EVENTS.SIGNUP_COMPLETED,
            ANALYTICS_EVENTS.DISCUSSION_STARTED,
            ANALYTICS_EVENTS.UPGRADE_CLICKED,
            ANALYTICS_EVENTS.PAYMENT_COMPLETED
        ].includes(eventType);
    }
    
    // Update conversion funnel
    // Funnel tracking disabled (Redis removed)
    async updateFunnel(userId, eventType) {
        // Disabled after Redis removal
    }
    
    // Get conversion metrics
    async getConversionMetrics(startDate, endDate) {
        return new Promise((resolve, reject) => {
            db.all(`
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(DISTINCT CASE WHEN event_type = ? THEN user_id END) as visitors,
                    COUNT(DISTINCT CASE WHEN event_type = ? THEN user_id END) as engaged,
                    COUNT(DISTINCT CASE WHEN event_type = ? THEN user_id END) as signups,
                    COUNT(DISTINCT CASE WHEN event_type = ? THEN user_id END) as active_users,
                    COUNT(DISTINCT CASE WHEN event_type = ? THEN user_id END) as paying_users
                FROM analytics_events
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            `, [
                ANALYTICS_EVENTS.LANDING_PAGE_VIEW,
                ANALYTICS_EVENTS.FIRST_INTERACTION,
                ANALYTICS_EVENTS.SIGNUP_COMPLETED,
                ANALYTICS_EVENTS.DISCUSSION_STARTED,
                ANALYTICS_EVENTS.PAYMENT_COMPLETED,
                startDate,
                endDate
            ], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }
    
    // Get user behavior metrics
    async getUserBehaviorMetrics(userId) {
        return new Promise((resolve, reject) => {
            db.all(`
                SELECT 
                    event_type,
                    COUNT(*) as count,
                    MIN(timestamp) as first_occurrence,
                    MAX(timestamp) as last_occurrence
                FROM analytics_events
                WHERE user_id = ?
                GROUP BY event_type
                ORDER BY count DESC
            `, [userId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }
    
    // Get revenue metrics
    async getRevenueMetrics(startDate, endDate) {
        return new Promise((resolve, reject) => {
            db.all(`
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(DISTINCT user_id) as new_customers,
                    COUNT(*) as total_payments,
                    SUM(CAST(json_extract(event_data, '$.amount') AS REAL)) as revenue,
                    AVG(CAST(json_extract(event_data, '$.amount') AS REAL)) as avg_order_value
                FROM analytics_events
                WHERE event_type = ? 
                AND timestamp BETWEEN ? AND ?
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            `, [ANALYTICS_EVENTS.PAYMENT_COMPLETED, startDate, endDate], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }
    
    // Get cost metrics (Claude API)
    async getCostMetrics(startDate, endDate) {
        return new Promise((resolve, reject) => {
            db.all(`
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(*) as api_calls,
                    SUM(CAST(json_extract(event_data, '$.tokens') AS INTEGER)) as total_tokens,
                    SUM(CAST(json_extract(event_data, '$.cost') AS REAL)) as total_cost,
                    AVG(CAST(json_extract(event_data, '$.cost') AS REAL)) as avg_cost_per_call
                FROM analytics_events
                WHERE event_type = ?
                AND timestamp BETWEEN ? AND ?
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            `, [ANALYTICS_EVENTS.CLAUDE_API_COST, startDate, endDate], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }
    
    // Get cohort retention
    async getCohortRetention(cohortDate, daysToTrack = 30) {
        const cohortUsers = await this.getCohortUsers(cohortDate);
        const retention = {};
        
        for (let day = 0; day <= daysToTrack; day++) {
            const checkDate = new Date(cohortDate);
            checkDate.setDate(checkDate.getDate() + day);
            
            const activeUsers = await this.getActiveUsersOnDate(
                cohortUsers,
                checkDate.toISOString().split('T')[0]
            );
            
            retention[`day_${day}`] = {
                active: activeUsers.length,
                percentage: (activeUsers.length / cohortUsers.length) * 100
            };
        }
        
        return {
            cohort_date: cohortDate,
            cohort_size: cohortUsers.length,
            retention
        };
    }
    
    // Helper: Get users who signed up on specific date
    async getCohortUsers(date) {
        return new Promise((resolve, reject) => {
            db.all(`
                SELECT DISTINCT user_id
                FROM analytics_events
                WHERE event_type = ?
                AND DATE(timestamp) = ?
            `, [ANALYTICS_EVENTS.SIGNUP_COMPLETED, date], (err, rows) => {
                if (err) reject(err);
                else resolve(rows.map(r => r.user_id));
            });
        });
    }
    
    // Helper: Get active users on specific date
    async getActiveUsersOnDate(userIds, date) {
        return new Promise((resolve, reject) => {
            const placeholders = userIds.map(() => '?').join(',');
            db.all(`
                SELECT DISTINCT user_id
                FROM analytics_events
                WHERE user_id IN (${placeholders})
                AND DATE(timestamp) = ?
                AND event_type IN (?, ?)
            `, [...userIds, date, ANALYTICS_EVENTS.DISCUSSION_STARTED, ANALYTICS_EVENTS.MESSAGE_SENT], 
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows.map(r => r.user_id));
            });
        });
    }
    
    // Get real-time metrics
    async getRealtimeMetrics(fiveMinutesAgo, todayStart) {
        return new Promise((resolve, reject) => {
            const queries = {
                activeNow: `
                    SELECT COUNT(DISTINCT user_id) as count
                    FROM analytics_events
                    WHERE timestamp > ?
                `,
                todayDiscussions: `
                    SELECT COUNT(*) as count
                    FROM analytics_events
                    WHERE event_type = ?
                    AND timestamp > ?
                `,
                todayRevenue: `
                    SELECT SUM(CAST(json_extract(event_data, '$.amount') AS REAL)) as total
                    FROM analytics_events
                    WHERE event_type = ?
                    AND timestamp > ?
                `,
                recentActivity: `
                    SELECT 
                        ae.timestamp,
                        ae.event_type,
                        ae.user_id,
                        u.email as user_email,
                        ae.event_data
                    FROM analytics_events ae
                    LEFT JOIN users u ON ae.user_id = u.id
                    ORDER BY ae.timestamp DESC
                    LIMIT 20
                `
            };
            
            const results = {};
            
            db.get(queries.activeNow, [fiveMinutesAgo], (err, row) => {
                if (err) return reject(err);
                results.activeNow = row?.count || 0;
                
                db.get(queries.todayDiscussions, [ANALYTICS_EVENTS.DISCUSSION_STARTED, todayStart], (err, row) => {
                    if (err) return reject(err);
                    results.todayDiscussions = row?.count || 0;
                    
                    db.get(queries.todayRevenue, [ANALYTICS_EVENTS.PAYMENT_COMPLETED, todayStart], (err, row) => {
                        if (err) return reject(err);
                        results.todayRevenue = row?.total || 0;
                        
                        db.all(queries.recentActivity, [], (err, rows) => {
                            if (err) return reject(err);
                            results.recentActivity = rows.map(row => ({
                                ...row,
                                details: this.formatEventDetails(row.event_type, row.event_data)
                            }));
                            resolve(results);
                        });
                    });
                });
            });
        });
    }
    
    // Get engagement metrics
    async getEngagementMetrics(startDate, endDate) {
        return new Promise((resolve, reject) => {
            const queries = {
                retentionRates: `
                    SELECT 
                        CAST((julianday(ae2.timestamp) - julianday(ae1.timestamp)) AS INTEGER) as days_after,
                        COUNT(DISTINCT ae2.user_id) * 100.0 / 
                        (SELECT COUNT(DISTINCT user_id) FROM analytics_events WHERE event_type = ? AND timestamp BETWEEN ? AND ?) as retention_rate
                    FROM analytics_events ae1
                    JOIN analytics_events ae2 ON ae1.user_id = ae2.user_id
                    WHERE ae1.event_type = ?
                    AND ae1.timestamp BETWEEN ? AND ?
                    AND ae2.timestamp > ae1.timestamp
                    AND (julianday(ae2.timestamp) - julianday(ae1.timestamp)) IN (1, 7, 14, 30)
                    GROUP BY days_after
                `,
                sessionDistribution: `
                    SELECT 
                        CASE 
                            WHEN session_duration < 60 THEN '< 1 min'
                            WHEN session_duration < 300 THEN '1-5 min'
                            WHEN session_duration < 900 THEN '5-15 min'
                            WHEN session_duration < 1800 THEN '15-30 min'
                            ELSE '> 30 min'
                        END as duration_bucket,
                        COUNT(*) as count
                    FROM (
                        SELECT 
                            user_id,
                            session_id,
                            (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24 * 60 * 60 as session_duration
                        FROM analytics_events
                        WHERE timestamp BETWEEN ? AND ?
                        AND session_id IS NOT NULL
                        GROUP BY user_id, session_id
                    )
                    GROUP BY duration_bucket
                `
            };
            
            const results = {};
            
            db.all(queries.retentionRates, [
                ANALYTICS_EVENTS.SIGNUP_COMPLETED, startDate, endDate,
                ANALYTICS_EVENTS.SIGNUP_COMPLETED, startDate, endDate
            ], (err, rows) => {
                if (err) return reject(err);
                results.retentionRates = [100]; // Day 0 is always 100%
                const retentionMap = {};
                rows.forEach(row => {
                    retentionMap[row.days_after] = row.retention_rate;
                });
                [1, 7, 14, 30].forEach(day => {
                    results.retentionRates.push(retentionMap[day] || 0);
                });
                
                db.all(queries.sessionDistribution, [startDate, endDate], (err, rows) => {
                    if (err) return reject(err);
                    const distribution = {
                        '< 1 min': 0,
                        '1-5 min': 0,
                        '5-15 min': 0,
                        '15-30 min': 0,
                        '> 30 min': 0
                    };
                    rows.forEach(row => {
                        distribution[row.duration_bucket] = row.count;
                    });
                    results.sessionDistribution = Object.values(distribution);
                    resolve(results);
                });
            });
        });
    }
    
    // Helper to format event details for display
    formatEventDetails(eventType, eventData) {
        try {
            const data = typeof eventData === 'string' ? JSON.parse(eventData) : eventData;
            switch(eventType) {
                case ANALYTICS_EVENTS.DISCUSSION_STARTED:
                    return `${data.format || 'chat'} discussion`;
                case ANALYTICS_EVENTS.PAYMENT_COMPLETED:
                    return `$${(data.amount || 0).toFixed(2)} payment`;
                case ANALYTICS_EVENTS.SIGNUP_COMPLETED:
                    return 'New user signup';
                default:
                    return '-';
            }
        } catch {
            return '-';
        }
    }
    
    // Get comprehensive dashboard data
    async getDashboardData() {
        const today = new Date().toISOString().split('T')[0];
        const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
        const lastWeek = new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0];
        const lastMonth = new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0];
        
        const [
            conversionMetrics,
            revenueMetrics,
            costMetrics,
            todayStats,
            yesterdayStats
        ] = await Promise.all([
            this.getConversionMetrics(lastMonth, today),
            this.getRevenueMetrics(lastMonth, today),
            this.getCostMetrics(lastMonth, today),
            this.getDailyStats(today),
            this.getDailyStats(yesterday)
        ]);
        
        return {
            overview: {
                today: todayStats,
                yesterday: yesterdayStats,
                change: this.calculateChange(todayStats, yesterdayStats)
            },
            conversion: {
                funnel: this.calculateFunnelRates(conversionMetrics),
                byDate: conversionMetrics
            },
            revenue: {
                total: revenueMetrics.reduce((sum, day) => sum + (day.revenue || 0), 0),
                byDate: revenueMetrics
            },
            costs: {
                total: costMetrics.reduce((sum, day) => sum + (day.total_cost || 0), 0),
                byDate: costMetrics
            },
            profitability: this.calculateProfitability(revenueMetrics, costMetrics)
        };
    }
    
    // Helper: Get daily stats
    async getDailyStats(date) {
        return new Promise((resolve, reject) => {
            db.get(`
                SELECT 
                    COUNT(DISTINCT CASE WHEN event_type = ? THEN user_id END) as visitors,
                    COUNT(DISTINCT CASE WHEN event_type = ? THEN user_id END) as signups,
                    COUNT(DISTINCT CASE WHEN event_type = ? THEN user_id END) as active_users,
                    COUNT(CASE WHEN event_type = ? THEN 1 END) as discussions,
                    COUNT(DISTINCT CASE WHEN event_type = ? THEN user_id END) as paying_users
                FROM analytics_events
                WHERE DATE(timestamp) = ?
            `, [
                ANALYTICS_EVENTS.LANDING_PAGE_VIEW,
                ANALYTICS_EVENTS.SIGNUP_COMPLETED,
                ANALYTICS_EVENTS.DISCUSSION_STARTED,
                ANALYTICS_EVENTS.DISCUSSION_STARTED,
                ANALYTICS_EVENTS.PAYMENT_COMPLETED,
                date
            ], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }
    
    // Helper: Calculate percentage change
    calculateChange(today, yesterday) {
        const metrics = ['visitors', 'signups', 'active_users', 'discussions'];
        const change = {};
        
        metrics.forEach(metric => {
            const todayVal = today[metric] || 0;
            const yesterdayVal = yesterday[metric] || 0;
            
            if (yesterdayVal === 0) {
                change[metric] = todayVal > 0 ? 100 : 0;
            } else {
                change[metric] = ((todayVal - yesterdayVal) / yesterdayVal) * 100;
            }
        });
        
        return change;
    }
    
    // Helper: Calculate funnel conversion rates
    calculateFunnelRates(conversionData) {
        const totals = conversionData.reduce((acc, day) => {
            acc.visitors += day.visitors || 0;
            acc.engaged += day.engaged || 0;
            acc.signups += day.signups || 0;
            acc.active_users += day.active_users || 0;
            acc.paying_users += day.paying_users || 0;
            return acc;
        }, { visitors: 0, engaged: 0, signups: 0, active_users: 0, paying_users: 0 });
        
        return {
            visitor_to_engaged: (totals.engaged / totals.visitors) * 100,
            engaged_to_signup: (totals.signups / totals.engaged) * 100,
            signup_to_active: (totals.active_users / totals.signups) * 100,
            active_to_paying: (totals.paying_users / totals.active_users) * 100,
            overall: (totals.paying_users / totals.visitors) * 100
        };
    }
    
    // Helper: Calculate profitability
    calculateProfitability(revenue, costs) {
        const totalRevenue = revenue.reduce((sum, day) => sum + (day.revenue || 0), 0);
        const totalCosts = costs.reduce((sum, day) => sum + (day.total_cost || 0), 0);
        
        return {
            revenue: totalRevenue,
            costs: totalCosts,
            profit: totalRevenue - totalCosts,
            margin: totalRevenue > 0 ? ((totalRevenue - totalCosts) / totalRevenue) * 100 : 0
        };
    }
    
    // Get session ID for user
    getSessionId(userId) {
        if (!this.sessionData.has(userId)) {
            this.sessionData.set(userId, `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`);
        }
        return this.sessionData.get(userId);
    }
}

// Export singleton instance
const analytics = new Analytics();

module.exports = {
    analytics,
    ANALYTICS_EVENTS
};