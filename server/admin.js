// Admin utilities for app management
const bcrypt = require('bcrypt');
const { db } = require('./database');

// Create admin user if it doesn't exist
async function createAdminUser() {
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@iconoclash.com';
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
    
    if (!ADMIN_PASSWORD) {
        console.log('⚠️  ADMIN_PASSWORD not set in environment variables');
        console.log('Generate one with: node -e "console.log(require(\'crypto\').randomBytes(16).toString(\'hex\'))"');
        return;
    }
    
    return new Promise((resolve, reject) => {
        // Check if admin exists
        db.get('SELECT * FROM users WHERE email = ?', [ADMIN_EMAIL], async (err, user) => {
            if (err) {
                console.error('Error checking admin user:', err);
                return reject(err);
            }
            
            if (user) {
                console.log('✅ Admin user already exists:', ADMIN_EMAIL);
                
                // Update to ensure admin privileges
                db.run(`
                    UPDATE users 
                    SET is_admin = 1, is_pro = 1, is_test_account = 1 
                    WHERE email = ?
                `, [ADMIN_EMAIL], (err) => {
                    if (err) console.error('Error updating admin privileges:', err);
                    else console.log('✅ Admin privileges updated');
                });
                
                return resolve(user);
            }
            
            // Create admin user
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
            
            db.run(`
                INSERT INTO users (email, password_hash, is_pro, is_admin, is_test_account, discussions_used)
                VALUES (?, ?, 1, 1, 1, 0)
            `, [ADMIN_EMAIL, hashedPassword], function(err) {
                if (err) {
                    console.error('Error creating admin user:', err);
                    return reject(err);
                }
                
                console.log('✅ Admin user created:', ADMIN_EMAIL);
                console.log('🔑 Login with your ADMIN_PASSWORD environment variable');
                resolve({ id: this.lastID, email: ADMIN_EMAIL });
            });
        });
    });
}

// Middleware to check if user is admin
function requireAdmin(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    db.get('SELECT is_admin FROM users WHERE id = ?', [req.user.userId], (err, user) => {
        if (err || !user || !user.is_admin) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        req.isAdmin = true;
        next();
    });
}

// Check if user is test account (doesn't affect analytics)
function isTestAccount(userId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
            if (err) {
                console.error('Error checking test account:', err);
                resolve(false); // Default to false if there's an error
            } else {
                // Check if is_test_account exists, default to false if not
                resolve(user && (user.is_test_account || false));
            }
        });
    });
}

module.exports = {
    createAdminUser,
    requireAdmin,
    isTestAccount
};