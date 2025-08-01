// Script to make all users Pro in the database
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'brilliant_minds.db');
const db = new sqlite3.Database(dbPath);

// Make all users Pro
db.run(`UPDATE users SET is_pro = 1, discussions_used = 0`, function(err) {
    if (err) {
        console.error('Error updating users:', err);
    } else {
        console.log(`✅ Updated ${this.changes} users to Pro status`);
    }
});

// Reset anonymous user limits
db.run(`UPDATE anonymous_users SET discussions_used = 0`, function(err) {
    if (err) {
        console.error('Error updating anonymous users:', err);
    } else {
        console.log(`✅ Reset limits for ${this.changes} anonymous users`);
    }
});

db.close();