// Database abstraction layer - supports both SQLite and PostgreSQL
const USE_POSTGRES = process.env.DATABASE_URL && process.env.NODE_ENV === 'production';

let db, initializeDatabase, pool;

if (USE_POSTGRES) {
    console.log('Using PostgreSQL database');
    const pgModule = require('./database-postgres');
    db = pgModule.db;
    initializeDatabase = pgModule.initializeDatabase;
    pool = pgModule.pool;
} else {
    console.log('Using SQLite database (development)');
    const sqliteModule = require('./database-sqlite');
    db = sqliteModule.db;
    initializeDatabase = sqliteModule.initializeDatabase;
}

module.exports = { db, initializeDatabase, pool, USE_POSTGRES };