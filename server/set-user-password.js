// Quick script to generate a password hash
const bcrypt = require('bcrypt');

const password = process.argv[2];
if (!password) {
    console.log('Usage: node set-user-password.js <password>');
    console.log('Example: node set-user-password.js NewPassword123');
    process.exit(1);
}

bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
        console.error('Error:', err);
        return;
    }
    
    console.log('\nPassword hash generated!');
    console.log('Use this SQL to update their password:\n');
    console.log(`UPDATE users`);
    console.log(`SET password_hash = '${hash}'`);
    console.log(`WHERE email = 'their-email@example.com';`);
    console.log('\nThen they can login with:');
    console.log('Email: their-email@example.com');
    console.log('Password:', password);
});