#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

console.log('🧠 Welcome to Brilliant Minds Setup!');
console.log('=====================================');
console.log('');

function askQuestion(question) {
    return new Promise((resolve) => {
        rl.question(question, resolve);
    });
}

async function setup() {
    try {
        // Check if .env already exists
        const envPath = path.join(__dirname, '.env');
        if (fs.existsSync(envPath)) {
            console.log('✅ .env file already exists');
            const overwrite = await askQuestion('Do you want to update your API key? (y/N): ');
            if (overwrite.toLowerCase() !== 'y') {
                console.log('Setup completed! Run "npm start" to launch the app.');
                rl.close();
                return;
            }
        }

        console.log('');
        console.log('📋 To get started, you need a Claude API key:');
        console.log('1. Visit: https://console.anthropic.com/');
        console.log('2. Sign up or log in');
        console.log('3. Go to "API Keys" section');
        console.log('4. Create a new API key');
        console.log('');

        const apiKey = await askQuestion('Enter your Claude API key: ');

        if (!apiKey || apiKey.trim().length === 0) {
            console.log('❌ No API key provided. Setup cancelled.');
            rl.close();
            return;
        }

        // Validate API key format (basic check)
        if (!apiKey.startsWith('sk-ant-')) {
            console.log('⚠️  Warning: API key doesn\'t look like a valid Claude API key');
            console.log('   Claude API keys typically start with "sk-ant-"');
            const proceed = await askQuestion('Continue anyway? (y/N): ');
            if (proceed.toLowerCase() !== 'y') {
                console.log('Setup cancelled.');
                rl.close();
                return;
            }
        }

        // Create .env file
        const envContent = `# Claude API Configuration
CLAUDE_API_KEY=${apiKey.trim()}

# Server Configuration
PORT=3000
`;

        fs.writeFileSync(envPath, envContent);
        console.log('');
        console.log('✅ .env file created successfully!');
        console.log('');
        console.log('🚀 Setup complete! You can now run:');
        console.log('   npm install    # Install dependencies');
        console.log('   npm start      # Start the server');
        console.log('');
        console.log('   Then open: http://localhost:3000');
        console.log('');
        console.log('💡 Tip: Keep your API key secure and never commit .env to version control');

    } catch (error) {
        console.error('❌ Setup failed:', error.message);
    } finally {
        rl.close();
    }
}

setup();
