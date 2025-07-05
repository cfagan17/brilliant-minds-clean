#!/usr/bin/env node

require('dotenv').config();

async function testAPI() {
    const port = process.env.PORT || 3000;
    const baseUrl = `http://localhost:${port}`;
    
    console.log('🧪 Testing Brilliant Minds API...');
    console.log('================================');
    
    try {
        // Test 1: Health check
        console.log('\n1. Testing health endpoint...');
        const healthResponse = await fetch(`${baseUrl}/api/health`);
        const healthData = await healthResponse.json();
        
        if (healthResponse.ok) {
            console.log('✅ Health check passed');
            console.log(`   Status: ${healthData.status}`);
            console.log(`   API Key configured: ${healthData.hasApiKey ? 'Yes' : 'No'}`);
        } else {
            console.log('❌ Health check failed');
            return;
        }
        
        // Test 2: Claude API
        if (healthData.hasApiKey) {
            console.log('\n2. Testing Claude API...');
            const testMessage = "You are Socrates. Respond briefly to this question: What is wisdom?";
            
            const claudeResponse = await fetch(`${baseUrl}/api/claude`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: testMessage,
                    figure: 'socrates'
                })
            });
            
            if (claudeResponse.ok) {
                const claudeData = await claudeResponse.json();
                console.log('✅ Claude API test passed');
                console.log(`   Response length: ${claudeData.content[0].text.length} characters`);
                console.log(`   Sample response: "${claudeData.content[0].text.substring(0, 100)}..."`);
            } else {
                const errorData = await claudeResponse.json();
                console.log('❌ Claude API test failed');
                console.log(`   Error: ${errorData.error}`);
                console.log(`   Status: ${claudeResponse.status}`);
            }
        } else {
            console.log('\n2. Skipping Claude API test (no API key configured)');
        }
        
        console.log('\n🎉 Testing complete!');
        console.log(`\n🌐 Your app should be available at: ${baseUrl}`);
        
    } catch (error) {
        console.log('\n❌ Test failed with error:');
        console.error(error.message);
        console.log('\n💡 Make sure your server is running with: npm start');
    }
}

testAPI();
