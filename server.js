require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;
// ADD THIS LINE - Initialize Stripe
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());
app.use(express.static('.')); // Serve static files from current directory

// API endpoint to proxy Claude requests
app.post('/api/claude', async (req, res) => {
    try {
        const { message, figure } = req.body;
        // Remove apiKey from req.body - we'll use our own
        
        console.log('Received request for figure:', figure);
        
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': CLAUDE_API_KEY,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 800,
                messages: [{
                    role: 'user',
                    content: message
                }]
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Claude API Error:', response.status, errorText);
            return res.status(response.status).json({ error: errorText });
        }
        
        const data = await response.json();
        res.json(data);
        
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ADD THIS NEW STRIPE ENDPOINT HERE
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { priceId } = req.body;
        
        console.log('Creating checkout session for price:', priceId);

        const session = await stripe.checkout.sessions.create({
            mode: 'subscription',
            payment_method_types: ['card'],
            line_items: [
                {
                    price: priceId,
                    quantity: 1,
                },
            ],
            success_url: `${req.headers.origin || req.headers.referer || 'https://your-app.vercel.app'}?success=true`,
            cancel_url: `${req.headers.origin || req.headers.referer || 'https://your-app.vercel.app'}?canceled=true`,
        });

        res.json({ sessionId: session.id });
    } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/chat.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'chat.html'));
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        hasApiKey: !!CLAUDE_API_KEY
    });
});

// Export the app for Vercel (remove the app.listen for serverless)
module.exports = app;

// Only listen when running locally (not on Vercel)
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Open your app at: http://localhost:${PORT}`);
    });
}