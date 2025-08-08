# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Iconoclash is a web application that allows users to chat with AI-powered historical figures. The app uses Claude API for AI conversations, includes user authentication, Stripe payment integration, and usage limits.

## Architecture

### Backend
- **Main Server**: `/server/server.js` - Express server handling API routes, authentication, and database operations
- **IMPORTANT**: Do NOT use the root `server.js.deprecated` file - it is not used in production
- **Database**: SQLite3 with tables for users and anonymous_users
- **Authentication**: JWT-based with bcrypt for password hashing
- **Payment**: Stripe integration for Pro subscriptions

### Frontend
- **Pages**: Multiple HTML files (index.html, chat.html, group.html, library.html, topics.html)
- **Deployment**: Configured for Vercel deployment with server in `/server` directory

### Key API Endpoints
- `/api/auth/*` - User registration, login, and authentication
- `/api/claude` - Proxies requests to Claude API with usage tracking
- `/api/create-checkout-session` - Stripe payment session creation
- `/api/analytics/*` - Usage analytics and dashboard

## Commands

```bash
# Install dependencies
npm install

# Run locally with environment variables
npm run dev

# Start production server
npm start

# Run from server directory (matches Vercel deployment)
cd server && npm start

# IMPORTANT: Always use server/server.js, never the root server.js.deprecated
```

## Environment Setup

Required environment variables:
- `CLAUDE_API_KEY` - Anthropic API key
- `STRIPE_SECRET_KEY` - Stripe secret key
- `JWT_SECRET` - Secret for JWT tokens (defaults to 'your-secret-key-here')

## Usage Limits

- **Anonymous users**: 10 discussions per day (resets daily)
- **Free registered users**: 10 discussions per day (resets daily)
- **Pro users**: Unlimited discussions ($2/month)

## Important Notes

- The app tracks discussions by session ID to prevent counting multiple messages in the same conversation
- Database is created automatically on first run
- Static files are served from the root directory
- Vercel deployment uses the `/server` directory as the build source