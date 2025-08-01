// Run this in the browser console to bypass usage limits for local testing

// Set yourself as a Pro user
usageState.isProUser = true;
usageState.totalDiscussions = 0;

// Save the state
localStorage.setItem('usageState', JSON.stringify(usageState));

// Update the UI
updateUsageUI();

console.log('✅ Usage limits bypassed! You are now a Pro user with unlimited discussions.');
console.log('Current state:', usageState);