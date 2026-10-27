const path = require('path');
const fs = require('fs');
const express = require('express');
const { XeroClient } = require('xero-node');

// Force dotenv to look directly in this folder for the .env file
require('dotenv').config({ path: path.join(__dirname, '.env') });



const app = express();
const port = 3000;
const TOKEN_PATH = path.join(__dirname, 'tokens.json');

const xero = new XeroClient({
  clientId: process.env.XERO_CLIENT_ID,
  clientSecret: process.env.XERO_CLIENT_SECRET,
  redirectUris: [process.env.XERO_REDIRECT_URI],
  
scopes: [
  'openid',
  'profile',
  'email',
  'offline_access',
  'accounting.settings',
  'accounting.settings.read',
  'accounting.contacts',
  'accounting.contacts.read',
  'accounting.attachments',
  'accounting.attachments.read',
  'accounting.budgets.read',
  'accounting.payments',
  'accounting.payments.read',
  'accounting.invoices',
  'accounting.invoices.read',
  'accounting.banktransactions',
  'accounting.banktransactions.read',
  'accounting.manualjournals',
  'accounting.manualjournals.read',
  'accounting.reports.aged.read',
  'accounting.reports.balancesheet.read',
  'accounting.reports.banksummary.read',
  'accounting.reports.budgetsummary.read',
  'accounting.reports.executivesummary.read',
  'accounting.reports.profitandloss.read',
  'accounting.reports.trialbalance.read',
  'accounting.reports.taxreports.read',
  'accounting.reports.tenninetynine.read',
  'files',
  'files.read',
  'assets',
  'assets.read'
]

});

// Helper: Save token to local json file
function saveTokens(tokenSet) {
  fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokenSet, null, 2));
}

// Route 1: Direct link to refresh token on demand
app.get('/refresh', async (req, res) => {
  try {
    if (!fs.existsSync(TOKEN_PATH)) return res.status(400).send("No existing tokens found. Please go to /login first.");
    
    const savedTokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
    xero.setTokenSet(savedTokens);
    
    // Refresh the token via Xero Node SDK
    const newTokens = await xero.refreshWithRefreshToken(process.env.XERO_CLIENT_ID, process.env.XERO_CLIENT_SECRET, savedTokens.refresh_token);
    saveTokens(newTokens);
    
    res.json({ message: "Token refreshed successfully!", expires_in: newTokens.expires_in });
  } catch (err) {
    res.status(500).send("Failed to refresh token: " + err.message);
  }
});

// Route 2: Trigger initial login flow
app.get('/login', async (req, res) => {
  try {
    const consentUrl = await xero.buildConsentUrl();
    res.redirect(consentUrl);
  } catch (err) {
    res.status(500).send("Error generating login URL: " + err.message);
  }
});

// Route 3: Receive callback from Xero
app.get('/callback', async (req, res) => {
  try {
    const tokenSet = await xero.apiCallback(req.url);
    saveTokens(tokenSet);
    res.send("Authentication successful! You can close this tab now. The tokens are saved locally.");
  } catch (err) {
    res.status(500).send("Error during callback: " + err.message);
  }
});

app.listen(port, () => {
  console.log(`Server running. If first time setup, log in here: http://localhost:${port}/login`);
});
