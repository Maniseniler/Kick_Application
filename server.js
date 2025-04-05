require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const session = require('express-session');

const app = express();

const ENDPOINT = {
	authURL: "https://id.kick.com/oauth/authorize",
	tokenURL: "https://id.kick.com/oauth/token",
};

const {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  SESSION_SECRET = crypto.randomBytes(32).toString('hex'),
  PORT = 3000
} = process.env;

function generateCodeVerifier() {
  const buffer = crypto.randomBytes(32);
  return buffer.toString("base64url");
}
function generateCodeChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return hash.toString("base64url");
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    httpOnly: true,
    maxAge: 1000 * 60 * 60 // 1 hour
  }
}));

// Scopes
const SCOPES = ['user:read','channel:read',];

// OAuth Redirect
app.get('/auth/kick', (req, res) => {
  const codeVerifier = generateCodeVerifier();
	const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = Buffer.from(JSON.stringify({ codeVerifier })).toString("base64",);
  
  // Store in session
  const authParams = new URLSearchParams({
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		response_type: "code",
		scope: SCOPES.join(" "),
		state,
		code_challenge: codeChallenge,
		code_challenge_method: "S256",
	});
  res.redirect(`${ENDPOINT.authURL}?${authParams.toString()}`);

  console.log(' ');
  console.log('Initiating OAuth with:');
  console.log('Client ID:', CLIENT_ID);
  console.log('Redirect URI:', REDIRECT_URI);
  console.log('State:', state);
  console.log('Code Challenge:', codeChallenge);
});

// Handle the redirect from the auth page
app.get('/auth/kick/callback',async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).json({ error: "Missing authorization code" });

  try {
    const { codeVerifier } = JSON.parse(Buffer.from(state, "base64").toString(),);
    const tokenParams = new URLSearchParams({
			grant_type: "authorization_code",
			client_id: CLIENT_ID,
			client_secret: CLIENT_SECRET,
			code,
			redirect_uri: REDIRECT_URI,
			code_verifier: codeVerifier,
		});

    const tokenResponse = await fetch(ENDPOINT.tokenURL,{
			method: "POST",
			headers: {"Content-Type": "application/x-www-form-urlencoded",},
			body: tokenParams,
		});
    const token = await tokenResponse.json();
		res.json(token);}
  catch (error) {res.status(500).json({ error: error.message });}
})

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`OAuth URL: http://localhost:${PORT}/auth/kick`);
  console.log(`Session secret: ${SESSION_SECRET.substring(0, 10)}...`);
});
