//-------------------------------------------------------------------------------------------------------------------------------------------|
// |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Starting ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
//-------------------------------------------------------------------------------------------------------------------------------------------|
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const session = require('express-session');
const Database = require('better-sqlite3');

const app = express();

//-------------------------------------------------------------------------------------------------------------------------------------------|
// |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Constants ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
//-------------------------------------------------------------------------------------------------------------------------------------------|

const ENDPOINT = {authURL: "https://id.kick.com/oauth/authorize",tokenURL: "https://id.kick.com/oauth/token",API:"https://api.kick.com/public/v1"};
const {CLIENT_ID,CLIENT_SECRET,REDIRECT_URI,SESSION_SECRET = crypto.randomBytes(32).toString('hex'),PORT = 3000} = process.env;
const SCOPES = ['user:read','channel:read','channel:write','chat:write','streamkey:read','events:subscribe'];

function generateCodeVerifier() {
  const buffer = crypto.randomBytes(32);
  return buffer.toString("base64url");
}
function generateCodeChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return hash.toString("base64url");
}

//-------------------------------------------------------------------------------------------------------------------------------------------|
// |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ DATABASE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
//-------------------------------------------------------------------------------------------------------------------------------------------|

const db = new Database('Auth.db');

try {
  db.pragma('journal_mode = WAL');
  db.prepare(`
  CREATE TABLE IF NOT EXISTS Tokens (
	id INTEGER PRIMARY KEY,
	slug TEXT,
  accessToken TEXT NOT NULL,
  refreshToken TEXT NOT NULL,
  expires INTEGER,
	createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
	scope TEXT,
  type TEXT,
	updatedAt TEXT DEFAULT CURRENT_TIMESTAMP
);`).run();
console.log('Database initialized successfully');
} catch (err) {
  console.error('Database initialization failed:', err);
  process.exit(1);
}

const tokenRepository = {
  save: (id, slug, accessToken, refreshToken, expires, scope, type) => {
    const stmt = db.prepare(`
      INSERT INTO Tokens (id, slug, accessToken, refreshToken, expires, scope, type, createdAt, updatedAt) 
      VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      ON CONFLICT(id) DO UPDATE SET
        slug = excluded.slug,
        accessToken = excluded.accessToken,
        refreshToken = excluded.refreshToken,
        expires = excluded.expires,
        scope = excluded.scope,
        type = excluded.type,
        updatedAt = CURRENT_TIMESTAMP
    `);
    return stmt.run(id, slug, accessToken, refreshToken, expires, scope, type);
  }
};

//-------------------------------------------------------------------------------------------------------------------------------------------|
// |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Middleware ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
//-------------------------------------------------------------------------------------------------------------------------------------------|

app.use(cors());
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false,httpOnly: true,maxAge: 1000 * 60 * 60 }
}));

//-------------------------------------------------------------------------------------------------------------------------------------------|
// |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OAuth Redirect ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
//-------------------------------------------------------------------------------------------------------------------------------------------|

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
  console.log('State:', state);
  console.log('Code Challenge:', codeChallenge);
});

//-------------------------------------------------------------------------------------------------------------------------------------------|
// |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OAuth Callback ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
//-------------------------------------------------------------------------------------------------------------------------------------------|

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

    const tokenData = await tokenResponse.json();

    const UserResponse = await fetch(ENDPOINT.API+"/channels",{
			method: "GET",
			headers: {"Authorization": `Bearer ${tokenData.access_token}`,'Accept': 'application/json',},
		});

    const UserData = await UserResponse.json();

    tokenRepository.save(UserData.data[(UserData.data.length)-1].broadcaster_user_id,UserData.data[(UserData.data.length)-1].slug,tokenData.access_token,tokenData.refresh_token,tokenData.expires_in,tokenData.scope,tokenData.token_type);
    res.json(tokenData);

  }
  catch (error) {res.status(500).json({ error: error.message });}
})

//-------------------------------------------------------------------------------------------------------------------------------------------|
// |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Starting Server ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|
//-------------------------------------------------------------------------------------------------------------------------------------------|

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`OAuth URL: http://localhost:${PORT}/auth/kick`);
  console.log(`Session secret: ${SESSION_SECRET.substring(0, 10)}...`);
});
