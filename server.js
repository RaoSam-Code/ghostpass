'use strict';

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── In-memory stores ────────────────────────────────────────────────────────
// users: { username -> { salt: hex, verifier: hex } }
const users = new Map();

// pending challenges: { username -> { challenge: hex, expiresAt: timestamp } }
const pendingChallenges = new Map();

// JWT secret (generated once at startup)
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = '1h';

// Challenge TTL: 2 minutes
const CHALLENGE_TTL_MS = 2 * 60 * 1000;

// ─── Rate limiters ────────────────────────────────────────────────────────────
// Restrict login-related endpoints to 10 requests per minute per IP to mitigate
// brute-force attacks (passwords are never sent, but challenges are a resource).
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

// General rate limiter for authenticated API routes.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

// ─── Helper: constant-time buffer comparison ─────────────────────────────────
function safeEqual(a, b) {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// ─── Middleware: authenticate JWT ────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────

/**
 * POST /api/register
 * Body: { username, salt, verifier }
 *
 * The client has already:
 *   1. Generated a random salt
 *   2. Derived verifier = PBKDF2(password, salt, 100,000 iters, SHA-256)
 *
 * The raw password is never transmitted or stored.
 */
app.post('/api/register', (req, res) => {
  const { username, salt, verifier } = req.body;

  if (!username || !salt || !verifier) {
    return res.status(400).json({ error: 'username, salt and verifier are required' });
  }

  // Validate hex strings (64-char = 32 bytes each)
  const hexRe = /^[0-9a-f]{64}$/i;
  if (!hexRe.test(salt) || !hexRe.test(verifier)) {
    return res.status(400).json({ error: 'salt and verifier must be 64-character hex strings' });
  }

  const normalised = username.trim().toLowerCase();
  if (!normalised || normalised.length < 3 || normalised.length > 64) {
    return res.status(400).json({ error: 'username must be 3–64 characters' });
  }

  if (users.has(normalised)) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  // Store only the mathematical verifier — no password ever reaches here
  users.set(normalised, { salt, verifier });
  return res.status(201).json({ message: 'Registration successful' });
});

/**
 * POST /api/challenge
 * Body: { username }
 *
 * Returns { challenge, salt } so the client can:
 *   1. Derive verifier = PBKDF2(password, salt)
 *   2. Compute proof   = HMAC-SHA256(verifier, challenge)
 */
app.post('/api/challenge', authLimiter, (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'username is required' });
  }

  const normalised = username.trim().toLowerCase();
  const user = users.get(normalised);

  if (!user) {
    // Return a dummy challenge to avoid user enumeration
    const dummyChallenge = crypto.randomBytes(32).toString('hex');
    const dummySalt = crypto.randomBytes(32).toString('hex');
    return res.status(200).json({ challenge: dummyChallenge, salt: dummySalt });
  }

  const challenge = crypto.randomBytes(32).toString('hex');
  pendingChallenges.set(normalised, {
    challenge,
    expiresAt: Date.now() + CHALLENGE_TTL_MS,
  });

  return res.status(200).json({ challenge, salt: user.salt });
});

/**
 * POST /api/verify
 * Body: { username, proof }
 *
 * The proof = HMAC-SHA256(verifier, challenge) computed entirely client-side.
 * Server recomputes the same HMAC and compares — password is never involved.
 */
app.post('/api/verify', authLimiter, (req, res) => {
  const { username, proof } = req.body;
  if (!username || !proof) {
    return res.status(400).json({ error: 'username and proof are required' });
  }

  const hexRe = /^[0-9a-f]{64}$/i;
  if (!hexRe.test(proof)) {
    return res.status(400).json({ error: 'proof must be a 64-character hex string' });
  }

  const normalised = username.trim().toLowerCase();
  const user = users.get(normalised);
  const pending = pendingChallenges.get(normalised);

  // Remove challenge immediately (single-use)
  pendingChallenges.delete(normalised);

  if (!user || !pending) {
    return res.status(401).json({ error: 'Authentication failed' });
  }

  if (Date.now() > pending.expiresAt) {
    return res.status(401).json({ error: 'Challenge expired, please try again' });
  }

  // Server-side HMAC: HMAC-SHA256(stored_verifier, challenge)
  const expectedProof = crypto
    .createHmac('sha256', Buffer.from(user.verifier, 'hex'))
    .update(Buffer.from(pending.challenge, 'hex'))
    .digest('hex');

  if (!safeEqual(proof, expectedProof)) {
    return res.status(401).json({ error: 'Authentication failed' });
  }

  const token = jwt.sign(
    { sub: normalised, jti: uuidv4() },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  return res.status(200).json({ token, username: normalised });
});

/**
 * GET /api/me
 * Returns the currently authenticated user (requires Bearer token).
 */
app.get('/api/me', apiLimiter, requireAuth, (req, res) => {
  return res.status(200).json({ username: req.user.sub });
});

/**
 * POST /api/logout
 * Client simply discards the token; this endpoint confirms the action.
 */
app.post('/api/logout', apiLimiter, requireAuth, (req, res) => {
  return res.status(200).json({ message: 'Logged out successfully' });
});

// ─── Start server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GhostPass server running on http://localhost:${PORT}`);
});

module.exports = app;
