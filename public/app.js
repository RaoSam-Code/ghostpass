/**
 * GhostPass — client-side Zero-Knowledge Authentication
 *
 * Protocol summary:
 *   REGISTER:  verifier = PBKDF2(password, salt, 100 000 iters, SHA-256)
 *              → server stores { username, salt, verifier }  (no password)
 *
 *   LOGIN:     1. fetch challenge + salt from server
 *              2. re-derive verifier = PBKDF2(password, salt)
 *              3. proof = HMAC-SHA256(verifier, challenge)
 *              4. send proof → server verifies without ever seeing password
 */

'use strict';

// ─── State ─────────────────────────────────────────────────────────────────
let sessionToken = null;
let lastChallenge = null;
let lastProof = null;

// ─── Crypto helpers (Web Crypto API) ───────────────────────────────────────

/** Encode a string to a Uint8Array. */
function encode(str) {
  return new TextEncoder().encode(str);
}

/** Convert ArrayBuffer to lowercase hex string. */
function toHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Convert a hex string to a Uint8Array. */
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Generate cryptographically random bytes and return as hex. */
function randomHex(byteLength) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return toHex(bytes.buffer);
}

/**
 * Derive a 256-bit verifier from a password and salt using PBKDF2-SHA-256.
 * @param {string} password  - raw password (never leaves this function's scope)
 * @param {string} saltHex   - 32-byte salt as hex
 * @returns {Promise<string>} - 32-byte verifier as hex
 */
async function deriveVerifier(password, saltHex) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: fromHex(saltHex),
      iterations: 100_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256  // 32 bytes
  );

  return toHex(bits);
}

/**
 * Compute HMAC-SHA-256(verifier, challenge).
 * @param {string} verifierHex  - 32-byte verifier as hex
 * @param {string} challengeHex - 32-byte server challenge as hex
 * @returns {Promise<string>}   - 32-byte HMAC as hex
 */
async function computeProof(verifierHex, challengeHex) {
  const key = await crypto.subtle.importKey(
    'raw',
    fromHex(verifierHex),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    fromHex(challengeHex)
  );

  return toHex(signature);
}

// ─── UI helpers ────────────────────────────────────────────────────────────

function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const el = document.getElementById(`view-${name}`);
  if (el) el.classList.add('active');
}

function setAlert(id, type, message) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `alert alert-${type} visible`;
  el.textContent = message;
}

function clearAlert(id) {
  const el = document.getElementById(id);
  if (el) { el.className = 'alert'; el.textContent = ''; }
}

function setLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  if (loading) {
    btn.dataset.originalText = btn.textContent;
    btn.innerHTML = '<span class="spinner"></span>&nbsp;Working…';
  } else {
    btn.innerHTML = btn.dataset.originalText || btn.textContent;
  }
}

function truncate(hex, chars = 12) {
  if (!hex) return '—';
  return hex.slice(0, chars) + '…' + hex.slice(-4);
}

// ─── API helpers ────────────────────────────────────────────────────────────

async function apiPost(path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(path, { method: 'POST', headers, body: JSON.stringify(body) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ─── Handlers ───────────────────────────────────────────────────────────────

async function handleRegister(event) {
  event.preventDefault();
  clearAlert('alert-register');

  const username = document.getElementById('reg-username').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm  = document.getElementById('reg-confirm').value;

  if (password !== confirm) {
    return setAlert('alert-register', 'error', 'Passwords do not match.');
  }
  if (password.length < 8) {
    return setAlert('alert-register', 'error', 'Password must be at least 8 characters.');
  }

  setLoading('btn-register', true);
  try {
    // 1. Generate random salt (32 bytes)
    const salt = randomHex(32);

    // 2. Derive verifier client-side — password stays here
    const verifier = await deriveVerifier(password, salt);

    // 3. Send only the verifier + salt to the server (never the password)
    await apiPost('/api/register', { username, salt, verifier });

    setAlert('alert-register', 'success', 'Account created! You can now sign in.');
    document.getElementById('form-register').reset();
  } catch (err) {
    setAlert('alert-register', 'error', err.message);
  } finally {
    setLoading('btn-register', false);
  }
}

async function handleLogin(event) {
  event.preventDefault();
  clearAlert('alert-login');

  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;

  setLoading('btn-login', true);
  try {
    // 1. Request a server challenge (and get back our salt)
    const { challenge, salt } = await apiPost('/api/challenge', { username });
    lastChallenge = challenge;

    // 2. Re-derive the verifier from the password using the server-provided salt
    const verifier = await deriveVerifier(password, salt);

    // 3. Compute proof = HMAC-SHA256(verifier, challenge) — all client-side
    const proof = await computeProof(verifier, challenge);
    lastProof = proof;

    // 4. Send only the proof; the verifier and password are never transmitted
    const { token } = await apiPost('/api/verify', { username, proof });
    sessionToken = token;

    // 5. Show dashboard
    showDashboard(username);
    document.getElementById('form-login').reset();
  } catch (err) {
    setAlert('alert-login', 'error', err.message);
    lastChallenge = null;
    lastProof = null;
  } finally {
    setLoading('btn-login', false);
  }
}

function showDashboard(username) {
  document.getElementById('dash-username').textContent = username;
  document.getElementById('info-user').textContent = username;
  document.getElementById('info-token').textContent = truncate(sessionToken, 16);
  document.getElementById('info-challenge').textContent = lastChallenge ? truncate(lastChallenge) : '—';
  document.getElementById('info-proof').textContent = lastProof ? truncate(lastProof) : '—';
  showView('dashboard');
}

async function handleLogout() {
  if (sessionToken) {
    try {
      await apiPost('/api/logout', {}, sessionToken);
    } catch {
      // ignore errors on logout
    }
  }
  sessionToken = null;
  lastChallenge = null;
  lastProof = null;
  showView('home');
}
