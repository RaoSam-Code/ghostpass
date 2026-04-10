# GhostPass — Zero-Knowledge Authentication System

GhostPass is a Zero-Knowledge Authentication System that lets a server verify a user's identity **without ever seeing, receiving, or storing the actual password**.

## The Problem

Traditional authentication sends passwords (or their hashes) to a centralized server:

- **Honeypot Vulnerability**: If the server is breached, every user's password is stolen.
- **Over-Collection of Data**: Platforms violate "data minimisation" principles by storing plaintext or hashed secrets.
- **Trust Deficit**: Users have no guarantee platforms are securing credentials properly.

## The GhostPass Solution

| Property | Guarantee |
|---|---|
| **Client-Side Cryptography** | PBKDF2 key derivation and HMAC-SHA-256 run entirely in the browser — the password never leaves the device. |
| **Challenge-Response Protocol** | Each login uses a fresh one-time server challenge, so no replay attacks are possible. |
| **Absolute Data Minimisation** | The server stores only a mathematical verifier. Even a full database leak yields zero exploitable credentials. |
| **Privacy-by-Design** | Aligns with GDPR/data-protection laws by removing the burden of storing sensitive credential data from organisations. |

## How It Works

### Registration

```
Client                                Server
──────                                ──────
salt   = random 256-bit value
verifier = PBKDF2(password, salt,
           100 000 iters, SHA-256)
                                      ← stores { username, salt, verifier }
                                         (password never transmitted)
```

### Login (Challenge-Response)

```
Client                                Server
──────                                ──────
      ── { username } ───────────────►
      ◄── { challenge, salt } ────────
verifier = PBKDF2(password, salt)
proof    = HMAC-SHA256(verifier,
                       challenge)
      ── { username, proof } ────────►
                                      expected = HMAC-SHA256(stored_verifier,
                                                             challenge)
                                      if proof == expected → issue JWT ✓
```

The raw password is **never** transmitted or stored anywhere on the server.

## Running Locally

```bash
npm install
npm start
# Open http://localhost:3000
```

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/register` | POST | Register with `{ username, salt, verifier }` |
| `/api/challenge` | POST | Fetch `{ challenge, salt }` for a username |
| `/api/verify` | POST | Submit `{ username, proof }` → returns JWT |
| `/api/me` | GET | Return current user (requires `Authorization: Bearer <token>`) |
| `/api/logout` | POST | Confirm logout (client discards token) |

## Tech Stack

- **Backend**: Node.js + Express
- **Frontend**: Vanilla JS with the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- **Crypto primitives**: PBKDF2-SHA-256 (key derivation) + HMAC-SHA-256 (proof) + JWT (session)
- **Storage**: In-memory (easily swappable for any persistent store)