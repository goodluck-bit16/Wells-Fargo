# Wells Fargo


## Run it

Requires Node.js 22.13 or newer. No `npm install` needed (zero dependencies).

```
npm start          # http://localhost:3000
npm test           # 11 backend tests
```

Optional settings (environment variables): `PORT`, `DB_PATH` (default `larkspur.db`), `COOKIE_SECURE=1` (set when serving over HTTPS), `TRUST_PROXY=1` (only behind a trusted reverse proxy).

## How it works

**For the customer**
1. Open an account with your name, email, and a password.
2. Pick checking or savings. Both accounts are created; your first deposit goes into the one you picked.
3. Deposit, transfer between your accounts, or send money to a payee. Everything shows up in Recent activity. Sign back in any time.

**Behind the scenes**
- `public/` is the website (HTML, CSS, JS). It talks to the server over a JSON API.
- `server.js` is the backend (Node `http` + built-in SQLite). Data lives in `larkspur.db`.
- Passwords are hashed with scrypt and a per-user salt. Plain passwords are never stored.
- Sign-in creates a random session token in an `HttpOnly`, `SameSite=Strict` cookie. Only a SHA-256 hash of the token is stored. Sessions last 8 hours.
- Money is stored as integer cents. The database refuses negative balances.
- Every deposit, transfer, and payment runs inside a database transaction, so it fully succeeds or changes nothing.
- Failed sign-ins are rate limited. Requests must be JSON and same-origin (CSRF protection). A Content Security Policy and other security headers are set on every response.

## API

| Method | Path | Body |
|---|---|---|
| POST | `/api/register` | `name, email, password, type, deposit` |
| POST | `/api/login` | `email, password` |
| POST | `/api/logout` | none |
| GET | `/api/me` | none |
| POST | `/api/deposit` | `account, amount` |
| POST | `/api/transfer` | `from, to, amount` |
| POST | `/api/send` | `from, payee, amount` |

## Before putting this anywhere real

Serve it over HTTPS (and set `COOKIE_SECURE=1`), add email verification and password reset, add two-factor sign-in, move rate limits to shared storage, and get a security review. Real banking also needs regulated partners, identity checks (KYC), and fraud monitoring.
