# OAuth2 JWT Bearer Flow for Authenticated DAST Scanning

Working implementation of the JWT Bearer OAuth2 grant type for authenticating a DAST scanner against a protected web application. Built from a real user engagement where 20 Salesforce targets needed permanent authenticated scan coverage without depending on expiring MFA exemptions.

**This is a local demo. No Salesforce account required.**

## The Problem

A user needed to run authenticated DAST scans against 20 Salesforce web applications. Their existing authentication used Form Auth with TOTP (time-based one-time password), which worked but depended on an MFA exemption from Salesforce that expires every 12 months and is painful to renew. They needed a permanent solution that could be templated across all 20 targets.

## Why Standard OAuth Flows Didn't Work

### Client Credentials Grant

The simplest OAuth flow. Your app sends a client ID and secret, gets back a token. Problem: the token only grants API access. DAST scanners need a browser session with cookies because they crawl rendered HTML pages. An API token can't create a browser session. Dead end.

### Authorization Code Grant (with PKCE)

The standard browser OAuth flow. The user is redirected to the login page, authenticates, and the app receives an authorization code to exchange for a token. Salesforce requires PKCE (Proof Key for Code Exchange) on this flow, which means the requesting app must generate a random code verifier, hash it, and send the hash upfront. The scanner doesn't generate PKCE parameters. Salesforce rejects the request without them. Dead end.

### JWT Bearer Grant (the solution)

No user interaction needed. No PKCE needed. The scanner builds a JWT containing four claims (client ID, username, audience, expiration), signs it with an RSA private key, and POSTs it to the token endpoint. The server verifies the signature against the registered public key and returns an access token.

The access token is still an API token. The critical step is navigating the browser to a session bridge endpoint (`/frontdoor` in this demo, `frontdoor.jsp` on Salesforce), which accepts the access token as a URL parameter and sets browser session cookies. After this redirect, the scanner has an authenticated browser session and can crawl every protected page.

## How This Demo Works

### The Server (`server.py`)

Simulates the OAuth2 provider with four components:

`POST /oauth2/token` accepts a signed JWT Bearer assertion. It decodes the JWT, verifies the RSA signature against the registered public key (`public.pem`), validates the claims (issuer, subject, audience, expiration), and returns an access token if everything checks out. If the signature doesn't match, the private key is wrong or the JWT was tampered with, and the request is rejected.

`GET /frontdoor?sid=TOKEN` accepts an access token as a URL parameter. If the token is valid and not expired, it creates a browser session by setting cookies and redirects to the protected dashboard. This is the bridge between API access and browser access.

`/dashboard`, `/settings`, `/reports`, `/admin/config`, `/api/users` are protected pages that return 401 without a valid session cookie. With an authenticated session, they return full page content. These represent the pages a DAST scanner needs to reach for complete coverage.

### The Authentication Script (`auth-script.js`)

A JavaScript script that runs in a browser and performs the full JWT Bearer flow:

1. **Loads jsrsasign** (open source RSA signing library) from Cloudflare's CDN using a synchronous XMLHttpRequest. The request is synchronous because some JavaScript execution environments (like DAST scanner script executors) don't wait for async operations. The library version is pinned to `11.1.0` to prevent upstream changes from affecting the script. Loading any library at runtime from a CDN is a supply chain risk. Pinning the exact version ensures the code we tested is the code that runs. In a production environment, you'd also use Subresource Integrity (SRI) hashes so the browser rejects the file if its content doesn't match the expected hash.

2. **Builds the JWT** with four claims: `iss` (client ID, identifies the requesting application), `sub` (username, who to authenticate as), `aud` (audience, which server this JWT is for), and `exp` (expiration, when this JWT becomes invalid).

3. **Signs the JWT** with the RSA private key using RS256 (RSA signature with SHA-256). The key is in JWK format (JSON Web Key) rather than PEM format. JWK represents the same key as a JSON object with each RSA component as a separate field. This avoids a PEM parsing failure that occurs in some browser sandboxes where the library's internal ASN.1 parser throws `RSASetPrivateEx E == null`.

4. **Exchanges the JWT for an access token** by POSTing it to the token endpoint with the `jwt-bearer` grant type. The server verifies the RSA signature against the public key and returns an access token.

5. **Navigates to the session bridge** (`/frontdoor?sid=TOKEN`) which sets browser session cookies. After the redirect, the browser has an authenticated session and can access all protected pages.

### Why RSA Signing?

The signature is the proof of identity. Without it, anyone could build a JWT claiming to be the scanner and the server would have no way to verify it. The private key never leaves the client. The public key is registered on the server. The server verifies the signature with the public key, confirming the JWT was created by someone who holds the private key, without ever seeing the private key itself.

If someone tampers with any claim in the JWT (changes the username, extends the expiration), the signature no longer matches and the server rejects it.

## Setup

### Generate RSA Key Pair

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

The public key is loaded by the server (simulates registering it in a Connected App). The private key is used by the authentication script to sign JWTs.

### Convert Private Key to JWK Format

```bash
node convert-key.js
```

Copy the output JSON object into `auth-script.js`, replacing `REPLACE_WITH_JWK`.

### Start the Server

```bash
pip install flask pyjwt cryptography
python3 server.py
```

Server runs on `http://127.0.0.1:5001`.

### Test the Flow

Verify protected pages are inaccessible without authentication:

```bash
curl http://127.0.0.1:5001/dashboard
# Returns 401 Unauthorized
```

Run the full JWT Bearer flow:

```bash
node -e "
const fs = require('fs');
const jwt = require('jsonwebtoken');
const privateKey = fs.readFileSync('private.pem');
const token = jwt.sign(
  { iss: 'demo-connected-app-consumer-key', sub: 'scanner@demo.org', aud: 'http://127.0.0.1:5001' },
  privateKey,
  { algorithm: 'RS256', expiresIn: 180 }
);
console.log('JWT signed successfully');
const http = require('http');
const postData = 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + encodeURIComponent(token);
const req = http.request({
  hostname: '127.0.0.1', port: 5001, path: '/oauth2/token', method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
}, (res) => {
  let data = '';
  res.on('data', c => data += c);
  res.on('end', () => console.log('Response:', data));
});
req.write(postData);
req.end();
"
```

Expected output:

```json
{
  "access_token": "<token>",
  "token_type": "Bearer",
  "instance_url": "http://127.0.0.1:5001",
  "issued_at": "<timestamp>"
}
```

Test the session bridge:

```bash
curl -v "http://127.0.0.1:5001/frontdoor?sid=<access_token>"
# Returns 302 redirect to /dashboard with Set-Cookie header
```

The `Set-Cookie` header is the moment the API token becomes a browser session.

### Browser Test

Open `authenticate.html` in a browser (serve it from the same origin or disable CORS). The script will execute the full flow and redirect to the authenticated dashboard.

## Files

| File | Purpose |
|------|---------|
| `server.py` | OAuth2 provider with token endpoint, session bridge, and protected pages |
| `auth-script.js` | Browser JavaScript that performs the JWT Bearer flow |
| `authenticate.html` | HTML page that loads and runs the auth script |
| `convert-key.js` | Converts PEM private key to JWK format |
| `requirements.txt` | Python dependencies for the server |
| `public.pem` | RSA public key (registered on the server, safe to share) |
| `private.pem` | RSA private key (used by the auth script, excluded from git) |

## Supply Chain Considerations

The authentication script loads jsrsasign from `cdnjs.cloudflare.com` at runtime. This is a supply chain dependency. Mitigations applied:

**Version pinning:** The script loads jsrsasign at version `11.1.0` specifically, not `latest`. This ensures the code that was tested is the code that runs in production.

**Trusted CDN:** Cloudflare's CDN serves files with its own integrity verification. The file is served from Cloudflare's infrastructure, not an arbitrary third-party host.

**Subresource Integrity (SRI):** In environments that support it, adding an `integrity` attribute to the script tag ensures the browser rejects the file if its content hash doesn't match the expected value. The scanner's script executor did not support SRI, so version pinning was the primary mitigation.

**Why not embed the library?** jsrsasign is approximately 338KB minified. Embedding it directly in the script would exceed the character limits of some script executors. Loading it at runtime is the practical tradeoff.
