"""
OAuth2 JWT Bearer Token Server

Simulates the OAuth2 provider side of a JWT Bearer flow:
1. /oauth2/token   - Accepts a signed JWT, verifies the RSA signature
                     against the registered public key, returns an access token
2. /frontdoor      - Accepts an access token as a URL parameter, creates a
                     browser session (cookies), redirects to the protected app
3. /dashboard      - Protected page, only accessible with a valid session
4. /settings       - Protected page
5. /api/users      - Protected API endpoint

Without authentication, all protected routes return 401.
"""

from flask import Flask, request, jsonify, redirect, session, render_template_string
import jwt as pyjwt
import secrets
import time
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Load the public key for JWT signature verification
# In production (Salesforce), this key is uploaded to the Connected App config
PUBLIC_KEY_PATH = os.path.join(os.path.dirname(__file__), 'public.pem')
with open(PUBLIC_KEY_PATH, 'r') as f:
    PUBLIC_KEY = f.read()

# In-memory token store (simulates the provider's token database)
active_tokens = {}

# Expected JWT claims (simulates Connected App configuration)
EXPECTED_CLIENT_ID = 'demo-connected-app-consumer-key'
EXPECTED_AUDIENCE = 'http://127.0.0.1:5001'
EXPECTED_USERNAME = 'scanner@demo.org'


# ============================================================
# OAuth2 Token Endpoint
# ============================================================
@app.route('/oauth2/token', methods=['POST'])
def token_endpoint():
    """
    Accepts a JWT Bearer assertion and returns an access token.

    Expected POST body (application/x-www-form-urlencoded):
      grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
      assertion=<signed JWT>

    The server:
    1. Checks grant_type is jwt-bearer
    2. Decodes the JWT header to confirm RS256
    3. Verifies the signature using the registered public key
    4. Validates the claims (issuer, subject, audience, expiration)
    5. Returns an access token if everything checks out
    """
    grant_type = request.form.get('grant_type', '')
    assertion = request.form.get('assertion', '')

    # Step 1: Verify grant type
    if grant_type != 'urn:ietf:params:oauth:grant-type:jwt-bearer':
        return jsonify({
            'error': 'unsupported_grant_type',
            'error_description': f'Expected jwt-bearer, got: {grant_type}'
        }), 400

    if not assertion:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing assertion parameter'
        }), 400

    # Step 2-3: Verify JWT signature with the registered public key
    try:
        decoded = pyjwt.decode(
            assertion,
            PUBLIC_KEY,
            algorithms=['RS256'],
            audience=EXPECTED_AUDIENCE
        )
    except pyjwt.ExpiredSignatureError:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'JWT has expired'
        }), 401
    except pyjwt.InvalidSignatureError:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': 'JWT signature verification failed. '
                                 'The private key does not match the registered public key.'
        }), 401
    except pyjwt.InvalidAudienceError:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': f'JWT audience does not match. Expected: {EXPECTED_AUDIENCE}'
        }), 401
    except Exception as e:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': str(e)
        }), 401

    # Step 4: Validate claims
    if decoded.get('iss') != EXPECTED_CLIENT_ID:
        return jsonify({
            'error': 'invalid_client',
            'error_description': f'Unknown client_id: {decoded.get("iss")}'
        }), 401

    if decoded.get('sub') != EXPECTED_USERNAME:
        return jsonify({
            'error': 'invalid_grant',
            'error_description': f'User not authorized: {decoded.get("sub")}'
        }), 401

    # Step 5: Issue access token
    access_token = secrets.token_urlsafe(48)
    active_tokens[access_token] = {
        'username': decoded['sub'],
        'issued_at': int(time.time()),
        'expires_in': 1800  # 30 minutes
    }

    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'instance_url': EXPECTED_AUDIENCE,
        'issued_at': str(int(time.time()))
    })


# ============================================================
# Frontdoor - Token to Session Bridge
# ============================================================
@app.route('/frontdoor')
def frontdoor():
    """
    Converts an API access token into a browser session.

    The client navigates here with ?sid=ACCESS_TOKEN.
    If the token is valid, the server sets a session cookie
    and redirects to the dashboard.

    This is how DAST scanners get browser-based access from
    an API token. Without this step, the scanner has a token
    but no cookies, and can't crawl web pages.
    """
    token = request.args.get('sid', '')

    if not token or token not in active_tokens:
        return render_template_string('''
            <h1>Invalid or expired session</h1>
            <p>The access token is not valid. Re-authenticate.</p>
        '''), 401

    token_data = active_tokens[token]

    # Check token expiration
    elapsed = int(time.time()) - token_data['issued_at']
    if elapsed > token_data['expires_in']:
        del active_tokens[token]
        return render_template_string('''
            <h1>Session expired</h1>
            <p>The access token has expired. Re-authenticate.</p>
        '''), 401

    # Set browser session cookie
    session['authenticated'] = True
    session['username'] = token_data['username']
    session['auth_method'] = 'JWT Bearer'

    return redirect('/dashboard')


# ============================================================
# Protected Pages (require authenticated session)
# ============================================================
def require_auth(f):
    """Decorator that checks for an authenticated session."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return render_template_string('''
                <h1>401 Unauthorized</h1>
                <p>This page requires authentication.</p>
                <p>A DAST scanner without a valid session would see this page
                   on every protected endpoint, resulting in zero authenticated coverage.</p>
            '''), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/dashboard')
@require_auth
def dashboard():
    return render_template_string('''
        <h1>Dashboard</h1>
        <p>Authenticated as: <strong>{{ username }}</strong></p>
        <p>Auth method: <strong>{{ method }}</strong></p>
        <nav>
            <a href="/settings">Settings</a> |
            <a href="/api/users">API: Users</a> |
            <a href="/reports">Reports</a> |
            <a href="/admin/config">Admin Config</a>
        </nav>
        <h2>Application Data</h2>
        <p>This content is only visible to authenticated users.
           A DAST scanner needs to reach this page to test for
           vulnerabilities behind the login.</p>
    ''', username=session['username'], method=session['auth_method'])


@app.route('/settings')
@require_auth
def settings():
    return render_template_string('''
        <h1>Settings</h1>
        <p>Authenticated as: <strong>{{ username }}</strong></p>
        <form>
            <label>Display Name: <input type="text" value="{{ username }}"></label><br>
            <label>Email: <input type="text" value="{{ username }}"></label><br>
            <button type="submit">Save</button>
        </form>
        <a href="/dashboard">Back to Dashboard</a>
    ''', username=session['username'])


@app.route('/reports')
@require_auth
def reports():
    return render_template_string('''
        <h1>Reports</h1>
        <p>Authenticated as: <strong>{{ username }}</strong></p>
        <ul>
            <li><a href="/reports/q1">Q1 Security Report</a></li>
            <li><a href="/reports/q2">Q2 Security Report</a></li>
            <li><a href="/reports/q3">Q3 Security Report</a></li>
        </ul>
        <a href="/dashboard">Back to Dashboard</a>
    ''', username=session['username'])


@app.route('/reports/<quarter>')
@require_auth
def report_detail(quarter):
    return render_template_string('''
        <h1>{{ quarter }} Security Report</h1>
        <p>Authenticated as: <strong>{{ username }}</strong></p>
        <p>Report data would be here. This page is only reachable
           with an authenticated session.</p>
        <a href="/reports">Back to Reports</a>
    ''', quarter=quarter.upper(), username=session['username'])


@app.route('/admin/config')
@require_auth
def admin_config():
    return render_template_string('''
        <h1>Admin Configuration</h1>
        <p>Authenticated as: <strong>{{ username }}</strong></p>
        <p>Sensitive admin settings. A scanner finding this page means
           authenticated crawl coverage is working.</p>
        <a href="/dashboard">Back to Dashboard</a>
    ''', username=session['username'])


@app.route('/api/users')
@require_auth
def api_users():
    return jsonify({
        'users': [
            {'id': 1, 'name': 'Alice', 'role': 'admin'},
            {'id': 2, 'name': 'Bob', 'role': 'user'},
            {'id': 3, 'name': 'Charlie', 'role': 'user'}
        ],
        'authenticated_as': session['username']
    })


# ============================================================
# Public Pages (no auth required)
# ============================================================
@app.route('/')
def index():
    return render_template_string('''
        <h1>OAuth2 JWT Bearer Flow Demo</h1>
        <p>This application requires JWT Bearer authentication.</p>
        <p>Protected pages: /dashboard, /settings, /reports, /admin/config, /api/users</p>
        <p>Token endpoint: POST /oauth2/token</p>
        <p>Session bridge: GET /frontdoor?sid=ACCESS_TOKEN</p>
    ''')


if __name__ == '__main__':
    app.run(port=5001, debug=True)
