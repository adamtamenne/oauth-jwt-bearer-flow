// JWT Bearer Authentication Script
//
// This script runs in a browser and authenticates against the OAuth2 server
// using the JWT Bearer flow. It mirrors the custom script built for a
// customer's Acunetix 360 scanner to authenticate against Salesforce.
//
// The flow:
// 1. Load jsrsasign (RSA signing library) from CDN
// 2. Build a JWT with the client ID, username, audience, and expiration
// 3. Sign the JWT with the RSA private key (JWK format)
// 4. POST the signed JWT to the token endpoint
// 5. Navigate to /frontdoor with the access token to get session cookies
//
// After step 5, the browser has an authenticated session and can access
// all protected pages.

(function() {

  try {

    // === CONFIGURATION ===
    var CONFIG = {
      tokenEndpoint: 'http://127.0.0.1:5001/oauth2/token',
      audience: 'http://127.0.0.1:5001',
      clientId: 'demo-connected-app-consumer-key',
      username: 'scanner@demo.org',
      jwtLifetimeSeconds: 180,
      frontdoorBase: 'http://127.0.0.1:5001'
    };

    // === PRIVATE KEY (JWK FORMAT) ===
    // Generated from private.pem using: node convert-key.js
    // JWK is used because PEM parsing fails in some browser sandboxes.
    // JWK represents the same key as a JSON object, avoiding the
    // PEM parser entirely.
    var PRIVATE_KEY_JWK = {"kty":"RSA","n":"zKlwAfMbJ5qV1uFyWRPWAsgeKzwWQoN94umYkLWSslS4K18LijxE5M5ef4vFUFzkLG2-Na9h-mRy-UWn4giE3spn9mHqITEmext9_O2FHcOrPjR2h9lUIpxrEy1FRG19I57pnEYhROGW6VXySl-Z5d5gUlV7eG01yrWhjGBzJIwTv4TQLlqSyPfkR8bOC_tmiCtpfwyxGFts4qndZbAOMQpfzoP2TwUoVDm0ABO5B8bskfeR5oKY-edk1Zripyct50t-ILox6izNZskZbqTnxjuEpTubyQuekBB62PgO0u4FJvj-9ZDcY6EADlH4O1AtxCyHNY7TZzeWAmx2emlkhw","e":"AQAB","d":"AbgKBO6-fKQ8u-8j8bhwgCLotfUbF-XrHAl970E03KLa8tgEzKaQpiK9AnGDppb-2eOIW0vt8E5KPg8mIxqS7WXPzEphYSrYFS4KXCItawmUGeYTMDUwErZYLQV8LCliG9KfbapvaD1ozX7lJ-nl7NtRa3-bcN40O0_CW7sJ7tEPpTQdHF548svOZZLJk2N6pYHujFT849Ri6dzZdr-sfyqQF1nllPRjwAPCS--GqRvNa5akvC-ucL9RsaK492khULezWmDumSU0z3QU4cacqP9QXPukYSXgb8aA_4UMWuijKfSjzh_TkfCwRwBvulKoAfHnj0IXk8IxXBmOU2X1SQ","p":"-8F_Xc_IK2qNaBsB_3VPqzPn92_vGMm-iscwlRynYsZ8o4apJS0zY459-ByTsAzm3fwEu6ek91pxkpEW-wgHfUqSMTtgWtKjvDV16RqQJWvUtsg6SLYGtYKHlFXf8FNTMZVXqOxdHst5N2GpGUreYzOOP8mWrD7ee9Bw2x39RMM","q":"0ByyUJeBx1GS7L_8BGQVSpVwiJfNfvHdUXsPjfhgQi4yZCcJwYVcxOqjNH1ULAglxi6JHEmzjEuF9ffH3EO4syQw7djtN_6T6vKWeJ3vFVI9xlmlu2tEfS4vcTs_xtC70G-jCrv4BMupC3WlaKbqB61trLx1mubxh_QqLxUQlO0","dp":"5XDj80t60pa5aTe0Cm2PvigAMLIC5kR3M2N2E2-Z3Zun3CDN5uPbAdDLXWQt9TTM82LLrXqMDiKPf1Rb7UzUBov_0H6cwilWsCDI5TkgRfqQUkUJWVsLokDj73yUKyLFn1rMGVfRRk-Kmb6XrkVdiGtkKR5AA5sIiS7eq9QZDqE","dq":"Ir8HzojdNCgcfca4Dwueumsk9MlTmARNzVLcj_mOKL6Jz0rtSBA6Iu6B_TuHmCpsFCCk58IuZhgd76lFBzOPXOmH-c4kHRs2Gx4RnWXRCyBGDB3fm-EW-EeDyEX6KfmjwfNBp4Mmr7ZJLQ6hZU2o-Ustao-0mv5ACVDs0huUPyk","qi":"CGWEOErl7D3lHtOd8TG4UyBcjBg333e747qS93noo-Z69JxYtVh26RMXayRi7A03zTmPP9WDdbfk88riFuEmFghY-5iOCbG98HpljSlZyELJAc7n-H_8YTqxJONr32y9tECaU00nvQRCGv_AB7Xtr7OShcLy_eQqT-5Lfyrb5ac"};
    // === STEP 1: Load jsrsasign for RSA signing ===
    // The browser doesn't have RSA signing built in.
    // We load jsrsasign from a public CDN at runtime.
    // The request MUST be synchronous (false) because some script
    // executors don't wait for async operations.
    var libXhr = new XMLHttpRequest();
    libXhr.open('GET', 'https://cdnjs.cloudflare.com/ajax/libs/jsrsasign/11.1.0/jsrsasign-all-min.js', false);
    libXhr.send();
    eval(libXhr.responseText);

    document.title = 'STEP1: jsrsasign loaded';

    // === STEP 2: Build the JWT ===
    // Header: RS256 algorithm (RSA signature with SHA-256)
    // Payload claims:
    //   iss = client ID (who is requesting access)
    //   sub = username (who to authenticate as)
    //   aud = audience (which server this JWT is for)
    //   exp = expiration (when this JWT becomes invalid)
    var header = { alg: 'RS256', typ: 'JWT' };
    var now = Math.floor(Date.now() / 1000);
    var payload = {
      iss: CONFIG.clientId,
      sub: CONFIG.username,
      aud: CONFIG.audience,
      exp: now + CONFIG.jwtLifetimeSeconds
    };

    // === STEP 3: Sign the JWT with the private key ===
    // KEYUTIL.getKey() parses the JWK into a key object
    // KJUR.jws.JWS.sign() creates the signed JWT string
    // The result looks like: eyJhbGci...eyJpc3Mi...SflKxwRJ...
    // (three base64url segments separated by dots)
    var prvKey = KEYUTIL.getKey(PRIVATE_KEY_JWK);
    var jwt = KJUR.jws.JWS.sign('RS256', JSON.stringify(header), JSON.stringify(payload), prvKey);

    document.title = 'STEP2: JWT signed';

    // === STEP 4: Exchange JWT for access token ===
    // POST the signed JWT to the token endpoint.
    // grant_type tells the server this is a JWT Bearer assertion.
    // The server verifies the signature with the registered public key.
    // If valid, it returns an access token.
    var xhr = new XMLHttpRequest();
    xhr.open('POST', CONFIG.tokenEndpoint, false);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send(
      'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') +
      '&assertion=' + encodeURIComponent(jwt)
    );

    document.title = 'STEP3: token response ' + xhr.status;

    var data = JSON.parse(xhr.responseText);
    if (!data.access_token) {
      throw new Error('No access token in response: ' + xhr.responseText);
    }

    document.title = 'STEP4: got access token';

    // === STEP 5: Convert token to browser session ===
    // Navigate to /frontdoor with the access token.
    // The server validates the token, sets session cookies,
    // and redirects to the protected dashboard.
    // After this, the browser has an authenticated session.
    document.location = CONFIG.frontdoorBase + '/frontdoor?sid=' + encodeURIComponent(data.access_token);

  } catch(e) {
    var msg = (typeof e === 'string') ? e : (e && e.message ? e.message : JSON.stringify(e));
    var stack = (e && e.stack) ? e.stack : 'no stack';
    document.title = 'ERROR: ' + msg;
    document.body.innerHTML = '<h1 style="color:red">Authentication Error</h1><pre>' + msg + '\n\n' + stack + '</pre>';
  }

})();
