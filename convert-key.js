// Converts private.pem to JWK format for use in auth-script.js
// Run: node convert-key.js

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const keyPath = path.join(__dirname, '..', 'private.pem');
const key = crypto.createPrivateKey(fs.readFileSync(keyPath));
const jwk = key.export({ format: 'jwk' });

console.log('Copy this JWK object into auth-script.js (replace REPLACE_WITH_JWK):\n');
console.log(JSON.stringify(jwk, null, 2));
