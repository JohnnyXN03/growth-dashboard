// /api/login.js — runs on Vercel's server, never in the browser.
// Checks the password and issues a signed session token.

const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false, error: 'Method not allowed' });
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }
  const { name, password } = body || {};

  if (!name || !password) {
    res.status(400).json({ ok: false, error: 'Name and password required' });
    return;
  }

  if (password !== process.env.APP_PASSWORD) {
    res.status(401).json({ ok: false, error: 'Incorrect password' });
    return;
  }

  // Signed token: name + timestamp + HMAC signature. No database needed —
  // the server can verify it's genuine just by re-computing the signature.
  const timestamp = Date.now().toString();
  const payload = `${name}.${timestamp}`;
  const signature = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(payload)
    .digest('hex');
  const token = `${payload}.${signature}`;

  res.status(200).json({ ok: true, token, name });
};
