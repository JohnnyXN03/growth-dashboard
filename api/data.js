// /api/data.js — the only thing that knows the real Apps Script secret.
// The browser only ever holds a session token, which is useless without
// this server behind it. This also talks to Apps Script server-to-server,
// so there's no browser CORS problem at all (that only applies to
// browser-originated requests).

const crypto = require('crypto');

const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [name, timestamp, signature] = parts;
  const expected = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(`${name}.${timestamp}`)
    .digest('hex');
  if (expected !== signature) return null;
  const age = Date.now() - parseInt(timestamp, 10);
  if (isNaN(age) || age > SESSION_MAX_AGE_MS || age < 0) return null;
  return { name };
}

module.exports = async (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  const session = verifyToken(token);

  if (!session) {
    res.status(401).json({ ok: false, error: 'Not logged in or session expired' });
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }
  const { action, ...payload } = body || {};

  if (!action) {
    res.status(400).json({ ok: false, error: 'Missing action' });
    return;
  }

  try {
    const scriptPayload = { action, secret: process.env.APPS_SCRIPT_SECRET, ...payload };
    const url = `${process.env.APPS_SCRIPT_URL}?payload=${encodeURIComponent(JSON.stringify(scriptPayload))}`;
    const response = await fetch(url);
    const json = await response.json();
    res.status(200).json(json);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
};
