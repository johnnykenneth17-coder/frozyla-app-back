// lib/email-service.js — transactional email through Brevo's REST API (https://developers.brevo.com).
// Credentials come ONLY from the server environment; nothing here is ever sent to a client.
//   BREVO_API_KEY        required  (Brevo > SMTP & API > API keys)
//   BREVO_SENDER_EMAIL   required  (a sender/domain verified in Brevo)
//   BREVO_SENDER_NAME    optional  (default "Frozyla")
//   FRONTEND_URL         required for reset links, e.g. https://app.frozyla.com
// Failures are returned, never thrown, and never log keys, tokens, message bodies or addresses.

const BREVO_URL = "https://api.brevo.com/v3/smtp/email";
const TIMEOUT_MS = 8000;

const isConfigured = () => Boolean(process.env.BREVO_API_KEY && process.env.BREVO_SENDER_EMAIL);

const esc = (v) =>
  String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

async function sendEmail({ to, name, subject, html, text }) {
  if (!isConfigured()) return { ok: false, code: "NOT_CONFIGURED" };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(BREVO_URL, {
      method: "POST",
      headers: { "api-key": process.env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        sender: { name: process.env.BREVO_SENDER_NAME || "Frozyla", email: process.env.BREVO_SENDER_EMAIL },
        to: [{ email: to, name: name || undefined }],
        subject, htmlContent: html, textContent: text,
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      let code = `HTTP_${res.status}`;
      try { const j = await res.json(); if (j && j.code) code = `BREVO_${j.code}`; } catch { /* non-JSON error body */ }
      console.error(`[EMAIL] Brevo rejected a message (${code})`);
      return { ok: false, code };
    }
    let messageId = null;
    try { messageId = (await res.json()).messageId || null; } catch { /* body optional */ }
    return { ok: true, messageId };
  } catch (err) {
    const code = err && err.name === "AbortError" ? "TIMEOUT" : "NETWORK_ERROR";
    console.error(`[EMAIL] Brevo request failed (${code})`);
    return { ok: false, code };
  } finally {
    clearTimeout(timer);
  }
}

const shell = (title, body) => `<!doctype html><html><body style="margin:0;background:#f6f6f6;font-family:Arial,Helvetica,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px">
<table width="480" cellpadding="0" cellspacing="0" style="max-width:480px;background:#fff;border-radius:12px;padding:28px">
<tr><td style="font-size:22px;font-weight:700;color:#E85D3A">frozyla</td></tr>
<tr><td style="padding-top:16px;font-size:18px;font-weight:600;color:#222">${esc(title)}</td></tr>
<tr><td style="padding-top:12px;font-size:14px;line-height:1.6;color:#444">${body}</td></tr>
</table></td></tr></table></body></html>`;

function passwordResetEmail({ name, resetUrl, ttlMinutes }) {
  return {
    subject: "Reset your Frozyla password",
    html: shell("Reset your password",
      `<p>Hi ${esc(name || "there")},</p><p>We received a request to reset your password. This link works once and expires in ${esc(ttlMinutes)} minutes.</p>
       <p style="margin:24px 0"><a href="${esc(resetUrl)}" style="background:#E85D3A;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:600">Choose a new password</a></p>
       <p>If you didn't ask for this, you can ignore this email; your password will not change.</p>`),
    text: `Hi ${name || "there"},\n\nReset your Frozyla password (link works once, expires in ${ttlMinutes} minutes):\n${resetUrl}\n\nIf you didn't ask for this, ignore this email.`,
  };
}
function passwordChangedEmail({ name }) {
  return {
    subject: "Your Frozyla password was changed",
    html: shell("Password changed",
      `<p>Hi ${esc(name || "there")},</p><p>Your password was just changed and you were signed out of your other devices.</p>
       <p>If this wasn't you, reset your password immediately and contact Frozyla support.</p>`),
    text: `Hi ${name || "there"},\n\nYour Frozyla password was just changed and other devices were signed out. If this wasn't you, reset your password immediately and contact support.`,
  };
}

module.exports = { isConfigured, sendEmail, passwordResetEmail, passwordChangedEmail, esc };
