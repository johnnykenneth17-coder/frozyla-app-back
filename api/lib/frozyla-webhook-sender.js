// frozyla-webhook-sender.js (Frozyla side)
//
// Fires a signed webhook to FEECENT after credit_wallet_from_feecent()
// resolves. NOT load-bearing for correctness — FEECENT's own
// getBillStatus() polling (bills-worker.js's pollAndFinalize) will
// eventually reach the same conclusion by asking Frozyla's /status
// endpoint directly, and that path is what handles the case where
// this webhook is lost entirely (network failure, FEECENT down,
// whatever). This exists purely so a successful/failed credit
// resolves in FEECENT within seconds instead of waiting for the next
// poll interval.
//
// Deliberately fire-and-forget: creditCustomerWallet() should return
// its response to FEECENT's own HTTP call regardless of whether this
// webhook send succeeds — a webhook delivery failure must never turn
// a successful credit into an error response for the /credit call
// that triggered it.

const crypto = require("crypto");
const hmac = require("./frozyla-hmac");

const FEECENT_WEBHOOK_URL = process.env.FEECENT_WEBHOOK_URL; // e.g. https://api.feecent.com/api/webhooks/frozyla
const HMAC_SECRET = process.env.FROZYLA_FEECENT_HMAC_SECRET; // same value as FEECENT's FEECENT_FROZYLA_HMAC_SECRET
const REQUEST_TIMEOUT_MS = 10000;

// status: 'success' | 'failed' | 'pending'
async function sendFeecentWebhook({ reference, status, amount, currency = "NGN", message }) {
  if (!FEECENT_WEBHOOK_URL || !HMAC_SECRET) {
    console.warn(
      "[FROZYLA-WEBHOOK-SENDER] FEECENT_WEBHOOK_URL/FROZYLA_FEECENT_HMAC_SECRET " +
        "not set — skipping webhook send. FEECENT's own polling will still " +
        "pick this up, just not as fast.",
    );
    return;
  }

  const path = new URL(FEECENT_WEBHOOK_URL).pathname;
  const eventId = crypto.randomUUID();
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = hmac.generateNonce();
  const body = {
    eventId,
    event: status === "success" ? "wallet.credit.completed" : "wallet.credit.failed",
    reference,
    status,
    amount,
    currency,
    message,
    timestamp: new Date().toISOString(),
  };
  const rawBody = JSON.stringify(body);
  const signature = hmac.sign({ secret: HMAC_SECRET, method: "POST", path, timestamp, nonce, rawBody });

  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(FEECENT_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Frozyla-Timestamp": timestamp,
        "X-Frozyla-Nonce": nonce,
        "X-Frozyla-Signature": signature,
      },
      body: rawBody,
      signal: controller.signal,
    });
    if (!res.ok) {
      console.warn(`[FROZYLA-WEBHOOK-SENDER] FEECENT responded ${res.status} for ${reference} — not retrying, polling covers this`);
    }
  } catch (err) {
    // Swallow — see file header. Logged for observability only.
    console.warn(`[FROZYLA-WEBHOOK-SENDER] Delivery failed for ${reference}:`, err.message);
  } finally {
    clearTimeout(timeoutHandle);
  }
}

module.exports = { sendFeecentWebhook };