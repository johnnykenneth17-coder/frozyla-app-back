// lib/feecent-payments-client.js (Frozyla side)
//
// Signs and calls Feecent's card-funding API
// (/api/v1/integrations/frozyla/funding/*). Uses the SAME
// lib/frozyla-hmac.js module already in this codebase (currently only
// used to VERIFY Feecent's inbound calls via
// frozyla-feecent-auth-middleware.js) — this file is the first thing
// in this codebase to use its sign() side, for the opposite direction.
//
// Deliberately a NEW, separate secret from FEECENT_FROZYLA_HMAC_SECRET
// (the one Feecent uses to sign ITS calls to Frozyla for the Bills
// integration) — see CARD_FUNDING_COMPLIANCE.md for why these two
// channels shouldn't share a secret.
//
// SAVED CARDS (provider tokens). Frozyla never holds a card number OR a
// chargeable token. When a customer opts in on the hosted checkout page,
// Feecent keeps the Flutterwave token and gives Frozyla back only an opaque
// card reference (cardRef). Every later call names that cardRef together with
// frozylaUserId, and Feecent must check the two belong together before it
// charges. The three calls below (saveCard flag, chargeSavedCard,
// deleteSavedCard) are specified in FEECENT_SAVED_CARDS_CONTRACT.md.
// A Feecent that has not implemented them yet answers 404/501, which this
// file reports as code NOT_SUPPORTED so callers can say "not available yet".
//
// New env vars needed on Frozyla's deployment:
//   FEECENT_PAYMENTS_API_BASE_URL   e.g. https://feecent-api.vercel.app
//   FROZYLA_FEECENT_PAYMENTS_HMAC_SECRET   byte-identical to Feecent's copy

const hmac = require("./frozyla-hmac");

const BASE_URL = process.env.FEECENT_PAYMENTS_API_BASE_URL;
const HMAC_SECRET = process.env.FROZYLA_FEECENT_PAYMENTS_HMAC_SECRET;
const REQUEST_TIMEOUT_MS = 15000;

if (!HMAC_SECRET) {
  console.warn(
    "[FEECENT-PAYMENTS-CLIENT] FROZYLA_FEECENT_PAYMENTS_HMAC_SECRET not set — " +
      "every card-funding request will fail until this is configured.",
  );
}

async function signedRequest({ method, path, body }) {
  if (!BASE_URL || !HMAC_SECRET) {
    return {
      ok: false,
      networkError: true,
      error: "Card funding is not configured (missing FEECENT_PAYMENTS_API_BASE_URL / FROZYLA_FEECENT_PAYMENTS_HMAC_SECRET)",
    };
  }

  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = hmac.generateNonce();
  const rawBody = body ? JSON.stringify(body) : "";
  const signature = hmac.sign({ secret: HMAC_SECRET, method, path, timestamp, nonce, rawBody });

  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-Frozyla-Timestamp": timestamp,
        "X-Frozyla-Nonce": nonce,
        "X-Frozyla-Signature": signature,
      },
      body: rawBody || undefined,
      signal: controller.signal,
    });

    let json = null;
    try {
      json = await res.json();
    } catch {
      // non-JSON response — caller handles via ok/status
    }
    return { ok: res.ok, status: res.status, json };
  } catch (err) {
    return {
      ok: false,
      networkError: true,
      error: err.name === "AbortError" ? "Request to Feecent timed out" : err.message,
    };
  } finally {
    clearTimeout(timeoutHandle);
  }
}

// ------------------------------------------------------------
// createCheckout({ frozylaUserId, amountMinor, currency, idempotencyKey })
// -> { success, checkoutUrl, reference, status } | { success:false, error, code }
// ------------------------------------------------------------
async function createCheckout({ frozylaUserId, amountMinor, currency = "NGN", idempotencyKey, saveCard = false }) {
  const body = { frozylaUserId, amountMinor, currency, idempotencyKey };
  // Only sent when true, so a Feecent that predates saved cards receives
  // exactly the body it always did.
  if (saveCard) body.saveCard = true;
  const result = await signedRequest({
    method: "POST",
    path: "/api/v1/integrations/frozyla/funding/checkout",
    body,
  });

  if (result.networkError) {
    return { success: false, error: result.error, code: "NETWORK_ERROR" };
  }
  if (!result.ok || !result.json || !result.json.success) {
    return {
      success: false,
      error: result.json?.message || `Feecent returned HTTP ${result.status}`,
      code: result.json?.code || "CHECKOUT_FAILED",
    };
  }
  return {
    success: true,
    checkoutUrl: result.json.data.checkoutUrl,
    reference: result.json.data.reference,
    status: result.json.data.status,
  };
}

// ------------------------------------------------------------
// getStatus(reference) -> { success, data: { status, frozylaUserId, amountMinor, ... } }
// ------------------------------------------------------------
async function getStatus(reference) {
  const result = await signedRequest({
    method: "GET",
    path: `/api/v1/integrations/frozyla/funding/status/${encodeURIComponent(reference)}`,
  });

  if (result.networkError) {
    return { success: false, error: result.error };
  }
  if (result.status === 404) {
    return { success: false, notFound: true };
  }
  if (!result.ok || !result.json || !result.json.success) {
    return { success: false, error: result.json?.message || `Feecent returned HTTP ${result.status}` };
  }
  return { success: true, data: result.json.data };
}

// A 404/501 without a Feecent error code means "that route does not exist
// there yet". A 404 WITH a code (CARD_NOT_FOUND ...) is a real answer.
function isUnsupported(result) {
  return (
    !result.networkError &&
    (result.status === 501 || result.status === 404) &&
    !(result.json && result.json.code)
  );
}

// ------------------------------------------------------------
// chargeSavedCard({ frozylaUserId, cardRef, amountMinor, currency, idempotencyKey })
// -> { success, reference, status, checkoutUrl? } | { success:false, code, error }
// checkoutUrl is returned only if the provider needs the customer to
// authenticate this charge (OTP / 3-D Secure); the app then opens it exactly
// like a normal hosted checkout. Otherwise the app just polls the status of
// `reference`, the same as it does today.
// ------------------------------------------------------------
async function chargeSavedCard({ frozylaUserId, cardRef, amountMinor, currency = "NGN", idempotencyKey }) {
  const result = await signedRequest({
    method: "POST",
    path: "/api/v1/integrations/frozyla/funding/saved-cards/charge",
    body: { frozylaUserId, cardRef, amountMinor, currency, idempotencyKey },
  });

  if (result.networkError) {
    // Ambiguous: Feecent may or may not have started the charge. The caller
    // must NOT tell the customer it failed, and a retry must reuse the same
    // idempotencyKey.
    return { success: false, uncertain: true, error: result.error, code: "NETWORK_ERROR" };
  }
  if (isUnsupported(result)) return { success: false, code: "NOT_SUPPORTED" };
  if (!result.ok || !result.json || !result.json.success) {
    return {
      success: false,
      error: result.json?.message || `Feecent returned HTTP ${result.status}`,
      code: result.json?.code || "CHARGE_FAILED",
    };
  }
  const d = result.json.data || {};
  return { success: true, reference: d.reference, status: d.status, checkoutUrl: d.checkoutUrl || null };
}

// ------------------------------------------------------------
// deleteSavedCard({ frozylaUserId, cardRef }) -> { success } | { success:false, code }
// Idempotent on Feecent's side: a card that is already gone counts as success.
// POST (not DELETE) so the signed body carries the ownership pair.
// ------------------------------------------------------------
async function deleteSavedCard({ frozylaUserId, cardRef }) {
  const result = await signedRequest({
    method: "POST",
    path: "/api/v1/integrations/frozyla/funding/saved-cards/delete",
    body: { frozylaUserId, cardRef },
  });

  if (result.networkError) return { success: false, uncertain: true, error: result.error, code: "NETWORK_ERROR" };
  if (isUnsupported(result)) return { success: false, code: "NOT_SUPPORTED" };
  if (!result.ok || !result.json || !result.json.success) {
    return { success: false, error: result.json?.message || `Feecent returned HTTP ${result.status}`, code: result.json?.code || "DELETE_FAILED" };
  }
  return { success: true };
}

module.exports = { createCheckout, getStatus, chargeSavedCard, deleteSavedCard };