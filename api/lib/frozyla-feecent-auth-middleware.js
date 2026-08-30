// frozyla-feecent-auth-middleware.js
//
// Server-to-server auth for the /api/v1/integrations/feecent/frozyla/*
// routes. This is deliberately NOT authMiddleware/staffMiddleware from
// your existing auth.js — those authenticate a logged-in Frozyla user
// or staff member via JWT. FEECENT is neither; it's authenticated
// purely by knowing the shared HMAC secret, same pattern as any
// server-to-server webhook consumer.
//
// CRITICAL MOUNTING REQUIREMENT: this reads req.rawBody, which only
// exists if the JSON body parser captured it BEFORE parsing. Your
// existing `app.use(express.json({ limit: "10mb" }))` in server.js
// does not do this, and once a body stream is consumed by one parser
// it cannot be re-read by another. That means this integration
// router MUST be mounted with its OWN body parser, and that mount
// must happen for these specific paths before (or instead of) the
// global express.json() call — the router below sets this up so you
// only need to `app.use("/api/v1/integrations/feecent/frozyla", frozylaIntegrationRouter)`
// wherever it fits in server.js's existing middleware order, ideally
// near the top before the global json() call, or on its own path
// prefix that the global parser doesn't also touch.

const bodyParser = require("body-parser");
const hmac = require("./frozyla-hmac");

const HMAC_SECRET = process.env.FEECENT_FROZYLA_HMAC_SECRET;

if (!HMAC_SECRET) {
  console.warn(
    "[FROZYLA-FEECENT-AUTH] FEECENT_FROZYLA_HMAC_SECRET not set — every " +
      "request from FEECENT will be rejected until this is configured. " +
      "Must be the SAME value as FEECENT's FEECENT_FROZYLA_HMAC_SECRET.",
  );
}

// Captures the exact raw bytes for signature verification while still
// populating req.body with the parsed object, same as express.json()
// would — existing route code that reads req.body works unchanged.
const rawBodyJson = bodyParser.json({
  limit: "1mb",
  verify: (req, _res, buf) => {
    req.rawBody = buf.toString("utf8");
  },
});

async function verifyFeecentSignature(req, res, next) {
  if (!HMAC_SECRET) {
    return res.status(503).json({
      success: false,
      message: "Integration temporarily unavailable",
    });
  }

  const timestamp = req.headers["x-feecent-timestamp"];
  const nonce = req.headers["x-feecent-nonce"];
  const signature = req.headers["x-feecent-signature"];
  const rawBody = req.rawBody || "";

  const { valid, reason } = hmac.verify({
    secret: HMAC_SECRET,
    method: req.method,
    path: req.path, // path only — see frozyla-hmac.js's normalization note
    timestamp,
    nonce,
    rawBody,
    signature,
  });

  if (!valid) {
    console.warn(`[FROZYLA-FEECENT-AUTH] Rejected request: ${reason}`);
    // Deliberately generic — never tell the caller WHICH check failed.
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  // Replay protection: first use of a nonce inserts; a repeat hits the
  // PK violation and is rejected. This runs AFTER signature
  // verification (no point burning a DB write on an unsigned request)
  // but BEFORE any business logic.
  const { createClient } = require("@supabase/supabase-js");
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY,
  );
  const { error: nonceErr } = await supabase
    .from("feecent_request_nonces")
    .insert({ nonce });

  if (nonceErr) {
    // Unique violation = replay. Anything else = fail closed — a
    // request we can't prove is fresh should not proceed.
    console.warn(
      `[FROZYLA-FEECENT-AUTH] Nonce check failed for ${nonce}:`,
      nonceErr.message,
    );
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  next();
}

module.exports = { rawBodyJson, verifyFeecentSignature };