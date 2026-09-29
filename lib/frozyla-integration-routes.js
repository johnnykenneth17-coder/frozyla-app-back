// frozyla-integration-routes.js
//
// The three endpoints FEECENT's frozyla-provider.js calls. All three
// require verifyFeecentSignature — no normal user/staff auth applies
// here, this is server-to-server only.
//
// Mount in server.js:
//   const { rawBodyJson, verifyFeecentSignature } = require("./frozyla-feecent-auth-middleware");
//   const frozylaIntegrationRouter = require("./frozyla-integration-routes");
//   app.use(
//     "/api/v1/integrations/feecent/frozyla",
//     rawBodyJson,
//     verifyFeecentSignature,
//     frozylaIntegrationRouter,
//   );
// Mount this BEFORE app.use(express.json(...)) touches the same path —
// see frozyla-feecent-auth-middleware.js's header note on why.
//
// Rate limiting (spec section 22/31 — enumeration protection on verify
// especially) isn't wired in below; apply the same rate-limit
// middleware pattern this codebase already uses elsewhere (I haven't
// seen where that's set up in server.js) to at least the /verify route,
// keyed by source IP since there's no per-caller identity finer than
// "is FEECENT" here.

const express = require("express");
const router = express.Router();
const service = require("./frozyla-integration-service");

// ------------------------------------------------------------
// POST /verify
// { customerId: "FRZ-102938" }
// -> { status: "success", customer: { id, name } }
// Returns only what FEECENT needs for on-screen confirmation — never
// balance, address, phone, or any other profile field.
// ------------------------------------------------------------
router.post("/verify", async (req, res) => {
  try {
    const { customerId } = req.body || {};
    if (!customerId || typeof customerId !== "string") {
      return res.status(400).json({ status: "error", message: "customerId is required" });
    }

    const customer = await service.findCustomerForVerification(customerId);
    if (!customer) {
      return res.status(404).json({ status: "error", message: "Customer not found" });
    }

    res.json({
      status: "success",
      customer: { id: customer.id, name: customer.name },
    });
  } catch (err) {
    console.error("[FROZYLA-INTEGRATION] /verify failed:", err);
    res.status(500).json({ status: "error", message: "Verification failed" });
  }
});

// ------------------------------------------------------------
// POST /credit
// { reference, customerId, amount, currency, idempotencyKey, timestamp }
// -> { status: "success" | "pending" | "failed", transactionId, message? }
// ------------------------------------------------------------
router.post("/credit", async (req, res) => {
  try {
    const { reference, customerId, amount, currency, idempotencyKey } =
      req.body || {};

    if (!reference || !customerId || !idempotencyKey) {
      return res.status(400).json({
        status: "failed",
        message: "reference, customerId and idempotencyKey are required",
      });
    }
    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ status: "failed", message: "Invalid amount" });
    }
    if (currency !== "NGN") {
      return res.status(400).json({ status: "failed", message: "Unsupported currency" });
    }

    const result = await service.creditCustomerWallet({
      reference,
      idempotencyKey,
      customerId,
      amount: numericAmount,
      rawRequest: req.body,
    });

    // service layer maps every outcome (including "already processed")
    // to this same shape — the route doesn't need its own branching.
    const httpStatus = result.status === "failed" && result.permanent ? 400 : 200;
    res.status(httpStatus).json({
      status: result.status,
      transactionId: result.reference,
      message: result.message,
    });
  } catch (err) {
    console.error("[FROZYLA-INTEGRATION] /credit failed:", err);
    // Unknown/unexpected error on OUR side after we might have already
    // started processing — never claim "failed" here, that could cause
    // FEECENT to treat this as final when it isn't. 500 tells FEECENT
    // this is uncertain and to check /status or retry (idempotently).
    res.status(500).json({ status: "error", message: "Credit processing error" });
  }
});

// ------------------------------------------------------------
// GET /status/:reference
// -> { status: "received" | "success" | "pending" | "failed", transactionId }
// Same lookup serves FEECENT's post-timeout reconciliation query and
// its normal poll-until-confirmed path — one source of truth either way.
// ------------------------------------------------------------
router.get("/status/:reference", async (req, res) => {
  try {
    const record = await service.getFundingRequestStatus(req.params.reference);
    if (!record) {
      return res.status(404).json({ status: "not_found" });
    }
    res.json({
      status: record.status === "credited" ? "success" : record.status,
      transactionId: record.reference,
      message: record.failure_reason || undefined,
    });
  } catch (err) {
    console.error("[FROZYLA-INTEGRATION] /status failed:", err);
    res.status(500).json({ status: "error", message: "Status check failed" });
  }
});

module.exports = router;