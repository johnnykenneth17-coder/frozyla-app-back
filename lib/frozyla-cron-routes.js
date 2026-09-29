// frozyla-cron-routes.js
//
// Mount in server.js:
//   const frozylaCronRouter = require("./frozyla-cron-routes");
//   app.use("/api/cron", frozylaCronRouter);
//
// Point your external cron service at POST /api/cron/process-jobs on
// whatever interval makes sense (FEECENT's own worker polls similarly
// frequently — 30-60s is reasonable to start; the fastest job in the
// backoff schedule retries after 30s anyway, so polling faster than
// that gains nothing).
//
// FROZYLA_CRON_SECRET is a NEW env var, separate from any FEECENT
// secret — this authenticates Frozyla's own cron caller, unrelated to
// the FEECENT<->Frozyla integration's HMAC secrets.

const express = require("express");
const router = express.Router();
const { runWorkerBatch } = require("./frozyla-job-worker");
const { runOrderReconciliationSweep } = require("./frozyla-order-reconciliation-service");

const CRON_SECRET = process.env.FROZYLA_CRON_SECRET;

if (!CRON_SECRET) {
  console.warn(
    "[FROZYLA-CRON] FROZYLA_CRON_SECRET not set — /api/cron/process-jobs will reject every request until this is configured.",
  );
}

function requireCronAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!CRON_SECRET || authHeader !== `Bearer ${CRON_SECRET}`) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  next();
}

router.post("/process-jobs", requireCronAuth, async (req, res) => {
  try {
    const result = await runWorkerBatch();
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("[FROZYLA-CRON] Worker batch failed:", err);
    res.status(500).json({ success: false, message: "Worker batch failed" });
  }
});

// Point a SEPARATE, less-frequent cron entry at this one — every
// 15-30 minutes is plenty; reconciliation is about catching drift
// over time, not reacting within seconds the way job processing is.
router.post("/reconcile-orders", requireCronAuth, async (req, res) => {
  try {
    const result = await runOrderReconciliationSweep();
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("[FROZYLA-CRON] Reconciliation sweep failed:", err);
    res.status(500).json({ success: false, message: "Reconciliation sweep failed" });
  }
});

module.exports = router;