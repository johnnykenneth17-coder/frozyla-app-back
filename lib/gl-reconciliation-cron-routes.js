// gl-reconciliation-cron-routes.js (Frozyla side) — Phase 2
//
// Mount in server.js alongside the existing cron routes:
//   const glReconciliationCronRouter = require("./lib/gl-reconciliation-cron-routes");
//   app.use("/api/cron/gl-reconciliation", glReconciliationCronRouter);
//
// Uses the SAME FROZYLA_CRON_SECRET already configured for
// frozyla-cron-routes.js — this is one more job on the same trusted
// cron caller, not a new trust boundary, unlike the card-funding
// cron secret (which guards a channel to a different party, Feecent).
//
// Suggested schedule (spec section 26 — different operations,
// different frequencies): account-balance + order/funding transaction
// checks hourly; Feecent credits + trial balance daily (trial balance
// especially — it's a full-table scan, no need to run it every hour).

const express = require("express");
const router = express.Router();
const reconciliationEngine = require("./reconciliation-engine");

const CRON_SECRET = process.env.FROZYLA_CRON_SECRET;

function requireCronAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!CRON_SECRET || authHeader !== `Bearer ${CRON_SECRET}`) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  next();
}

router.post("/account-balances", requireCronAuth, async (req, res) => {
  try {
    const result = await reconciliationEngine.reconcileAccountBalances();
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("[GL-RECONCILIATION-CRON] Account balance check failed:", err);
    res.status(500).json({ success: false, message: "Account balance reconciliation failed" });
  }
});

router.post("/transactions", requireCronAuth, async (req, res) => {
  try {
    const [orders, funding] = await Promise.all([
      reconciliationEngine.reconcileOrderTransactions(),
      reconciliationEngine.reconcileFundingTransactions(),
    ]);
    res.json({ success: true, orders, funding });
  } catch (err) {
    console.error("[GL-RECONCILIATION-CRON] Transaction check failed:", err);
    res.status(500).json({ success: false, message: "Transaction reconciliation failed" });
  }
});

router.post("/feecent", requireCronAuth, async (req, res) => {
  try {
    const result = await reconciliationEngine.reconcileFeecentCredits();
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("[GL-RECONCILIATION-CRON] Feecent check failed:", err);
    res.status(500).json({ success: false, message: "Feecent reconciliation failed" });
  }
});

router.post("/trial-balance", requireCronAuth, async (req, res) => {
  try {
    const result = await reconciliationEngine.reconcileTrialBalance();
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("[GL-RECONCILIATION-CRON] Trial balance check failed:", err);
    res.status(500).json({ success: false, message: "Trial balance check failed" });
  }
});

router.post("/full-sweep", requireCronAuth, async (req, res) => {
  try {
    const result = await reconciliationEngine.runFullReconciliationSweep();
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("[GL-RECONCILIATION-CRON] Full sweep failed:", err);
    res.status(500).json({ success: false, message: "Full reconciliation sweep failed" });
  }
});

module.exports = router;