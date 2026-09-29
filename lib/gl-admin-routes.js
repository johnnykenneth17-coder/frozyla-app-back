// gl-admin-routes.js (Frozyla side) — Phase 3
//
// Mount in server.js alongside your other admin routes:
//   const glAdminRouter = require("./lib/gl-admin-routes");
//   app.use("/api/admin/gl", authMiddleware, adminMiddleware, glAdminRouter);
//
// Mounted at /api/admin/gl, NOT /api/admin/ledger — your existing
// /api/admin/ledger/* routes (discrepancies, full, entry/:id,
// balance/:userId, :id/merge, :id/reject, stats) are already live and
// mounted there. See DANGEROUS_ROUTES_TO_RETIRE.md for why those
// specific routes (:id/merge and :id/reject) need to be retired, not
// merely left alongside this — but that's a deliberate follow-up
// step, not something this file does by occupying the same path.
//
// Every write route here goes through ledger-service.js /
// account-restriction SQL functions — nothing in this file ever
// updates a balance, freezes an account, or posts a journal entry
// directly. Read routes hit the report_*()/gl_admin_dashboard_summary()
// SQL functions from 027_gl_ledger_phase3_admin.sql.

const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);
const ledgerService = require("./ledger-service");
const alertingService = require("./alerting-service");

// ============================================================
// DASHBOARD
// ============================================================
router.get("/dashboard", async (req, res) => {
  try {
    const { data, error } = await supabase.rpc("gl_admin_dashboard_summary");
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] dashboard failed:", err);
    res.status(500).json({ success: false, message: "Failed to load dashboard" });
  }
});

// ============================================================
// RECONCILIATION CASES — list / detail / investigate / resolve
// ============================================================
router.get("/cases", async (req, res) => {
  try {
    const { status, severity, case_type, owner_id, limit, offset } = req.query;
    let query = supabase.from("reconciliation_cases").select("*", { count: "exact" }).order("detected_at", { ascending: false });
    if (status) query = query.eq("status", status);
    if (severity) query = query.eq("severity", severity);
    if (case_type) query = query.eq("case_type", case_type);
    if (owner_id) query = query.eq("owner_id", owner_id);
    const lim = limit ? Math.min(parseInt(limit, 10) || 50, 200) : 50;
    const off = offset ? parseInt(offset, 10) || 0 : 0;
    query = query.range(off, off + lim - 1);

    const { data, count, error } = await query;
    if (error) throw error;
    res.json({ success: true, data, total: count });
  } catch (err) {
    console.error("[GL-ADMIN] GET /cases failed:", err);
    res.status(500).json({ success: false, message: "Failed to load cases" });
  }
});

// Full case detail: everything spec section 16 asks the admin to be
// able to see in one place — case, events, related journal entry +
// lines, related transaction, amendment history, account balance
// snapshot.
router.get("/cases/:id", async (req, res) => {
  try {
    const { data: gl_case, error } = await supabase.from("reconciliation_cases").select("*").eq("id", req.params.id).maybeSingle();
    if (error) throw error;
    if (!gl_case) return res.status(404).json({ success: false, message: "Case not found" });

    const [{ data: events }, { data: amendments }] = await Promise.all([
      supabase.from("investigation_events").select("*").eq("case_id", req.params.id).order("created_at", { ascending: true }),
      supabase.from("amendment_requests").select("*, amendment_approvals(*)").eq("case_id", req.params.id),
    ]);

    let journalEntry = null;
    if (gl_case.journal_entry_id) {
      const { data: entry } = await supabase.from("gl_journal_entries").select("*, gl_journal_lines(*)").eq("id", gl_case.journal_entry_id).maybeSingle();
      journalEntry = entry;
    }

    let accountBalance = null;
    if (gl_case.account_id && gl_case.owner_id) {
      const { data: acct } = await supabase.from("gl_accounts").select("account_code").eq("id", gl_case.account_id).maybeSingle();
      if (acct) accountBalance = await ledgerService.getAccountBalance({ accountCode: acct.account_code, ownerId: gl_case.owner_id });
    }

    let restrictions = null;
    if (gl_case.owner_id) {
      const { data } = await supabase.from("account_restrictions").select("*").eq("user_id", gl_case.owner_id).order("created_at", { ascending: false });
      restrictions = data;
    }

    res.json({ success: true, data: { case: gl_case, events, amendments, journalEntry, accountBalance, restrictions } });
  } catch (err) {
    console.error("[GL-ADMIN] GET /cases/:id failed:", err);
    res.status(500).json({ success: false, message: "Failed to load case detail" });
  }
});

router.post("/cases/:id/notes", async (req, res) => {
  try {
    const { content } = req.body || {};
    if (!content) return res.status(400).json({ success: false, message: "content is required" });
    const event = await ledgerService.addInvestigationEvent({
      caseId: req.params.id, eventType: "note", actorId: req.userId, actorRole: req.userRole === "super_admin" ? "SUPER_ADMIN" : "ADMIN", content,
    });
    res.json({ success: true, data: event });
  } catch (err) {
    console.error("[GL-ADMIN] POST /cases/:id/notes failed:", err);
    res.status(500).json({ success: false, message: "Failed to add note" });
  }
});

router.post("/cases/:id/status", async (req, res) => {
  try {
    const { status, reason } = req.body || {};
    if (!status) return res.status(400).json({ success: false, message: "status is required" });
    await ledgerService.updateCaseStatus({
      caseId: req.params.id, newStatus: status, actorId: req.userId,
      actorRole: req.userRole === "super_admin" ? "SUPER_ADMIN" : "ADMIN", reason,
    });
    res.json({ success: true });
  } catch (err) {
    console.error("[GL-ADMIN] POST /cases/:id/status failed:", err);
    res.status(500).json({ success: false, message: "Failed to update case status" });
  }
});

router.post("/cases/:id/assign", async (req, res) => {
  try {
    const { admin_id } = req.body || {};
    const { error } = await supabase.from("reconciliation_cases").update({ assigned_admin_id: admin_id }).eq("id", req.params.id);
    if (error) throw error;
    await ledgerService.addInvestigationEvent({
      caseId: req.params.id, eventType: "assignment", actorId: req.userId, actorRole: "ADMIN",
      content: `Assigned to ${admin_id}`,
    });
    res.json({ success: true });
  } catch (err) {
    console.error("[GL-ADMIN] POST /cases/:id/assign failed:", err);
    res.status(500).json({ success: false, message: "Failed to assign case" });
  }
});

// ============================================================
// AMENDMENTS — maker-checker
// ============================================================
router.post("/amendments", async (req, res) => {
  try {
    const { caseId, originalJournalEntryId, amendmentType, amount, reason } = req.body || {};
    if (!originalJournalEntryId || !amendmentType || !amount || !reason) {
      return res.status(400).json({ success: false, message: "originalJournalEntryId, amendmentType, amount, and reason are required" });
    }
    const amendment = await ledgerService.requestAmendment({
      caseId, originalJournalEntryId, amendmentType, amount, reason, requestedBy: req.userId,
    });
    res.json({ success: true, data: amendment });
  } catch (err) {
    console.error("[GL-ADMIN] POST /amendments failed:", err);
    res.status(500).json({ success: false, message: "Failed to create amendment request" });
  }
});

router.get("/amendments", async (req, res) => {
  try {
    const { status } = req.query;
    let query = supabase.from("amendment_requests").select("*, amendment_approvals(*)").order("created_at", { ascending: false });
    if (status) query = query.eq("status", status);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] GET /amendments failed:", err);
    res.status(500).json({ success: false, message: "Failed to load amendments" });
  }
});

router.post("/amendments/:id/approve", async (req, res) => {
  try {
    const { decision, comments, correctionLines } = req.body || {};
    if (!["APPROVED", "REJECTED"].includes(decision)) {
      return res.status(400).json({ success: false, message: "decision must be APPROVED or REJECTED" });
    }
    // For PARTIAL_CORRECTION/ADJUSTMENT amendments the request body
    // must also supply the correction's own balanced lines — a
    // REVERSAL amendment ignores correctionLines entirely (it mirrors
    // the original automatically inside post_amendment_correction()).
    const result = await ledgerService.approveAmendment({
      amendmentRequestId: req.params.id, approvedBy: req.userId, decision, comments, correctionLines,
    });
    res.json({ success: true, data: result });
  } catch (err) {
    if (err.code === "SELF_APPROVAL_REJECTED") {
      return res.status(403).json({ success: false, code: err.code, message: err.message });
    }
    if (err.code === "NOT_PENDING") {
      return res.status(400).json({ success: false, code: err.code, message: err.message });
    }
    console.error("[GL-ADMIN] POST /amendments/:id/approve failed:", err);
    res.status(500).json({ success: false, message: "Failed to process approval" });
  }
});

// ============================================================
// ACCOUNT RESTRICTIONS
// ============================================================
router.post("/accounts/:userId/restrict", async (req, res) => {
  try {
    const { action, scope, reason, caseNumber, expectedDuration } = req.body || {};
    const { data, error } = await supabase.rpc("restrict_user_account", {
      p_user_id: req.params.userId,
      p_action: action,
      p_scope: scope || "all_transactions",
      p_reason: reason,
      p_performed_by: req.userId,
      p_case_number: caseNumber || null,
      p_expected_duration: expectedDuration || "indefinite",
    });
    if (error) throw error;
    if (!data.success) return res.status(400).json({ success: false, code: data.code });
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] POST /accounts/:userId/restrict failed:", err);
    res.status(500).json({ success: false, message: "Failed to restrict account" });
  }
});

router.post("/accounts/:userId/unfreeze", async (req, res) => {
  try {
    const { reason, caseNumber } = req.body || {};
    const { data, error } = await supabase.rpc("unfreeze_user_account", {
      p_user_id: req.params.userId,
      p_reason: reason,
      p_performed_by: req.userId,
      p_case_number: caseNumber || null,
    });
    if (error) throw error;
    if (!data.success) return res.status(400).json({ success: false, code: data.code });
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] POST /accounts/:userId/unfreeze failed:", err);
    res.status(500).json({ success: false, message: "Failed to unfreeze account" });
  }
});

// ============================================================
// ACCOUNT / TRANSACTION DETAIL (spec sections 38/39)
// ============================================================
router.get("/accounts/:userId", async (req, res) => {
  try {
    const balance = await ledgerService.getAccountBalance({ accountCode: "2000", ownerId: req.params.userId });
    const { data: lines } = await supabase
      .from("gl_journal_lines")
      .select("*, gl_journal_entries(*)")
      .eq("owner_id", req.params.userId)
      .order("created_at", { ascending: false })
      .limit(100);
    const { data: cases } = await supabase.from("reconciliation_cases").select("*").eq("owner_id", req.params.userId).order("detected_at", { ascending: false });
    const { data: restrictions } = await supabase.from("account_restrictions").select("*").eq("user_id", req.params.userId).order("created_at", { ascending: false });

    res.json({ success: true, data: { balance, journalLines: lines, cases, restrictions } });
  } catch (err) {
    console.error("[GL-ADMIN] GET /accounts/:userId failed:", err);
    res.status(500).json({ success: false, message: "Failed to load account detail" });
  }
});

router.get("/journal-entries/:reference", async (req, res) => {
  try {
    const { data: entry, error } = await supabase
      .from("gl_journal_entries")
      .select("*, gl_journal_lines(*, gl_accounts(account_code, account_name))")
      .eq("journal_reference", req.params.reference)
      .maybeSingle();
    if (error) throw error;
    if (!entry) return res.status(404).json({ success: false, message: "Journal entry not found" });

    const reversalStatus = await ledgerService.getReversalStatus(entry.id);
    const { data: relatedCases } = await supabase.from("reconciliation_cases").select("*").eq("journal_entry_id", entry.id);

    res.json({ success: true, data: { entry, reversalStatus, relatedCases } });
  } catch (err) {
    console.error("[GL-ADMIN] GET /journal-entries/:reference failed:", err);
    res.status(500).json({ success: false, message: "Failed to load journal entry" });
  }
});

// ============================================================
// REPORTS
// ============================================================
router.get("/reports/trial-balance", async (req, res) => {
  try {
    const { data, error } = await supabase.rpc("report_trial_balance");
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] trial-balance report failed:", err);
    res.status(500).json({ success: false, message: "Failed to generate trial balance" });
  }
});

router.get("/reports/customer-liability", async (req, res) => {
  try {
    const limit = req.query.limit ? Math.min(parseInt(req.query.limit, 10) || 100, 500) : 100;
    const offset = req.query.offset ? parseInt(req.query.offset, 10) || 0 : 0;
    const { data, error } = await supabase.rpc("report_customer_liability", { p_limit: limit, p_offset: offset });
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] customer-liability report failed:", err);
    res.status(500).json({ success: false, message: "Failed to generate report" });
  }
});

router.get("/reports/revenue", async (req, res) => {
  try {
    const since = req.query.since || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const until = req.query.until || new Date().toISOString();
    const { data, error } = await supabase.rpc("report_revenue", { p_since: since, p_until: until });
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] revenue report failed:", err);
    res.status(500).json({ success: false, message: "Failed to generate revenue report" });
  }
});

router.get("/reports/suspense", async (req, res) => {
  try {
    const { data, error } = await supabase.rpc("report_suspense");
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] suspense report failed:", err);
    res.status(500).json({ success: false, message: "Failed to generate suspense report" });
  }
});

router.get("/reports/reversals", async (req, res) => {
  try {
    const since = req.query.since || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const until = req.query.until || new Date().toISOString();
    const { data, error } = await supabase.rpc("report_reversals_and_corrections", { p_since: since, p_until: until });
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] reversals report failed:", err);
    res.status(500).json({ success: false, message: "Failed to generate reversals report" });
  }
});

router.get("/reports/audit-log", async (req, res) => {
  try {
    const { entity_type, since, limit } = req.query;
    const { data, error } = await supabase.rpc("report_audit_log", {
      p_entity_type: entity_type || null,
      p_since: since || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      p_limit: limit ? Math.min(parseInt(limit, 10) || 200, 1000) : 200,
    });
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] audit-log report failed:", err);
    res.status(500).json({ success: false, message: "Failed to generate audit report" });
  }
});

// ============================================================
// ALERTS
// ============================================================
router.get("/alerts", async (req, res) => {
  try {
    const { acknowledged } = req.query;
    let query = supabase.from("system_alerts").select("*").order("created_at", { ascending: false }).limit(200);
    if (acknowledged !== undefined) query = query.eq("acknowledged", acknowledged === "true");
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[GL-ADMIN] GET /alerts failed:", err);
    res.status(500).json({ success: false, message: "Failed to load alerts" });
  }
});

router.post("/alerts/:id/acknowledge", async (req, res) => {
  try {
    const result = await alertingService.acknowledgeAlert({ alertId: req.params.id, acknowledgedBy: req.userId });
    res.json({ success: true, data: result });
  } catch (err) {
    console.error("[GL-ADMIN] POST /alerts/:id/acknowledge failed:", err);
    res.status(500).json({ success: false, message: "Failed to acknowledge alert" });
  }
});

module.exports = router;