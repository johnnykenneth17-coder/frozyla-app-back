// reconciliation-engine.js (Frozyla side) — Phase 2
//
// DETECTION ONLY. Every check in this file ends the same way: call
// ledger-service.js's createInvestigationCase() and stop. Nothing
// here ever freezes an account, reverses a transaction, or changes a
// balance — see Rule 4 in the original spec, and
// create_reconciliation_case()'s own contract in the SQL migration
// (022/023). If you're tempted to add an "and then also fix it"
// step to one of these checks, don't — that decision belongs to a
// human administrator via the amendment workflow, not to this file.
//
// Four checks, matching spec section 13:
//   A. Account balance reconciliation  — users.balance vs gl-derived balance
//   B. Transaction reconciliation      — every PAID order / credited funding
//                                         request has a matching gl posting
//   C. Feecent <-> Frozyla             — cross-system, via the existing
//                                         feecent_funding_requests table
//   D. Trial balance                    — system-wide: total debits = total credits

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);
const ledgerService = require("./ledger-service");
const alertingService = require("./alerting-service");

const TOLERANCE = 0.01;

function severityForDifference(diff) {
  const abs = Math.abs(diff);
  if (abs <= 1) return "LOW";
  if (abs <= 100) return "MEDIUM";
  if (abs <= 10000) return "HIGH";
  return "CRITICAL";
}

// Every case-creation call in this file should go through here rather
// than calling ledgerService.createInvestigationCase() directly — this
// is the one place that also fires an alert when severity is CRITICAL,
// so no individual check function has to remember to do that itself.
async function createCaseAndMaybeAlert(params) {
  const caseResult = await ledgerService.createInvestigationCase(params);
  if (params.severity === "CRITICAL") {
    await alertingService.alertOnCriticalCase({
      caseNumber: caseResult.case_number,
      caseType: params.caseType,
    }).catch((err) => console.error("[RECONCILIATION-ENGINE] Alert dispatch failed (case was still created):", err));
  }
  return caseResult;
}

// ------------------------------------------------------------
// A. ACCOUNT BALANCE RECONCILIATION
// Compares users.balance (the operational mirror) against the
// gl-derived balance for account 2000, per user. These two are
// supposed to always agree because Phase 2's cutover functions set
// both in the same transaction — a real mismatch here means either a
// bug, a manual DB edit, or a code path that still bypasses the new
// engine (e.g. something not yet migrated in Phase 2). Never assume
// which; that's what the case is for.
// ------------------------------------------------------------
async function reconcileAccountBalances({ limit = 500 } = {}) {
  const results = { checked: 0, matched: 0, mismatched: 0, casesCreated: [] };

  const { data: users, error } = await supabase.from("users").select("id, balance").limit(limit);
  if (error) throw error;

  for (const user of users || []) {
    results.checked++;
    const glBalance = await ledgerService.getAccountBalance({ accountCode: "2000", ownerId: user.id });
    const operational = Number(user.balance || 0);
    const ledgerDerived = Number(glBalance.ledger_balance || 0);
    const difference = Math.round((operational - ledgerDerived) * 100) / 100;

    if (Math.abs(difference) <= TOLERANCE) {
      results.matched++;
      continue;
    }

    results.mismatched++;
    const caseResult = await createCaseAndMaybeAlert({
      caseType: "ACCOUNT_BALANCE_MISMATCH",
      severity: severityForDifference(difference),
      accountCode: "2000",
      ownerId: user.id,
      expectedAmount: ledgerDerived,
      actualAmount: operational,
      detectedBy: "SYSTEM",
    });
    results.casesCreated.push(caseResult.case_number);
  }

  return results;
}

// ------------------------------------------------------------
// B. TRANSACTION RECONCILIATION
// Every 'PAID' order should have exactly one gl_journal_entries row
// with source_system='frozyla' and idempotency_key = 'ORDER-<id>'.
// Every 'credited' feecent_funding_requests row should have exactly
// one with idempotency_key = 'FEECENT-<reference>'. A missing entry
// means money moved (order marked PAID / funding marked credited)
// without the ledger recording it — exactly the "wallet debit without
// ledger" case the original Frozyla reconciliation trigger was
// supposed to catch but couldn't (see AUDIT.md #4).
// ------------------------------------------------------------
async function reconcileOrderTransactions({ sinceHours = 24 * 7, limit = 1000 } = {}) {
  const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000).toISOString();
  const results = { checked: 0, matched: 0, missingJournal: 0, casesCreated: [] };

  const { data: orders, error } = await supabase
    .from("orders")
    .select("id, total, created_at")
    .eq("status", "PAID")
    .gte("created_at", since)
    .limit(limit);
  if (error) throw error;

  for (const order of orders || []) {
    results.checked++;
    const { data: entry } = await supabase
      .from("gl_journal_entries")
      .select("id")
      .eq("idempotency_key", `ORDER-${order.id}`)
      .maybeSingle();

    if (entry) {
      results.matched++;
      continue;
    }

    results.missingJournal++;
    const caseResult = await createCaseAndMaybeAlert({
      caseType: "MISSING_JOURNAL_FOR_ORDER",
      severity: severityForDifference(order.total),
      externalReference: order.id,
      expectedAmount: order.total,
      actualAmount: 0,
      detectedBy: "SYSTEM",
    });
    results.casesCreated.push(caseResult.case_number);
  }

  return results;
}

async function reconcileFundingTransactions({ sinceHours = 24 * 7, limit = 1000 } = {}) {
  const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000).toISOString();
  const results = { checked: 0, matched: 0, missingJournal: 0, casesCreated: [] };

  const { data: fundings, error } = await supabase
    .from("card_funding_requests")
    .select("id, amount, processed_at")
    .eq("status", "approved")
    .gte("processed_at", since)
    .limit(limit);
  if (error) throw error;

  for (const funding of fundings || []) {
    results.checked++;
    const { data: entry } = await supabase
      .from("gl_journal_entries")
      .select("id")
      .eq("idempotency_key", `FUNDING-APPROVAL-${funding.id}`)
      .maybeSingle();

    if (entry) {
      results.matched++;
      continue;
    }

    results.missingJournal++;
    const caseResult = await createCaseAndMaybeAlert({
      caseType: "MISSING_JOURNAL_FOR_FUNDING",
      severity: severityForDifference(funding.amount),
      externalReference: funding.id,
      expectedAmount: funding.amount,
      actualAmount: 0,
      detectedBy: "SYSTEM",
    });
    results.casesCreated.push(caseResult.case_number);
  }

  return results;
}

// ------------------------------------------------------------
// C. FEECENT <-> FROZYLA CROSS-SYSTEM RECONCILIATION
//
// feecent_funding_requests is Frozyla's own record of every credit
// Feecent has asked for — it already carries everything spec section
// 13F asks to reconcile (reference, amount, currency, status,
// idempotency key). This checks Frozyla's two sides of that record
// agree with each other: a 'credited' request should have exactly one
// matching gl_journal_entries row (source_system='feecent') for the
// SAME amount. A 'received' (not yet resolved) request older than a
// grace period is also worth surfacing — it suggests
// credit_wallet_from_feecent() never got called again to finish it.
//
// This is Frozyla's side of the check. It does not call out to
// Feecent's own API to independently verify Feecent's records — that
// cross-check already exists (frozyla-reconciliation-service.js on
// Feecent's side, built earlier in this project) and duplicating it
// here would just be two systems polling each other redundantly.
// ------------------------------------------------------------
async function reconcileFeecentCredits({ sinceHours = 24 * 7, graceMinutes = 30, limit = 1000 } = {}) {
  const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000).toISOString();
  const graceCutoff = new Date(Date.now() - graceMinutes * 60 * 1000).toISOString();
  const results = { checked: 0, matched: 0, amountMismatch: 0, missingJournal: 0, stalePending: 0, casesCreated: [] };

  const { data: requests, error } = await supabase
    .from("feecent_funding_requests")
    .select("id, reference, customer_id, amount, status, requested_at")
    .gte("requested_at", since)
    .limit(limit);
  if (error) throw error;

  for (const req of requests || []) {
    results.checked++;

    if (req.status === "received" && req.requested_at < graceCutoff) {
      results.stalePending++;
      const caseResult = await createCaseAndMaybeAlert({
        caseType: "FEECENT_CREDIT_STALE_PENDING",
        severity: "MEDIUM",
        ownerId: req.customer_id,
        externalReference: req.reference,
        expectedAmount: req.amount,
        detectedBy: "SYSTEM",
      });
      results.casesCreated.push(caseResult.case_number);
      continue;
    }

    if (req.status !== "credited") continue;

    const { data: entry } = await supabase
      .from("gl_journal_entries")
      .select("id, gl_journal_lines(debit_amount, credit_amount, owner_id, gl_accounts(account_code))")
      .eq("idempotency_key", `FEECENT-${req.reference}`)
      .maybeSingle();

    if (!entry) {
      results.missingJournal++;
      const caseResult = await createCaseAndMaybeAlert({
        caseType: "FEECENT_CREDIT_MISSING_JOURNAL",
        severity: severityForDifference(req.amount),
        ownerId: req.customer_id,
        externalReference: req.reference,
        expectedAmount: req.amount,
        actualAmount: 0,
        detectedBy: "SYSTEM",
      });
      results.casesCreated.push(caseResult.case_number);
      continue;
    }

    // Found the entry — now confirm the amount actually posted to the
    // customer's wallet (2000) matches what Feecent asked for, not
    // just that SOME entry with the right idempotency key exists.
    const walletLine = (entry.gl_journal_lines || []).find(
      (l) => l.gl_accounts?.account_code === "2000" && l.owner_id === req.customer_id,
    );
    const postedAmount = Number(walletLine?.credit_amount || 0);
    if (Math.abs(postedAmount - Number(req.amount)) > TOLERANCE) {
      results.amountMismatch++;
      const caseResult = await createCaseAndMaybeAlert({
        caseType: "FEECENT_CREDIT_AMOUNT_MISMATCH",
        severity: severityForDifference(postedAmount - Number(req.amount)),
        ownerId: req.customer_id,
        externalReference: req.reference,
        expectedAmount: req.amount,
        actualAmount: postedAmount,
        detectedBy: "SYSTEM",
      });
      results.casesCreated.push(caseResult.case_number);
      continue;
    }

    results.matched++;
  }

  return results;
}

// ------------------------------------------------------------
// D. TRIAL BALANCE — the system-wide invariant. If this is ever
// non-zero, something bypassed post_journal_entry() entirely (direct
// insert into gl_journal_lines is blocked by the immutability
// trigger for UPDATE/DELETE but NOT for INSERT — this check exists
// specifically to catch a hypothetical future bug/bypass of that
// kind, since the per-entry balance check inside post_journal_entry()
// can only ever prevent an unbalanced entry from THAT function, not
// from some other future code path that INSERTs into gl_journal_lines
// directly).
// ------------------------------------------------------------
async function reconcileTrialBalance() {
  const { data, error } = await supabase.rpc("get_trial_balance_check");
  if (error) throw error;

  const difference = Math.round((Number(data.total_debits) - Number(data.total_credits)) * 100) / 100;
  if (Math.abs(difference) <= TOLERANCE) {
    return { balanced: true, totalDebits: data.total_debits, totalCredits: data.total_credits };
  }

  const caseResult = await createCaseAndMaybeAlert({
    caseType: "SYSTEM_WIDE_LEDGER_IMBALANCE",
    severity: "CRITICAL",
    expectedAmount: data.total_debits,
    actualAmount: data.total_credits,
    detectedBy: "SYSTEM",
  });
  return { balanced: false, totalDebits: data.total_debits, totalCredits: data.total_credits, caseNumber: caseResult.case_number };
}

async function runFullReconciliationSweep() {
  return {
    accountBalances: await reconcileAccountBalances(),
    orderTransactions: await reconcileOrderTransactions(),
    fundingTransactions: await reconcileFundingTransactions(),
    feecentCredits: await reconcileFeecentCredits(),
    trialBalance: await reconcileTrialBalance(),
    ranAt: new Date().toISOString(),
  };
}

module.exports = {
  reconcileAccountBalances,
  reconcileOrderTransactions,
  reconcileFundingTransactions,
  reconcileFeecentCredits,
  reconcileTrialBalance,
  runFullReconciliationSweep,
};