// ledger-service.js (Frozyla side) — Phase 1
//
// The ONLY module business services should call to touch the new
// general ledger (gl_* tables). No route/controller should ever
// insert into gl_journal_entries/gl_journal_lines/gl_transactions
// directly — everything goes through here, which itself does nothing
// but call the SQL functions in 022_gl_ledger_phase1_core.sql /
// 023_gl_ledger_phase1_reconciliation.sql. All the actual invariant
// enforcement (balance, immutability, concurrency, maker-checker)
// lives in those SQL functions, on purpose — this file is a thin,
// typed-ish wrapper, not a second place those rules could drift out
// of sync with the database.
//
// NOT wired into any existing route yet — see
// LEDGER_ARCHITECTURE_AND_MIGRATION_PLAN.md's Phase 2 for the cutover
// of create_and_pay_order/credit_wallet_from_feecent/the funding
// routes onto this.

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const glTransactionStateMachine = require("./gl-transaction-state-machine");

// ============================================================
// JOURNAL POSTING
// ============================================================

/**
 * Post a balanced double-entry journal. Idempotent on idempotencyKey.
 * @param {Object} params
 * @param {string} params.idempotencyKey
 * @param {string} params.description
 * @param {string} params.sourceSystem - 'frozyla' | 'feecent' | 'admin' | 'migration'
 * @param {string} [params.sourceReference]
 * @param {Array<{accountCode: string, ownerId?: string|null, debit?: number, credit?: number, description?: string}>} params.lines
 * @param {string} [params.currency]
 * @param {string} [params.createdBy]
 * @param {Object} [params.metadata]
 */
async function postJournal({
  idempotencyKey,
  description,
  sourceSystem,
  sourceReference = null,
  lines,
  currency = "NGN",
  createdBy = "system",
  metadata = {},
}) {
  if (!idempotencyKey) throw Object.assign(new Error("idempotencyKey is required"), { code: "MISSING_IDEMPOTENCY_KEY" });
  if (!Array.isArray(lines) || lines.length < 2) {
    throw Object.assign(new Error("A journal needs at least two lines"), { code: "INVALID_LINES" });
  }

  const { data, error } = await supabase.rpc("post_journal_entry", {
    p_idempotency_key: idempotencyKey,
    p_description: description,
    p_source_system: sourceSystem,
    p_source_reference: sourceReference,
    p_lines: lines.map((l) => ({
      account_code: l.accountCode,
      owner_id: l.ownerId || null,
      debit: l.debit || 0,
      credit: l.credit || 0,
      description: l.description || description,
    })),
    p_currency: currency,
    p_created_by: createdBy,
    p_metadata: metadata,
  });

  if (error) throw error;
  if (!data.success) {
    const err = new Error(data.code === "UNBALANCED_JOURNAL"
      ? `Unbalanced journal: debits ${data.total_debits} != credits ${data.total_credits}`
      : `Journal posting rejected: ${data.code}`);
    err.code = data.code;
    throw err;
  }
  return data; // { success, duplicate, journal_entry_id, journal_reference, ... }
}

async function reverseJournal({ originalEntryId, reason, createdBy, idempotencyKey }) {
  const { data, error } = await supabase.rpc("reverse_journal_entry", {
    p_original_entry_id: originalEntryId,
    p_reason: reason,
    p_created_by: createdBy,
    p_idempotency_key: idempotencyKey || null,
  });
  if (error) throw error;
  return data;
}

async function getReversalStatus(journalEntryId) {
  const { data, error } = await supabase.rpc("get_journal_entry_reversal_status", { p_entry_id: journalEntryId });
  if (error) throw error;
  return data;
}

// ============================================================
// ACCOUNT BALANCES (read-only from here — never written directly)
// ============================================================

async function getAccountBalance({ accountCode, ownerId = null }) {
  const { data: account, error: accountError } = await supabase
    .from("gl_accounts")
    .select("id")
    .eq("account_code", accountCode)
    .single();
  if (accountError || !account) throw new Error(`Unknown account_code: ${accountCode}`);

  const { data, error } = await supabase
    .from("gl_account_balances_v")
    .select("*")
    .eq("account_id", account.id)
    .eq("owner_key", ownerId || "00000000-0000-0000-0000-000000000000")
    .maybeSingle();
  if (error) throw error;

  return data || {
    ledger_balance: 0,
    pending_debit: 0,
    pending_credit: 0,
    available_balance: 0,
    total_debits: 0,
    total_credits: 0,
  };
}

// Independently recomputes a balance straight from journal lines,
// bypassing the incremental cache entirely — this is the "prove the
// answer" primitive from the spec's closing principle. Two numbers
// (this, and getAccountBalance()'s cached value) that should always
// agree; a mismatch between them is itself something Phase 2's
// reconciliation engine checks for.
async function rebuildAccountBalance({ accountCode, ownerId = null }) {
  const { data: account, error: accountError } = await supabase
    .from("gl_accounts")
    .select("id")
    .eq("account_code", accountCode)
    .single();
  if (accountError || !account) throw new Error(`Unknown account_code: ${accountCode}`);

  const { data, error } = await supabase.rpc("rebuild_gl_account_balance", {
    p_account_id: account.id,
    p_owner_id: ownerId,
  });
  if (error) throw error;
  return data;
}

// ============================================================
// TRANSACTIONS (business-level lifecycle)
// ============================================================

async function createTransaction({
  transactionReference,
  transactionType,
  amount,
  currency = "NGN",
  idempotencyKey,
  sourceSystem,
  sourceReference = null,
  ownerId = null,
  ownerType = null,
  metadata = {},
}) {
  const { data: existing, error: lookupErr } = await supabase
    .from("gl_transactions")
    .select("*")
    .eq("idempotency_key", idempotencyKey)
    .maybeSingle();
  if (lookupErr) throw lookupErr;
  if (existing) return existing;

  const { data, error } = await supabase
    .from("gl_transactions")
    .insert({
      transaction_reference: transactionReference,
      transaction_type: transactionType,
      amount,
      currency,
      idempotency_key: idempotencyKey,
      source_system: sourceSystem,
      source_reference: sourceReference,
      owner_id: ownerId,
      owner_type: ownerType,
      metadata,
    })
    .select()
    .single();
  if (error) {
    if (error.code === "23505") {
      const { data: raced } = await supabase.from("gl_transactions").select("*").eq("idempotency_key", idempotencyKey).maybeSingle();
      if (raced) return raced;
    }
    throw error;
  }
  return data;
}

async function transitionTransaction({ id, fromStatuses, toStatus, journalEntryId = null, failureReason = null }) {
  for (const from of fromStatuses) {
    glTransactionStateMachine.assertTransition(from, toStatus);
  }
  const { data, error } = await supabase.rpc("transition_gl_transaction_status", {
    p_id: id,
    p_from_statuses: fromStatuses,
    p_to_status: toStatus,
    p_journal_entry_id: journalEntryId,
    p_failure_reason: failureReason,
  });
  if (error) throw error;
  return data;
}

// ============================================================
// RECONCILIATION CASES (detection only — see Rule 4)
// ============================================================

/**
 * The ONLY function anywhere in this codebase that should create a
 * reconciliation case. Does exactly one thing: records a discrepancy.
 * Never touches users, gl_accounts, gl_transactions, or anything
 * else — no freezing, no reversing, no crediting/debiting. Phase 2's
 * reconciliation engine is the (only) intended caller today; Phase 3
 * admin actions read cases, they don't create them this way.
 */
async function createInvestigationCase({
  caseType,
  severity,
  accountCode = null,
  ownerId = null,
  transactionId = null,
  journalEntryId = null,
  externalReference = null,
  expectedAmount = null,
  actualAmount = null,
  currency = "NGN",
  detectedBy = "SYSTEM",
}) {
  let accountId = null;
  if (accountCode) {
    const { data: account } = await supabase.from("gl_accounts").select("id").eq("account_code", accountCode).maybeSingle();
    accountId = account?.id || null;
  }

  const { data, error } = await supabase.rpc("create_reconciliation_case", {
    p_case_type: caseType,
    p_severity: severity,
    p_account_id: accountId,
    p_owner_id: ownerId,
    p_transaction_id: transactionId,
    p_journal_entry_id: journalEntryId,
    p_external_reference: externalReference,
    p_expected_amount: expectedAmount,
    p_actual_amount: actualAmount,
    p_currency: currency,
    p_detected_by: detectedBy,
  });
  if (error) throw error;
  return data;
}

async function addInvestigationEvent({ caseId, eventType, actorId, actorRole, content, metadata = {} }) {
  const { data, error } = await supabase
    .from("investigation_events")
    .insert({ case_id: caseId, event_type: eventType, actor_id: actorId, actor_role: actorRole, content, metadata })
    .select()
    .single();
  if (error) throw error;
  return data;
}

// Case status/assignment/root-cause updates are plain UPDATEs on
// reconciliation_cases (that table isn't append-only — its whole
// point is to track evolving investigation state) but MUST be
// accompanied by an investigation_events row recording who changed
// what and why, so the append-only trail still exists even though the
// case row itself is mutable. Enforced here by doing both in one call
// rather than leaving it to every caller to remember.
async function updateCaseStatus({ caseId, newStatus, actorId, actorRole, reason }) {
  const { data: current, error: fetchErr } = await supabase
    .from("reconciliation_cases")
    .select("status")
    .eq("id", caseId)
    .single();
  if (fetchErr) throw fetchErr;

  const { error } = await supabase
    .from("reconciliation_cases")
    .update({ status: newStatus })
    .eq("id", caseId);
  if (error) throw error;

  await addInvestigationEvent({
    caseId,
    eventType: "status_change",
    actorId,
    actorRole,
    content: `${current.status} -> ${newStatus}: ${reason || ""}`,
    metadata: { from: current.status, to: newStatus },
  });

  await writeAuditLog({
    actorId, actorRole, action: "reconciliation_case_status_change",
    entityType: "reconciliation_case", entityId: caseId,
    oldState: { status: current.status }, newState: { status: newStatus }, reason,
  });
}

// ============================================================
// AMENDMENTS (maker-checker)
// ============================================================

async function requestAmendment({ caseId = null, originalJournalEntryId, amendmentType, amount, currency = "NGN", reason, requestedBy }) {
  const requestNumber = `AMD-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
  const { data, error } = await supabase
    .from("amendment_requests")
    .insert({
      request_number: requestNumber,
      case_id: caseId,
      original_journal_entry_id: originalJournalEntryId,
      amendment_type: amendmentType,
      amount,
      currency,
      reason,
      requested_by: requestedBy,
    })
    .select()
    .single();
  if (error) throw error;

  await writeAuditLog({
    actorId: requestedBy, actorRole: "ADMIN", action: "amendment_requested",
    entityType: "amendment_request", entityId: data.id, reason,
    newState: { amendment_type: amendmentType, amount, original_journal_entry_id: originalJournalEntryId },
  });

  return data;
}

// Enforces maker != checker at this layer too (defense in depth —
// the database trigger is the real guarantee, see
// gl_enforce_maker_checker() in the SQL migration).
async function approveAmendment({ amendmentRequestId, approvedBy, decision, comments }) {
  const { data: amendment, error: fetchErr } = await supabase
    .from("amendment_requests")
    .select("requested_by, status")
    .eq("id", amendmentRequestId)
    .single();
  if (fetchErr) throw fetchErr;
  if (amendment.requested_by === approvedBy) {
    throw Object.assign(new Error("The requester of an amendment cannot also approve it"), { code: "SELF_APPROVAL_REJECTED" });
  }
  if (amendment.status !== "PENDING") {
    throw Object.assign(new Error(`Amendment is already ${amendment.status}`), { code: "NOT_PENDING" });
  }

  const { error: approvalErr } = await supabase
    .from("amendment_approvals")
    .insert({ amendment_request_id: amendmentRequestId, approved_by: approvedBy, decision, comments });
  if (approvalErr) throw approvalErr;

  const { error: updateErr } = await supabase
    .from("amendment_requests")
    .update({ status: decision === "APPROVED" ? "APPROVED" : "REJECTED" })
    .eq("id", amendmentRequestId);
  if (updateErr) throw updateErr;

  await writeAuditLog({
    actorId: approvedBy, actorRole: "ADMIN", action: `amendment_${decision.toLowerCase()}`,
    entityType: "amendment_request", entityId: amendmentRequestId, reason: comments,
  });

  if (decision === "APPROVED") {
    return postAmendment({ amendmentRequestId });
  }
  return { status: "REJECTED" };
}

async function postAmendment({ amendmentRequestId, correctionLines = null }) {
  const { data, error } = await supabase.rpc("post_amendment_correction", {
    p_amendment_request_id: amendmentRequestId,
    p_correction_lines: correctionLines,
  });
  if (error) throw error;
  return data;
}

// ============================================================
// AUDIT LOG
// ============================================================

async function writeAuditLog({ actorId, actorRole, action, entityType, entityId, caseId = null, oldState = null, newState = null, reason = null, requestId = null, ipAddress = null, metadata = {} }) {
  const { error } = await supabase.from("audit_logs").insert({
    actor_id: String(actorId),
    actor_role: actorRole,
    action,
    entity_type: entityType,
    entity_id: entityId ? String(entityId) : null,
    case_id: caseId,
    old_state: oldState,
    new_state: newState,
    reason,
    request_id: requestId,
    ip_address: ipAddress,
    metadata,
  });
  if (error) console.error("[LEDGER-SERVICE] audit log write failed:", error);
}

module.exports = {
  postJournal,
  reverseJournal,
  getReversalStatus,
  getAccountBalance,
  rebuildAccountBalance,
  createTransaction,
  transitionTransaction,
  createInvestigationCase,
  addInvestigationEvent,
  updateCaseStatus,
  requestAmendment,
  approveAmendment,
  postAmendment,
  writeAuditLog,
};