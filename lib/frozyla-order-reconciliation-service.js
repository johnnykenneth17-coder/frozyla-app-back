// frozyla-order-reconciliation-service.js
//
// Internal consistency sweep (spec section 37) — this is DIFFERENT
// from the FEECENT<->Frozyla reconciliation sweep (which compares two
// SEPARATE systems' records of the same external transaction). This
// one checks Frozyla's own tables against each other: did every paid
// order actually get a ledger entry, does every ledger entry trace
// back to a real order, etc. Same principle as that sweep though:
// flag, never auto-correct — a human decides what a real mismatch
// means, this only surfaces it.
//
// Deliberately NOT checking user.balance vs account_balances.balance
// divergence — that's already handled automatically by the existing
// create_reconciliation_entry() trigger, which flags it into
// ledger_reconciliation on every ledger_line_items insert. Duplicating
// that check here would just be a second, redundant system watching
// the same thing.

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

async function flagOrder(orderId, notes) {
  await supabase
    .from("orders")
    .update({ reconciliation_status: "mismatch", reconciliation_notes: notes })
    .eq("id", orderId)
    .eq("reconciliation_status", "none"); // don't overwrite an existing flag/resolution
}

// ------------------------------------------------------------
// Check 1: a successfully-paid order with no matching debit in
// wallet_transactions. Should be structurally impossible given
// create_and_pay_order() writes both atomically — this check exists
// for defense-in-depth (manual DB edits, pre-Phase-1 data, bugs) not
// because the normal path can produce it.
// ------------------------------------------------------------
async function checkPaidOrdersWithoutWalletTransaction({ sinceHours = 72 } = {}) {
  const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000).toISOString();

  const { data: orders, error } = await supabase
    .from("orders")
    .select("id, total, created_at")
    .eq("payment_status", "SUCCESS")
    .eq("reconciliation_status", "none")
    .gte("created_at", since);
  if (error) throw error;

  let flagged = 0;
  for (const order of orders || []) {
    const { data: txns, error: txErr } = await supabase
      .from("wallet_transactions")
      .select("id")
      .eq("order_id", order.id)
      .eq("category", "order")
      .eq("transaction_type", "debit");
    if (txErr) throw txErr;

    if (!txns || txns.length === 0) {
      await flagOrder(order.id, `payment_status=SUCCESS but no matching order-debit wallet_transactions row found.`);
      flagged++;
    } else if (txns.length > 1) {
      await flagOrder(order.id, `${txns.length} order-debit wallet_transactions rows found for this order — possible duplicate charge.`);
      flagged++;
    }
  }
  return { checked: (orders || []).length, flagged };
}

// ------------------------------------------------------------
// Check 2: an order-category wallet_transaction with no matching
// ledger_entries row (reference_type='order'). Catches a case where
// the wallet moved money but the ledger write somehow didn't happen —
// exactly the "wallet debit without ledger" case spec section 37
// calls out.
// ------------------------------------------------------------
async function checkWalletTransactionsWithoutLedger({ sinceHours = 72 } = {}) {
  const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000).toISOString();

  const { data: txns, error } = await supabase
    .from("wallet_transactions")
    .select("id, order_id, category")
    .in("category", ["order", "refund"])
    .gte("created_at", since);
  if (error) throw error;

  let flagged = 0;
  for (const txn of txns || []) {
    if (!txn.order_id) continue;

    const { data: entries, error: entryErr } = await supabase
      .from("ledger_entries")
      .select("id")
      .eq("reference_type", txn.category)
      .eq("reference_id", txn.order_id);
    if (entryErr) throw entryErr;

    if (!entries || entries.length === 0) {
      const { data: order } = await supabase
        .from("orders")
        .select("reconciliation_status")
        .eq("id", txn.order_id)
        .maybeSingle();
      if (order && order.reconciliation_status === "none") {
        await flagOrder(
          txn.order_id,
          `wallet_transactions row (${txn.category}, id ${txn.id}) exists with no matching ledger_entries row.`,
        );
        flagged++;
      }
    }
  }
  return { checked: (txns || []).length, flagged };
}

// ------------------------------------------------------------
// Check 3: an order marked REFUNDED with no refund-category
// wallet_transaction/ledger entry — refund_order() should always
// write both together, so this is another defense-in-depth check.
// ------------------------------------------------------------
async function checkRefundedOrdersWithoutRefundRecord({ sinceHours = 72 } = {}) {
  const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000).toISOString();

  const { data: orders, error } = await supabase
    .from("orders")
    .select("id")
    .eq("payment_status", "REFUNDED")
    .eq("reconciliation_status", "none")
    .gte("updated_at", since);
  if (error) throw error;

  let flagged = 0;
  for (const order of orders || []) {
    const { data: txns, error: txErr } = await supabase
      .from("wallet_transactions")
      .select("id")
      .eq("order_id", order.id)
      .eq("category", "refund");
    if (txErr) throw txErr;

    if (!txns || txns.length === 0) {
      await flagOrder(order.id, `payment_status=REFUNDED but no refund-category wallet_transactions row found.`);
      flagged++;
    } else if (txns.length > 1) {
      await flagOrder(order.id, `${txns.length} refund wallet_transactions rows found — possible duplicate refund.`);
      flagged++;
    }
  }
  return { checked: (orders || []).length, flagged };
}

// ------------------------------------------------------------
// Check 4: orphaned wallet_transactions — an order/refund category
// row pointing at an order_id that doesn't exist at all. Given the
// FK constraint on wallet_transactions.order_id, this should be
// impossible under normal operation; checked anyway since a
// reconciliation engine's job is to not assume its own invariants hold.
// ------------------------------------------------------------
async function checkOrphanedWalletTransactions({ sinceHours = 72 } = {}) {
  const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000).toISOString();

  const { data: txns, error } = await supabase
    .from("wallet_transactions")
    .select("id, order_id, category")
    .in("category", ["order", "refund"])
    .not("order_id", "is", null)
    .gte("created_at", since);
  if (error) throw error;

  let flagged = 0;
  for (const txn of txns || []) {
    const { data: order, error: orderErr } = await supabase
      .from("orders")
      .select("id")
      .eq("id", txn.order_id)
      .maybeSingle();
    if (orderErr) throw orderErr;

    if (!order) {
      // Nothing to flag ON the order (it doesn't exist) — this goes to
      // reconciliation_alerts instead, same table FEECENT's own
      // webhook handler uses for orphaned events, for the same reason:
      // there's no order row to attach a flag to.
      await supabase.from("reconciliation_alerts").insert({
        user_id: null,
        operational_balance: 0,
        ledger_balance: 0,
        difference: 0,
        status: "open",
        severity: "high",
        notes: `Orphaned wallet_transactions row (id ${txn.id}, category ${txn.category}) references order_id ${txn.order_id}, which does not exist in orders.`,
      });
      flagged++;
    }
  }
  return { checked: (txns || []).length, flagged };
}

async function runOrderReconciliationSweep({ sinceHours = 72 } = {}) {
  const results = {
    paidWithoutWalletTx: await checkPaidOrdersWithoutWalletTransaction({ sinceHours }),
    walletTxWithoutLedger: await checkWalletTransactionsWithoutLedger({ sinceHours }),
    refundedWithoutRefundRecord: await checkRefundedOrdersWithoutRefundRecord({ sinceHours }),
    orphanedWalletTx: await checkOrphanedWalletTransactions({ sinceHours }),
  };
  results.totalFlagged = Object.values(results).reduce((sum, r) => sum + (r.flagged || 0), 0);
  return results;
}

module.exports = { runOrderReconciliationSweep };