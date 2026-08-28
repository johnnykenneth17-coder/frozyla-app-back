// frozyla-integration-service.js
//
// Business logic behind frozyla-integration-routes.js. The actual
// money movement now happens inside credit_wallet_from_feecent() (see
// 003_credit_wallet_from_feecent_function.sql) — this file just
// resolves the customer, calls that one atomic function, and maps its
// result onto the { status, reference, message } shape the routes
// layer expects. No separate "insert the request row" step here
// anymore: the Postgres function does that AND the idempotency check
// AND the ledger write in one transaction, which closes the race
// window a two-step JS-then-SQL approach would have had.

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);
const { sendFeecentWebhook } = require("./frozyla-webhook-sender");

// ------------------------------------------------------------
// customerId (e.g. "FRZ-102938") is matched against users.account_number.
// Confirmed from introspection: users has no dedicated
// "frozyla_customer_id"-style column — account_number is the closest
// fit (same convention FEECENT itself uses on its own accounts table).
// Not 100% confirmed the VALUES in that column actually look like
// "FRZ-102938" — spot-check a real user's account_number before
// relying on this in production; if the format doesn't match, tell me
// and I'll adjust this one query.
// ------------------------------------------------------------
async function findCustomerForVerification(customerId) {
  const { data, error } = await supabase
    .from("users")
    .select("id, name, account_number")
    .eq("account_number", customerId)
    .maybeSingle();

  if (error) {
    console.error("[FROZYLA-INTEGRATION] Customer lookup failed:", error);
    throw error;
  }
  if (!data) return null;

  return { id: data.id, displayId: data.account_number || data.id, name: data.name };
}

// ------------------------------------------------------------
// Idempotent credit. Returns one of:
//   { status: "success", reference, message: null }
//   { status: "pending",  reference, message: null }
//   { status: "failed", reference, permanent: true,  message } <- don't retry
//   { status: "failed", reference, permanent: false, message } <- transient, FEECENT will retry
// ------------------------------------------------------------
async function creditCustomerWallet({ reference, idempotencyKey, customerId, amount, rawRequest }) {
  // Resolve the external Frozyla ID to an internal user_id BEFORE
  // calling the RPC — the RPC checks existence by internal id, not by
  // whatever format FEECENT sends as customerId.
  const customer = await findCustomerForVerification(customerId);
  if (!customer) {
    return { status: "failed", reference, permanent: true, message: "Unknown customer" };
  }

  const { data: result, error } = await supabase.rpc("credit_wallet_from_feecent", {
    p_reference: reference,
    p_idempotency_key: idempotencyKey,
    p_customer_id: customer.id,
    p_amount: amount,
    p_currency: "NGN",
    p_raw_request: rawRequest,
  });

  if (error) {
    console.error("[FROZYLA-INTEGRATION] credit_wallet_from_feecent RPC failed:", error);
    // DB-level failure — genuinely uncertain whether anything was
    // written (function may have partially executed before erroring,
    // though the transaction wrapper means it shouldn't have
    // committed). Treat as transient/retryable, never permanent.
    return { status: "failed", reference, permanent: false, message: "Internal error" };
  }

  switch (result.status) {
    case "credited":
      sendFeecentWebhook({ reference: result.reference, status: "success", amount }).catch(() => {});
      return { status: "success", reference: result.reference, message: null };
    case "pending":
      // Idempotency hit on a request still mid-flight from a previous
      // attempt (crash between insert and the return in a prior call,
      // or a genuine concurrent duplicate) — tell FEECENT to check back.
      // No webhook here — nothing has actually resolved yet to report.
      return { status: "pending", reference: result.reference, message: null };
    case "duplicate": // legacy shape guard, RPC currently never returns this literal — kept for forward-compat
    case "credited_previously":
      return { status: "success", reference: result.reference, message: null };
    case "failed":
      sendFeecentWebhook({
        reference: result.reference,
        status: "failed",
        amount,
        message: result.reason,
      }).catch(() => {});
      return {
        status: "failed",
        reference: result.reference,
        permanent: ["INVALID_AMOUNT", "UNSUPPORTED_CURRENCY", "CUSTOMER_NOT_FOUND"].includes(result.reason),
        message: result.reason,
      };
    default:
      console.error("[FROZYLA-INTEGRATION] Unrecognized RPC result:", result);
      return { status: "failed", reference, permanent: false, message: "Internal error" };
  }
}

async function getFundingRequestStatus(reference) {
  const { data, error } = await supabase
    .from("feecent_funding_requests")
    .select("reference, status, failure_reason")
    .eq("reference", reference)
    .maybeSingle();

  if (error) {
    console.error("[FROZYLA-INTEGRATION] Status lookup failed:", error);
    throw error;
  }
  return data || null;
}

module.exports = {
  findCustomerForVerification,
  creditCustomerWallet,
  getFundingRequestStatus,
};