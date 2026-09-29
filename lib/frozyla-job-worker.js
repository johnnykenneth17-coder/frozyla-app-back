// frozyla-job-worker.js
//
// Invoked from an external cron hitting frozyla-cron-routes.js (this
// app has no persistent process — `module.exports = app` with no
// app.listen(), same serverless deployment shape as FEECENT — so
// there's no in-process setInterval loop to run this from; a cron
// service calling the route periodically is the only option, exactly
// FEECENT's own documented pattern).
//
// One invocation does ONE bounded batch of work — dispatch pending
// outbox events into jobs, then process a batch of claimable jobs —
// and returns. It does not loop indefinitely; the cron's own interval
// is the loop.

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Attempt 1 -> 30s, 2 -> 2min, 3 -> 10min, 4 -> 30min, 5th failure -> dead_letter
// (spec's own example schedule). Jitter (±20%) avoids every job that
// failed in the same batch retrying at the exact same instant.
const BACKOFF_SCHEDULE_SECONDS = [30, 120, 600, 1800];

function nextRetryDelaySeconds(attemptCount) {
  const base = BACKOFF_SCHEDULE_SECONDS[Math.min(attemptCount - 1, BACKOFF_SCHEDULE_SECONDS.length - 1)];
  const jitter = base * 0.2 * (Math.random() * 2 - 1); // ±20%
  return Math.max(5, Math.round(base + jitter));
}

// ------------------------------------------------------------
// Job handlers. Each returns normally on success, or throws.
// Throwing an error with `.permanent = true` sends the job straight
// to dead_letter without consuming retry attempts on something that
// can never succeed (e.g. "this integration doesn't exist yet") —
// distinct from a genuine transient failure, which retries normally.
//
// send_push_notification is the only one with a REAL implementation
// today — it's backed by the payment_notifications table, which
// already existed and was previously written synchronously,
// fire-and-forget, inside the order route itself (see
// PHASE1_ORDER_PATCH.md). Moving it here makes it properly retryable
// instead of "insert and hope."
//
// The other three are honest stubs — matching the same philosophy
// FEECENT's payment-provider.js already uses (NotImplementedError,
// loud and immediate, never fake success). No email provider, SMS
// provider, restaurant integration, or delivery/driver system exists
// anywhere in the codebase reviewed so far — building fake versions
// of those would be worse than admitting they're not built. These
// jobs will visibly sit in dead_letter (Phase 5-equivalent admin view
// still to come) until real integrations exist, at which point only
// this one function per job type needs to change — the queue,
// retry, and dead-letter machinery around it doesn't.
// ------------------------------------------------------------

class PermanentJobError extends Error {
  constructor(message) {
    super(message);
    this.permanent = true;
  }
}

const STATUS_MESSAGES = {
  CONFIRMED: "Your order has been confirmed and the restaurant is getting started.",
  PREPARING: "Your order is being prepared.",
  READY_FOR_PICKUP: "Your order is ready for pickup!",
  READY_FOR_DELIVERY: "Your order is ready and will be out for delivery shortly.",
  OUT_FOR_DELIVERY: "Your order is out for delivery.",
  DELIVERED: "Your order has been delivered. Enjoy!",
  CANCELLATION_PENDING: "Your cancellation request is being processed.",
  CANCELLED: "Your order has been cancelled.",
  REFUND_PENDING: "Your refund is being processed.",
  REFUNDED: "Your refund has been completed.",
  FULFILLMENT_FAILED: "There was a problem fulfilling your order — our team is looking into it.",
};

const JOB_HANDLERS = {
  async send_push_notification(payload) {
    const { error } = await supabase.from("payment_notifications").insert([
      {
        user_id: payload.user_id,
        type: "payment_success",
        title: "Order Placed Successfully 🎉",
        message: `Your order #${payload.order_id} has been placed. ₦${Number(payload.total).toFixed(2)} has been deducted from your wallet.`,
        reference: payload.order_id,
        created_at: new Date().toISOString(),
      },
    ]);
    if (error) throw error; // transient DB error — retry normally
  },

  // Fan-out target for ORDER_STATUS_CHANGED.
  async send_status_update_notification(payload) {
    const message = STATUS_MESSAGES[payload.to_status];
    if (!message) return; // no customer-facing message for this status — nothing to send, not an error

    const { data: order, error: orderErr } = await supabase
      .from("orders")
      .select("id, user_id")
      .eq("id", payload.order_id)
      .maybeSingle();
    if (orderErr) throw orderErr;
    if (!order) return; // order gone — nothing to notify about

    const { error } = await supabase.from("payment_notifications").insert([
      {
        user_id: order.user_id,
        type: "order_status",
        title: "Order Update",
        message,
        reference: order.id,
        created_at: new Date().toISOString(),
      },
    ]);
    if (error) throw error;
  },

  async send_order_confirmation_email(_payload) {
    throw new PermanentJobError(
      "No email provider is configured for Frozyla yet — this job type has no real implementation. " +
        "Wire in a real email service here, then remove this PermanentJobError.",
    );
  },

  async notify_restaurant(_payload) {
    throw new PermanentJobError(
      "No restaurant/kitchen notification system exists yet — this job type has no real implementation.",
    );
  },

  async create_delivery_workflow(_payload) {
    throw new PermanentJobError(
      "No delivery/driver system exists yet — this job type has no real implementation.",
    );
  },
};

// ------------------------------------------------------------
// Step 1: fan pending outbox events into background_jobs rows.
// ------------------------------------------------------------
async function dispatchOutboxEvents({ limit = 20 } = {}) {
  const { data, error } = await supabase.rpc("dispatch_pending_outbox_events", { p_limit: limit });
  if (error) throw error;
  return data || [];
}

// ------------------------------------------------------------
// Step 2: claim and process a batch of due jobs.
// ------------------------------------------------------------
async function processJobs({ limit = 20 } = {}) {
  const { data: jobs, error } = await supabase.rpc("claim_next_jobs", { p_limit: limit });
  if (error) throw error;

  const results = { processed: 0, completed: 0, retrying: 0, deadLettered: 0 };

  for (const job of jobs || []) {
    results.processed++;
    const handler = JOB_HANDLERS[job.job_type];

    if (!handler) {
      // Unknown job_type — shouldn't happen (fan-out table in 007 only
      // ever creates known types), but fail safe: dead-letter rather
      // than leave it stuck in 'processing' forever.
      await supabase
        .from("background_jobs")
        .update({ status: "dead_letter", last_error: `Unknown job_type: ${job.job_type}`, updated_at: new Date().toISOString() })
        .eq("id", job.id);
      results.deadLettered++;
      continue;
    }

    try {
      await handler(job.payload);
      await supabase
        .from("background_jobs")
        .update({ status: "completed", completed_at: new Date().toISOString(), updated_at: new Date().toISOString() })
        .eq("id", job.id);
      results.completed++;
    } catch (err) {
      const attemptCount = job.attempt_count + 1;
      const isPermanent = err.permanent === true;
      const exhausted = attemptCount >= job.max_attempts;

      if (isPermanent || exhausted) {
        await supabase
          .from("background_jobs")
          .update({
            status: "dead_letter",
            attempt_count: attemptCount,
            last_error: err.message,
            updated_at: new Date().toISOString(),
          })
          .eq("id", job.id);
        results.deadLettered++;
      } else {
        const delaySeconds = nextRetryDelaySeconds(attemptCount);
        await supabase
          .from("background_jobs")
          .update({
            status: "retrying",
            attempt_count: attemptCount,
            next_retry_at: new Date(Date.now() + delaySeconds * 1000).toISOString(),
            last_error: err.message,
            updated_at: new Date().toISOString(),
          })
          .eq("id", job.id);
        results.retrying++;
      }
    }
  }

  return results;
}

async function runWorkerBatch() {
  const dispatched = await dispatchOutboxEvents();
  const jobResults = await processJobs();
  return { dispatched, jobResults };
}

module.exports = { runWorkerBatch, dispatchOutboxEvents, processJobs, JOB_HANDLERS };