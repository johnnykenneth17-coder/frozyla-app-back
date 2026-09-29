// push-sender.js (Frozyla side)
//
// No APNs/FCM credentials exist anywhere in this codebase — this is
// an honest stub, matching frozyla-job-worker.js's own established
// pattern for other unbuilt integrations (email, restaurant
// notifications). It throws loudly rather than pretending delivery
// succeeded. Wire in a real push provider (FCM for both platforms via
// a unified send, or APNs+FCM separately) here, then this file's
// callers (below) need no changes.
//
// Once real sending exists, these are the events this project's own
// rider work needs it for — added as new job types on the SAME
// background_jobs queue frozyla-job-worker.js already processes, not
// a second queue:
//   - rider_run_assigned: "New delivery assigned" (spec section 23)
//   - rider_order_added: "Order #X added to your delivery run"
//   - rider_order_removed: "Your assignment for order #X was cancelled"
//   - rider_run_updated: generic "Admin updated your delivery"

class PushNotConfiguredError extends Error {
  constructor(message) {
    super(message);
    this.name = "PushNotConfiguredError";
    this.permanent = true; // same convention as frozyla-job-worker.js's PermanentJobError — dead-letters instead of retrying forever
  }
}

async function sendPushToUser(_userId, _title, _body, _data) {
  throw new PushNotConfiguredError(
    "No push notification provider (FCM/APNs) is configured yet — this is an honest stub, not a real send. " +
      "Wire in a real provider here, then remove this error.",
  );
}

// ------------------------------------------------------------
// New background_jobs handlers — add these to
// frozyla-job-worker.js's JOB_HANDLERS map (that file's own
// dispatch/retry/dead-letter machinery is reused unchanged; only
// these four handler functions are new).
// ------------------------------------------------------------
const RIDER_JOB_HANDLERS = {
  async rider_run_assigned(payload) {
    await sendPushToUser(payload.rider_id, "New delivery assigned", `Delivery run ${payload.run_number} — ${payload.order_count} order(s).`, { runId: payload.delivery_run_id });
  },
  async rider_order_added(payload) {
    await sendPushToUser(payload.rider_id, "Order added to your run", `Order #${payload.order_id} has been added to your delivery run.`, { orderId: payload.order_id });
  },
  async rider_order_removed(payload) {
    await sendPushToUser(payload.rider_id, "Delivery assignment cancelled", `Your assignment for order #${payload.order_id} has been cancelled.${payload.reason ? " Reason: " + payload.reason : ""}`, { orderId: payload.order_id });
  },
  async rider_run_updated(payload) {
    await sendPushToUser(payload.rider_id, "Delivery updated", payload.message || "Admin updated your delivery.", { runId: payload.delivery_run_id });
  },
};

module.exports = { sendPushToUser, RIDER_JOB_HANDLERS, PushNotConfiguredError };