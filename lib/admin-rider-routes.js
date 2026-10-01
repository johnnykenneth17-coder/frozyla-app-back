// admin-rider-routes.js (Frozyla side)
//
// Mount in server.js:
//   const adminRiderRouter = require("./lib/admin-rider-routes");
//   app.use("/api/admin/riders", authMiddleware, adminMiddleware, adminRiderRouter);
//
// This is the "existing Admin System is the source of truth" half of
// the spec (section 3) — every assignment decision happens here, the
// rider app only ever reads/acts on what this creates.

const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// ============================================================
// LIST RIDERS
// ============================================================
router.get("/", async (req, res) => {
  try {
    const { data: riders, error } = await supabase
      .from("users")
      .select("id, name, email, phone, rider_availability_status, status, account_status, created_at")
      .eq("role", "delivery")
      .order("name", { ascending: true });
    if (error) throw error;

    // Active run count per rider, in one query rather than N+1.
    const { data: activeRuns } = await supabase
      .from("delivery_runs")
      .select("rider_id")
      .in("status", ["PENDING", "ACTIVE"]);
    const activeCountByRider = (activeRuns || []).reduce((acc, r) => {
      acc[r.rider_id] = (acc[r.rider_id] || 0) + 1;
      return acc;
    }, {});

    res.json({
      success: true,
      data: riders.map((r) => ({ ...r, activeRunCount: activeCountByRider[r.id] || 0 })),
    });
  } catch (error) {
    console.error("[ADMIN-RIDERS] list error:", error);
    res.status(500).json({ success: false, message: "Failed to load riders" });
  }
});

// ============================================================
// ORDERS READY TO ASSIGN
// Orders marked ready that are not already in an active/pending run.
// (Must stay above any "/:id/..." routes.)
// ============================================================
router.get("/ready-orders", async (req, res) => {
  try {
    const { data: orders, error } = await supabase
      .from("orders")
      .select("id, status, total, delivery_address, created_at")
      .in("status", ["ready", "READY_FOR_DELIVERY", "READY_FOR_PICKUP"])
      .not("delivery_address", "is", null)
      .order("created_at", { ascending: true })
      .limit(200);
    if (error) throw error;

    // Exclude orders that already sit in a live run.
    const { data: liveRuns } = await supabase
      .from("delivery_runs")
      .select("id")
      .in("status", ["PENDING", "ACTIVE"]);
    const liveRunIds = (liveRuns || []).map((r) => r.id);

    let assigned = new Set();
    if (liveRunIds.length > 0) {
      const { data: runOrders } = await supabase
        .from("delivery_run_orders")
        .select("order_id")
        .in("delivery_run_id", liveRunIds)
        .is("removed_at", null);
      assigned = new Set((runOrders || []).map((r) => r.order_id));
    }

    res.json({ success: true, data: (orders || []).filter((o) => !assigned.has(o.id)) });
  } catch (error) {
    console.error("[ADMIN-RIDERS] ready-orders error:", error);
    res.status(500).json({ success: false, message: "Failed to load ready orders" });
  }
});

router.get("/:id/location", async (req, res) => {
  try {
    const { data, error } = await supabase.rpc("get_rider_current_location", { p_rider_id: req.params.id });
    if (error) throw error;
    res.json({ success: true, data: data?.[0] || null });
  } catch (error) {
    console.error("[ADMIN-RIDERS] location error:", error);
    res.status(500).json({ success: false, message: "Failed to load rider location" });
  }
});

// ============================================================
// ASSIGN A DELIVERY RUN
// ============================================================
router.post("/assign", async (req, res) => {
  try {
    const { riderId, orderIds } = req.body || {};
    if (!riderId || !Array.isArray(orderIds) || orderIds.length === 0) {
      return res.status(400).json({ success: false, message: "riderId and a non-empty orderIds array are required" });
    }

    const { data, error } = await supabase.rpc("assign_delivery_run", {
      p_rider_id: riderId, p_order_ids: orderIds, p_created_by: req.userId,
    });
    if (error) throw error;
    if (!data.success) {
      const statusByCode = { RIDER_NOT_FOUND: 404, NOT_A_RIDER: 400, NO_ORDERS_PROVIDED: 400, ORDER_NOT_FOUND: 404, ORDER_NOT_READY: 409, ORDER_ALREADY_ASSIGNED: 409 };
      return res.status(statusByCode[data.code] || 400).json({ success: false, code: data.code, orderId: data.order_id, message: data.current_status ? `Order is ${data.current_status}` : undefined });
    }
    res.json({ success: true, data });
  } catch (error) {
    console.error("[ADMIN-RIDERS] assign error:", error);
    res.status(500).json({ success: false, message: "Failed to assign delivery run" });
  }
});

router.post("/runs/:id/add-order", async (req, res) => {
  try {
    const { orderId, sequenceNumber } = req.body || {};
    const { data, error } = await supabase.rpc("add_order_to_run", {
      p_delivery_run_id: req.params.id, p_order_id: orderId, p_sequence_number: sequenceNumber || null,
    });
    if (error) throw error;
    if (!data.success) return res.status(400).json({ success: false, code: data.code });
    res.json({ success: true });
  } catch (error) {
    console.error("[ADMIN-RIDERS] add-order error:", error);
    res.status(500).json({ success: false, message: "Failed to add order to run" });
  }
});

router.post("/runs/:id/remove-order", async (req, res) => {
  try {
    const { orderId, reason } = req.body || {};
    if (!reason) return res.status(400).json({ success: false, message: "reason is required" });
    const { data, error } = await supabase.rpc("remove_order_from_run", {
      p_delivery_run_id: req.params.id, p_order_id: orderId, p_reason: reason,
    });
    if (error) throw error;
    if (!data.success) return res.status(400).json({ success: false, code: data.code });

    // Notify the rider's app in real time if this run is currently
    // theirs and active — reuses the existing outbox/notification
    // infrastructure rather than inventing a second one (spec section 22).
    await supabase.from("outbox_events").insert({
      event_type: "DELIVERY_RUN_ORDER_REMOVED",
      aggregate_type: "delivery_run",
      aggregate_id: req.params.id,
      payload: { order_id: orderId, reason },
    });

    res.json({ success: true, data });
  } catch (error) {
    console.error("[ADMIN-RIDERS] remove-order error:", error);
    res.status(500).json({ success: false, message: "Failed to remove order from run" });
  }
});

// ============================================================
// LIST / VIEW RUNS
// ============================================================
router.get("/runs", async (req, res) => {
  try {
    const { status, riderId, limit, offset } = req.query;
    let query = supabase.from("delivery_runs").select("*, users:users!delivery_runs_rider_id_fkey(name, phone)", { count: "exact" }).order("created_at", { ascending: false });
    if (status) query = query.eq("status", status);
    if (riderId) query = query.eq("rider_id", riderId);
    const lim = limit ? Math.min(parseInt(limit, 10) || 50, 200) : 50;
    const off = offset ? parseInt(offset, 10) || 0 : 0;
    query = query.range(off, off + lim - 1);

    const { data, count, error } = await query;
    if (error) throw error;
    res.json({ success: true, data, total: count });
  } catch (error) {
    console.error("[ADMIN-RIDERS] list runs error:", error);
    res.status(500).json({ success: false, message: "Failed to load delivery runs" });
  }
});

router.get("/runs/:id", async (req, res) => {
  try {
    const { data: run, error } = await supabase.from("delivery_runs").select("*, users:users!delivery_runs_rider_id_fkey(name, phone)").eq("id", req.params.id).maybeSingle();
    if (error) throw error;
    if (!run) return res.status(404).json({ success: false, message: "Run not found" });

    const { data: orders } = await supabase
      .from("delivery_run_orders")
      .select("order_id, sequence_number, removed_at, removed_reason, orders(status, total, delivery_address)")
      .eq("delivery_run_id", req.params.id)
      .order("sequence_number", { ascending: true });

    const { data: events } = await supabase.from("rider_delivery_events").select("*").eq("delivery_run_id", req.params.id).order("created_at", { ascending: true });
    const { data: failures } = await supabase.from("delivery_failure_reports").select("*").eq("delivery_run_id", req.params.id);

    res.json({ success: true, data: { run, orders, events, failures } });
  } catch (error) {
    console.error("[ADMIN-RIDERS] run detail error:", error);
    res.status(500).json({ success: false, message: "Failed to load run detail" });
  }
});

// ============================================================
// SUSPEND / REACTIVATE A RIDER — reuses the SAME account-restriction
// system built for the ledger project (restrict_user_account /
// unfreeze_user_account), rather than a second, unaudited status
// flip. That system was built generic to any user, not
// customer-specific, so this is a direct, appropriate reuse.
// ============================================================
router.post("/:id/suspend", async (req, res) => {
  try {
    const { reason } = req.body || {};
    if (!reason) return res.status(400).json({ success: false, message: "reason is required" });

    const { data, error } = await supabase.rpc("restrict_user_account", {
      p_user_id: req.params.id, p_action: "RESTRICT", p_scope: "delivery_actions",
      p_reason: reason, p_performed_by: req.userId,
    });
    if (error) throw error;
    if (!data.success) return res.status(400).json({ success: false, code: data.code });
    res.json({ success: true, data });
  } catch (error) {
    console.error("[ADMIN-RIDERS] suspend error:", error);
    res.status(500).json({ success: false, message: "Failed to suspend rider" });
  }
});

router.post("/:id/reactivate", async (req, res) => {
  try {
    const { reason } = req.body || {};
    if (!reason) return res.status(400).json({ success: false, message: "reason is required" });

    const { data, error } = await supabase.rpc("unfreeze_user_account", {
      p_user_id: req.params.id, p_reason: reason, p_performed_by: req.userId,
    });
    if (error) throw error;
    if (!data.success) return res.status(400).json({ success: false, code: data.code });
    res.json({ success: true, data });
  } catch (error) {
    console.error("[ADMIN-RIDERS] reactivate error:", error);
    res.status(500).json({ success: false, message: "Failed to reactivate rider" });
  }
});

module.exports = router;