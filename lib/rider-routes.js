// rider-routes.js (Frozyla side)
//
// Mount in server.js:
//   const riderMiddleware = require("./lib/rider-middleware");
//   const riderRouter = require("./lib/rider-routes");
//   app.use("/api/rider", authMiddleware, riderMiddleware, riderRouter);
//
// Every write route re-validates the rider-to-order/run relationship
// server-side via the SQL functions in
// 029_rider_app_functions.sql — this file is a thin HTTP wrapper,
// same discipline as ledger-service.js/gl-admin-routes.js elsewhere
// in this project. No route here trusts a client-supplied rider id,
// order state, or timestamp — req.userId (from the existing JWT) is
// the only rider identity ever used.

const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);
const ledgerService = require("./ledger-service");

// ============================================================
// DASHBOARD
// ============================================================
router.get("/dashboard", async (req, res) => {
  try {
    const riderId = req.userId;
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);

    const [{ data: activeRun }, { data: todayEvents }, earnings] = await Promise.all([
      supabase.from("delivery_runs").select("*, delivery_run_orders(order_id, sequence_number)").eq("rider_id", riderId).in("status", ["PENDING", "ACTIVE"]).order("created_at", { ascending: false }).limit(1).maybeSingle(),
      supabase.from("rider_delivery_events").select("event_type").eq("rider_id", riderId).eq("event_type", "PIN_VERIFIED").gte("created_at", todayStart.toISOString()),
      ledgerService.getAccountBalance({ accountCode: "6000", ownerId: riderId }),
    ]);

    const { count: activeOrdersCount } = activeRun
      ? { count: (activeRun.delivery_run_orders || []).length }
      : { count: 0 };

    res.json({
      success: true,
      data: {
        riderStatus: req.rider.rider_availability_status,
        activeRun: activeRun ? { id: activeRun.id, runNumber: activeRun.run_number, status: activeRun.status, orderCount: (activeRun.delivery_run_orders || []).length } : null,
        activeOrders: activeOrdersCount,
        completedToday: (todayEvents || []).length,
        todaysEarnings: earnings.ledger_balance, // NOTE: lifetime balance today, see /earnings for a proper today/week breakdown
      },
    });
  } catch (error) {
    console.error("[RIDER] dashboard error:", error);
    res.status(500).json({ success: false, message: "Failed to load dashboard" });
  }
});

// ============================================================
// AVAILABILITY
// ============================================================
router.post("/availability", async (req, res) => {
  try {
    const { status } = req.body || {};
    if (!["AVAILABLE", "OFFLINE"].includes(status)) {
      return res.status(400).json({ success: false, message: "status must be AVAILABLE or OFFLINE" });
    }
    const { data, error } = await supabase.rpc("set_rider_availability", { p_rider_id: req.userId, p_status: status });
    if (error) throw error;
    if (!data.success) {
      const statusByCode = { HAS_ACTIVE_RUN: 400, INVALID_MANUAL_STATUS: 400, NOT_A_RIDER: 403 };
      return res.status(statusByCode[data.code] || 400).json({ success: false, code: data.code, message: data.message });
    }
    res.json({ success: true, data });
  } catch (error) {
    console.error("[RIDER] availability error:", error);
    res.status(500).json({ success: false, message: "Failed to update availability" });
  }
});

// ============================================================
// ACTIVE DELIVERY RUN
// ============================================================
router.get("/runs/active", async (req, res) => {
  try {
    const { data: run, error } = await supabase
      .from("delivery_runs")
      .select("*")
      .eq("rider_id", req.userId)
      .in("status", ["PENDING", "ACTIVE"])
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error) throw error;
    if (!run) return res.json({ success: true, data: null });

    const { data: runOrders } = await supabase
      .from("delivery_run_orders")
      .select("order_id, sequence_number, orders(id, status, total, delivery_address, delivery_fee_amount, items, user_id, users(name, phone))")
      .eq("delivery_run_id", run.id)
      .is("removed_at", null)
      .order("sequence_number", { ascending: true });

    res.json({
      success: true,
      data: {
        id: run.id,
        runNumber: run.run_number,
        status: run.status,
        pickupConfirmedAt: run.pickup_confirmed_at,
        orders: (runOrders || []).map((ro) => ({
          orderId: ro.order_id,
          sequence: ro.sequence_number,
          status: ro.orders?.status,
          total: ro.orders?.total,
          deliveryFee: ro.orders?.delivery_fee_amount,
          address: ro.orders?.delivery_address,
          items: ro.orders?.items,
          customerName: ro.orders?.users?.name,
          customerPhone: ro.orders?.users?.phone,
        })),
      },
    });
  } catch (error) {
    console.error("[RIDER] active run error:", error);
    res.status(500).json({ success: false, message: "Failed to load active run" });
  }
});

// ============================================================
// PICKUP
// ============================================================
router.post("/runs/:id/confirm-pickup", async (req, res) => {
  try {
    const { data, error } = await supabase.rpc("confirm_run_pickup", { p_delivery_run_id: req.params.id, p_rider_id: req.userId });
    if (error) throw error;
    if (!data.success) {
      const statusByCode = { RUN_NOT_FOUND: 404, NOT_YOUR_RUN: 403, ALREADY_CONFIRMED_OR_INVALID: 400, ORDER_NOT_READY: 409 };
      return res.status(statusByCode[data.code] || 400).json({ success: false, code: data.code, message: data.message || data.code });
    }
    res.json({ success: true, data });
  } catch (error) {
    console.error("[RIDER] confirm-pickup error:", error);
    res.status(500).json({ success: false, message: "Failed to confirm pickup" });
  }
});

// ============================================================
// ARRIVAL
// ============================================================
router.post("/arrival", async (req, res) => {
  try {
    const { orderId, deliveryRunId, arrivalType, latitude, longitude } = req.body || {};
    const { data, error } = await supabase.rpc("record_rider_arrival", {
      p_rider_id: req.userId, p_order_id: orderId || null, p_delivery_run_id: deliveryRunId || null,
      p_arrival_type: arrivalType, p_latitude: latitude || null, p_longitude: longitude || null,
    });
    if (error) throw error;
    if (!data.success) {
      return res.status(data.code === "NOT_ASSIGNED" ? 403 : 400).json({ success: false, code: data.code });
    }
    res.json({ success: true });
  } catch (error) {
    console.error("[RIDER] arrival error:", error);
    res.status(500).json({ success: false, message: "Failed to record arrival" });
  }
});

// ============================================================
// PIN VERIFICATION -> DELIVERED
// ============================================================
router.post("/orders/:id/verify-pin", async (req, res) => {
  try {
    const { pin, latitude, longitude, proofPhotoUrl } = req.body || {};
    if (!pin) return res.status(400).json({ success: false, message: "pin is required" });

    const { data, error } = await supabase.rpc("verify_delivery_pin_and_complete", {
      p_rider_id: req.userId, p_order_id: req.params.id, p_pin: String(pin),
      p_latitude: latitude || null, p_longitude: longitude || null, p_proof_photo_url: proofPhotoUrl || null,
    });
    if (error) throw error;

    if (!data.success) {
      const statusByCode = {
        NOT_ASSIGNED_OR_RUN_INACTIVE: 403, NO_PIN_ISSUED: 404, ALREADY_DELIVERED: 409,
        TOO_MANY_ATTEMPTS: 429, INCORRECT_PIN: 400,
      };
      return res.status(statusByCode[data.code] || 400).json({ success: false, code: data.code, attemptsRemaining: data.attempts_remaining });
    }
    res.json({ success: true, data });
  } catch (error) {
    console.error("[RIDER] verify-pin error:", error);
    res.status(500).json({ success: false, message: "Failed to verify delivery" });
  }
});

// ============================================================
// DELIVERY FAILURE
// ============================================================
router.post("/orders/:id/report-failure", async (req, res) => {
  try {
    const { reasonCode, notes, attemptedContacts, latitude, longitude } = req.body || {};
    const validReasons = ["CUSTOMER_UNAVAILABLE", "WRONG_ADDRESS", "CUSTOMER_REFUSED", "CANNOT_CONTACT", "ACCESS_PROBLEM", "DAMAGED_ORDER", "OTHER"];
    if (!validReasons.includes(reasonCode)) {
      return res.status(400).json({ success: false, message: "Invalid reasonCode", validReasons });
    }

    const { data, error } = await supabase.rpc("report_delivery_failure", {
      p_rider_id: req.userId, p_order_id: req.params.id, p_reason_code: reasonCode,
      p_notes: notes || null, p_attempted_contacts: attemptedContacts || 0,
      p_latitude: latitude || null, p_longitude: longitude || null,
    });
    if (error) throw error;
    if (!data.success) {
      return res.status(data.code === "NOT_ASSIGNED_OR_RUN_INACTIVE" ? 403 : 400).json({ success: false, code: data.code });
    }
    res.json({ success: true, data });
  } catch (error) {
    console.error("[RIDER] report-failure error:", error);
    res.status(500).json({ success: false, message: "Failed to report delivery failure" });
  }
});

// ============================================================
// LOCATION PING
// ============================================================
router.post("/locations", async (req, res) => {
  try {
    const { latitude, longitude, deliveryRunId } = req.body || {};
    if (typeof latitude !== "number" || typeof longitude !== "number") {
      return res.status(400).json({ success: false, message: "latitude and longitude are required numbers" });
    }
    // recorded_at is NOT accepted from the client — server DEFAULT
    // NOW() is the only timestamp ever stored (spec section 15/25).
    const { error } = await supabase.from("rider_locations").insert({
      rider_id: req.userId, latitude, longitude, delivery_run_id: deliveryRunId || null,
    });
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error("[RIDER] location ping error:", error);
    res.status(500).json({ success: false, message: "Failed to record location" });
  }
});

// ============================================================
// EARNINGS
// ============================================================
router.get("/earnings", async (req, res) => {
  try {
    const riderId = req.userId;
    const lifetimeBalance = await ledgerService.getAccountBalance({ accountCode: "6000", ownerId: riderId });

    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    const weekStart = new Date(); weekStart.setDate(weekStart.getDate() - 7);

    const { data: account } = await supabase.from("gl_accounts").select("id").eq("account_code", "6000").single();

    const [{ data: todayLines }, { data: weekLines }] = await Promise.all([
      supabase.from("gl_journal_lines").select("credit_amount").eq("account_id", account.id).eq("owner_id", riderId).gte("created_at", todayStart.toISOString()),
      supabase.from("gl_journal_lines").select("credit_amount").eq("account_id", account.id).eq("owner_id", riderId).gte("created_at", weekStart.toISOString()),
    ]);

    const sumCredits = (rows) => (rows || []).reduce((s, r) => s + Number(r.credit_amount || 0), 0);

    res.json({
      success: true,
      data: {
        lifetimeBalance: lifetimeBalance.ledger_balance,
        today: sumCredits(todayLines),
        thisWeek: sumCredits(weekLines),
        completedToday: (todayLines || []).length,
      },
    });
  } catch (error) {
    console.error("[RIDER] earnings error:", error);
    res.status(500).json({ success: false, message: "Failed to load earnings" });
  }
});

// ============================================================
// DELIVERY HISTORY
// ============================================================
router.get("/history", async (req, res) => {
  try {
    const { period, limit, offset } = req.query;
    let since = new Date(0);
    const now = new Date();
    if (period === "today") { since = new Date(); since.setHours(0, 0, 0, 0); }
    else if (period === "yesterday") { since = new Date(); since.setDate(since.getDate() - 1); since.setHours(0, 0, 0, 0); }
    else if (period === "week") { since = new Date(now - 7 * 24 * 60 * 60 * 1000); }
    else if (period === "month") { since = new Date(now - 30 * 24 * 60 * 60 * 1000); }

    const lim = limit ? Math.min(parseInt(limit, 10) || 50, 200) : 50;
    const off = offset ? parseInt(offset, 10) || 0 : 0;

    const { data: events, error } = await supabase
      .from("rider_delivery_events")
      .select("order_id, delivery_run_id, event_type, created_at, orders(status, total, delivery_address)")
      .eq("rider_id", req.userId)
      .in("event_type", ["PIN_VERIFIED", "DELIVERY_FAILED"])
      .gte("created_at", since.toISOString())
      .order("created_at", { ascending: false })
      .range(off, off + lim - 1);
    if (error) throw error;

    res.json({
      success: true,
      data: (events || []).map((e) => ({
        orderId: e.order_id,
        outcome: e.event_type === "PIN_VERIFIED" ? "DELIVERED" : "FAILED",
        status: e.orders?.status,
        total: e.orders?.total,
        area: e.orders?.delivery_address,
        when: e.created_at,
      })),
    });
  } catch (error) {
    console.error("[RIDER] history error:", error);
    res.status(500).json({ success: false, message: "Failed to load delivery history" });
  }
});

// ============================================================
// PROFILE
// ============================================================
router.get("/profile", async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("id, name, email, phone, rider_availability_status, status, account_status, created_at")
      .eq("id", req.userId)
      .single();
    if (error) throw error;
    res.json({ success: true, data: user });
  } catch (error) {
    console.error("[RIDER] profile error:", error);
    res.status(500).json({ success: false, message: "Failed to load profile" });
  }
});

module.exports = router;