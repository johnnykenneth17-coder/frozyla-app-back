// lib/rider-earnings-routes.js
// Mount: app.use("/api/admin/rider-earnings", authMiddleware, adminMiddleware, router);
// Thin wrapper over migrations/006. A rider can never reach these routes (adminMiddleware), and rider
// endpoints expose earnings read-only, so a rider cannot influence their own amount.

const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const ledgerService = require("./ledger-service");
const router = express.Router();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STATUSES = ["pending", "needs_review", "payable", "paid", "cancelled", "adjusted"];
const clampInt = (v, d, min, max) => Math.min(Math.max(parseInt(v, 10) || d, min), max);
const STATUS = { ALREADY_PAID: 409, EARNING_CANCELLED: 409, ORDER_NOT_FOUND_OR_CLOSED: 404 };
const fail = (res, data) => res.status(STATUS[data && data.code] || 400).json({ success: false, ...data });
const serverError = (res, tag, err) => { console.error(`[RIDER-EARNINGS] ${tag}:`, err && err.message); res.status(500).json({ success: false, message: "Request failed" }); };
const audit = (req, action, entityId, newState, reason) =>
  ledgerService.writeAuditLog({ actorId: req.userId, actorRole: req.userRole, action, entityType: "rider_earning", entityId, newState, reason, ipAddress: req.ip }).catch(() => {});

router.get("/settings", async (req, res) => {
  try {
    const { data, error } = await supabase.from("payment_settings").select("value").eq("key", "rider_default_earning").maybeSingle();
    if (error) throw error;
    const n = data ? Number(data.value) : null;
    res.json({ success: true, data: { defaultEarning: Number.isFinite(n) ? n : null, configured: Number.isFinite(n) } });
  } catch (e) { serverError(res, "settings", e); }
});

router.put("/settings", async (req, res) => {
  try {
    const amount = Number(req.body && req.body.defaultEarning), reason = String((req.body && req.body.reason) || "").trim();
    if (!Number.isFinite(amount) || amount < 0 || amount > 1000000) return res.status(400).json({ success: false, code: "INVALID_AMOUNT", message: "defaultEarning must be between 0 and 1,000,000" });
    if (reason.length < 3) return res.status(400).json({ success: false, message: "a reason is required" });
    const { data, error } = await supabase.rpc("set_rider_default_earning", { p_amount: Math.round(amount * 100) / 100, p_actor: req.userId, p_reason: reason.slice(0, 300) });
    if (error) throw error;
    if (!data.success) return fail(res, data);
    audit(req, "rider_default_earning_changed", "rider_default_earning", { amount }, reason);
    res.json({ success: true });
  } catch (e) { serverError(res, "set default", e); }
});

router.get("/earnings", async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 50, 1, 200), offset = clampInt(req.query.offset, 0, 0, 1e6);
    let q = supabase.from("delivery_earnings")
      .select("id, order_id, rider_id, amount, source, status, customer_delivery_fee, override_reason, paid_at, paid_reference, created_at, updated_at, rider:users!delivery_earnings_rider_id_fkey(name, phone)", { count: "exact" })
      .order("created_at", { ascending: false }).range(offset, offset + limit - 1);
    if (UUID.test(req.query.riderId || "")) q = q.eq("rider_id", req.query.riderId);
    if (STATUSES.includes(req.query.status)) q = q.eq("status", req.query.status);
    if (req.query.orderId) q = q.eq("order_id", String(req.query.orderId).slice(0, 60));
    if (req.query.from && !isNaN(Date.parse(req.query.from))) q = q.gte("created_at", new Date(req.query.from).toISOString());
    if (req.query.to && !isNaN(Date.parse(req.query.to))) q = q.lte("created_at", new Date(req.query.to).toISOString());
    const { data, count, error } = await q; if (error) throw error;
    res.json({ success: true, data, total: count });
  } catch (e) { serverError(res, "list earnings", e); }
});

// Outstanding payable per rider + earnings awaiting review.
router.get("/summary", async (req, res) => {
  try {
    const { data, error } = await supabase.from("delivery_earnings").select("rider_id, amount, status, rider:users!delivery_earnings_rider_id_fkey(name)").in("status", ["payable", "adjusted", "needs_review"]).limit(5000);
    if (error) throw error;
    const byRider = {}; let needsReview = 0;
    for (const r of data || []) {
      if (r.status === "needs_review") { needsReview++; continue; }
      const k = r.rider_id; byRider[k] = byRider[k] || { riderId: k, name: r.rider && r.rider.name, payable: 0, orders: 0 };
      byRider[k].payable = Math.round((byRider[k].payable + Number(r.amount)) * 100) / 100; byRider[k].orders++;
    }
    res.json({ success: true, data: { needsReview, riders: Object.values(byRider).sort((a, b) => b.payable - a.payable), truncated: (data || []).length >= 5000 } });
  } catch (e) { serverError(res, "summary", e); }
});

// Per-order override / adjustment. requestId makes a retried click harmless.
router.put("/orders/:orderId", async (req, res) => {
  try {
    const b = req.body || {}, amount = Number(b.amount), reason = String(b.reason || "").trim(), requestId = String(b.requestId || "").trim();
    if (!/^[A-Za-z0-9._:-]{8,100}$/.test(requestId)) return res.status(400).json({ success: false, code: "REQUEST_ID_REQUIRED", message: "requestId is required" });
    if (!Number.isFinite(amount) || amount < 0 || amount > 1000000) return res.status(400).json({ success: false, code: "INVALID_AMOUNT", message: "amount must be between 0 and 1,000,000" });
    if (reason.length < 3) return res.status(400).json({ success: false, code: "REASON_REQUIRED", message: "a reason is required" });
    const { data, error } = await supabase.rpc("admin_set_rider_earning", { p_order_id: String(req.params.orderId).slice(0, 60), p_amount: Math.round(amount * 100) / 100, p_reason: reason.slice(0, 300), p_actor: req.userId, p_request_id: requestId });
    if (error) throw error;
    if (!data.success) return fail(res, data);
    audit(req, "rider_earning_override", req.params.orderId, { amount }, reason);
    res.json({ success: true, data });
  } catch (e) { serverError(res, "override", e); }
});

// Records that a payout was made elsewhere. It does NOT move money.
router.post("/mark-paid", async (req, res) => {
  try {
    const ids = req.body && req.body.orderIds, ref = String((req.body && req.body.reference) || "").trim();
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > 200 || ids.some((i) => typeof i !== "string" || i.length > 60)) return res.status(400).json({ success: false, message: "orderIds must be 1-200 order ids" });
    if (ref.length < 3 || ref.length > 100) return res.status(400).json({ success: false, code: "REFERENCE_REQUIRED", message: "a payout reference is required" });
    const { data, error } = await supabase.rpc("mark_rider_earnings_paid", { p_order_ids: ids, p_reference: ref, p_actor: req.userId });
    if (error) throw error;
    if (!data.success) return fail(res, data);
    audit(req, "rider_earnings_marked_paid", ref, { count: data.marked_paid }, "payout recorded");
    res.json({ success: true, data });
  } catch (e) { serverError(res, "mark paid", e); }
});

router.get("/audit", async (req, res) => {
  try {
    let q = supabase.from("rider_earning_audit").select("*").order("created_at", { ascending: false }).limit(clampInt(req.query.limit, 50, 1, 200));
    if (req.query.orderId) q = q.eq("order_id", String(req.query.orderId).slice(0, 60));
    const { data, error } = await q; if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { serverError(res, "audit", e); }
});

module.exports = router;
