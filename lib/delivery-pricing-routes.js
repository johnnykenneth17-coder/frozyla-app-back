// lib/delivery-pricing-routes.js
// Mount (server.js):
//   app.use("/api/admin/delivery", authMiddleware, adminMiddleware, adminRouter);   // pricing, locations, preview
//   app.use("/api/delivery",       authMiddleware, requireActiveAccount, customerRouter); // area picker + quote
// The browser never calculates a price. Every number below comes from the SQL functions in
// migrations/004 (resolve_delivery_fee etc.), the SAME ones create_and_pay_order uses at checkout.

const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const ledgerService = require("./ledger-service");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const TYPES = ["country", "state", "lga", "city", "community", "street", "estate", "hotel", "building", "business", "other"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (v) => typeof v === "string" && UUID.test(v);
const clampInt = (v, d, min, max) => Math.min(Math.max(parseInt(v, 10) || d, min), max);
const cleanName = (v) => (typeof v === "string" ? v.replace(/\s+/g, " ").trim() : "");
const STATUS = { LOCATION_NOT_FOUND: 404, NOT_FOUND: 404, PARENT_NOT_FOUND: 404, DUPLICATE_LOCATION: 409, HAS_ACTIVE_CHILDREN: 409, VALIDATION_FAILED: 422, NO_DELIVERY_FEE: 422, LOCATION_INACTIVE: 422 };
const fail = (res, data) => res.status(STATUS[data && data.code] || 400).json({ success: false, ...data });
const serverError = (res, tag, err) => { console.error(`[DELIVERY-PRICING] ${tag}:`, err && err.message); res.status(500).json({ success: false, message: "Request failed" }); };
const audit = (req, action, entityId, oldState, newState, reason) =>
  ledgerService.writeAuditLog({ actorId: req.userId, actorRole: req.userRole, action, entityType: "delivery_pricing", entityId, oldState, newState, reason, ipAddress: req.ip }).catch(() => {});

// proposed rules: validated shape only; the SQL validator does the business checks
function parseProposed(body) {
  const p = body && body.proposed;
  if (p === undefined || p === null) return { value: null };
  if (!Array.isArray(p) || p.length > 200) return { error: "proposed must be an array of at most 200 rules" };
  const out = [];
  for (const r of p) {
    if (!r || !isUuid(r.locationId)) return { error: "each proposed rule needs a valid locationId" };
    const status = r.status === undefined ? "active" : r.status;
    if (!["active", "inactive", "draft"].includes(status)) return { error: "proposed status must be active, inactive or draft" };
    const fee = r.customerFee === undefined ? null : Number(r.customerFee);
    if (status === "active" && (fee === null || !Number.isFinite(fee))) return { error: "an active proposed rule needs a numeric customerFee" };
    out.push({ location_id: r.locationId, customer_fee: fee, status, currency: r.currency || "NGN" });
  }
  return { value: out };
}

// ===================================================================== ADMIN
const adminRouter = express.Router();

adminRouter.get("/locations", async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 50, 1, 200), offset = clampInt(req.query.offset, 0, 0, 1e6);
    let q = supabase.from("delivery_locations")
      .select("id, parent_id, location_type, name, is_active, archived_at, created_at, updated_at, rule:delivery_pricing_rules(id, customer_fee, status, effective_from, effective_to)", { count: "exact" })
      .order("location_type").order("name").range(offset, offset + limit - 1);
    if (req.query.parentId === "root") q = q.is("parent_id", null);
    else if (isUuid(req.query.parentId)) q = q.eq("parent_id", req.query.parentId);
    if (TYPES.includes(req.query.type)) q = q.eq("location_type", req.query.type);
    if (req.query.includeArchived !== "true") q = q.is("archived_at", null);
    if (req.query.search) q = q.ilike("name", `%${String(req.query.search).replace(/[%_,()]/g, " ").trim().slice(0, 60)}%`);
    if (req.query.unpriced === "true") q = q.is("rule", null);
    const { data, count, error } = await q;
    if (error) throw error;
    const rows = (data || []).map((l) => ({ ...l, rule: Array.isArray(l.rule) ? l.rule[0] || null : l.rule || null }));
    res.json({ success: true, data: rows, total: count });
  } catch (e) { serverError(res, "list locations", e); }
});

adminRouter.post("/locations", async (req, res) => {
  try {
    const name = cleanName(req.body && req.body.name), type = req.body && req.body.type, parentId = (req.body && req.body.parentId) || null;
    if (!name || name.length > 120) return res.status(400).json({ success: false, message: "name is required (max 120 characters)" });
    if (!TYPES.includes(type)) return res.status(400).json({ success: false, message: "invalid location type" });
    if (parentId !== null && !isUuid(parentId)) return res.status(400).json({ success: false, message: "invalid parentId" });
    const { data, error } = await supabase.rpc("create_delivery_location", { p_name: name, p_type: type, p_parent_id: parentId, p_actor: req.userId });
    if (error) throw error;
    if (!data.success) return fail(res, data);
    audit(req, "delivery_location_created", data.id, null, { name, type, parentId });
    res.status(201).json({ success: true, id: data.id });
  } catch (e) { serverError(res, "create location", e); }
});

adminRouter.patch("/locations/:id", async (req, res) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ success: false, message: "invalid id" });
    const b = req.body || {};
    if (b.parentId !== undefined && b.parentId !== null && !isUuid(b.parentId)) return res.status(400).json({ success: false, message: "invalid parentId" });
    if (b.isActive !== undefined && typeof b.isActive !== "boolean") return res.status(400).json({ success: false, message: "isActive must be boolean" });
    const name = b.name === undefined ? null : cleanName(b.name);
    if (name !== null && (!name || name.length > 120)) return res.status(400).json({ success: false, message: "name must be 1-120 characters" });
    const { data, error } = await supabase.rpc("update_delivery_location", { p_id: req.params.id, p_name: name, p_parent_id: b.parentId || null, p_is_active: b.isActive === undefined ? null : b.isActive, p_actor: req.userId });
    if (error) throw error;
    if (!data.success) return fail(res, data);
    audit(req, "delivery_location_updated", req.params.id, null, { name, parentId: b.parentId, isActive: b.isActive });
    res.json({ success: true });
  } catch (e) { serverError(res, "update location", e); }
});

adminRouter.post("/locations/:id/archive", async (req, res) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ success: false, message: "invalid id" });
    const { data, error } = await supabase.rpc("archive_delivery_location", { p_id: req.params.id, p_actor: req.userId });
    if (error) throw error;
    if (!data.success) return fail(res, data);
    audit(req, "delivery_location_archived", req.params.id, null, { archived: true });
    res.json({ success: true });
  } catch (e) { serverError(res, "archive location", e); }
});

// create/update the rule on a location. Validation runs in SQL; errors block, warnings are returned.
adminRouter.put("/locations/:id/rule", async (req, res) => {
  try {
    if (!isUuid(req.params.id)) return res.status(400).json({ success: false, message: "invalid id" });
    const b = req.body || {};
    const fee = Number(b.customerFee);
    if (!Number.isFinite(fee) || fee < 0 || fee > 1000000) return res.status(400).json({ success: false, code: "INVALID_FEE", message: "customerFee must be a number between 0 and 1,000,000" });
    if (!["draft", "active", "inactive"].includes(b.status)) return res.status(400).json({ success: false, code: "INVALID_STATUS", message: "status must be draft, active or inactive" });
    if (!b.reason || String(b.reason).trim().length < 3) return res.status(400).json({ success: false, message: "a reason is required for the audit log" });
    const date = (v) => (v ? new Date(v).toISOString() : null);
    let from, to;
    try { from = date(b.effectiveFrom); to = date(b.effectiveTo); } catch { return res.status(400).json({ success: false, message: "invalid effective date" }); }
    const { data, error } = await supabase.rpc("upsert_delivery_rule", { p_location_id: req.params.id, p_fee: Math.round(fee * 100) / 100, p_status: b.status, p_from: from, p_to: to, p_actor: req.userId, p_reason: String(b.reason).trim().slice(0, 300) });
    if (error) throw error;
    if (!data.success) return fail(res, data);
    audit(req, "delivery_rule_" + data.action, req.params.id, data.old_fee === undefined ? null : { fee: data.old_fee }, { fee, status: b.status }, b.reason);
    res.json({ success: true, ruleId: data.rule_id, action: data.action });
  } catch (e) { serverError(res, "save rule", e); }
});

adminRouter.get("/history", async (req, res) => {
  try {
    let q = supabase.from("delivery_pricing_history").select("*", { count: "exact" }).order("changed_at", { ascending: false }).range(0, clampInt(req.query.limit, 50, 1, 200) - 1);
    if (isUuid(req.query.locationId)) q = q.eq("location_id", req.query.locationId);
    const { data, count, error } = await q; if (error) throw error;
    res.json({ success: true, data, total: count });
  } catch (e) { serverError(res, "history", e); }
});

adminRouter.get("/coverage", async (req, res) => {
  try { const { data, error } = await supabase.rpc("delivery_pricing_coverage"); if (error) throw error; res.json({ success: true, data }); }
  catch (e) { serverError(res, "coverage", e); }
});

// ---------------------------------------------------------------- PREVIEW (read-only: nothing below writes)
adminRouter.post("/preview", async (req, res) => {
  try {
    const b = req.body || {};
    if (!isUuid(b.locationId)) return res.status(400).json({ success: false, message: "locationId is required" });
    const parsed = parseProposed(b); if (parsed.error) return res.status(400).json({ success: false, message: parsed.error });
    const unreg = b.unregisteredName ? cleanName(b.unregisteredName).slice(0, 120) : null;
    const { data, error } = await supabase.rpc("resolve_delivery_fee", { p_location_id: b.locationId, p_proposed: parsed.value, p_unregistered_name: unreg });
    if (error) throw error;
    let validation = null;
    if (parsed.value) { const v = await supabase.rpc("validate_delivery_pricing", { p_proposed: parsed.value }); if (!v.error) validation = v.data; }
    res.json({ success: true, data, validation, mode: parsed.value ? "proposed" : "live" });
  } catch (e) { serverError(res, "preview", e); }
});

adminRouter.post("/preview/validate", async (req, res) => {
  try {
    const parsed = parseProposed(req.body); if (parsed.error || !parsed.value) return res.status(400).json({ success: false, message: parsed.error || "proposed is required" });
    const { data, error } = await supabase.rpc("validate_delivery_pricing", { p_proposed: parsed.value }); if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { serverError(res, "validate", e); }
});

adminRouter.post("/preview/impact", async (req, res) => {
  try {
    const parsed = parseProposed(req.body); if (parsed.error || !parsed.value) return res.status(400).json({ success: false, message: parsed.error || "proposed is required" });
    const { data, error } = await supabase.rpc("analyze_pricing_impact", { p_proposed: parsed.value, p_limit: 2000 }); if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { serverError(res, "impact", e); }
});

adminRouter.post("/preview/batch", async (req, res) => {
  try {
    const tests = req.body && req.body.tests;
    if (!Array.isArray(tests) || tests.length === 0 || tests.length > 100) return res.status(400).json({ success: false, message: "tests must contain 1-100 entries" });
    const parsed = parseProposed(req.body); if (parsed.error) return res.status(400).json({ success: false, message: parsed.error });
    const results = [];
    for (const t of tests) {
      if (!t || !isUuid(t.locationId)) { results.push({ input: t, error: "invalid locationId" }); continue; }
      const { data, error } = await supabase.rpc("resolve_delivery_fee", { p_location_id: t.locationId, p_proposed: parsed.value, p_unregistered_name: t.unregisteredName ? cleanName(t.unregisteredName).slice(0, 120) : null });
      if (error) { results.push({ input: t, error: "lookup failed" }); continue; }
      const expected = t.expectedFee === undefined || t.expectedFee === null || t.expectedFee === "" ? null : Number(t.expectedFee);
      results.push({
        input: t, found: data.found, fee: data.found ? data.fee : null, label: data.label || null, ruleLocation: data.rule_location_name || null,
        fallbackUsed: data.fallback_used || false, checkoutPermitted: data.checkout_permitted, reason: data.reason, code: data.code || null,
        expectedFee: expected, matchesExpected: expected === null ? null : (data.found && Number(data.fee) === expected),
      });
    }
    res.json({ success: true, data: results, summary: { total: results.length, blocked: results.filter((r) => r.found === false).length, mismatches: results.filter((r) => r.matchesExpected === false).length } });
  } catch (e) { serverError(res, "batch", e); }
});

// ---------------------------------------------------------------- settings
adminRouter.get("/settings", async (req, res) => {
  try {
    const { data, error } = await supabase.from("payment_settings").select("key, value").in("key", ["delivery_pricing_enforced", "delivery_quote_ttl_minutes"]);
    if (error) throw error;
    const m = Object.fromEntries((data || []).map((r) => [r.key, r.value]));
    res.json({ success: true, data: { enforced: m.delivery_pricing_enforced === "true", quoteTtlMinutes: Number(m.delivery_quote_ttl_minutes || 10) } });
  } catch (e) { serverError(res, "settings", e); }
});
adminRouter.put("/settings", async (req, res) => {
  try {
    const b = req.body || {};
    if (typeof b.enforced !== "boolean") return res.status(400).json({ success: false, message: "enforced must be true or false" });
    if (!b.reason || String(b.reason).trim().length < 3) return res.status(400).json({ success: false, message: "a reason is required" });
    if (b.enforced) {   // refuse to enforce with nothing priced: every delivery would be blocked
      const { count } = await supabase.from("delivery_pricing_rules").select("id", { count: "exact", head: true }).eq("status", "active");
      if (!count) return res.status(422).json({ success: false, code: "NO_ACTIVE_RULES", message: "Create at least one active delivery price before enforcing." });
    }
    const { error } = await supabase.from("payment_settings").upsert({ key: "delivery_pricing_enforced", value: String(b.enforced), updated_by: req.userId, updated_at: new Date().toISOString() }, { onConflict: "key" });
    if (error) throw error;
    audit(req, "delivery_pricing_enforcement_changed", "delivery_pricing_enforced", null, { enforced: b.enforced }, b.reason);
    res.json({ success: true });
  } catch (e) { serverError(res, "settings update", e); }
});

// ===================================================================== CUSTOMER
const customerRouter = express.Router();

// Area picker: active, non-archived children of a parent (or the roots). Names and types only.
customerRouter.get("/locations", async (req, res) => {
  try {
    let q = supabase.from("delivery_locations").select("id, name, location_type, parent_id").eq("is_active", true).is("archived_at", null).order("name").limit(200);
    if (isUuid(req.query.parentId)) q = q.eq("parent_id", req.query.parentId); else q = q.is("parent_id", null);
    if (req.query.search) q = q.ilike("name", `%${String(req.query.search).replace(/[%_,()]/g, " ").trim().slice(0, 60)}%`);
    const { data, error } = await q; if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { serverError(res, "customer locations", e); }
});

// The fee the customer is shown AND later confirms. Only a quote id, amount and expiry leave the server:
// no rule ids, no fallback chain, nothing internal.
customerRouter.post("/quote", async (req, res) => {
  try {
    const b = req.body || {};
    if (!isUuid(b.locationId)) return res.status(400).json({ success: false, message: "Please select your delivery area" });
    const { data, error } = await supabase.rpc("issue_delivery_quote", { p_user_id: req.userId, p_location_id: b.locationId, p_unregistered: b.unregisteredName ? cleanName(b.unregisteredName).slice(0, 120) : null });
    if (error) throw error;
    if (!data.success) return res.status(422).json({ success: false, code: data.code, message: data.message });
    res.json({ success: true, data: { quoteId: data.quote_id, fee: Number(data.fee), currency: "NGN", expiresAt: data.expires_at } });
  } catch (e) { serverError(res, "quote", e); }
});

module.exports = { adminRouter, customerRouter };
