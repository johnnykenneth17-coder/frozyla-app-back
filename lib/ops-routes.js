// ============================================
// OPERATIONS CENTER - Live health & activity feed
// Mount at /api/admin/ops in server.js
// ============================================

const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");

const {
  authMiddleware,
  staffMiddleware,
} = require("../../middleware/auth");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY,
);

router.use(authMiddleware, staffMiddleware);

// How long an order can sit in "processing" before it's flagged as stuck
const STUCK_ORDER_MINUTES = 30;

// ===== HEALTH =====
// Queue depths + a DB round-trip check. Cheap enough to poll every 30-60s.
router.get("/health", async (req, res) => {
  const dbCheckStart = Date.now();
  try {
    const { error: pingError } = await supabase
      .from("users")
      .select("id", { count: "exact", head: true });
    const dbLatencyMs = Date.now() - dbCheckStart;
    const dbOk = !pingError;

    const [
      pendingFunding,
      openTickets,
      urgentTickets,
      discrepancies,
      stuckOrders,
    ] = await Promise.all([
      supabase
        .from("card_funding_requests")
        .select("*", { count: "exact", head: true })
        .eq("status", "pending"),
      supabase
        .from("support_tickets")
        .select("*", { count: "exact", head: true })
        .in("status", ["open", "in_progress"]),
      supabase
        .from("support_tickets")
        .select("*", { count: "exact", head: true })
        .eq("priority", "urgent")
        .in("status", ["open", "in_progress"]),
      supabase
        .from("account_ledger")
        .select("*", { count: "exact", head: true })
        .eq("status", "flagged"),
      supabase
        .from("orders")
        .select("*", { count: "exact", head: true })
        .eq("status", "processing")
        .lt(
          "created_at",
          new Date(Date.now() - STUCK_ORDER_MINUTES * 60 * 1000).toISOString(),
        ),
    ]);

    const queues = {
      pending_funding_requests: pendingFunding.count || 0,
      open_support_tickets: openTickets.count || 0,
      urgent_support_tickets: urgentTickets.count || 0,
      ledger_discrepancies: discrepancies.count || 0,
      stuck_orders: stuckOrders.count || 0,
    };

    // Simple traffic-light status: red if anything urgent/flagged is piling up
    let status = "healthy";
    if (
      queues.urgent_support_tickets > 0 ||
      queues.ledger_discrepancies > 0 ||
      queues.stuck_orders > 0
    ) {
      status = "attention";
    }
    if (!dbOk) status = "down";

    res.json({
      success: true,
      status,
      checked_at: new Date().toISOString(),
      database: { ok: dbOk, latency_ms: dbLatencyMs },
      queues,
    });
  } catch (error) {
    console.error("Ops health error:", error);
    res.status(500).json({
      success: false,
      status: "down",
      message: "Failed to load system health",
    });
  }
});

// ===== ACTIVITY FEED =====
// Merged, most-recent-first feed of orders / funding requests / tickets
router.get("/activity", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);

    const [ordersRes, fundingRes, ticketsRes] = await Promise.all([
      supabase
        .from("orders")
        .select("id,user_id,total,status,created_at")
        .order("created_at", { ascending: false })
        .limit(limit),
      supabase
        .from("card_funding_requests")
        .select("id,user_id,amount,status,requested_at")
        .order("requested_at", { ascending: false })
        .limit(limit),
      supabase
        .from("support_tickets")
        .select("id,user_id,subject,status,priority,created_at")
        .order("created_at", { ascending: false })
        .limit(limit),
    ]);

    if (ordersRes.error) throw ordersRes.error;
    if (fundingRes.error) throw fundingRes.error;
    if (ticketsRes.error) throw ticketsRes.error;

    const events = [
      ...(ordersRes.data || []).map((o) => ({
        type: "order",
        id: o.id,
        user_id: o.user_id,
        summary: `Order #${o.id} · ₦${Number(o.total).toFixed(2)}`,
        status: o.status,
        timestamp: o.created_at,
      })),
      ...(fundingRes.data || []).map((f) => ({
        type: "funding_request",
        id: f.id,
        user_id: f.user_id,
        summary: `Funding request · ₦${Number(f.amount).toFixed(2)}`,
        status: f.status,
        timestamp: f.requested_at,
      })),
      ...(ticketsRes.data || []).map((t) => ({
        type: "support_ticket",
        id: t.id,
        user_id: t.user_id,
        summary: t.subject,
        status: t.status,
        priority: t.priority,
        timestamp: t.created_at,
      })),
    ]
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, limit);

    res.json({ success: true, activity: events });
  } catch (error) {
    console.error("Ops activity error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to load activity feed",
    });
  }
});

module.exports = router;