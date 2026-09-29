// ============================================
// ANALYTICS PLATFORM - Read-only reporting API
// Mount at /api/admin/analytics in server.js
// ============================================

const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");

const {
  authMiddleware,
  staffMiddleware,
} = require("../middleware/auth");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY,
);

// All analytics endpoints require staff-level access (admin/manager/staff)
router.use(authMiddleware, staffMiddleware);

// ===== HELPERS =====

// Resolve a period string into a start Date (null = all-time)
function getPeriodStart(period) {
  const now = new Date();
  switch (period) {
    case "today": {
      const d = new Date(now);
      d.setHours(0, 0, 0, 0);
      return d;
    }
    case "week":
    case "7d":
      return new Date(now - 7 * 24 * 60 * 60 * 1000);
    case "month":
    case "30d":
      return new Date(now - 30 * 24 * 60 * 60 * 1000);
    case "90d":
      return new Date(now - 90 * 24 * 60 * 60 * 1000);
    case "year":
    case "365d":
      return new Date(now - 365 * 24 * 60 * 60 * 1000);
    case "all":
      return null;
    default:
      return new Date(now - 30 * 24 * 60 * 60 * 1000);
  }
}

// Pull every row for a query, paging past Supabase's default 1000-row cap
async function fetchAll(queryFactory, pageSize = 1000) {
  let all = [];
  let from = 0;
  while (true) {
    const { data, error } = await queryFactory().range(
      from,
      from + pageSize - 1,
    );
    if (error) throw error;
    if (!data || data.length === 0) break;
    all = all.concat(data);
    if (data.length < pageSize) break;
    from += pageSize;
  }
  return all;
}

// Bucket an array of rows by day (YYYY-MM-DD) using a date field, filling gaps with zeros
function bucketByDay(rows, dateField, start, valueFn) {
  const buckets = {};
  const end = new Date();
  const cursor = new Date(start);
  cursor.setHours(0, 0, 0, 0);
  while (cursor <= end) {
    buckets[cursor.toISOString().slice(0, 10)] = 0;
    cursor.setDate(cursor.getDate() + 1);
  }
  for (const row of rows) {
    const day = new Date(row[dateField]).toISOString().slice(0, 10);
    if (!(day in buckets)) buckets[day] = 0;
    buckets[day] += valueFn(row);
  }
  return Object.entries(buckets)
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([date, value]) => ({ date, value }));
}

// ===== OVERVIEW =====
// Single-call summary for the dashboard header cards
router.get("/overview", async (req, res) => {
  try {
    const period = req.query.period || "month";
    const since = getPeriodStart(period);

    let ordersQuery = () =>
      supabase.from("orders").select("id,total,status,created_at");
    if (since) {
      const s = since.toISOString();
      ordersQuery = () =>
        supabase
          .from("orders")
          .select("id,total,status,created_at")
          .gte("created_at", s);
    }
    const orders = await fetchAll(ordersQuery);

    const ordersByStatus = orders.reduce((acc, o) => {
      acc[o.status] = (acc[o.status] || 0) + 1;
      return acc;
    }, {});

    const deliveredOrders = orders.filter((o) => o.status === "delivered");
    const revenue = deliveredOrders.reduce(
      (sum, o) => sum + Number(o.total),
      0,
    );
    const avgOrderValue =
      deliveredOrders.length > 0 ? revenue / deliveredOrders.length : 0;

    // New customers in period
    let newCustomersCount = 0;
    if (since) {
      const { count, error } = await supabase
        .from("users")
        .select("*", { count: "exact", head: true })
        .eq("role", "user")
        .gte("created_at", since.toISOString());
      if (error) throw error;
      newCustomersCount = count || 0;
    }

    const { count: totalCustomers, error: totalCustErr } = await supabase
      .from("users")
      .select("*", { count: "exact", head: true })
      .eq("role", "user");
    if (totalCustErr) throw totalCustErr;

    // Wallet funding volume in period (completed funding credits)
    let walletQuery = () =>
      supabase
        .from("wallet_transactions")
        .select("amount,category,status,created_at")
        .eq("category", "funding")
        .eq("status", "completed");
    if (since) {
      const s = since.toISOString();
      walletQuery = () =>
        supabase
          .from("wallet_transactions")
          .select("amount,category,status,created_at")
          .eq("category", "funding")
          .eq("status", "completed")
          .gte("created_at", s);
    }
    const fundingTx = await fetchAll(walletQuery);
    const walletFundingVolume = fundingTx.reduce(
      (sum, t) => sum + Number(t.amount),
      0,
    );

    // Operational queues (all-time, not period-bound)
    const { count: pendingFunding, error: pfErr } = await supabase
      .from("card_funding_requests")
      .select("*", { count: "exact", head: true })
      .eq("status", "pending");
    if (pfErr) throw pfErr;

    const { count: openTickets, error: otErr } = await supabase
      .from("support_tickets")
      .select("*", { count: "exact", head: true })
      .in("status", ["open", "in_progress"]);
    if (otErr) throw otErr;

    const { count: discrepancies, error: dErr } = await supabase
      .from("account_ledger")
      .select("*", { count: "exact", head: true })
      .eq("status", "flagged");
    if (dErr) throw dErr;

    res.json({
      success: true,
      period,
      overview: {
        total_orders: orders.length,
        orders_by_status: ordersByStatus,
        revenue,
        avg_order_value: avgOrderValue,
        new_customers: newCustomersCount,
        total_customers: totalCustomers || 0,
        wallet_funding_volume: walletFundingVolume,
        pending_funding_requests: pendingFunding || 0,
        open_support_tickets: openTickets || 0,
        ledger_discrepancies: discrepancies || 0,
      },
    });
  } catch (error) {
    console.error("Analytics overview error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to load analytics overview",
    });
  }
});

// ===== REVENUE SERIES (for the revenue chart) =====
router.get("/revenue-series", async (req, res) => {
  try {
    const period = req.query.period || "30d";
    const since = getPeriodStart(period) || getPeriodStart("90d");
    const s = since.toISOString();

    const orders = await fetchAll(() =>
      supabase
        .from("orders")
        .select("total,status,created_at")
        .gte("created_at", s),
    );

    const revenueSeries = bucketByDay(
      orders.filter((o) => o.status === "delivered"),
      "created_at",
      since,
      (o) => Number(o.total),
    );
    const orderCountSeries = bucketByDay(orders, "created_at", since, () => 1);

    res.json({
      success: true,
      period,
      revenue: revenueSeries,
      orders: orderCountSeries,
    });
  } catch (error) {
    console.error("Revenue series error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to load revenue series",
    });
  }
});

// ===== TOP PRODUCTS =====
router.get("/products/top", async (req, res) => {
  try {
    const period = req.query.period || "month";
    const limit = Math.min(parseInt(req.query.limit, 10) || 10, 50);
    const since = getPeriodStart(period);

    let query = () => supabase.from("orders").select("items,status,created_at");
    if (since) {
      const s = since.toISOString();
      query = () =>
        supabase
          .from("orders")
          .select("items,status,created_at")
          .gte("created_at", s);
    }
    const orders = await fetchAll(query);

    const tally = {};
    for (const order of orders) {
      if (order.status === "cancelled") continue;
      const items = Array.isArray(order.items) ? order.items : [];
      for (const item of items) {
        const key = item.id || item.name;
        if (!key) continue;
        if (!tally[key]) {
          tally[key] = {
            id: item.id || key,
            name: item.name || "Unknown item",
            quantity: 0,
            revenue: 0,
          };
        }
        const qty = Number(item.quantity) || 0;
        const price = Number(item.price) || 0;
        tally[key].quantity += qty;
        tally[key].revenue += qty * price;
      }
    }

    const topProducts = Object.values(tally)
      .sort((a, b) => b.revenue - a.revenue)
      .slice(0, limit);

    res.json({ success: true, period, products: topProducts });
  } catch (error) {
    console.error("Top products error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to load top products",
    });
  }
});

// ===== CUSTOMER GROWTH =====
router.get("/customers/growth", async (req, res) => {
  try {
    const period = req.query.period || "30d";
    const since = getPeriodStart(period) || getPeriodStart("90d");
    const s = since.toISOString();

    const newUsers = await fetchAll(() =>
      supabase
        .from("users")
        .select("id,created_at")
        .eq("role", "user")
        .gte("created_at", s),
    );
    const signupSeries = bucketByDay(newUsers, "created_at", since, () => 1);

    // Repeat purchase rate among customers who ordered in the period
    const orders = await fetchAll(() =>
      supabase
        .from("orders")
        .select("user_id,created_at")
        .gte("created_at", s),
    );
    const ordersByUser = {};
    for (const o of orders) {
      if (!o.user_id) continue;
      ordersByUser[o.user_id] = (ordersByUser[o.user_id] || 0) + 1;
    }
    const activeCustomers = Object.keys(ordersByUser).length;
    const repeatCustomers = Object.values(ordersByUser).filter(
      (c) => c > 1,
    ).length;
    const repeatRate =
      activeCustomers > 0 ? (repeatCustomers / activeCustomers) * 100 : 0;

    res.json({
      success: true,
      period,
      signups: signupSeries,
      active_customers: activeCustomers,
      repeat_customers: repeatCustomers,
      repeat_purchase_rate: Math.round(repeatRate * 10) / 10,
    });
  } catch (error) {
    console.error("Customer growth error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to load customer growth",
    });
  }
});

// ===== WALLET / FUNDING ANALYTICS =====
router.get("/wallet", async (req, res) => {
  try {
    const period = req.query.period || "30d";
    const since = getPeriodStart(period) || getPeriodStart("90d");
    const s = since.toISOString();

    const transactions = await fetchAll(() =>
      supabase
        .from("wallet_transactions")
        .select("transaction_type,amount,status,created_at")
        .eq("status", "completed")
        .gte("created_at", s),
    );

    const creditsSeries = bucketByDay(
      transactions.filter((t) => t.transaction_type === "credit"),
      "created_at",
      since,
      (t) => Number(t.amount),
    );
    const debitsSeries = bucketByDay(
      transactions.filter((t) => t.transaction_type === "debit"),
      "created_at",
      since,
      (t) => Number(t.amount),
    );

    const fundingRequests = await fetchAll(() =>
      supabase
        .from("card_funding_requests")
        .select("status,amount,requested_at,processed_at")
        .gte("requested_at", s),
    );

    const approved = fundingRequests.filter((f) => f.status === "approved");
    const rejected = fundingRequests.filter((f) => f.status === "rejected");
    const totalDecided = approved.length + rejected.length;
    const approvalRate =
      totalDecided > 0 ? (approved.length / totalDecided) * 100 : 0;

    const processingTimes = approved
      .filter((f) => f.processed_at)
      .map(
        (f) =>
          (new Date(f.processed_at) - new Date(f.requested_at)) / 60000, // minutes
      );
    const avgProcessingMinutes =
      processingTimes.length > 0
        ? processingTimes.reduce((a, b) => a + b, 0) / processingTimes.length
        : 0;

    res.json({
      success: true,
      period,
      credits: creditsSeries,
      debits: debitsSeries,
      funding_requests: {
        total: fundingRequests.length,
        approved: approved.length,
        rejected: rejected.length,
        pending: fundingRequests.filter((f) => f.status === "pending").length,
        approval_rate: Math.round(approvalRate * 10) / 10,
        avg_processing_minutes: Math.round(avgProcessingMinutes),
      },
    });
  } catch (error) {
    console.error("Wallet analytics error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to load wallet analytics",
    });
  }
});

module.exports = router;