// Get staff performance metrics - FIXED
app.get("/api/admin/staff/metrics", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { period = 'month' } = req.query;
    
    // Get staff list with proper roles
    const { data: staff, error: staffError } = await supabase
      .from("users")
      .select("id, name, email, role, status")
      .in("role", ["admin", "manager", "staff", "chef", "delivery", "support"]);

    if (staffError) {
      console.error('Staff fetch error:', staffError);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch staff"
      });
    }

    // If no staff found, return empty metrics
    if (!staff || staff.length === 0) {
      return res.json({
        success: true,
        metrics: {
          staff: [],
          summary: {
            total_staff: 0,
            active_staff: 0,
            total_orders_handled: 0,
            total_tickets_resolved: 0,
            period: period
          }
        }
      });
    }

    // Get metrics for each staff member
    const metrics = await Promise.all(staff.map(async (member) => {
      // Orders handled
      const { count: ordersHandled } = await supabase
        .from("orders")
        .select("*", { count: 'exact', head: true })
        .eq("assigned_staff_id", member.id);

      // Tickets resolved
      const { count: ticketsResolved } = await supabase
        .from("support_tickets")
        .select("*", { count: 'exact', head: true })
        .eq("assigned_to", member.id)
        .eq("status", "resolved");

      return {
        ...member,
        orders_handled: ordersHandled || 0,
        tickets_resolved: ticketsResolved || 0
      };
    }));

    // Calculate totals
    const totalStaff = metrics.length;
    const activeStaff = metrics.filter(m => m.status === 'active').length;
    const totalOrders = metrics.reduce((sum, m) => sum + (m.orders_handled || 0), 0);
    const totalTickets = metrics.reduce((sum, m) => sum + (m.tickets_resolved || 0), 0);

    res.json({
      success: true,
      metrics: {
        staff: metrics,
        summary: {
          total_staff: totalStaff,
          active_staff: activeStaff,
          total_orders_handled: totalOrders,
          total_tickets_resolved: totalTickets,
          period: period
        }
      }
    });
  } catch (error) {
    console.error("Get staff metrics error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch staff metrics"
    });
  }
});