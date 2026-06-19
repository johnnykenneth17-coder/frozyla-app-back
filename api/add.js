// ============================================
// COMPLETE STAFF MANAGEMENT ROUTES
// ============================================

// Get all staff members (users with staff roles)
app.get("/api/admin/staff", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("users")
      .select("id, email, name, role, phone, created_at, updated_at, last_login, status, delivery_instructions")
      .in("role", ["admin", "manager", "staff", "chef", "delivery", "support"])
      .order("created_at", { ascending: false });

    if (error) throw error;

    // Get staff statistics
    const staffWithStats = await Promise.all((data || []).map(async (staff) => {
      // Count orders handled by this staff
      const { count: orderCount, error: orderError } = await supabase
        .from("orders")
        .select("*", { count: 'exact', head: true })
        .eq("assigned_staff_id", staff.id);

      if (orderError) console.error('Order count error:', orderError);

      // Get last active time
      const lastActive = staff.last_login || staff.updated_at || staff.created_at;

      return {
        ...staff,
        order_count: orderCount || 0,
        last_active: lastActive
      };
    }));

    res.json({
      success: true,
      staff: staffWithStats
    });
  } catch (error) {
    console.error("Get staff error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch staff"
    });
  }
});

// Get single staff member
app.get("/api/admin/staff/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from("users")
      .select("id, email, name, role, phone, created_at, updated_at, last_login, status, delivery_instructions")
      .eq("id", id)
      .single();

    if (error || !data) {
      return res.status(404).json({
        success: false,
        message: "Staff member not found"
      });
    }

    // Get staff statistics
    const { count: orderCount, error: orderError } = await supabase
      .from("orders")
      .select("*", { count: 'exact', head: true })
      .eq("assigned_staff_id", id);

    const { count: resolvedTickets, error: ticketError } = await supabase
      .from("support_tickets")
      .select("*", { count: 'exact', head: true })
      .eq("assigned_to", id)
      .eq("status", "resolved");

    res.json({
      success: true,
      staff: {
        ...data,
        order_count: orderCount || 0,
        resolved_tickets: resolvedTickets || 0
      }
    });
  } catch (error) {
    console.error("Get staff error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch staff"
    });
  }
});

// Create staff member (admin only)
app.post("/api/admin/staff", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { email, password, name, role, phone, delivery_instructions } = req.body;

    // Validate required fields
    if (!email || !password || !name || !role) {
      return res.status(400).json({
        success: false,
        message: "Email, password, name, and role are required"
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email format"
      });
    }

    // Validate password length
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters"
      });
    }

    // Check if user exists
    const { data: existing, error: checkError } = await supabase
      .from("users")
      .select("id")
      .eq("email", email)
      .single();

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "User with this email already exists"
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userId = uuidv4();

    // Create staff user
    const { data, error } = await supabase
      .from("users")
      .insert([{
        id: userId,
        email: email.toLowerCase(),
        password: hashedPassword,
        name: name.trim(),
        role: role,
        phone: phone || null,
        delivery_instructions: delivery_instructions || null,
        status: 'active',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }])
      .select("id, email, name, role, phone, created_at, status")
      .single();

    if (error) {
      console.error("Create staff error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to create staff member: " + error.message
      });
    }

    res.status(201).json({
      success: true,
      message: "Staff member created successfully",
      staff: data
    });
  } catch (error) {
    console.error("Create staff error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create staff member"
    });
  }
});

// Update staff member
app.put("/api/admin/staff/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, role, phone, delivery_instructions, status } = req.body;

    // Verify staff exists
    const { data: existing, error: checkError } = await supabase
      .from("users")
      .select("id, role")
      .eq("id", id)
      .single();

    if (checkError || !existing) {
      return res.status(404).json({
        success: false,
        message: "Staff member not found"
      });
    }

    // Prevent changing own role to something lower
    if (id === req.userId && role && role !== existing.role) {
      return res.status(400).json({
        success: false,
        message: "You cannot change your own role"
      });
    }

    const updateData = {
      name: name || existing.name,
      role: role || existing.role,
      phone: phone || null,
      delivery_instructions: delivery_instructions || null,
      status: status || 'active',
      updated_at: new Date().toISOString()
    };

    const { data, error } = await supabase
      .from("users")
      .update(updateData)
      .eq("id", id)
      .select("id, email, name, role, phone, created_at, updated_at, status")
      .single();

    if (error) {
      console.error("Update staff error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to update staff member"
      });
    }

    res.json({
      success: true,
      message: "Staff member updated successfully",
      staff: data
    });
  } catch (error) {
    console.error("Update staff error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update staff member"
    });
  }
});

// Delete/Deactivate staff member (admin only)
app.delete("/api/admin/staff/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent deleting own account
    if (id === req.userId) {
      return res.status(400).json({
        success: false,
        message: "You cannot delete your own account"
      });
    }

    // Check if staff exists
    const { data: existing, error: checkError } = await supabase
      .from("users")
      .select("id, role")
      .eq("id", id)
      .single();

    if (checkError || !existing) {
      return res.status(404).json({
        success: false,
        message: "Staff member not found"
      });
    }

    // Soft delete - deactivate and demote to user
    const { error } = await supabase
      .from("users")
      .update({
        status: 'inactive',
        role: 'user', // Demote to regular user
        updated_at: new Date().toISOString()
      })
      .eq("id", id);

    if (error) {
      console.error("Delete staff error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to deactivate staff member"
      });
    }

    res.json({
      success: true,
      message: "Staff member deactivated successfully"
    });
  } catch (error) {
    console.error("Delete staff error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to deactivate staff member"
    });
  }
});

// Update staff role
app.patch("/api/admin/staff/:id/role", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    const validRoles = ["admin", "manager", "staff", "chef", "delivery", "support"];
    if (!validRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        message: "Invalid role. Must be one of: " + validRoles.join(", ")
      });
    }

    // Prevent changing own role
    if (id === req.userId) {
      return res.status(400).json({
        success: false,
        message: "You cannot change your own role"
      });
    }

    const { data, error } = await supabase
      .from("users")
      .update({
        role: role,
        updated_at: new Date().toISOString()
      })
      .eq("id", id)
      .select("id, email, name, role")
      .single();

    if (error || !data) {
      return res.status(404).json({
        success: false,
        message: "Staff member not found"
      });
    }

    res.json({
      success: true,
      message: "Staff role updated successfully",
      staff: data
    });
  } catch (error) {
    console.error("Update staff role error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update staff role"
    });
  }
});

// Update staff status (active/inactive/on_leave)
app.patch("/api/admin/staff/:id/status", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!['active', 'inactive', 'on_leave'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid status. Must be active, inactive, or on_leave"
      });
    }

    // Prevent deactivating own account
    if (id === req.userId && status !== 'active') {
      return res.status(400).json({
        success: false,
        message: "You cannot change your own status"
      });
    }

    const { data, error } = await supabase
      .from("users")
      .update({
        status: status,
        updated_at: new Date().toISOString()
      })
      .eq("id", id)
      .select("id, email, name, role, status")
      .single();

    if (error || !data) {
      return res.status(404).json({
        success: false,
        message: "Staff member not found"
      });
    }

    res.json({
      success: true,
      message: `Staff status updated to ${status}`,
      staff: data
    });
  } catch (error) {
    console.error("Update staff status error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update staff status"
    });
  }
});

// Get staff performance metrics
app.get("/api/admin/staff/metrics", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { period = 'month' } = req.query;
    
    let dateFilter = new Date();
    if (period === 'week') {
      dateFilter.setDate(dateFilter.getDate() - 7);
    } else if (period === 'month') {
      dateFilter.setMonth(dateFilter.getMonth() - 1);
    } else if (period === 'year') {
      dateFilter.setFullYear(dateFilter.getFullYear() - 1);
    }

    // Get staff list
    const { data: staff, error: staffError } = await supabase
      .from("users")
      .select("id, name, email, role, status")
      .in("role", ["admin", "manager", "staff", "chef", "delivery", "support"]);

    if (staffError) throw staffError;

    // Get metrics for each staff member
    const metrics = await Promise.all((staff || []).map(async (member) => {
      // Orders handled
      const { count: ordersHandled, error: orderError } = await supabase
        .from("orders")
        .select("*", { count: 'exact', head: true })
        .eq("assigned_staff_id", member.id)
        .gte("created_at", dateFilter.toISOString());

      // Tickets resolved
      const { count: ticketsResolved, error: ticketError } = await supabase
        .from("support_tickets")
        .select("*", { count: 'exact', head: true })
        .eq("assigned_to", member.id)
        .eq("status", "resolved")
        .gte("resolved_at", dateFilter.toISOString());

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