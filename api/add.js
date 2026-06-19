// ============================================
// SUPPORT SYSTEM ROUTES
// ============================================

// ===== USER SUPPORT ROUTES =====

// Create a new support ticket
app.post("/api/support/tickets", authMiddleware, async (req, res) => {
  try {
    const { subject, message } = req.body;

    if (!subject || !message) {
      return res.status(400).json({
        success: false,
        message: "Subject and message are required"
      });
    }

    // Create ticket
    const ticketId = uuidv4();
    const { data: ticket, error: ticketError } = await supabase
      .from("support_tickets")
      .insert([{
        id: ticketId,
        user_id: req.userId,
        subject: subject,
        status: "open",
        priority: "normal",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (ticketError) throw ticketError;

    // Create initial message
    const { error: messageError } = await supabase
      .from("support_messages")
      .insert([{
        ticket_id: ticketId,
        sender_id: req.userId,
        sender_type: "user",
        message: message,
        is_read: false,
        created_at: new Date().toISOString()
      }]);

    if (messageError) throw messageError;

    res.status(201).json({
      success: true,
      message: "Support ticket created",
      ticket: ticket
    });
  } catch (error) {
    console.error("Create ticket error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create support ticket"
    });
  }
});

// Get user's support tickets
app.get("/api/support/tickets", authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("support_tickets")
      .select(`
        *,
        messages:support_messages(
          id,
          message,
          sender_type,
          created_at,
          is_read
        )
      `)
      .eq("user_id", req.userId)
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({
      success: true,
      tickets: data || []
    });
  } catch (error) {
    console.error("Get tickets error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch tickets"
    });
  }
});

// Get a single ticket with all messages
app.get("/api/support/tickets/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Get ticket
    const { data: ticket, error: ticketError } = await supabase
      .from("support_tickets")
      .select("*")
      .eq("id", id)
      .eq("user_id", req.userId)
      .single();

    if (ticketError || !ticket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found"
      });
    }

    // Get messages
    const { data: messages, error: messagesError } = await supabase
      .from("support_messages")
      .select(`
        *,
        sender:users!sender_id(name, email)
      `)
      .eq("ticket_id", id)
      .order("created_at", { ascending: true });

    if (messagesError) throw messagesError;

    // Mark messages as read
    await supabase
      .from("support_messages")
      .update({ 
        is_read: true, 
        read_at: new Date().toISOString() 
      })
      .eq("ticket_id", id)
      .eq("sender_type", "admin")
      .eq("is_read", false);

    res.json({
      success: true,
      ticket: ticket,
      messages: messages || []
    });
  } catch (error) {
    console.error("Get ticket error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch ticket"
    });
  }
});

// Send a message to a ticket
app.post("/api/support/tickets/:id/messages", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        success: false,
        message: "Message is required"
      });
    }

    // Verify ticket belongs to user
    const { data: ticket, error: ticketError } = await supabase
      .from("support_tickets")
      .select("id, status")
      .eq("id", id)
      .eq("user_id", req.userId)
      .single();

    if (ticketError || !ticket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found"
      });
    }

    if (ticket.status === "closed") {
      return res.status(400).json({
        success: false,
        message: "This ticket is closed"
      });
    }

    // If ticket is resolved, reopen it
    let statusUpdate = {};
    if (ticket.status === "resolved") {
      statusUpdate.status = "in_progress";
    }

    // Create message
    const { data: newMessage, error: messageError } = await supabase
      .from("support_messages")
      .insert([{
        ticket_id: id,
        sender_id: req.userId,
        sender_type: "user",
        message: message,
        is_read: false,
        created_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (messageError) throw messageError;

    // Update ticket
    await supabase
      .from("support_tickets")
      .update({
        status: statusUpdate.status || ticket.status,
        updated_at: new Date().toISOString()
      })
      .eq("id", id);

    res.status(201).json({
      success: true,
      message: "Message sent",
      data: newMessage
    });
  } catch (error) {
    console.error("Send message error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to send message"
    });
  }
});

// ===== ADMIN SUPPORT ROUTES =====

// Get all tickets (admin only)
app.get("/api/admin/support/tickets", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { status, priority } = req.query;
    
    let query = supabase
      .from("support_tickets")
      .select(`
        *,
        user:users!user_id(name, email),
        messages:support_messages(
          id,
          message,
          sender_type,
          created_at,
          is_read
        )
      `)
      .order("created_at", { ascending: false });

    if (status && status !== "all") {
      query = query.eq("status", status);
    }

    if (priority && priority !== "all") {
      query = query.eq("priority", priority);
    }

    const { data, error } = await query;

    if (error) throw error;

    // Count unread messages for each ticket
    const ticketsWithUnread = (data || []).map(ticket => {
      const unreadCount = (ticket.messages || []).filter(
        m => !m.is_read && m.sender_type === "user"
      ).length;
      return {
        ...ticket,
        unread_count: unreadCount
      };
    });

    res.json({
      success: true,
      tickets: ticketsWithUnread
    });
  } catch (error) {
    console.error("Admin get tickets error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch tickets"
    });
  }
});

// Get a single ticket for admin
app.get("/api/admin/support/tickets/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: ticket, error: ticketError } = await supabase
      .from("support_tickets")
      .select(`
        *,
        user:users!user_id(name, email),
        messages:support_messages(
          *,
          sender:users!sender_id(name, email)
        )
      `)
      .eq("id", id)
      .single();

    if (ticketError || !ticket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found"
      });
    }

    // Mark unread user messages as read
    await supabase
      .from("support_messages")
      .update({ 
        is_read: true, 
        read_at: new Date().toISOString() 
      })
      .eq("ticket_id", id)
      .eq("sender_type", "user")
      .eq("is_read", false);

    // Update ticket status if open
    if (ticket.status === "open") {
      await supabase
        .from("support_tickets")
        .update({ 
          status: "in_progress",
          updated_at: new Date().toISOString()
        })
        .eq("id", id);
    }

    res.json({
      success: true,
      ticket: ticket
    });
  } catch (error) {
    console.error("Admin get ticket error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch ticket"
    });
  }
});

// Admin send message to ticket
app.post("/api/admin/support/tickets/:id/messages", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        success: false,
        message: "Message is required"
      });
    }

    const { data: ticket, error: ticketError } = await supabase
      .from("support_tickets")
      .select("id, status")
      .eq("id", id)
      .single();

    if (ticketError || !ticket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found"
      });
    }

    if (ticket.status === "closed") {
      return res.status(400).json({
        success: false,
        message: "This ticket is closed"
      });
    }

    // Create admin message
    const { data: newMessage, error: messageError } = await supabase
      .from("support_messages")
      .insert([{
        ticket_id: id,
        sender_id: req.userId,
        sender_type: "admin",
        message: message,
        is_read: false,
        created_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (messageError) throw messageError;

    // Update ticket status to in_progress if not resolved
    await supabase
      .from("support_tickets")
      .update({
        status: ticket.status === "resolved" ? "in_progress" : ticket.status,
        updated_at: new Date().toISOString()
      })
      .eq("id", id);

    res.status(201).json({
      success: true,
      message: "Reply sent",
      data: newMessage
    });
  } catch (error) {
    console.error("Admin send message error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to send reply"
    });
  }
});

// Update ticket status (admin)
app.patch("/api/admin/support/tickets/:id/status", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = ["open", "in_progress", "resolved", "closed"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid status"
      });
    }

    const updateData = {
      status: status,
      updated_at: new Date().toISOString()
    };

    if (status === "resolved") {
      updateData.resolved_at = new Date().toISOString();
    }

    if (status === "closed") {
      updateData.closed_at = new Date().toISOString();
    }

    const { data, error } = await supabase
      .from("support_tickets")
      .update(updateData)
      .eq("id", id)
      .select()
      .single();

    if (error || !data) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found"
      });
    }

    res.json({
      success: true,
      message: "Ticket status updated",
      ticket: data
    });
  } catch (error) {
    console.error("Update ticket status error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update ticket status"
    });
  }
});

// Get ticket stats (admin)
app.get("/api/admin/support/stats", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data: tickets, error } = await supabase
      .from("support_tickets")
      .select("status, priority");

    if (error) throw error;

    const stats = {
      total: tickets.length,
      open: tickets.filter(t => t.status === "open").length,
      in_progress: tickets.filter(t => t.status === "in_progress").length,
      resolved: tickets.filter(t => t.status === "resolved").length,
      closed: tickets.filter(t => t.status === "closed").length,
      high_priority: tickets.filter(t => t.priority === "high" || t.priority === "urgent").length
    };

    res.json({
      success: true,
      stats: stats
    });
  } catch (error) {
    console.error("Get support stats error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch stats"
    });
  }
});