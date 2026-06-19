// ============================================
// Frozyla Backend - Production Ready API
// ============================================

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const { v4: uuidv4 } = require("uuid");

// IMPORTANT: Fix the path to auth.js - it's now in ../middleware/auth.js
const {
  authMiddleware,
  adminMiddleware,
  staffMiddleware,
  signupUser,
  loginUser,
  getProfile,
  changePassword,
  refreshToken,
} = require("../middleware/auth");

const app = express();
const PORT = process.env.PORT || 5000;

// ===== SECURITY MIDDLEWARE =====
app.use(helmet());

// ===== CORS CONFIGURATION =====
const allowedOrigins = [
  "http://127.0.0.1:5500",
  "http://127.0.0.1:5501",
  "http://127.0.0.1:5502",
  "http://localhost:3000",
  "http://localhost:5000",
  "http://localhost:5500",
  "http://localhost:5501",
  "http://localhost:5502",
  "https://frozyla-app.vercel.app",
  "https://frozyla.vercel.app",
  "https://frozyla-app-back.vercel.app",
  // Add your production frontend URL here
  "https://your-frontend-domain.vercel.app",
];

// Enable CORS with proper configuration
app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);

      // Allow if origin is in the allowed list or in development
      if (
        allowedOrigins.indexOf(origin) !== -1 ||
        process.env.NODE_ENV === "development"
      ) {
        callback(null, true);
      } else {
        console.log(`CORS blocked origin: ${origin}`);
        callback(new Error(`Origin ${origin} not allowed by CORS`));
      }
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    credentials: true,
    maxAge: 86400, // 24 hours
  }),
);

// Handle preflight requests
app.options("*", cors());

// ===== RATE LIMITING =====
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later.",
});
app.use("/api", limiter);

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: "Too many authentication attempts, please try again later.",
});
app.use("/api/auth", authLimiter);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ===== SUPABASE INIT =====
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY,
);

// ===== HEALTH CHECK =====
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    version: "2.0.0",
  });
});

// ===== CORS TEST ENDPOINT =====
app.get("/api/cors-test", (req, res) => {
  res.json({
    success: true,
    message: "CORS is working!",
    origin: req.headers.origin || "No origin",
    timestamp: new Date().toISOString(),
  });
});

// ===== AUTH ROUTES =====
app.post("/api/auth/signup", signupUser);
app.post("/api/auth/login", loginUser);
app.get("/api/auth/profile", authMiddleware, getProfile);
app.post("/api/auth/change-password", authMiddleware, changePassword);
app.post("/api/auth/refresh", authMiddleware, refreshToken);

// ===== ADMIN ROUTES =====
app.get(
  "/api/admin/users",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("users")
        .select("id, email, name, role, created_at, last_login")
        .order("created_at", { ascending: false });

      if (error) throw error;
      res.json({ success: true, users: data || [] });
    } catch (error) {
      console.error("Admin users error:", error);
      res
        .status(500)
        .json({ success: false, message: "Failed to fetch users" });
    }
  },
);

app.patch(
  "/api/admin/users/:id/role",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role } = req.body;
      const validRoles = ["user", "admin", "manager", "staff"];

      if (!validRoles.includes(role)) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid role" });
      }

      if (id === req.userId) {
        return res
          .status(400)
          .json({ success: false, message: "Cannot change your own role" });
      }

      const { data, error } = await supabase
        .from("users")
        .update({ role, updated_at: new Date().toISOString() })
        .eq("id", id)
        .select("id, email, name, role")
        .single();

      if (error || !data) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      res.json({ success: true, message: "User role updated", user: data });
    } catch (error) {
      console.error("Admin role update error:", error);
      res
        .status(500)
        .json({ success: false, message: "Failed to update user role" });
    }
  },
);

// ===== MENU ROUTES =====
app.get("/api/menu", async (req, res) => {
  try {
    const { category } = req.query;
    let query = supabase.from("menu_items").select("*");

    if (category && category !== "all") {
      query = query.eq("category", category);
    }

    const { data, error } = await query.order("name");

    if (error) {
      console.error("Menu error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch menu",
        error: error.message,
      });
    }

    // REMOVED: Mock data fallback - Now properly handles empty database
    if (!data || data.length === 0) {
      return res.json({
        success: true,
        items: [],
        message: "No menu items found. Add items using the admin panel.",
      });
    }

    res.json({ success: true, items: data });
  } catch (error) {
    console.error("Menu error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
});

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
        message: "Subject and message are required",
      });
    }

    // Create ticket
    const ticketId = uuidv4();
    const { data: ticket, error: ticketError } = await supabase
      .from("support_tickets")
      .insert([
        {
          id: ticketId,
          user_id: req.userId,
          subject: subject,
          status: "open",
          priority: "normal",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ])
      .select()
      .single();

    if (ticketError) throw ticketError;

    // Create initial message
    const { error: messageError } = await supabase
      .from("support_messages")
      .insert([
        {
          ticket_id: ticketId,
          sender_id: req.userId,
          sender_type: "user",
          message: message,
          is_read: false,
          created_at: new Date().toISOString(),
        },
      ]);

    if (messageError) throw messageError;

    res.status(201).json({
      success: true,
      message: "Support ticket created",
      ticket: ticket,
    });
  } catch (error) {
    console.error("Create ticket error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create support ticket",
    });
  }
});

// Get user's support tickets
app.get("/api/support/tickets", authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("support_tickets")
      .select(
        `
        *,
        messages:support_messages(
          id,
          message,
          sender_type,
          created_at,
          is_read
        )
      `,
      )
      .eq("user_id", req.userId)
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({
      success: true,
      tickets: data || [],
    });
  } catch (error) {
    console.error("Get tickets error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch tickets",
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
        message: "Ticket not found",
      });
    }

    // Get messages
    const { data: messages, error: messagesError } = await supabase
      .from("support_messages")
      .select(
        `
        *,
        sender:users!sender_id(name, email)
      `,
      )
      .eq("ticket_id", id)
      .order("created_at", { ascending: true });

    if (messagesError) throw messagesError;

    // Mark messages as read
    await supabase
      .from("support_messages")
      .update({
        is_read: true,
        read_at: new Date().toISOString(),
      })
      .eq("ticket_id", id)
      .eq("sender_type", "admin")
      .eq("is_read", false);

    res.json({
      success: true,
      ticket: ticket,
      messages: messages || [],
    });
  } catch (error) {
    console.error("Get ticket error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch ticket",
    });
  }
});

// Send a message to a ticket
app.post(
  "/api/support/tickets/:id/messages",
  authMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { message } = req.body;

      if (!message) {
        return res.status(400).json({
          success: false,
          message: "Message is required",
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
          message: "Ticket not found",
        });
      }

      if (ticket.status === "closed") {
        return res.status(400).json({
          success: false,
          message: "This ticket is closed",
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
        .insert([
          {
            ticket_id: id,
            sender_id: req.userId,
            sender_type: "user",
            message: message,
            is_read: false,
            created_at: new Date().toISOString(),
          },
        ])
        .select()
        .single();

      if (messageError) throw messageError;

      // Update ticket
      await supabase
        .from("support_tickets")
        .update({
          status: statusUpdate.status || ticket.status,
          updated_at: new Date().toISOString(),
        })
        .eq("id", id);

      res.status(201).json({
        success: true,
        message: "Message sent",
        data: newMessage,
      });
    } catch (error) {
      console.error("Send message error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to send message",
      });
    }
  },
);

// ===== ADMIN SUPPORT ROUTES =====

// Get all tickets (admin only)
app.get(
  "/api/admin/support/tickets",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { status, priority } = req.query;

      let query = supabase
        .from("support_tickets")
        .select(
          `
        *,
        user:users!user_id(name, email),
        messages:support_messages(
          id,
          message,
          sender_type,
          created_at,
          is_read
        )
      `,
        )
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
      const ticketsWithUnread = (data || []).map((ticket) => {
        const unreadCount = (ticket.messages || []).filter(
          (m) => !m.is_read && m.sender_type === "user",
        ).length;
        return {
          ...ticket,
          unread_count: unreadCount,
        };
      });

      res.json({
        success: true,
        tickets: ticketsWithUnread,
      });
    } catch (error) {
      console.error("Admin get tickets error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch tickets",
      });
    }
  },
);

// Get a single ticket for admin
app.get(
  "/api/admin/support/tickets/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { data: ticket, error: ticketError } = await supabase
        .from("support_tickets")
        .select(
          `
        *,
        user:users!user_id(name, email),
        messages:support_messages(
          *,
          sender:users!sender_id(name, email)
        )
      `,
        )
        .eq("id", id)
        .single();

      if (ticketError || !ticket) {
        return res.status(404).json({
          success: false,
          message: "Ticket not found",
        });
      }

      // Mark unread user messages as read
      await supabase
        .from("support_messages")
        .update({
          is_read: true,
          read_at: new Date().toISOString(),
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
            updated_at: new Date().toISOString(),
          })
          .eq("id", id);
      }

      res.json({
        success: true,
        ticket: ticket,
      });
    } catch (error) {
      console.error("Admin get ticket error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch ticket",
      });
    }
  },
);

// Admin send message to ticket
app.post(
  "/api/admin/support/tickets/:id/messages",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { message } = req.body;

      if (!message) {
        return res.status(400).json({
          success: false,
          message: "Message is required",
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
          message: "Ticket not found",
        });
      }

      if (ticket.status === "closed") {
        return res.status(400).json({
          success: false,
          message: "This ticket is closed",
        });
      }

      // Create admin message
      const { data: newMessage, error: messageError } = await supabase
        .from("support_messages")
        .insert([
          {
            ticket_id: id,
            sender_id: req.userId,
            sender_type: "admin",
            message: message,
            is_read: false,
            created_at: new Date().toISOString(),
          },
        ])
        .select()
        .single();

      if (messageError) throw messageError;

      // Update ticket status to in_progress if not resolved
      await supabase
        .from("support_tickets")
        .update({
          status: ticket.status === "resolved" ? "in_progress" : ticket.status,
          updated_at: new Date().toISOString(),
        })
        .eq("id", id);

      res.status(201).json({
        success: true,
        message: "Reply sent",
        data: newMessage,
      });
    } catch (error) {
      console.error("Admin send message error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to send reply",
      });
    }
  },
);

// Update ticket status (admin)
app.patch(
  "/api/admin/support/tickets/:id/status",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      const validStatuses = ["open", "in_progress", "resolved", "closed"];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid status",
        });
      }

      const updateData = {
        status: status,
        updated_at: new Date().toISOString(),
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
          message: "Ticket not found",
        });
      }

      res.json({
        success: true,
        message: "Ticket status updated",
        ticket: data,
      });
    } catch (error) {
      console.error("Update ticket status error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update ticket status",
      });
    }
  },
);

// Get ticket stats (admin)
app.get(
  "/api/admin/support/stats",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { data: tickets, error } = await supabase
        .from("support_tickets")
        .select("status, priority");

      if (error) throw error;

      const stats = {
        total: tickets.length,
        open: tickets.filter((t) => t.status === "open").length,
        in_progress: tickets.filter((t) => t.status === "in_progress").length,
        resolved: tickets.filter((t) => t.status === "resolved").length,
        closed: tickets.filter((t) => t.status === "closed").length,
        high_priority: tickets.filter(
          (t) => t.priority === "high" || t.priority === "urgent",
        ).length,
      };

      res.json({
        success: true,
        stats: stats,
      });
    } catch (error) {
      console.error("Get support stats error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch stats",
      });
    }
  },
);

// ============================================
// ADDRESS MANAGEMENT ROUTES
// ============================================

// ===== USER ADDRESS ROUTES =====

// Get all user addresses
app.get("/api/addresses", authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("user_addresses")
      .select("*")
      .eq("user_id", req.userId)
      .order("is_default", { ascending: false })
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({
      success: true,
      addresses: data || []
    });
  } catch (error) {
    console.error("Get addresses error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch addresses"
    });
  }
});

// Add new address
app.post("/api/addresses", authMiddleware, async (req, res) => {
  try {
    const { 
      address_line1, 
      address_line2, 
      city, 
      state, 
      zip_code, 
      country,
      address_type,
      is_default,
      latitude,
      longitude,
      place_id,
      formatted_address
    } = req.body;

    if (!address_line1 || !city || !state || !zip_code) {
      return res.status(400).json({
        success: false,
        message: "Address line 1, city, state, and zip code are required"
      });
    }

    // If this is set as default, unset other defaults
    if (is_default) {
      await supabase
        .from("user_addresses")
        .update({ is_default: false })
        .eq("user_id", req.userId);
    }

    const { data, error } = await supabase
      .from("user_addresses")
      .insert([{
        user_id: req.userId,
        address_line1,
        address_line2: address_line2 || null,
        city,
        state,
        zip_code,
        country: country || 'USA',
        address_type: address_type || 'home',
        is_default: is_default || false,
        latitude: latitude || null,
        longitude: longitude || null,
        place_id: place_id || null,
        formatted_address: formatted_address || null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Address added successfully",
      address: data
    });
  } catch (error) {
    console.error("Add address error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to add address"
    });
  }
});

// Update address
app.put("/api/addresses/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      address_line1, 
      address_line2, 
      city, 
      state, 
      zip_code, 
      country,
      address_type,
      is_default,
      latitude,
      longitude,
      place_id,
      formatted_address
    } = req.body;

    // Verify address belongs to user
    const { data: existing, error: checkError } = await supabase
      .from("user_addresses")
      .select("id")
      .eq("id", id)
      .eq("user_id", req.userId)
      .single();

    if (checkError || !existing) {
      return res.status(404).json({
        success: false,
        message: "Address not found"
      });
    }

    // If this is set as default, unset other defaults
    if (is_default) {
      await supabase
        .from("user_addresses")
        .update({ is_default: false })
        .eq("user_id", req.userId)
        .neq("id", id);
    }

    const updateData = {
      address_line1,
      address_line2: address_line2 || null,
      city,
      state,
      zip_code,
      country: country || 'USA',
      address_type: address_type || 'home',
      is_default: is_default || false,
      latitude: latitude || null,
      longitude: longitude || null,
      place_id: place_id || null,
      formatted_address: formatted_address || null,
      updated_at: new Date().toISOString()
    };

    const { data, error } = await supabase
      .from("user_addresses")
      .update(updateData)
      .eq("id", id)
      .select()
      .single();

    if (error) throw error;

    res.json({
      success: true,
      message: "Address updated successfully",
      address: data
    });
  } catch (error) {
    console.error("Update address error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update address"
    });
  }
});

// Delete address
app.delete("/api/addresses/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase
      .from("user_addresses")
      .delete()
      .eq("id", id)
      .eq("user_id", req.userId);

    if (error) throw error;

    res.json({
      success: true,
      message: "Address deleted successfully"
    });
  } catch (error) {
    console.error("Delete address error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete address"
    });
  }
});

// Set default address
app.patch("/api/addresses/:id/default", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Verify address belongs to user
    const { data: existing, error: checkError } = await supabase
      .from("user_addresses")
      .select("id")
      .eq("id", id)
      .eq("user_id", req.userId)
      .single();

    if (checkError || !existing) {
      return res.status(404).json({
        success: false,
        message: "Address not found"
      });
    }

    // Unset all defaults
    await supabase
      .from("user_addresses")
      .update({ is_default: false })
      .eq("user_id", req.userId);

    // Set this as default
    const { data, error } = await supabase
      .from("user_addresses")
      .update({ 
        is_default: true,
        updated_at: new Date().toISOString()
      })
      .eq("id", id)
      .select()
      .single();

    if (error) throw error;

    res.json({
      success: true,
      message: "Default address updated",
      address: data
    });
  } catch (error) {
    console.error("Set default address error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to set default address"
    });
  }
});

// ===== ORDER DELIVERY ROUTES =====

// Update order with delivery details
app.patch("/api/orders/:id/delivery", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      delivery_phone,
      delivery_instructions,
      delivery_address,
      delivery_latitude,
      delivery_longitude,
      delivery_place_id,
      delivery_formatted_address
    } = req.body;

    // Verify order belongs to user
    const { data: order, error: checkError } = await supabase
      .from("orders")
      .select("id")
      .eq("id", id)
      .eq("user_id", req.userId)
      .single();

    if (checkError || !order) {
      return res.status(404).json({
        success: false,
        message: "Order not found"
      });
    }

    const updateData = {
      delivery_phone: delivery_phone || null,
      delivery_instructions: delivery_instructions || null,
      delivery_address: delivery_address || null,
      delivery_latitude: delivery_latitude || null,
      delivery_longitude: delivery_longitude || null,
      delivery_place_id: delivery_place_id || null,
      delivery_formatted_address: delivery_formatted_address || null,
      updated_at: new Date().toISOString()
    };

    const { data, error } = await supabase
      .from("orders")
      .update(updateData)
      .eq("id", id)
      .select()
      .single();

    if (error) throw error;

    res.json({
      success: true,
      message: "Delivery details updated",
      order: data
    });
  } catch (error) {
    console.error("Update delivery error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update delivery details"
    });
  }
});

// Update delivery status (admin only)
app.patch("/api/admin/orders/:id/delivery-status", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { delivery_status, tracking_id } = req.body;

    const validStatuses = ['pending', 'preparing', 'ready', 'out_for_delivery', 'delivered', 'failed'];
    if (!validStatuses.includes(delivery_status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid delivery status"
      });
    }

    const updateData = {
      delivery_status,
      updated_at: new Date().toISOString()
    };

    if (delivery_status === 'out_for_delivery') {
      updateData.estimated_delivery_time = new Date(Date.now() + 30 * 60000); // 30 minutes from now
    }

    if (delivery_status === 'delivered') {
      updateData.actual_delivery_time = new Date().toISOString();
    }

    if (tracking_id) {
      updateData.delivery_tracking_id = tracking_id;
    }

    const { data, error } = await supabase
      .from("orders")
      .update(updateData)
      .eq("id", id)
      .select()
      .single();

    if (error || !data) {
      return res.status(404).json({
        success: false,
        message: "Order not found"
      });
    }

    res.json({
      success: true,
      message: "Delivery status updated",
      order: data
    });
  } catch (error) {
    console.error("Update delivery status error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update delivery status"
    });
  }
});

// Get delivery tracking info
app.get("/api/orders/:id/track", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    let query = supabase
      .from("orders")
      .select("id, delivery_status, delivery_address, delivery_formatted_address, delivery_latitude, delivery_longitude, estimated_delivery_time, actual_delivery_time, delivery_tracking_id, status, created_at, total")
      .eq("id", id);

    // Non-admin users can only see their own orders
    if (req.userRole !== 'admin') {
      query = query.eq("user_id", req.userId);
    }

    const { data, error } = await query.single();

    if (error || !data) {
      return res.status(404).json({
        success: false,
        message: "Order not found"
      });
    }

    res.json({
      success: true,
      tracking: data
    });
  } catch (error) {
    console.error("Track order error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to get tracking info"
    });
  }
});

// ===== ADMIN MENU ROUTES =====
app.post(
  "/api/admin/menu",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { name, description, price, category, image_url } = req.body;

      if (!name || !price || !category) {
        return res.status(400).json({
          success: false,
          message: "Name, price, and category are required",
        });
      }

      const itemId = `item_${Date.now()}`;
      const { data, error } = await supabase
        .from("menu_items")
        .insert([
          {
            id: itemId,
            name,
            description: description || "",
            price: parseFloat(price),
            category,
            image_url: image_url || null,
            created_at: new Date().toISOString(),
          },
        ])
        .select()
        .single();

      if (error) throw error;

      res.status(201).json({
        success: true,
        message: "Menu item created",
        item: data,
      });
    } catch (error) {
      console.error("Menu creation error:", error);
      res
        .status(500)
        .json({ success: false, message: "Failed to create menu item" });
    }
  },
);

app.patch(
  "/api/admin/menu/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, description, price, category, image_url } = req.body;

      const updateData = {};
      if (name) updateData.name = name;
      if (description !== undefined) updateData.description = description;
      if (price) updateData.price = parseFloat(price);
      if (category) updateData.category = category;
      if (image_url !== undefined) updateData.image_url = image_url;
      updateData.updated_at = new Date().toISOString();

      const { data, error } = await supabase
        .from("menu_items")
        .update(updateData)
        .eq("id", id)
        .select()
        .single();

      if (error || !data) {
        return res
          .status(404)
          .json({ success: false, message: "Menu item not found" });
      }

      res.json({ success: true, message: "Menu item updated", item: data });
    } catch (error) {
      console.error("Menu update error:", error);
      res
        .status(500)
        .json({ success: false, message: "Failed to update menu item" });
    }
  },
);

app.delete(
  "/api/admin/menu/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { error } = await supabase.from("menu_items").delete().eq("id", id);

      if (error) throw error;

      res.json({ success: true, message: "Menu item deleted" });
    } catch (error) {
      console.error("Menu delete error:", error);
      res
        .status(500)
        .json({ success: false, message: "Failed to delete menu item" });
    }
  },
);

// ===== ADMIN USER DETAILS ROUTE =====
app.get(
  "/api/admin/users/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { data, error } = await supabase
        .from("users")
        .select("id, email, name, role, phone, created_at, last_login")
        .eq("id", id)
        .single();

      if (error || !data) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      res.json({
        success: true,
        user: data,
      });
    } catch (error) {
      console.error("Admin user details error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch user details",
      });
    }
  },
);

// ===== ORDERS ROUTES =====
app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const { items, total, delivery_address, notes } = req.body;

    if (!items || !items.length) {
      return res.status(400).json({
        success: false,
        message: "Order must contain items",
      });
    }

    const orderId = `FZ-${Date.now().toString().slice(-6)}`;
    const orderData = {
      id: orderId,
      user_id: req.userId,
      items: JSON.stringify(items),
      total: total || items.reduce((sum, i) => sum + i.price * i.quantity, 0),
      status: "processing",
      delivery_address: delivery_address || "Store pickup",
      notes: notes || "",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const { data, error } = await supabase
      .from("orders")
      .insert([orderData])
      .select()
      .single();

    if (error) {
      console.error("Order creation error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to create order",
      });
    }

    res.status(201).json({
      success: true,
      message: "Order created",
      order: data,
    });
  } catch (error) {
    console.error("Order error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

app.get("/api/orders", authMiddleware, async (req, res) => {
  try {
    let query = supabase
      .from("orders")
      .select("*")
      .order("created_at", { ascending: false });

    if (req.userRole !== "admin") {
      query = query.eq("user_id", req.userId);
    }

    const { data, error } = await query;

    if (error) {
      console.error("Orders fetch error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch orders",
      });
    }

    res.json({ success: true, orders: data || [] });
  } catch (error) {
    console.error("Orders error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

app.get("/api/orders/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    let query = supabase.from("orders").select("*").eq("id", id);

    if (req.userRole !== "admin") {
      query = query.eq("user_id", req.userId);
    }

    const { data, error } = await query.single();

    if (error || !data) {
      return res.status(404).json({
        success: false,
        message: "Order not found",
      });
    }

    res.json({ success: true, order: data });
  } catch (error) {
    console.error("Order fetch error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

app.patch("/api/orders/:id/status", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const validStatuses = [
      "processing",
      "preparing",
      "ready",
      "delivered",
      "cancelled",
    ];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid status",
      });
    }

    let query = supabase
      .from("orders")
      .update({ status, updated_at: new Date().toISOString() })
      .eq("id", id);

    if (req.userRole !== "admin") {
      query = query.eq("user_id", req.userId);
    }

    const { data, error } = await query.select().single();

    if (error || !data) {
      return res.status(404).json({
        success: false,
        message: "Order not found",
      });
    }

    res.json({
      success: true,
      message: "Order updated",
      order: data,
    });
  } catch (error) {
    console.error("Order update error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

// ===== FAVORITES ROUTES =====
app.get("/api/favorites", authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("favorites")
      .select("*")
      .eq("user_id", req.userId);

    if (error) {
      console.error("Favorites error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch favorites",
      });
    }

    res.json({ success: true, favorites: data || [] });
  } catch (error) {
    console.error("Favorites error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

app.post("/api/favorites/toggle", authMiddleware, async (req, res) => {
  try {
    const { itemId } = req.body;
    if (!itemId) {
      return res.status(400).json({
        success: false,
        message: "Item ID required",
      });
    }

    const { data: existing } = await supabase
      .from("favorites")
      .select("id")
      .eq("user_id", req.userId)
      .eq("item_id", itemId)
      .single();

    if (existing) {
      const { error } = await supabase
        .from("favorites")
        .delete()
        .eq("id", existing.id);

      if (error) throw error;
      return res.json({
        success: true,
        message: "Favorite removed",
        favorited: false,
      });
    } else {
      const { data, error } = await supabase
        .from("favorites")
        .insert([
          {
            user_id: req.userId,
            item_id: itemId,
            created_at: new Date().toISOString(),
          },
        ])
        .select()
        .single();

      if (error) throw error;
      return res.json({
        success: true,
        message: "Favorite added",
        favorited: true,
        favorite: data,
      });
    }
  } catch (error) {
    console.error("Toggle favorite error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

// ===== 404 Handler =====
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

// ===== Global Error Handler =====
app.use((err, req, res, next) => {
  console.error("Global error:", err);
  res.status(500).json({
    success: false,
    message: "Internal server error",
  });
});

// ===== EXPORT FOR VERCEL =====
module.exports = app;
