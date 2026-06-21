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
  generateAccountNumber,
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
/*const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later.",
});*/
const limiter = rateLimit({
  //windowMs: 15 * 60 * 1000, // 15 minutes
  windowMs: 60 * 1000,
  max: 5000, // 100 requests per 15 minutes
  message: {
    success: false,
    message: "Too many requests from this IP, please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

//app.use("/api", limiter);

app.use("/api", (req, res, next) => {
  // If authenticated, use auth limiter
  if (req.headers.authorization) {
    return authLimiter(req, res, next);
  }
  // Otherwise use general limiter
  return limiter(req, res, next);
});

const authLimiter = rateLimit({
  //windowMs: 10 * 60 * 1000,
  //max: 20,
  windowMs: 60 * 1000, // 1 minute
  max: 200,
  message: "Too many authentication attempts, please try again later.",
});
app.use("/api/auth", authLimiter);

// ✅ NEW: Very lenient limiter for admin users
const adminLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 200, // 200 requests per minute
  message: {
    success: false,
    message: "Admin rate limit exceeded.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Admin routes - more lenient
app.use("/api/admin", (req, res, next) => {
  return adminLimiter(req, res, next);
});

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
      addresses: data || [],
    });
  } catch (error) {
    console.error("Get addresses error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch addresses",
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
      formatted_address,
    } = req.body;

    if (!address_line1 || !city || !state || !zip_code) {
      return res.status(400).json({
        success: false,
        message: "Address line 1, city, state, and zip code are required",
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
      .insert([
        {
          user_id: req.userId,
          address_line1,
          address_line2: address_line2 || null,
          city,
          state,
          zip_code,
          country: country || "USA",
          address_type: address_type || "home",
          is_default: is_default || false,
          latitude: latitude || null,
          longitude: longitude || null,
          place_id: place_id || null,
          formatted_address: formatted_address || null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ])
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({
      success: true,
      message: "Address added successfully",
      address: data,
    });
  } catch (error) {
    console.error("Add address error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to add address",
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
      formatted_address,
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
        message: "Address not found",
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
      country: country || "USA",
      address_type: address_type || "home",
      is_default: is_default || false,
      latitude: latitude || null,
      longitude: longitude || null,
      place_id: place_id || null,
      formatted_address: formatted_address || null,
      updated_at: new Date().toISOString(),
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
      address: data,
    });
  } catch (error) {
    console.error("Update address error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update address",
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
      message: "Address deleted successfully",
    });
  } catch (error) {
    console.error("Delete address error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete address",
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
        message: "Address not found",
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
        updated_at: new Date().toISOString(),
      })
      .eq("id", id)
      .select()
      .single();

    if (error) throw error;

    res.json({
      success: true,
      message: "Default address updated",
      address: data,
    });
  } catch (error) {
    console.error("Set default address error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to set default address",
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
      delivery_formatted_address,
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
        message: "Order not found",
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
      updated_at: new Date().toISOString(),
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
      order: data,
    });
  } catch (error) {
    console.error("Update delivery error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update delivery details",
    });
  }
});

// Update delivery status (admin only)
app.patch(
  "/api/admin/orders/:id/delivery-status",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { delivery_status, tracking_id } = req.body;

      const validStatuses = [
        "pending",
        "preparing",
        "ready",
        "out_for_delivery",
        "delivered",
        "failed",
      ];
      if (!validStatuses.includes(delivery_status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid delivery status",
        });
      }

      const updateData = {
        delivery_status,
        updated_at: new Date().toISOString(),
      };

      if (delivery_status === "out_for_delivery") {
        updateData.estimated_delivery_time = new Date(Date.now() + 30 * 60000); // 30 minutes from now
      }

      if (delivery_status === "delivered") {
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
          message: "Order not found",
        });
      }

      res.json({
        success: true,
        message: "Delivery status updated",
        order: data,
      });
    } catch (error) {
      console.error("Update delivery status error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update delivery status",
      });
    }
  },
);

// Get delivery tracking info
app.get("/api/orders/:id/track", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    let query = supabase
      .from("orders")
      .select(
        "id, delivery_status, delivery_address, delivery_formatted_address, delivery_latitude, delivery_longitude, estimated_delivery_time, actual_delivery_time, delivery_tracking_id, status, created_at, total",
      )
      .eq("id", id);

    // Non-admin users can only see their own orders
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

    res.json({
      success: true,
      tracking: data,
    });
  } catch (error) {
    console.error("Track order error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to get tracking info",
    });
  }
});

// ============================================
// COMPLETE STAFF MANAGEMENT ROUTES
// ============================================

// Get all staff members (users with staff roles)
app.get(
  "/api/admin/staff",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("users")
        .select(
          "id, email, name, role, phone, created_at, updated_at, last_login, status, delivery_instructions",
        )
        .in("role", [
          "admin",
          "manager",
          "staff",
          "chef",
          "delivery",
          "support",
        ])
        .order("created_at", { ascending: false });

      if (error) throw error;

      // Get staff statistics
      const staffWithStats = await Promise.all(
        (data || []).map(async (staff) => {
          // Count orders handled by this staff
          const { count: orderCount, error: orderError } = await supabase
            .from("orders")
            .select("*", { count: "exact", head: true })
            .eq("assigned_staff_id", staff.id);

          if (orderError) console.error("Order count error:", orderError);

          // Get last active time
          const lastActive =
            staff.last_login || staff.updated_at || staff.created_at;

          return {
            ...staff,
            order_count: orderCount || 0,
            last_active: lastActive,
          };
        }),
      );

      res.json({
        success: true,
        staff: staffWithStats,
      });
    } catch (error) {
      console.error("Get staff error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch staff",
      });
    }
  },
);

// Get single staff member
app.get(
  "/api/admin/staff/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { data, error } = await supabase
        .from("users")
        .select(
          "id, email, name, role, phone, created_at, updated_at, last_login, status, delivery_instructions",
        )
        .eq("id", id)
        .single();

      if (error || !data) {
        return res.status(404).json({
          success: false,
          message: "Staff member not found",
        });
      }

      // Get staff statistics
      const { count: orderCount, error: orderError } = await supabase
        .from("orders")
        .select("*", { count: "exact", head: true })
        .eq("assigned_staff_id", id);

      const { count: resolvedTickets, error: ticketError } = await supabase
        .from("support_tickets")
        .select("*", { count: "exact", head: true })
        .eq("assigned_to", id)
        .eq("status", "resolved");

      res.json({
        success: true,
        staff: {
          ...data,
          order_count: orderCount || 0,
          resolved_tickets: resolvedTickets || 0,
        },
      });
    } catch (error) {
      console.error("Get staff error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch staff",
      });
    }
  },
);

// Create staff member (admin only)
app.post(
  "/api/admin/staff",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { email, password, name, role, phone, delivery_instructions } =
        req.body;

      // Validate required fields
      if (!email || !password || !name || !role) {
        return res.status(400).json({
          success: false,
          message: "Email, password, name, and role are required",
        });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          message: "Invalid email format",
        });
      }

      // Validate password length
      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: "Password must be at least 6 characters",
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
          message: "User with this email already exists",
        });
      }

      // Hash password
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const userId = uuidv4();

      // Create staff user
      const { data, error } = await supabase
        .from("users")
        .insert([
          {
            id: userId,
            email: email.toLowerCase(),
            password: hashedPassword,
            name: name.trim(),
            role: role,
            phone: phone || null,
            delivery_instructions: delivery_instructions || null,
            status: "active",
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ])
        .select("id, email, name, role, phone, created_at, status")
        .single();

      if (error) {
        console.error("Create staff error:", error);
        return res.status(500).json({
          success: false,
          message: "Failed to create staff member: " + error.message,
        });
      }

      res.status(201).json({
        success: true,
        message: "Staff member created successfully",
        staff: data,
      });
    } catch (error) {
      console.error("Create staff error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to create staff member",
      });
    }
  },
);

// Update staff member
app.put(
  "/api/admin/staff/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
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
          message: "Staff member not found",
        });
      }

      // Prevent changing own role to something lower
      if (id === req.userId && role && role !== existing.role) {
        return res.status(400).json({
          success: false,
          message: "You cannot change your own role",
        });
      }

      const updateData = {
        name: name || existing.name,
        role: role || existing.role,
        phone: phone || null,
        delivery_instructions: delivery_instructions || null,
        status: status || "active",
        updated_at: new Date().toISOString(),
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
          message: "Failed to update staff member",
        });
      }

      res.json({
        success: true,
        message: "Staff member updated successfully",
        staff: data,
      });
    } catch (error) {
      console.error("Update staff error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update staff member",
      });
    }
  },
);

// Delete/Deactivate staff member (admin only)
app.delete(
  "/api/admin/staff/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;

      // Prevent deleting own account
      if (id === req.userId) {
        return res.status(400).json({
          success: false,
          message: "You cannot delete your own account",
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
          message: "Staff member not found",
        });
      }

      // Soft delete - deactivate and demote to user
      const { error } = await supabase
        .from("users")
        .update({
          status: "inactive",
          role: "user", // Demote to regular user
          updated_at: new Date().toISOString(),
        })
        .eq("id", id);

      if (error) {
        console.error("Delete staff error:", error);
        return res.status(500).json({
          success: false,
          message: "Failed to deactivate staff member",
        });
      }

      res.json({
        success: true,
        message: "Staff member deactivated successfully",
      });
    } catch (error) {
      console.error("Delete staff error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to deactivate staff member",
      });
    }
  },
);

// Update staff role
app.patch(
  "/api/admin/staff/:id/role",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role } = req.body;

      const validRoles = [
        "admin",
        "manager",
        "staff",
        "chef",
        "delivery",
        "support",
      ];
      if (!validRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          message: "Invalid role. Must be one of: " + validRoles.join(", "),
        });
      }

      // Prevent changing own role
      if (id === req.userId) {
        return res.status(400).json({
          success: false,
          message: "You cannot change your own role",
        });
      }

      const { data, error } = await supabase
        .from("users")
        .update({
          role: role,
          updated_at: new Date().toISOString(),
        })
        .eq("id", id)
        .select("id, email, name, role")
        .single();

      if (error || !data) {
        return res.status(404).json({
          success: false,
          message: "Staff member not found",
        });
      }

      res.json({
        success: true,
        message: "Staff role updated successfully",
        staff: data,
      });
    } catch (error) {
      console.error("Update staff role error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update staff role",
      });
    }
  },
);

// Update staff status (active/inactive/on_leave)
app.patch(
  "/api/admin/staff/:id/status",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!["active", "inactive", "on_leave"].includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid status. Must be active, inactive, or on_leave",
        });
      }

      // Prevent deactivating own account
      if (id === req.userId && status !== "active") {
        return res.status(400).json({
          success: false,
          message: "You cannot change your own status",
        });
      }

      const { data, error } = await supabase
        .from("users")
        .update({
          status: status,
          updated_at: new Date().toISOString(),
        })
        .eq("id", id)
        .select("id, email, name, role, status")
        .single();

      if (error || !data) {
        return res.status(404).json({
          success: false,
          message: "Staff member not found",
        });
      }

      res.json({
        success: true,
        message: `Staff status updated to ${status}`,
        staff: data,
      });
    } catch (error) {
      console.error("Update staff status error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update staff status",
      });
    }
  },
);

// Get staff performance metrics
/*app.get(
  "/api/admin/staff/metrics",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { period = "month" } = req.query;

      let dateFilter = new Date();
      if (period === "week") {
        dateFilter.setDate(dateFilter.getDate() - 7);
      } else if (period === "month") {
        dateFilter.setMonth(dateFilter.getMonth() - 1);
      } else if (period === "year") {
        dateFilter.setFullYear(dateFilter.getFullYear() - 1);
      }

      // Get staff list
      const { data: staff, error: staffError } = await supabase
        .from("users")
        .select("id, name, email, role, status")
        .in("role", [
          "admin",
          "manager",
          "staff",
          "chef",
          "delivery",
          "support",
        ]);

      if (staffError) throw staffError;

      // Get metrics for each staff member
      const metrics = await Promise.all(
        (staff || []).map(async (member) => {
          // Orders handled
          const { count: ordersHandled, error: orderError } = await supabase
            .from("orders")
            .select("*", { count: "exact", head: true })
            .eq("assigned_staff_id", member.id)
            .gte("created_at", dateFilter.toISOString());

          // Tickets resolved
          const { count: ticketsResolved, error: ticketError } = await supabase
            .from("support_tickets")
            .select("*", { count: "exact", head: true })
            .eq("assigned_to", member.id)
            .eq("status", "resolved")
            .gte("resolved_at", dateFilter.toISOString());

          return {
            ...member,
            orders_handled: ordersHandled || 0,
            tickets_resolved: ticketsResolved || 0,
          };
        }),
      );

      // Calculate totals
      const totalStaff = metrics.length;
      const activeStaff = metrics.filter((m) => m.status === "active").length;
      const totalOrders = metrics.reduce(
        (sum, m) => sum + (m.orders_handled || 0),
        0,
      );
      const totalTickets = metrics.reduce(
        (sum, m) => sum + (m.tickets_resolved || 0),
        0,
      );

      res.json({
        success: true,
        metrics: {
          staff: metrics,
          summary: {
            total_staff: totalStaff,
            active_staff: activeStaff,
            total_orders_handled: totalOrders,
            total_tickets_resolved: totalTickets,
            period: period,
          },
        },
      });
    } catch (error) {
      console.error("Get staff metrics error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch staff metrics",
      });
    }
  },
);*/

// Get staff performance metrics - FIXED
app.get(
  "/api/admin/staff/metrics",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { period = "month" } = req.query;

      // Get staff list with proper roles
      const { data: staff, error: staffError } = await supabase
        .from("users")
        .select("id, name, email, role, status")
        .in("role", [
          "admin",
          "manager",
          "staff",
          "chef",
          "delivery",
          "support",
        ]);

      if (staffError) {
        console.error("Staff fetch error:", staffError);
        return res.status(500).json({
          success: false,
          message: "Failed to fetch staff",
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
              period: period,
            },
          },
        });
      }

      // Get metrics for each staff member
      const metrics = await Promise.all(
        staff.map(async (member) => {
          // Orders handled
          const { count: ordersHandled } = await supabase
            .from("orders")
            .select("*", { count: "exact", head: true })
            .eq("assigned_staff_id", member.id);

          // Tickets resolved
          const { count: ticketsResolved } = await supabase
            .from("support_tickets")
            .select("*", { count: "exact", head: true })
            .eq("assigned_to", member.id)
            .eq("status", "resolved");

          return {
            ...member,
            orders_handled: ordersHandled || 0,
            tickets_resolved: ticketsResolved || 0,
          };
        }),
      );

      // Calculate totals
      const totalStaff = metrics.length;
      const activeStaff = metrics.filter((m) => m.status === "active").length;
      const totalOrders = metrics.reduce(
        (sum, m) => sum + (m.orders_handled || 0),
        0,
      );
      const totalTickets = metrics.reduce(
        (sum, m) => sum + (m.tickets_resolved || 0),
        0,
      );

      res.json({
        success: true,
        metrics: {
          staff: metrics,
          summary: {
            total_staff: totalStaff,
            active_staff: activeStaff,
            total_orders_handled: totalOrders,
            total_tickets_resolved: totalTickets,
            period: period,
          },
        },
      });
    } catch (error) {
      console.error("Get staff metrics error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch staff metrics",
      });
    }
  },
);

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

/*app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const {
      items,
      total,
      delivery_address,
      notes,
      delivery_phone,
      delivery_instructions,
    } = req.body;

    if (!items || !items.length) {
      return res.status(400).json({
        success: false,
        message: "Order must contain items",
      });
    }

    const orderTotal =
      total || items.reduce((sum, i) => sum + i.price * i.quantity, 0);
    const orderId = `FZ-${Date.now().toString().slice(-6)}`;

    // ✅ STEP 1: Check user balance FIRST
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("balance")
      .eq("id", req.userId)
      .single();

    if (userError || !user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const currentBalance = parseFloat(user.balance);

    if (currentBalance < orderTotal) {
      return res.status(400).json({
        success: false,
        message: "Insufficient balance",
        required: orderTotal,
        balance: currentBalance,
        shortfall: orderTotal - currentBalance,
      });
    }

    // ✅ STEP 2: Create the order FIRST
    const orderData = {
      id: orderId,
      user_id: req.userId,
      items: JSON.stringify(items),
      total: orderTotal,
      status: "processing",
      delivery_address: delivery_address || "Store pickup",
      delivery_phone: delivery_phone || null,
      delivery_instructions: delivery_instructions || null,
      notes: notes || "",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const { data: order, error: orderError } = await supabase
      .from("orders")
      .insert([orderData])
      .select()
      .single();

    if (orderError) {
      console.error("Order creation error:", orderError);
      return res.status(500).json({
        success: false,
        message: "Failed to create order",
        error: orderError.message,
      });
    }

    // ✅ STEP 3: NOW deduct from wallet (order exists, so foreign key works)
    const reference = generateReference();

    // Get user's current balance again (might have changed)
    const { data: freshUser, error: freshError } = await supabase
      .from("users")
      .select("balance")
      .eq("id", req.userId)
      .single();

    if (freshError) {
      throw freshError;
    }

    const freshBalance = parseFloat(freshUser.balance);

    // Double-check balance hasn't changed
    if (freshBalance < orderTotal) {
      // Rollback: Delete the order
      await supabase.from("orders").delete().eq("id", orderId);
      return res.status(400).json({
        success: false,
        message: "Insufficient balance. Order cancelled.",
      });
    }

    // Create transaction record with the order_id
    const transactionId = uuidv4();
    const { error: txError } = await supabase
      .from("wallet_transactions")
      .insert([
        {
          id: transactionId,
          user_id: req.userId,
          transaction_type: "debit",
          amount: orderTotal,
          balance_before: freshBalance,
          balance_after: freshBalance - orderTotal,
          reference: reference,
          description: `Order payment - ${orderId}`,
          category: "order",
          order_id: orderId, // ✅ ORDER EXISTS NOW! No foreign key error
          status: "completed",
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        },
      ]);

    if (txError) {
      console.error("Transaction creation error:", txError);
      // Rollback: Delete the order
      await supabase.from("orders").delete().eq("id", orderId);
      throw txError;
    }

    // ✅ STEP 4: Update user's balance
    const { error: updateError } = await supabase
      .from("users")
      .update({
        balance: freshBalance - orderTotal,
        updated_at: new Date().toISOString(),
      })
      .eq("id", req.userId);

    if (updateError) {
      console.error("Balance update error:", updateError);
      // Rollback: Delete order and transaction
      await supabase.from("orders").delete().eq("id", orderId);
      await supabase
        .from("wallet_transactions")
        .delete()
        .eq("id", transactionId);
      throw updateError;
    }

    // ✅ STEP 5: Update account ledger
    await updateAccountLedger(req.userId);

    // ✅ STEP 6: Create notification
    await supabase.from("payment_notifications").insert([
      {
        user_id: req.userId,
        type: "payment_success",
        title: "Order Placed Successfully 🎉",
        message: `Your order #${orderId} has been placed. ₦${orderTotal.toFixed(2)} has been deducted from your wallet.`,
        reference: orderId,
        created_at: new Date().toISOString(),
      },
    ]);

    res.status(201).json({
      success: true,
      message: "Order created successfully",
      order: order,
      balance_after: freshBalance - orderTotal,
      transaction_id: transactionId,
    });
  } catch (error) {
    console.error("Order error:", error);

    // Attempt to clean up any orphaned data
    try {
      // If there's an order ID but no transaction, delete the order
      if (orderId) {
        await supabase.from("orders").delete().eq("id", orderId);
      }
    } catch (cleanupError) {
      console.error("Cleanup error:", cleanupError);
    }

    res.status(500).json({
      success: false,
      message: error.message || "Failed to create order",
    });
  }
});*/

// server.js - Updated POST /api/orders with full ledger

app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const {
      items,
      total,
      delivery_address,
      notes,
      delivery_phone,
      delivery_instructions,
    } = req.body;

    if (!items || !items.length) {
      return res.status(400).json({
        success: false,
        message: "Order must contain items",
      });
    }

    const orderTotal =
      total || items.reduce((sum, i) => sum + i.price * i.quantity, 0);
    const orderId = `FZ-${Date.now().toString().slice(-6)}`;

    // STEP 1: Check user balance
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("balance")
      .eq("id", req.userId)
      .single();

    if (userError || !user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const currentBalance = parseFloat(user.balance);

    if (currentBalance < orderTotal) {
      return res.status(400).json({
        success: false,
        message: "Insufficient balance",
        required: orderTotal,
        balance: currentBalance,
        shortfall: orderTotal - currentBalance,
      });
    }

    // STEP 2: Create order
    const orderData = {
      id: orderId,
      user_id: req.userId,
      items: JSON.stringify(items),
      total: orderTotal,
      status: "processing",
      delivery_address: delivery_address || "Store pickup",
      delivery_phone: delivery_phone || null,
      delivery_instructions: delivery_instructions || null,
      notes: notes || "",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const { data: order, error: orderError } = await supabase
      .from("orders")
      .insert([orderData])
      .select()
      .single();

    if (orderError) {
      console.error("Order creation error:", orderError);
      return res.status(500).json({
        success: false,
        message: "Failed to create order",
        error: orderError.message,
      });
    }

    // STEP 3: Create double-entry ledger entries
    const reference = generateReference();

    // Get user's current balance for transaction
    const { data: freshUser } = await supabase
      .from("users")
      .select("balance")
      .eq("id", req.userId)
      .single();

    const freshBalance = parseFloat(freshUser.balance);

    // Create ledger entry with double-entry
    const ledgerResult = await createLedgerEntry({
      description: `Order #${orderId} - ${items.length} items`,
      referenceType: "order",
      referenceId: orderId,
      createdBy: req.userId,
      entries: [
        {
          // Debit: User Wallet (money leaves user)
          accountCode: "2000", // User Wallet Liability
          userId: req.userId,
          debit: orderTotal,
          credit: 0,
          description: `Order payment for #${orderId}`,
        },
        {
          // Credit: Frozyla Revenue (money enters company)
          accountCode: "1001", // Frozyla Revenue Account
          userId: null, // Company account
          debit: 0,
          credit: orderTotal,
          description: `Revenue from order #${orderId}`,
        },
      ],
    });

    if (!ledgerResult || ledgerResult.error) {
      // Rollback order
      await supabase.from("orders").delete().eq("id", orderId);
      throw new Error("Failed to create ledger entry");
    }

    // STEP 4: Update user's balance
    const { error: updateError } = await supabase
      .from("users")
      .update({
        balance: freshBalance - orderTotal,
        updated_at: new Date().toISOString(),
      })
      .eq("id", req.userId);

    if (updateError) {
      // Rollback: Delete order and ledger entries
      await supabase.from("orders").delete().eq("id", orderId);
      await supabase
        .from("ledger_entries")
        .delete()
        .eq("id", ledgerResult.entry.id);
      throw updateError;
    }

    // STEP 5: Create wallet transaction record
    const transactionId = uuidv4();
    await supabase.from("wallet_transactions").insert([
      {
        id: transactionId,
        user_id: req.userId,
        transaction_type: "debit",
        amount: orderTotal,
        balance_before: freshBalance,
        balance_after: freshBalance - orderTotal,
        reference: reference,
        description: `Order payment - ${orderId}`,
        category: "order",
        order_id: orderId,
        ledger_entry_id: ledgerResult.entry.id,
        status: "completed",
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      },
    ]);

    // STEP 6: Create notification
    await supabase.from("payment_notifications").insert([
      {
        user_id: req.userId,
        type: "payment_success",
        title: "Order Placed Successfully 🎉",
        message: `Your order #${orderId} has been placed. ₦${orderTotal.toFixed(2)} has been deducted from your wallet.`,
        reference: orderId,
        created_at: new Date().toISOString(),
      },
    ]);

    res.status(201).json({
      success: true,
      message: "Order created successfully",
      order: order,
      balance_after: freshBalance - orderTotal,
      transaction_id: transactionId,
      ledger_entry_id: ledgerResult.entry.id,
    });
  } catch (error) {
    console.error("Order error:", error);
    res.status(500).json({
      success: false,
      message: error.message || "Failed to create order",
    });
  }
});

// server.js - Add rollback helper

/*async function rollbackOrder(orderId, transactionId) {
    const errors = [];
    
    try {
        if (transactionId) {
            const { error } = await supabase
                .from("wallet_transactions")
                .delete()
                .eq("id", transactionId);
            if (error) errors.push({ table: 'wallet_transactions', error });
        }
    } catch (e) {
        errors.push({ table: 'wallet_transactions', error: e });
    }

    try {
        if (orderId) {
            const { error } = await supabase
                .from("orders")
                .delete()
                .eq("id", orderId);
            if (error) errors.push({ table: 'orders', error });
        }
    } catch (e) {
        errors.push({ table: 'orders', error: e });
    }

    if (errors.length > 0) {
        console.error('Rollback errors:', errors);
    }
    
    return errors;
}*/

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

// ============================================
// PAYMENT & WALLET SYSTEM ROUTES
// ============================================

// ===== HELPER FUNCTIONS =====

function generateReference() {
  const prefix = "FZ";
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `${prefix}${timestamp}${random}`;
}

/*function generateAccountNumber() {
    // Generate a 10-digit number only (no letters)
    let accountNumber = '';
    for (let i = 0; i < 10; i++) {
        accountNumber += Math.floor(Math.random() * 10);
    }
    return accountNumber;
}

async function updateUserBalance(
  userId,
  amount,
  transactionType,
  description,
  category,
  reference,
  orderId = null,
  fundingRequestId = null,
) {
  // Start a transaction
  const { data: user, error: userError } = await supabase
    .from("users")
    .select("balance")
    .eq("id", userId)
    .single();

  if (userError || !user) {
    throw new Error("User not found");
  }

  const balanceBefore = parseFloat(user.balance);
  const amountNum = parseFloat(amount);
  let balanceAfter;

  if (transactionType === "credit") {
    balanceAfter = balanceBefore + amountNum;
  } else if (transactionType === "debit") {
    if (balanceBefore < amountNum) {
      throw new Error("Insufficient balance");
    }
    balanceAfter = balanceBefore - amountNum;
  } else {
    throw new Error("Invalid transaction type");
  }

  // Update user balance
  const { error: updateError } = await supabase
    .from("users")
    .update({
      balance: balanceAfter,
      updated_at: new Date().toISOString(),
    })
    .eq("id", userId);

  if (updateError) throw updateError;

  // Create transaction record
  const transactionId = uuidv4();
  const { error: txError } = await supabase.from("wallet_transactions").insert([
    {
      id: transactionId,
      user_id: userId,
      transaction_type: transactionType,
      amount: amountNum,
      balance_before: balanceBefore,
      balance_after: balanceAfter,
      reference: reference,
      description: description,
      category: category,
      order_id: orderId,
      funding_request_id: fundingRequestId,
      status: "completed",
      created_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
    },
  ]);

  if (txError) throw txError;

  // Update account ledger
  await updateAccountLedger(userId);

  return { balanceBefore, balanceAfter, transactionId };
}*/

// server.js - Fixed updateUserBalance helper

async function updateUserBalance(
  userId,
  amount,
  transactionType,
  description,
  category,
  reference,
  orderId = null,
  fundingRequestId = null,
) {
  // Start a transaction
  const { data: user, error: userError } = await supabase
    .from("users")
    .select("balance")
    .eq("id", userId)
    .single();

  if (userError || !user) {
    throw new Error("User not found");
  }

  const balanceBefore = parseFloat(user.balance);
  const amountNum = parseFloat(amount);
  let balanceAfter;

  if (transactionType === "credit") {
    balanceAfter = balanceBefore + amountNum;
  } else if (transactionType === "debit") {
    if (balanceBefore < amountNum) {
      throw new Error("Insufficient balance");
    }
    balanceAfter = balanceBefore - amountNum;
  } else {
    throw new Error("Invalid transaction type");
  }

  // Update user balance
  const { error: updateError } = await supabase
    .from("users")
    .update({
      balance: balanceAfter,
      updated_at: new Date().toISOString(),
    })
    .eq("id", userId);

  if (updateError) throw updateError;

  // Create transaction record
  const transactionId = uuidv4();
  const transactionData = {
    id: transactionId,
    user_id: userId,
    transaction_type: transactionType,
    amount: amountNum,
    balance_before: balanceBefore,
    balance_after: balanceAfter,
    reference: reference || generateReference(),
    description: description,
    category: category,
    funding_request_id: fundingRequestId,
    status: "completed",
    created_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
  };

  // ✅ Only add order_id if it exists and is valid
  if (orderId) {
    // Verify order exists before adding the reference
    const { data: orderCheck, error: orderCheckError } = await supabase
      .from("orders")
      .select("id")
      .eq("id", orderId)
      .single();

    if (!orderCheckError && orderCheck) {
      transactionData.order_id = orderId;
    } else {
      // Order doesn't exist, log warning but proceed without order_id
      console.warn(
        `Order ${orderId} not found, creating transaction without order reference`,
      );
    }
  }

  const { error: txError } = await supabase
    .from("wallet_transactions")
    .insert([transactionData]);

  if (txError) throw txError;

  // Update account ledger
  await updateAccountLedger(userId);

  return { balanceBefore, balanceAfter, transactionId };
}

async function updateAccountLedger(userId) {
  const { data: user, error: userError } = await supabase
    .from("users")
    .select("balance")
    .eq("id", userId)
    .single();

  if (userError || !user) return;

  const actualBalance = parseFloat(user.balance);

  // Get latest ledger entry
  const { data: latestLedger, error: ledgerError } = await supabase
    .from("account_ledger")
    .select("ledger_balance")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(1);

  let ledgerBalance = actualBalance;

  if (!ledgerError && latestLedger && latestLedger.length > 0) {
    ledgerBalance = parseFloat(latestLedger[0].ledger_balance);
  }

  const difference = actualBalance - ledgerBalance;
  const status = Math.abs(difference) < 0.01 ? "matched" : "flagged";

  const { error: insertError } = await supabase.from("account_ledger").insert([
    {
      user_id: userId,
      ledger_balance: ledgerBalance,
      actual_balance: actualBalance,
      status: status,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
  ]);

  if (insertError) {
    console.error("Failed to update ledger:", insertError);
  }
}

// ===== USER ROUTES =====

// Get user wallet balance
/*app.get("/api/wallet/balance", authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("balance, account_number, account_status")
      .eq("id", req.userId)
      .single();

    if (error || !user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.json({
      success: true,
      balance: parseFloat(user.balance),
      account_number: user.account_number,
      account_status: user.account_status,
    });
  } catch (error) {
    console.error("Wallet balance error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch balance",
    });
  }
});

// Get user transactions
app.get("/api/wallet/transactions", authMiddleware, async (req, res) => {
  try {
    const { limit = 50, offset = 0, type, start_date, end_date } = req.query;

    let query = supabase
      .from("wallet_transactions")
      .select("*")
      .eq("user_id", req.userId)
      .order("created_at", { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    if (type) {
      query = query.eq("transaction_type", type);
    }

    if (start_date) {
      query = query.gte("created_at", start_date);
    }

    if (end_date) {
      query = query.lte("created_at", end_date);
    }

    const { data: transactions, error } = await query;

    if (error) throw error;

    // Get total count
    const { count, error: countError } = await supabase
      .from("wallet_transactions")
      .select("*", { count: "exact", head: true })
      .eq("user_id", req.userId);

    res.json({
      success: true,
      transactions: transactions || [],
      total: count || 0,
      limit: parseInt(limit),
      offset: parseInt(offset),
    });
  } catch (error) {
    console.error("Transactions error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch transactions",
    });
  }
});*/

// server.js - Fixed GET /api/wallet/balance

// Get user wallet balance
app.get("/api/wallet/balance", authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("balance, account_number, account_status, name, email")
      .eq("id", req.userId)
      .single();

    if (error || !user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Ensure account number exists
    let accountNumber = user.account_number;
    if (!accountNumber) {
      accountNumber = generateAccountNumber();
      await supabase
        .from("users")
        .update({ account_number: accountNumber })
        .eq("id", req.userId);
    }

    // Get total spent (sum of all debit transactions)
    const { data: spentData, error: spentError } = await supabase
      .from("wallet_transactions")
      .select("amount")
      .eq("user_id", req.userId)
      .eq("transaction_type", "debit")
      .eq("status", "completed");

    let totalSpent = 0;
    if (!spentError && spentData) {
      totalSpent = spentData.reduce(
        (sum, tx) => sum + parseFloat(tx.amount),
        0,
      );
    }

    // Get total orders count
    const { count: ordersCount, error: ordersError } = await supabase
      .from("orders")
      .select("*", { count: "exact", head: true })
      .eq("user_id", req.userId);

    res.json({
      success: true,
      balance: parseFloat(user.balance) || 0,
      account_number: accountNumber,
      account_status: user.account_status || "active",
      total_spent: totalSpent,
      total_orders: ordersError ? 0 : ordersCount || 0,
      user: {
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Wallet balance error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch balance",
      error: error.message,
    });
  }
});

// server.js - Add GET /api/wallet/transactions/:id

// Get single transaction details
app.get("/api/wallet/transactions/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: transaction, error } = await supabase
      .from("wallet_transactions")
      .select(
        `
                *,
                order:orders!wallet_transactions_order_id_fkey(
                    id,
                    status,
                    total,
                    created_at,
                    items
                ),
                funding_request:card_funding_requests(
                    id,
                    amount,
                    status,
                    requested_at,
                    approved_at
                )
            `,
      )
      .eq("id", id)
      .eq("user_id", req.userId)
      .single();

    if (error || !transaction) {
      return res.status(404).json({
        success: false,
        message: "Transaction not found",
      });
    }

    // Format the response
    const formattedTransaction = {
      id: transaction.id,
      user_id: transaction.user_id,
      transaction_type: transaction.transaction_type,
      amount: parseFloat(transaction.amount),
      balance_before: parseFloat(transaction.balance_before),
      balance_after: parseFloat(transaction.balance_after),
      reference: transaction.reference,
      description: transaction.description,
      category: transaction.category,
      order_id: transaction.order_id,
      order: transaction.order
        ? {
            id: transaction.order.id,
            status: transaction.order.status,
            total: parseFloat(transaction.order.total),
            created_at: transaction.order.created_at,
            items: transaction.order.items
              ? JSON.parse(transaction.order.items)
              : [],
          }
        : null,
      funding_request_id: transaction.funding_request_id,
      funding_request: transaction.funding_request
        ? {
            id: transaction.funding_request.id,
            amount: parseFloat(transaction.funding_request.amount),
            status: transaction.funding_request.status,
            requested_at: transaction.funding_request.requested_at,
          }
        : null,
      status: transaction.status,
      created_at: transaction.created_at,
      completed_at: transaction.completed_at,
    };

    res.json({
      success: true,
      transaction: formattedTransaction,
    });
  } catch (error) {
    console.error("Transaction detail error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch transaction",
      error: error.message,
    });
  }
});

// server.js - Fixed GET /api/wallet/transactions

// Get user transactions
app.get("/api/wallet/transactions", authMiddleware, async (req, res) => {
  try {
    const {
      limit = 50,
      offset = 0,
      type,
      start_date,
      end_date,
      order_id,
    } = req.query;

    // Build the query
    let query = supabase
      .from("wallet_transactions")
      .select(
        `
                *,
                order:orders!wallet_transactions_order_id_fkey(
                    id,
                    status,
                    total,
                    created_at
                ),
                funding_request:card_funding_requests(
                    id,
                    amount,
                    status,
                    requested_at
                )
            `,
      )
      .eq("user_id", req.userId)
      .order("created_at", { ascending: false });

    // Apply filters
    if (type) {
      query = query.eq("transaction_type", type);
    }

    if (order_id) {
      query = query.eq("order_id", order_id);
    }

    if (start_date) {
      query = query.gte("created_at", start_date);
    }

    if (end_date) {
      query = query.lte("created_at", end_date);
    }

    // Apply pagination
    const from = parseInt(offset);
    const to = from + parseInt(limit) - 1;
    query = query.range(from, to);

    const { data: transactions, error } = await query;

    if (error) {
      console.error("Transactions fetch error:", error);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch transactions",
        error: error.message,
      });
    }

    // Get total count
    let countQuery = supabase
      .from("wallet_transactions")
      .select("*", { count: "exact", head: true })
      .eq("user_id", req.userId);

    if (type) {
      countQuery = countQuery.eq("transaction_type", type);
    }

    if (order_id) {
      countQuery = countQuery.eq("order_id", order_id);
    }

    if (start_date) {
      countQuery = countQuery.gte("created_at", start_date);
    }

    if (end_date) {
      countQuery = countQuery.lte("created_at", end_date);
    }

    const { count, error: countError } = await countQuery;

    if (countError) {
      console.error("Count error:", countError);
    }

    // Format the response
    const formattedTransactions = (transactions || []).map((tx) => ({
      id: tx.id,
      user_id: tx.user_id,
      transaction_type: tx.transaction_type,
      amount: parseFloat(tx.amount),
      balance_before: parseFloat(tx.balance_before),
      balance_after: parseFloat(tx.balance_after),
      reference: tx.reference,
      description: tx.description,
      category: tx.category,
      order_id: tx.order_id,
      order: tx.order
        ? {
            id: tx.order.id,
            status: tx.order.status,
            total: parseFloat(tx.order.total),
            created_at: tx.order.created_at,
          }
        : null,
      funding_request_id: tx.funding_request_id,
      funding_request: tx.funding_request
        ? {
            id: tx.funding_request.id,
            amount: parseFloat(tx.funding_request.amount),
            status: tx.funding_request.status,
            requested_at: tx.funding_request.requested_at,
          }
        : null,
      status: tx.status,
      created_at: tx.created_at,
      completed_at: tx.completed_at,
    }));

    res.json({
      success: true,
      transactions: formattedTransactions,
      total: count || 0,
      limit: parseInt(limit),
      offset: parseInt(offset),
    });
  } catch (error) {
    console.error("Transactions error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch transactions",
      error: error.message,
    });
  }
});

// Get user cards
app.get("/api/wallet/cards", authMiddleware, async (req, res) => {
  try {
    const { data: cards, error } = await supabase
      .from("payment_cards")
      .select("*")
      .eq("user_id", req.userId)
      .order("is_default", { ascending: false })
      .order("created_at", { ascending: false });

    if (error) throw error;

    // Mask card numbers
    const maskedCards = (cards || []).map((card) => ({
      ...card,
      card_number: card.card_number.replace(/\d(?=\d{4})/g, "*"),
    }));

    res.json({
      success: true,
      cards: maskedCards,
    });
  } catch (error) {
    console.error("Get cards error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch cards",
    });
  }
});

// Add payment card
app.post("/api/wallet/cards", authMiddleware, async (req, res) => {
  try {
    const {
      card_number,
      card_holder_name,
      expiry_month,
      expiry_year,
      card_type,
      is_default,
    } = req.body;

    if (!card_number || !card_holder_name || !expiry_month || !expiry_year) {
      return res.status(400).json({
        success: false,
        message: "All card details are required",
      });
    }

    // Validate expiry date
    const now = new Date();
    const expMonth = parseInt(expiry_month);
    const expYear = parseInt(expiry_year);
    const expDate = new Date(expYear, expMonth - 1);

    if (expDate < now) {
      return res.status(400).json({
        success: false,
        message: "Card has expired",
      });
    }

    // If this is default, unset other defaults
    if (is_default) {
      await supabase
        .from("payment_cards")
        .update({ is_default: false })
        .eq("user_id", req.userId);
    }

    const { data: card, error } = await supabase
      .from("payment_cards")
      .insert([
        {
          user_id: req.userId,
          card_number: card_number, // In production, encrypt this
          card_holder_name: card_holder_name,
          expiry_month: expiry_month,
          expiry_year: expiry_year,
          card_type: card_type || "other",
          is_default: is_default || false,
          is_verified: false,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ])
      .select()
      .single();

    if (error) throw error;

    // Mask card number for response
    card.card_number = card.card_number.replace(/\d(?=\d{4})/g, "*");

    res.status(201).json({
      success: true,
      message: "Card added successfully",
      card: card,
    });
  } catch (error) {
    console.error("Add card error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to add card",
    });
  }
});

// Set default card
app.patch("/api/wallet/cards/:id/default", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Verify card belongs to user
    const { data: existing, error: checkError } = await supabase
      .from("payment_cards")
      .select("id")
      .eq("id", id)
      .eq("user_id", req.userId)
      .single();

    if (checkError || !existing) {
      return res.status(404).json({
        success: false,
        message: "Card not found",
      });
    }

    // Unset all defaults
    await supabase
      .from("payment_cards")
      .update({ is_default: false })
      .eq("user_id", req.userId);

    // Set this as default
    const { data: card, error } = await supabase
      .from("payment_cards")
      .update({
        is_default: true,
        updated_at: new Date().toISOString(),
      })
      .eq("id", id)
      .select()
      .single();

    if (error) throw error;

    card.card_number = card.card_number.replace(/\d(?=\d{4})/g, "*");

    res.json({
      success: true,
      message: "Default card updated",
      card: card,
    });
  } catch (error) {
    console.error("Set default card error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update default card",
    });
  }
});

// Delete card
app.delete("/api/wallet/cards/:id", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase
      .from("payment_cards")
      .delete()
      .eq("id", id)
      .eq("user_id", req.userId);

    if (error) throw error;

    res.json({
      success: true,
      message: "Card deleted successfully",
    });
  } catch (error) {
    console.error("Delete card error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete card",
    });
  }
});

// Create card funding request
app.post("/api/wallet/fund", authMiddleware, async (req, res) => {
  try {
    const { card_id, amount } = req.body;

    if (!card_id || !amount) {
      return res.status(400).json({
        success: false,
        message: "Card and amount are required",
      });
    }

    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid amount",
      });
    }

    // Get min/max funding limits from settings
    const { data: settings } = await supabase
      .from("payment_settings")
      .select("key, value")
      .in("key", ["min_funding_amount", "max_funding_amount"]);

    const minFunding = parseFloat(
      settings?.find((s) => s.key === "min_funding_amount")?.value || "10",
    );
    const maxFunding = parseFloat(
      settings?.find((s) => s.key === "max_funding_amount")?.value || "100000",
    );

    if (amountNum < minFunding) {
      return res.status(400).json({
        success: false,
        message: `Minimum funding amount is ₦${minFunding.toFixed(2)}`,
      });
    }

    if (amountNum > maxFunding) {
      return res.status(400).json({
        success: false,
        message: `Maximum funding amount is ₦${maxFunding.toFixed(2)}`,
      });
    }

    // Verify card belongs to user
    const { data: card, error: cardError } = await supabase
      .from("payment_cards")
      .select("id, is_verified")
      .eq("id", card_id)
      .eq("user_id", req.userId)
      .single();

    if (cardError || !card) {
      return res.status(404).json({
        success: false,
        message: "Card not found",
      });
    }

    // Create funding request
    const fundingId = uuidv4();
    const { data: funding, error } = await supabase
      .from("card_funding_requests")
      .insert([
        {
          id: fundingId,
          user_id: req.userId,
          card_id: card_id,
          amount: amountNum,
          status: "pending",
          requested_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        },
      ])
      .select()
      .single();

    if (error) throw error;

    // Create notification
    await supabase.from("payment_notifications").insert([
      {
        user_id: req.userId,
        type: "funding_request",
        title: "Funding Request Created",
        message: `Your request to fund ₦${amountNum.toFixed(2)} has been submitted and is pending approval.`,
        reference: fundingId,
        created_at: new Date().toISOString(),
      },
    ]);

    res.status(201).json({
      success: true,
      message: "Funding request created",
      request: funding,
    });
  } catch (error) {
    console.error("Funding request error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create funding request",
    });
  }
});

// Get user funding requests
app.get("/api/wallet/funding-requests", authMiddleware, async (req, res) => {
  try {
    const { status, limit = 50, offset = 0 } = req.query;

    let query = supabase
      .from("card_funding_requests")
      .select(
        `
                *,
                card:payment_cards(card_number, card_holder_name, card_type)
            `,
      )
      .eq("user_id", req.userId)
      .order("requested_at", { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    if (status) {
      query = query.eq("status", status);
    }

    const { data: requests, error } = await query;

    if (error) throw error;

    // Mask card numbers
    const maskedRequests = (requests || []).map((req) => ({
      ...req,
      card: req.card
        ? {
            ...req.card,
            card_number: req.card.card_number.replace(/\d(?=\d{4})/g, "*"),
          }
        : null,
    }));

    res.json({
      success: true,
      requests: maskedRequests,
      limit: parseInt(limit),
      offset: parseInt(offset),
    });
  } catch (error) {
    console.error("Get funding requests error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch funding requests",
    });
  }
});

// ===== ADMIN ROUTES =====

// Get all funding requests (admin)
/*app.get(
  "/api/admin/funding-requests",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { status, limit = 50, offset = 0 } = req.query;

      let query = supabase
        .from("card_funding_requests")
        .select(
          `
                *,
                user:users(id, name, email, account_number, balance),
                card:payment_cards(card_number, card_holder_name, card_type),
                approved_by_user:users!approved_by(id, name, email)
            `,
        )
        .order("requested_at", { ascending: false })
        .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

      if (status) {
        query = query.eq("status", status);
      }

      const { data: requests, error } = await query;

      if (error) throw error;

      res.json({
        success: true,
        requests: requests || [],
        limit: parseInt(limit),
        offset: parseInt(offset),
      });
    } catch (error) {
      console.error("Admin funding requests error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch funding requests",
      });
    }
  },
);*/

// server.js - Replace the admin funding requests endpoint

// Get all funding requests (admin)
app.get(
  "/api/admin/funding-requests",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { status, limit = 50, offset = 0 } = req.query;

      // Build the query with proper relationship aliases
      let query = supabase
        .from("card_funding_requests")
        .select(
          `
          *,
          user:users!card_funding_requests_user_id_fkey(
            id, 
            name, 
            email, 
            account_number, 
            balance
          ),
          card:payment_cards(
            card_number, 
            card_holder_name, 
            card_type
          ),
          approved_by_user:users!card_funding_requests_approved_by_fkey(
            id, 
            name, 
            email
          )
        `,
        )
        .order("requested_at", { ascending: false });

      // Apply status filter
      if (status && status !== "all") {
        query = query.eq("status", status);
      }

      // Apply pagination
      if (limit) {
        query = query.range(
          parseInt(offset),
          parseInt(offset) + parseInt(limit) - 1,
        );
      }

      const { data: requests, error } = await query;

      if (error) {
        console.error("Admin funding requests error:", error);
        return res.status(500).json({
          success: false,
          message: "Failed to fetch funding requests",
          error: error.message,
        });
      }

      // Get total count for pagination
      let countQuery = supabase
        .from("card_funding_requests")
        .select("*", { count: "exact", head: true });

      if (status && status !== "all") {
        countQuery = countQuery.eq("status", status);
      }

      const { count, error: countError } = await countQuery;

      if (countError) {
        console.error("Count error:", countError);
      }

      // Mask card numbers for security
      const maskedRequests = (requests || []).map((req) => {
        // Create a copy to avoid mutating original
        const requestCopy = { ...req };

        if (requestCopy.card) {
          requestCopy.card = {
            ...requestCopy.card,
            card_number: requestCopy.card.card_number
              ? requestCopy.card.card_number.replace(/\d(?=\d{4})/g, "*")
              : null,
          };
        }

        return requestCopy;
      });

      res.json({
        success: true,
        requests: maskedRequests || [],
        total: count || 0,
        limit: parseInt(limit),
        offset: parseInt(offset),
      });
    } catch (error) {
      console.error("Admin funding requests error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch funding requests",
        error: error.message,
      });
    }
  },
);

// Approve funding request (admin)
/*app.patch(
  "/api/admin/funding-requests/:id/approve",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { admin_notes } = req.body;

      // Get funding request
      const { data: funding, error: fundingError } = await supabase
        .from("card_funding_requests")
        .select("*")
        .eq("id", id)
        .single();

      if (fundingError || !funding) {
        return res.status(404).json({
          success: false,
          message: "Funding request not found",
        });
      }

      if (funding.status !== "pending") {
        return res.status(400).json({
          success: false,
          message: `Request is already ${funding.status}`,
        });
      }

      if (new Date(funding.expires_at) < new Date()) {
        return res.status(400).json({
          success: false,
          message: "Funding request has expired",
        });
      }

      const amount = parseFloat(funding.amount);
      const reference = generateReference();

      // Update user balance
      await updateUserBalance(
        funding.user_id,
        amount,
        "credit",
        `Funding via card - ${reference}`,
        "funding",
        reference,
        null,
        funding.id,
      );

      // Update funding request
      const { data: updatedFunding, error: updateError } = await supabase
        .from("card_funding_requests")
        .update({
          status: "approved",
          admin_notes: admin_notes || null,
          processed_at: new Date().toISOString(),
          approved_by: req.userId,
        })
        .eq("id", id)
        .select()
        .single();

      if (updateError) throw updateError;

      // Create notification for user
      await supabase.from("payment_notifications").insert([
        {
          user_id: funding.user_id,
          type: "funding_approved",
          title: "Funding Approved ✅",
          message: `Your funding request of ₦${amount.toFixed(2)} has been approved and credited to your wallet.`,
          reference: id,
          created_at: new Date().toISOString(),
        },
      ]);

      res.json({
        success: true,
        message: "Funding request approved",
        request: updatedFunding,
      });
    } catch (error) {
      console.error("Approve funding error:", error);
      res.status(500).json({
        success: false,
        message: error.message || "Failed to approve funding",
      });
    }
  },
);*/

// server.js - Updated funding approval with ledger

app.patch(
  "/api/admin/funding-requests/:id/approve",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { admin_notes } = req.body;

      // Get funding request
      const { data: funding, error: fundingError } = await supabase
        .from("card_funding_requests")
        .select("*")
        .eq("id", id)
        .single();

      if (fundingError || !funding) {
        return res.status(404).json({
          success: false,
          message: "Funding request not found",
        });
      }

      if (funding.status !== "pending") {
        return res.status(400).json({
          success: false,
          message: `Request is already ${funding.status}`,
        });
      }

      const amount = parseFloat(funding.amount);
      const reference = generateReference();

      // Get user's current balance
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("balance")
        .eq("id", funding.user_id)
        .single();

      if (userError || !user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      const currentBalance = parseFloat(user.balance);

      // Create double-entry ledger entry
      const ledgerResult = await createLedgerEntry({
        description: `Funding request #${id.slice(0, 8)} - ₦${amount.toFixed(2)}`,
        referenceType: "funding",
        referenceId: id,
        createdBy: req.userId,
        entries: [
          {
            // Debit: Frozyla Funding Account (money leaves company)
            accountCode: "1002", // Frozyla Funding Account
            userId: null,
            debit: amount,
            credit: 0,
            description: `Funding request #${id.slice(0, 8)}`,
          },
          {
            // Credit: User Wallet (money enters user)
            accountCode: "2000", // User Wallet Liability
            userId: funding.user_id,
            debit: 0,
            credit: amount,
            description: `Funding request #${id.slice(0, 8)}`,
          },
        ],
      });

      if (!ledgerResult || ledgerResult.error) {
        throw new Error("Failed to create ledger entry");
      }

      // Update user balance
      const { error: updateError } = await supabase
        .from("users")
        .update({
          balance: currentBalance + amount,
          updated_at: new Date().toISOString(),
        })
        .eq("id", funding.user_id);

      if (updateError) {
        // Rollback ledger entry
        await supabase
          .from("ledger_entries")
          .delete()
          .eq("id", ledgerResult.entry.id);
        throw updateError;
      }

      // Update funding request
      const { data: updatedFunding, error: updateFundingError } = await supabase
        .from("card_funding_requests")
        .update({
          status: "approved",
          admin_notes: admin_notes || null,
          processed_at: new Date().toISOString(),
          approved_by: req.userId,
        })
        .eq("id", id)
        .select()
        .single();

      if (updateFundingError) throw updateFundingError;

      // Create wallet transaction
      const transactionId = uuidv4();
      await supabase.from("wallet_transactions").insert([
        {
          id: transactionId,
          user_id: funding.user_id,
          transaction_type: "credit",
          amount: amount,
          balance_before: currentBalance,
          balance_after: currentBalance + amount,
          reference: reference,
          description: `Funding approved - ${reference}`,
          category: "funding",
          funding_request_id: id,
          ledger_entry_id: ledgerResult.entry.id,
          status: "completed",
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        },
      ]);

      // Create notification
      await supabase.from("payment_notifications").insert([
        {
          user_id: funding.user_id,
          type: "funding_approved",
          title: "Funding Approved ✅",
          message: `Your funding request of ₦${amount.toFixed(2)} has been approved and credited to your wallet.`,
          reference: id,
          created_at: new Date().toISOString(),
        },
      ]);

      res.json({
        success: true,
        message: "Funding request approved",
        request: updatedFunding,
        ledger_entry_id: ledgerResult.entry.id,
      });
    } catch (error) {
      console.error("Approve funding error:", error);
      res.status(500).json({
        success: false,
        message: error.message || "Failed to approve funding",
      });
    }
  },
);

// Reject funding request (admin)
app.patch(
  "/api/admin/funding-requests/:id/reject",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { reason } = req.body;

      if (!reason) {
        return res.status(400).json({
          success: false,
          message: "Rejection reason is required",
        });
      }

      // Get funding request
      const { data: funding, error: fundingError } = await supabase
        .from("card_funding_requests")
        .select("*")
        .eq("id", id)
        .single();

      if (fundingError || !funding) {
        return res.status(404).json({
          success: false,
          message: "Funding request not found",
        });
      }

      if (funding.status !== "pending") {
        return res.status(400).json({
          success: false,
          message: `Request is already ${funding.status}`,
        });
      }

      // Update funding request
      const { data: updatedFunding, error: updateError } = await supabase
        .from("card_funding_requests")
        .update({
          status: "rejected",
          reason: reason,
          processed_at: new Date().toISOString(),
          approved_by: req.userId,
        })
        .eq("id", id)
        .select()
        .single();

      if (updateError) throw updateError;

      // Create notification for user
      await supabase.from("payment_notifications").insert([
        {
          user_id: funding.user_id,
          type: "funding_rejected",
          title: "Funding Rejected ❌",
          message: `Your funding request of ₦${parseFloat(funding.amount).toFixed(2)} was rejected. Reason: ${reason}`,
          reference: id,
          created_at: new Date().toISOString(),
        },
      ]);

      res.json({
        success: true,
        message: "Funding request rejected",
        request: updatedFunding,
      });
    } catch (error) {
      console.error("Reject funding error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to reject funding",
      });
    }
  },
);

// server.js - Ledger Helper Functions

//const { v4: uuidv4 } = require("uuid");

// Generate entry number
function generateEntryNumber() {
  const year = new Date().getFullYear();
  const count = Math.floor(Math.random() * 10000)
    .toString()
    .padStart(4, "0");
  return `LE-${year}-${count}`;
}

// Create a ledger entry (double-entry)
async function createLedgerEntry({
  description,
  referenceType,
  referenceId,
  entries = [], // Array of { accountCode, userId, debit, credit, description }
  createdBy,
}) {
  const entryNumber = generateEntryNumber();
  const entryId = uuidv4();

  // Validate: Total debits must equal total credits
  let totalDebits = 0;
  let totalCredits = 0;

  entries.forEach((e) => {
    totalDebits += parseFloat(e.debit || 0);
    totalCredits += parseFloat(e.credit || 0);
  });

  if (Math.abs(totalDebits - totalCredits) > 0.01) {
    throw new Error(
      `Total debits (${totalDebits}) must equal total credits (${totalCredits})`,
    );
  }

  // Create entry
  const { data: entry, error: entryError } = await supabase
    .from("ledger_entries")
    .insert([
      {
        id: entryId,
        entry_number: entryNumber,
        transaction_date: new Date().toISOString(),
        description: description,
        reference_type: referenceType,
        reference_id: referenceId,
        created_by: createdBy,
        created_at: new Date().toISOString(),
        is_posted: true,
        posted_at: new Date().toISOString(),
        posted_by: createdBy,
      },
    ])
    .select()
    .single();

  if (entryError) throw entryError;

  // Create line items
  const lineItems = [];
  for (const e of entries) {
    // Get account ID from code
    const { data: account, error: accountError } = await supabase
      .from("ledger_accounts")
      .select("id")
      .eq("account_code", e.accountCode)
      .single();

    if (accountError || !account) {
      throw new Error(`Account not found: ${e.accountCode}`);
    }

    // Get current balance for this account
    const { data: currentBalance, error: balanceError } = await supabase
      .from("account_balances")
      .select("balance")
      .eq("account_id", account.id)
      .eq("user_id", e.userId || null)
      .maybeSingle();

    const balanceBefore = currentBalance
      ? parseFloat(currentBalance.balance)
      : 0;
    const debit = parseFloat(e.debit || 0);
    const credit = parseFloat(e.credit || 0);
    const balanceAfter = balanceBefore + debit - credit;

    const { data: lineItem, error: lineError } = await supabase
      .from("ledger_line_items")
      .insert([
        {
          entry_id: entryId,
          account_id: account.id,
          user_id: e.userId || null,
          debit_amount: debit,
          credit_amount: credit,
          balance_before: balanceBefore,
          balance_after: balanceAfter,
          description: e.description || description,
          created_at: new Date().toISOString(),
        },
      ])
      .select()
      .single();

    if (lineError) {
      // Rollback entry
      await supabase.from("ledger_entries").delete().eq("id", entryId);
      throw lineError;
    }

    lineItems.push(lineItem);
  }

  return { entry, lineItems };
}

// Get ledger balance for a user
async function getUserLedgerBalance(userId) {
  const { data, error } = await supabase
    .from("account_balances")
    .select("balance, total_debits, total_credits, updated_at")
    .eq("account_id", getAccountId("2000")) // User Wallet Liability account
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    console.error("Get ledger balance error:", error);
    return { balance: 0, total_debits: 0, total_credits: 0 };
  }

  return {
    balance: data ? parseFloat(data.balance) : 0,
    total_debits: data ? parseFloat(data.total_debits) : 0,
    total_credits: data ? parseFloat(data.total_credits) : 0,
    updated_at: data ? data.updated_at : null,
  };
}

// Get account ID by code
async function getAccountId(accountCode) {
  const { data, error } = await supabase
    .from("ledger_accounts")
    .select("id")
    .eq("account_code", accountCode)
    .single();

  if (error || !data) {
    throw new Error(`Account not found: ${accountCode}`);
  }

  return data.id;
}

// Get Frozyla account ID
async function getFrozylaAccountId() {
  const { data, error } = await supabase
    .from("ledger_accounts")
    .select("id")
    .eq("account_code", "1000") // Frozyla Master Account
    .single();

  if (error || !data) {
    // Create Frozyla account if it doesn't exist
    const { data: newAccount, error: createError } = await supabase
      .from("ledger_accounts")
      .insert([
        {
          account_code: "1000",
          account_name: "Frozyla Master Account",
          account_type: "asset",
          is_system: true,
          is_active: true,
          description: "Main company account",
        },
      ])
      .select()
      .single();

    if (createError) throw createError;
    return newAccount.id;
  }

  return data.id;
}

// Get all users with balance info (admin)
/*app.get(
  "/api/admin/users/balances",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { data: users, error } = await supabase
        .from("users")
        .select(
          "id, name, email, account_number, balance, account_status, created_at, last_login",
        )
        .order("created_at", { ascending: false });

      if (error) throw error;

      // Get latest ledger for each user
      const usersWithLedger = await Promise.all(
        (users || []).map(async (user) => {
          const { data: ledger } = await supabase
            .from("account_ledger")
            .select("ledger_balance, status, created_at")
            .eq("user_id", user.id)
            .order("created_at", { ascending: false })
            .limit(1);

          return {
            ...user,
            balance: parseFloat(user.balance),
            ledger_balance:
              ledger && ledger.length > 0
                ? parseFloat(ledger[0].ledger_balance)
                : null,
            ledger_status:
              ledger && ledger.length > 0 ? ledger[0].status : "unknown",
            ledger_updated:
              ledger && ledger.length > 0 ? ledger[0].created_at : null,
          };
        }),
      );

      res.json({
        success: true,
        users: usersWithLedger,
      });
    } catch (error) {
      console.error("Get users balances error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch users",
      });
    }
  },
);*/

// server.js - Fixed GET /api/admin/users/balances

// Get all users with balance info (admin)
app.get(
  "/api/admin/users/balances",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { search, status, limit = 50, offset = 0 } = req.query;

      // Build the query
      let query = supabase
        .from("users")
        .select(
          "id, name, email, account_number, balance, account_status, role, created_at, last_login",
        )
        .order("created_at", { ascending: false });

      // Apply filters
      if (search) {
        query = query.or(
          `name.ilike.%${search}%,email.ilike.%${search}%,account_number.ilike.%${search}%`,
        );
      }

      if (status) {
        query = query.eq("account_status", status);
      }

      // Apply pagination
      const from = parseInt(offset);
      const to = from + parseInt(limit) - 1;
      query = query.range(from, to);

      const { data: users, error } = await query;

      if (error) {
        console.error("Users fetch error:", error);
        return res.status(500).json({
          success: false,
          message: "Failed to fetch users",
          error: error.message,
        });
      }

      // Get transaction summary for each user
      const usersWithStats = await Promise.all(
        (users || []).map(async (user) => {
          // Get total spent
          const { data: spentData } = await supabase
            .from("wallet_transactions")
            .select("amount")
            .eq("user_id", user.id)
            .eq("transaction_type", "debit")
            .eq("status", "completed");

          const totalSpent = spentData
            ? spentData.reduce((sum, tx) => sum + parseFloat(tx.amount), 0)
            : 0;

          // Get total credited
          const { data: creditedData } = await supabase
            .from("wallet_transactions")
            .select("amount")
            .eq("user_id", user.id)
            .eq("transaction_type", "credit")
            .eq("status", "completed");

          const totalCredited = creditedData
            ? creditedData.reduce((sum, tx) => sum + parseFloat(tx.amount), 0)
            : 0;

          // Get order count
          const { count: ordersCount } = await supabase
            .from("orders")
            .select("*", { count: "exact", head: true })
            .eq("user_id", user.id);

          // Get latest ledger entry
          const { data: latestLedger } = await supabase
            .from("account_ledger")
            .select("ledger_balance, status, created_at")
            .eq("user_id", user.id)
            .order("created_at", { ascending: false })
            .limit(1);

          return {
            ...user,
            balance: parseFloat(user.balance),
            total_spent: totalSpent,
            total_credited: totalCredited,
            total_orders: ordersCount || 0,
            ledger:
              latestLedger && latestLedger.length > 0
                ? {
                    ledger_balance: parseFloat(latestLedger[0].ledger_balance),
                    status: latestLedger[0].status,
                    updated_at: latestLedger[0].created_at,
                  }
                : null,
          };
        }),
      );

      // Get total count
      let countQuery = supabase
        .from("users")
        .select("*", { count: "exact", head: true });

      if (search) {
        countQuery = countQuery.or(
          `name.ilike.%${search}%,email.ilike.%${search}%,account_number.ilike.%${search}%`,
        );
      }

      if (status) {
        countQuery = countQuery.eq("account_status", status);
      }

      const { count, error: countError } = await countQuery;

      if (countError) {
        console.error("Count error:", countError);
      }

      // Get summary statistics
      const { data: summaryData } = await supabase
        .from("users")
        .select("balance, account_status");

      let summary = {
        total_users: count || 0,
        total_balance: 0,
        active_users: 0,
        suspended_users: 0,
      };

      if (summaryData) {
        summaryData.forEach((user) => {
          summary.total_balance += parseFloat(user.balance || 0);
          if (user.account_status === "active") {
            summary.active_users += 1;
          } else if (user.account_status === "suspended") {
            summary.suspended_users += 1;
          }
        });
      }

      res.json({
        success: true,
        users: usersWithStats,
        total: count || 0,
        limit: parseInt(limit),
        offset: parseInt(offset),
        summary: summary,
      });
    } catch (error) {
      console.error("Get users balances error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch users",
        error: error.message,
      });
    }
  },
);

// Get account ledger discrepancies (admin)
/*app.get(
  "/api/admin/ledger/discrepancies",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { data: discrepancies, error } = await supabase
        .from("account_ledger")
        .select(
          `
                *,
                user:users(id, name, email, account_number, balance)
            `,
        )
        .eq("status", "flagged")
        .order("created_at", { ascending: false });

      if (error) throw error;

      res.json({
        success: true,
        discrepancies: discrepancies || [],
      });
    } catch (error) {
      console.error("Get discrepancies error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch discrepancies",
      });
    }
  },
);*/

// server.js - Add GET /api/admin/ledger

// Get all ledger entries (admin only)
/*app.get(
    "/api/admin/ledger",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {
        try {
            const { 
                limit = 50, 
                offset = 0, 
                status,
                user_id,
                start_date,
                end_date 
            } = req.query;

            // Build the query
            let query = supabase
                .from("account_ledger")
                .select(`
                    *,
                    user:users!account_ledger_user_id_fkey(
                        id,
                        name,
                        email,
                        account_number,
                        balance,
                        created_at as user_joined_at
                    )
                `)
                .order("created_at", { ascending: false });

            // Apply filters
            if (status) {
                query = query.eq("status", status);
            }

            if (user_id) {
                query = query.eq("user_id", user_id);
            }

            if (start_date) {
                query = query.gte("created_at", start_date);
            }

            if (end_date) {
                query = query.lte("created_at", end_date);
            }

            // Apply pagination
            const from = parseInt(offset);
            const to = from + parseInt(limit) - 1;
            query = query.range(from, to);

            const { data: ledgerEntries, error } = await query;

            if (error) {
                console.error("Admin ledger fetch error:", error);
                return res.status(500).json({
                    success: false,
                    message: "Failed to fetch ledger entries",
                    error: error.message,
                });
            }

            // Get total count
            let countQuery = supabase
                .from("account_ledger")
                .select("*", { count: "exact", head: true });

            if (status) {
                countQuery = countQuery.eq("status", status);
            }

            if (user_id) {
                countQuery = countQuery.eq("user_id", user_id);
            }

            if (start_date) {
                countQuery = countQuery.gte("created_at", start_date);
            }

            if (end_date) {
                countQuery = countQuery.lte("created_at", end_date);
            }

            const { count, error: countError } = await countQuery;

            if (countError) {
                console.error("Count error:", countError);
            }

            // Get summary statistics
            const { data: summaryData, error: summaryError } = await supabase
                .from("account_ledger")
                .select("status, difference")
                .eq("status", "flagged");

            let summary = {
                total_entries: count || 0,
                total_flagged: 0,
                total_matched: 0,
                total_discrepancy: 0,
            };

            if (!summaryError && summaryData) {
                summary.total_flagged = summaryData.filter(s => s.status === "flagged").length;
                summary.total_matched = summaryData.filter(s => s.status === "matched").length;
                
                // Calculate total discrepancy amount
                const flaggedEntries = summaryData.filter(s => s.status === "flagged");
                summary.total_discrepancy = flaggedEntries.reduce(
                    (sum, s) => sum + Math.abs(parseFloat(s.difference || 0)),
                    0
                );
            }

            // Format the response
            const formattedEntries = (ledgerEntries || []).map(entry => ({
                id: entry.id,
                user_id: entry.user_id,
                user: entry.user ? {
                    id: entry.user.id,
                    name: entry.user.name,
                    email: entry.user.email,
                    account_number: entry.user.account_number,
                    balance: parseFloat(entry.user.balance),
                    joined_at: entry.user.user_joined_at,
                } : null,
                ledger_balance: parseFloat(entry.ledger_balance),
                actual_balance: parseFloat(entry.actual_balance),
                difference: parseFloat(entry.difference),
                status: entry.status,
                flagged_reason: entry.flagged_reason,
                resolved_at: entry.resolved_at,
                created_at: entry.created_at,
                updated_at: entry.updated_at,
            }));

            res.json({
                success: true,
                ledger: formattedEntries,
                total: count || 0,
                limit: parseInt(limit),
                offset: parseInt(offset),
                summary: summary,
            });

        } catch (error) {
            console.error("Admin ledger error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch ledger entries",
                error: error.message,
            });
        }
    },
);*/

// server.js - Add GET /api/admin/ledger/full

// Get full ledger report (admin only)
app.get(
  "/api/admin/ledger",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const {
        start_date,
        end_date,
        user_id,
        account_code,
        limit = 100,
        offset = 0,
      } = req.query;

      // Build query
      let query = supabase
        .from("ledger_line_items")
        .select(
          `
                    *,
                    entry:ledger_entries(
                        entry_number,
                        transaction_date,
                        description,
                        reference_type,
                        reference_id,
                        created_at,
                        created_by:users!ledger_entries_created_by_fkey(name, email)
                    ),
                    account:ledger_accounts(
                        account_code,
                        account_name,
                        account_type
                    ),
                    user:users!ledger_line_items_user_id_fkey(
                        id,
                        name,
                        email,
                        account_number
                    )
                `,
        )
        .order("created_at", { ascending: false });

      // Apply filters
      if (start_date) {
        query = query.gte("created_at", start_date);
      }

      if (end_date) {
        query = query.lte("created_at", end_date);
      }

      if (user_id) {
        query = query.eq("user_id", user_id);
      }

      if (account_code) {
        // First get account id
        const { data: account } = await supabase
          .from("ledger_accounts")
          .select("id")
          .eq("account_code", account_code)
          .single();

        if (account) {
          query = query.eq("account_id", account.id);
        }
      }

      // Apply pagination
      const from = parseInt(offset);
      const to = from + parseInt(limit) - 1;
      query = query.range(from, to);

      const { data: lineItems, error } = await query;

      if (error) {
        console.error("Ledger report error:", error);
        return res.status(500).json({
          success: false,
          message: "Failed to fetch ledger report",
          error: error.message,
        });
      }

      // Get summary
      const { data: summary, error: summaryError } = await supabase
        .from("account_balances")
        .select(
          `
                    account:ledger_accounts(account_code, account_name),
                    user:users(id, name, email),
                    balance,
                    total_debits,
                    total_credits,
                    updated_at
                `,
        )
        .order("updated_at", { ascending: false });

      if (summaryError) {
        console.error("Summary error:", summaryError);
      }

      // Format response
      const formattedItems = (lineItems || []).map((item) => ({
        id: item.id,
        entry_number: item.entry?.entry_number,
        transaction_date: item.entry?.transaction_date,
        description: item.entry?.description || item.description,
        reference_type: item.entry?.reference_type,
        reference_id: item.entry?.reference_id,
        account_code: item.account?.account_code,
        account_name: item.account?.account_name,
        account_type: item.account?.account_type,
        user: item.user
          ? {
              id: item.user.id,
              name: item.user.name,
              email: item.user.email,
              account_number: item.user.account_number,
            }
          : null,
        debit_amount: parseFloat(item.debit_amount),
        credit_amount: parseFloat(item.credit_amount),
        balance_before: parseFloat(item.balance_before),
        balance_after: parseFloat(item.balance_after),
        created_at: item.created_at,
        created_by: item.entry?.created_by,
      }));

      res.json({
        success: true,
        line_items: formattedItems,
        total: formattedItems.length,
        limit: parseInt(limit),
        offset: parseInt(offset),
        summary: summary || [],
      });
    } catch (error) {
      console.error("Ledger report error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch ledger report",
        error: error.message,
      });
    }
  },
);

// server.js - Add GET /api/admin/ledger/balance/:userId

// Get account balance for a specific user (admin only)
app.get(
  "/api/admin/ledger/balance/:userId",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Get user info
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("id, name, email, account_number, balance")
        .eq("id", userId)
        .single();

      if (userError || !user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      // Get ledger balance
      const ledgerBalance = await getUserLedgerBalance(userId);

      // Get recent transactions
      const { data: transactions, error: txError } = await supabase
        .from("wallet_transactions")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(20);

      if (txError) {
        console.error("Transactions fetch error:", txError);
      }

      // Get reconciliation status
      const { data: reconciliation, error: recError } = await supabase
        .from("ledger_reconciliation")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(1);

      if (recError) {
        console.error("Reconciliation error:", recError);
      }

      res.json({
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          account_number: user.account_number,
          balance: parseFloat(user.balance),
        },
        ledger_balance: ledgerBalance,
        transactions: transactions || [],
        reconciliation:
          reconciliation && reconciliation.length > 0
            ? reconciliation[0]
            : null,
      });
    } catch (error) {
      console.error("Account balance error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch account balance",
        error: error.message,
      });
    }
  },
);

// server.js - Add GET /api/admin/transactions

// Get all transactions (admin only)
app.get(
  "/api/admin/transactions",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const {
        limit = 50,
        offset = 0,
        type,
        status,
        user_id,
        start_date,
        end_date,
        search,
      } = req.query;

      // Build the query
      let query = supabase
        .from("wallet_transactions")
        .select(
          `
                    *,
                    user:users!wallet_transactions_user_id_fkey(
                        id,
                        name,
                        email,
                        account_number
                    ),
                    order:orders!wallet_transactions_order_id_fkey(
                        id,
                        status,
                        total,
                        created_at
                    ),
                    funding_request:card_funding_requests(
                        id,
                        amount,
                        status,
                        requested_at
                    )
                `,
        )
        .order("created_at", { ascending: false });

      // Apply filters
      if (type) {
        query = query.eq("transaction_type", type);
      }

      if (status) {
        query = query.eq("status", status);
      }

      if (user_id) {
        query = query.eq("user_id", user_id);
      }

      if (start_date) {
        query = query.gte("created_at", start_date);
      }

      if (end_date) {
        query = query.lte("created_at", end_date);
      }

      // Search by reference or description
      if (search) {
        query = query.or(
          `reference.ilike.%${search}%,description.ilike.%${search}%`,
        );
      }

      // Apply pagination
      const from = parseInt(offset);
      const to = from + parseInt(limit) - 1;
      query = query.range(from, to);

      const { data: transactions, error } = await query;

      if (error) {
        console.error("Admin transactions fetch error:", error);
        return res.status(500).json({
          success: false,
          message: "Failed to fetch transactions",
          error: error.message,
        });
      }

      // Get total count for pagination
      let countQuery = supabase
        .from("wallet_transactions")
        .select("*", { count: "exact", head: true });

      if (type) {
        countQuery = countQuery.eq("transaction_type", type);
      }

      if (status) {
        countQuery = countQuery.eq("status", status);
      }

      if (user_id) {
        countQuery = countQuery.eq("user_id", user_id);
      }

      if (start_date) {
        countQuery = countQuery.gte("created_at", start_date);
      }

      if (end_date) {
        countQuery = countQuery.lte("created_at", end_date);
      }

      if (search) {
        countQuery = countQuery.or(
          `reference.ilike.%${search}%,description.ilike.%${search}%`,
        );
      }

      const { count, error: countError } = await countQuery;

      if (countError) {
        console.error("Count error:", countError);
      }

      // Get summary statistics
      const { data: summaryData, error: summaryError } = await supabase
        .from("wallet_transactions")
        .select("transaction_type, amount, status")
        .eq("status", "completed");

      let summary = {
        total_credit: 0,
        total_debit: 0,
        total_volume: 0,
        total_transactions: count || 0,
      };

      if (!summaryError && summaryData) {
        summaryData.forEach((tx) => {
          const amount = parseFloat(tx.amount);
          summary.total_volume += amount;
          if (tx.transaction_type === "credit") {
            summary.total_credit += amount;
          } else if (tx.transaction_type === "debit") {
            summary.total_debit += amount;
          }
        });
      }

      // Format the response
      const formattedTransactions = (transactions || []).map((tx) => ({
        id: tx.id,
        user_id: tx.user_id,
        user: tx.user
          ? {
              id: tx.user.id,
              name: tx.user.name,
              email: tx.user.email,
              account_number: tx.user.account_number,
            }
          : null,
        transaction_type: tx.transaction_type,
        amount: parseFloat(tx.amount),
        balance_before: parseFloat(tx.balance_before),
        balance_after: parseFloat(tx.balance_after),
        reference: tx.reference,
        description: tx.description,
        category: tx.category,
        order_id: tx.order_id,
        order: tx.order
          ? {
              id: tx.order.id,
              status: tx.order.status,
              total: parseFloat(tx.order.total),
              created_at: tx.order.created_at,
            }
          : null,
        funding_request_id: tx.funding_request_id,
        funding_request: tx.funding_request
          ? {
              id: tx.funding_request.id,
              amount: parseFloat(tx.funding_request.amount),
              status: tx.funding_request.status,
              requested_at: tx.funding_request.requested_at,
            }
          : null,
        status: tx.status,
        created_at: tx.created_at,
        completed_at: tx.completed_at,
      }));

      res.json({
        success: true,
        transactions: formattedTransactions,
        total: count || 0,
        limit: parseInt(limit),
        offset: parseInt(offset),
        summary: summary,
      });
    } catch (error) {
      console.error("Admin transactions error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch transactions",
        error: error.message,
      });
    }
  },
);

// server.js - Fixed GET /api/admin/ledger/discrepancies

// Get account ledger discrepancies (admin)
app.get(
  "/api/admin/ledger/discrepancies",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      // Get all flagged discrepancies
      const { data: discrepancies, error } = await supabase
        .from("account_ledger")
        .select(
          `
                    *,
                    user:users!account_ledger_user_id_fkey(
                        id, 
                        name, 
                        email, 
                        account_number, 
                        balance
                    )
                `,
        )
        .eq("status", "flagged")
        .order("created_at", { ascending: false });

      if (error) {
        console.error("Ledger discrepancies error:", error);
        return res.status(500).json({
          success: false,
          message: "Failed to fetch ledger discrepancies",
          error: error.message,
        });
      }

      // Format the response
      const formattedDiscrepancies = (discrepancies || []).map((entry) => ({
        id: entry.id,
        user_id: entry.user_id,
        user: entry.user
          ? {
              id: entry.user.id,
              name: entry.user.name,
              email: entry.user.email,
              account_number: entry.user.account_number,
              balance: parseFloat(entry.user.balance),
            }
          : null,
        ledger_balance: parseFloat(entry.ledger_balance),
        actual_balance: parseFloat(entry.actual_balance),
        difference: parseFloat(entry.difference),
        status: entry.status,
        flagged_reason: entry.flagged_reason,
        resolved_at: entry.resolved_at,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
      }));

      // Also get recent ledger entries for each user
      const usersWithLedger = await Promise.all(
        (discrepancies || []).map(async (entry) => {
          const { data: recentEntries } = await supabase
            .from("account_ledger")
            .select("ledger_balance, actual_balance, status, created_at")
            .eq("user_id", entry.user_id)
            .order("created_at", { ascending: false })
            .limit(5);

          return {
            ...entry,
            recent_entries: recentEntries || [],
          };
        }),
      );

      res.json({
        success: true,
        discrepancies: formattedDiscrepancies,
        total: formattedDiscrepancies.length,
      });
    } catch (error) {
      console.error("Ledger discrepancies error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch ledger discrepancies",
        error: error.message,
      });
    }
  },
);

// Merge user balance with ledger (admin)
/*app.patch(
  "/api/admin/ledger/:id/merge",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { data: ledger, error: ledgerError } = await supabase
        .from("account_ledger")
        .select("*")
        .eq("id", id)
        .single();

      if (ledgerError || !ledger) {
        return res.status(404).json({
          success: false,
          message: "Ledger entry not found",
        });
      }

      // Update user balance to match ledger
      const { error: updateError } = await supabase
        .from("users")
        .update({
          balance: ledger.ledger_balance,
          updated_at: new Date().toISOString(),
        })
        .eq("id", ledger.user_id);

      if (updateError) throw updateError;

      // Update ledger status
      const { data: updatedLedger, error: statusError } = await supabase
        .from("account_ledger")
        .update({
          status: "resolved",
          resolved_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .eq("id", id)
        .select()
        .single();

      if (statusError) throw statusError;

      // Create a new ledger entry with matched balance
      await updateAccountLedger(ledger.user_id);

      // Create notification
      await supabase.from("payment_notifications").insert([
        {
          user_id: ledger.user_id,
          type: "adjustment",
          title: "Balance Adjustment",
          message: `Your wallet balance has been adjusted to match the ledger balance of ₦${parseFloat(ledger.ledger_balance).toFixed(2)}.`,
          created_at: new Date().toISOString(),
        },
      ]);

      res.json({
        success: true,
        message: "Balance merged with ledger",
        ledger: updatedLedger,
      });
    } catch (error) {
      console.error("Merge ledger error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to merge balance",
      });
    }
  },
);*/

// server.js - Updated merge ledger

app.patch(
  "/api/admin/ledger/:id/merge",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { notes } = req.body;

      // Get reconciliation entry
      const { data: reconciliation, error: recError } = await supabase
        .from("ledger_reconciliation")
        .select("*")
        .eq("id", id)
        .single();

      if (recError || !reconciliation) {
        return res.status(404).json({
          success: false,
          message: "Reconciliation entry not found",
        });
      }

      if (reconciliation.status === "resolved") {
        return res.status(400).json({
          success: false,
          message: "This entry has already been resolved",
        });
      }

      // Update user balance to match ledger
      const { error: updateError } = await supabase
        .from("users")
        .update({
          balance: reconciliation.ledger_balance,
          updated_at: new Date().toISOString(),
        })
        .eq("id", reconciliation.user_id);

      if (updateError) throw updateError;

      // Create adjustment transaction
      const adjustmentAmount =
        reconciliation.actual_balance - reconciliation.ledger_balance;
      const reference = generateReference();

      if (Math.abs(adjustmentAmount) > 0.01) {
        // Create ledger entry for the adjustment
        await createLedgerEntry({
          description: `Balance adjustment - merging with ledger`,
          referenceType: "adjustment",
          referenceId: id,
          createdBy: req.userId,
          entries: [
            {
              accountCode: "2000", // User Wallet
              userId: reconciliation.user_id,
              debit: adjustmentAmount > 0 ? Math.abs(adjustmentAmount) : 0,
              credit: adjustmentAmount < 0 ? Math.abs(adjustmentAmount) : 0,
              description: `Balance adjustment - merged with ledger`,
            },
            {
              accountCode: "3000", // User Equity
              userId: reconciliation.user_id,
              debit: adjustmentAmount < 0 ? Math.abs(adjustmentAmount) : 0,
              credit: adjustmentAmount > 0 ? Math.abs(adjustmentAmount) : 0,
              description: `Balance adjustment - merged with ledger`,
            },
          ],
        });

        // Create wallet transaction
        await supabase.from("wallet_transactions").insert([
          {
            user_id: reconciliation.user_id,
            transaction_type: "adjustment",
            amount: Math.abs(adjustmentAmount),
            balance_before: reconciliation.actual_balance,
            balance_after: reconciliation.ledger_balance,
            reference: reference,
            description: `Balance adjustment - merged with ledger (${adjustmentAmount > 0 ? "credit" : "debit"})`,
            category: "adjustment",
            status: "completed",
            created_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
          },
        ]);
      }

      // Update reconciliation status
      const { data: updated, error: statusError } = await supabase
        .from("ledger_reconciliation")
        .update({
          status: "merged",
          resolved_at: new Date().toISOString(),
          resolved_by: req.userId,
          resolution_notes: notes || `Merged with ledger balance`,
          updated_at: new Date().toISOString(),
        })
        .eq("id", id)
        .select()
        .single();

      if (statusError) throw statusError;

      // Create notification
      await supabase.from("payment_notifications").insert([
        {
          user_id: reconciliation.user_id,
          type: "adjustment",
          title: "Balance Adjustment",
          message: `Your wallet balance has been adjusted to match the ledger. New balance: ₦${reconciliation.ledger_balance.toFixed(2)}`,
          created_at: new Date().toISOString(),
        },
      ]);

      res.json({
        success: true,
        message: "Balance merged with ledger",
        reconciliation: updated,
      });
    } catch (error) {
      console.error("Merge ledger error:", error);
      res.status(500).json({
        success: false,
        message: error.message || "Failed to merge balance",
      });
    }
  },
);

// Reset user balance to ledger (admin)
/*app.patch(
  "/api/admin/ledger/:id/reset",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { data: ledger, error: ledgerError } = await supabase
        .from("account_ledger")
        .select("*")
        .eq("id", id)
        .single();

      if (ledgerError || !ledger) {
        return res.status(404).json({
          success: false,
          message: "Ledger entry not found",
        });
      }

      // Reset user balance to ledger balance
      const { error: updateError } = await supabase
        .from("users")
        .update({
          balance: ledger.ledger_balance,
          updated_at: new Date().toISOString(),
        })
        .eq("id", ledger.user_id);

      if (updateError) throw updateError;

      // Create adjustment transaction
      const reference = generateReference();
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("balance")
        .eq("id", ledger.user_id)
        .single();

      if (!userError && user) {
        await supabase.from("wallet_transactions").insert([
          {
            user_id: ledger.user_id,
            transaction_type: "adjustment",
            amount:
              parseFloat(ledger.ledger_balance) -
              parseFloat(ledger.actual_balance),
            balance_before: parseFloat(ledger.actual_balance),
            balance_after: parseFloat(user.balance),
            reference: reference,
            description: `Balance reset to match ledger - ${reference}`,
            category: "adjustment",
            status: "completed",
            created_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
          },
        ]);
      }

      // Update ledger status
      const { data: updatedLedger, error: statusError } = await supabase
        .from("account_ledger")
        .update({
          status: "resolved",
          resolved_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .eq("id", id)
        .select()
        .single();

      if (statusError) throw statusError;

      // Create new ledger entry
      await updateAccountLedger(ledger.user_id);

      // Create notification
      await supabase.from("payment_notifications").insert([
        {
          user_id: ledger.user_id,
          type: "adjustment",
          title: "Balance Reset",
          message: `Your wallet balance has been reset to ₦${parseFloat(ledger.ledger_balance).toFixed(2)} to match the ledger.`,
          created_at: new Date().toISOString(),
        },
      ]);

      res.json({
        success: true,
        message: "Balance reset to ledger",
        ledger: updatedLedger,
      });
    } catch (error) {
      console.error("Reset ledger error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to reset balance",
      });
    }
  },
);*/

// server.js - Updated reset ledger

app.patch(
  "/api/admin/ledger/:id/reset",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { notes } = req.body;

      // Get reconciliation entry
      const { data: reconciliation, error: recError } = await supabase
        .from("ledger_reconciliation")
        .select("*")
        .eq("id", id)
        .single();

      if (recError || !reconciliation) {
        return res.status(404).json({
          success: false,
          message: "Reconciliation entry not found",
        });
      }

      if (reconciliation.status === "resolved") {
        return res.status(400).json({
          success: false,
          message: "This entry has already been resolved",
        });
      }

      // Update reconciliation status to rejected
      const { data: updated, error: statusError } = await supabase
        .from("ledger_reconciliation")
        .update({
          status: "rejected",
          resolved_at: new Date().toISOString(),
          resolved_by: req.userId,
          resolution_notes: notes || `Rejected - keeping user balance`,
          updated_at: new Date().toISOString(),
        })
        .eq("id", id)
        .select()
        .single();

      if (statusError) throw statusError;

      // Create notification
      await supabase.from("payment_notifications").insert([
        {
          user_id: reconciliation.user_id,
          type: "adjustment",
          title: "Balance Adjustment Rejected",
          message: `The balance adjustment request has been rejected. Your balance remains ₦${reconciliation.actual_balance.toFixed(2)}`,
          created_at: new Date().toISOString(),
        },
      ]);

      res.json({
        success: true,
        message: "Balance adjustment rejected",
        reconciliation: updated,
      });
    } catch (error) {
      console.error("Reset ledger error:", error);
      res.status(500).json({
        success: false,
        message: error.message || "Failed to reject adjustment",
      });
    }
  },
);

// server.js - Add this endpoint

// Get ledger stats (admin only)
app.get(
  "/api/admin/ledger/stats",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      // Get reconciliation stats
      const { data: reconciliation, error: recError } = await supabase
        .from("ledger_reconciliation")
        .select("status, difference");

      if (recError) {
        console.error("Reconciliation stats error:", recError);
      }

      let totalEntries = 0;
      let matched = 0;
      let flagged = 0;
      let merged = 0;
      let rejected = 0;
      let totalDiscrepancy = 0;

      (reconciliation || []).forEach((entry) => {
        totalEntries++;
        if (entry.status === "matched") matched++;
        else if (entry.status === "flagged") flagged++;
        else if (entry.status === "merged") merged++;
        else if (entry.status === "rejected") rejected++;

        if (entry.status === "flagged") {
          totalDiscrepancy += Math.abs(parseFloat(entry.difference || 0));
        }
      });

      // Get total volume from transactions
      const { data: volumeData, error: volError } = await supabase
        .from("wallet_transactions")
        .select("amount")
        .eq("status", "completed");

      let totalVolume = 0;
      if (!volError && volumeData) {
        (volumeData || []).forEach((tx) => {
          totalVolume += parseFloat(tx.amount || 0);
        });
      }

      res.json({
        success: true,
        stats: {
          total_entries: totalEntries,
          matched: matched,
          flagged: flagged,
          merged: merged,
          rejected: rejected,
          total_discrepancy: totalDiscrepancy,
          total_volume: totalVolume,
        },
      });
    } catch (error) {
      console.error("Ledger stats error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch ledger stats",
        error: error.message,
      });
    }
  },
);

// server.js - Add this endpoint

// Get single ledger entry with line items (admin only)
app.get(
  "/api/admin/ledger/entry/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;

      // Get the entry
      const { data: entry, error: entryError } = await supabase
        .from("ledger_entries")
        .select(
          `
                    *,
                    created_by_user:users!ledger_entries_created_by_fkey(id, name, email),
                    posted_by_user:users!ledger_entries_posted_by_fkey(id, name, email)
                `,
        )
        .eq("id", id)
        .single();

      if (entryError || !entry) {
        return res.status(404).json({
          success: false,
          message: "Ledger entry not found",
        });
      }

      // Get line items
      const { data: lineItems, error: lineError } = await supabase
        .from("ledger_line_items")
        .select(
          `
                    *,
                    account:ledger_accounts(account_code, account_name, account_type),
                    user:users!ledger_line_items_user_id_fkey(id, name, email, account_number)
                `,
        )
        .eq("entry_id", id)
        .order("created_at", { ascending: true });

      if (lineError) {
        console.error("Line items error:", lineError);
      }

      res.json({
        success: true,
        entry: {
          ...entry,
          created_by_name: entry.created_by_user?.name,
          posted_by_name: entry.posted_by_user?.name,
          line_items: lineItems || [],
        },
      });
    } catch (error) {
      console.error("Get ledger entry error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch ledger entry",
        error: error.message,
      });
    }
  },
);

// Get all notifications (user)
app.get("/api/notifications", authMiddleware, async (req, res) => {
  try {
    const { limit = 50, offset = 0, unread_only = false } = req.query;

    let query = supabase
      .from("payment_notifications")
      .select("*")
      .eq("user_id", req.userId)
      .order("created_at", { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    if (unread_only === "true") {
      query = query.eq("is_read", false);
    }

    const { data: notifications, error } = await query;

    if (error) throw error;

    const { count, error: countError } = await supabase
      .from("payment_notifications")
      .select("*", { count: "exact", head: true })
      .eq("user_id", req.userId);

    const { count: unreadCount, error: unreadError } = await supabase
      .from("payment_notifications")
      .select("*", { count: "exact", head: true })
      .eq("user_id", req.userId)
      .eq("is_read", false);

    res.json({
      success: true,
      notifications: notifications || [],
      total: count || 0,
      unread_count: unreadCount || 0,
      limit: parseInt(limit),
      offset: parseInt(offset),
    });
  } catch (error) {
    console.error("Notifications error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch notifications",
    });
  }
});

// Mark notification as read
app.patch("/api/notifications/:id/read", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase
      .from("payment_notifications")
      .update({
        is_read: true,
        read_at: new Date().toISOString(),
      })
      .eq("id", id)
      .eq("user_id", req.userId);

    if (error) throw error;

    res.json({
      success: true,
      message: "Notification marked as read",
    });
  } catch (error) {
    console.error("Mark notification read error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update notification",
    });
  }
});

// Mark all notifications as read
app.patch("/api/notifications/read-all", authMiddleware, async (req, res) => {
  try {
    const { error } = await supabase
      .from("payment_notifications")
      .update({
        is_read: true,
        read_at: new Date().toISOString(),
      })
      .eq("user_id", req.userId)
      .eq("is_read", false);

    if (error) throw error;

    res.json({
      success: true,
      message: "All notifications marked as read",
    });
  } catch (error) {
    console.error("Mark all read error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update notifications",
    });
  }
});

// Get payment settings (admin)
app.get(
  "/api/admin/payment-settings",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { data: settings, error } = await supabase
        .from("payment_settings")
        .select("*")
        .order("key");

      if (error) throw error;

      res.json({
        success: true,
        settings: settings || [],
      });
    } catch (error) {
      console.error("Get settings error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to fetch settings",
      });
    }
  },
);

// Update payment settings (admin)
app.patch(
  "/api/admin/payment-settings",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { settings } = req.body;

      if (!settings || typeof settings !== "object") {
        return res.status(400).json({
          success: false,
          message: "Settings object is required",
        });
      }

      const results = [];
      for (const [key, value] of Object.entries(settings)) {
        const { data, error } = await supabase
          .from("payment_settings")
          .update({
            value: String(value),
            updated_at: new Date().toISOString(),
            updated_by: req.userId,
          })
          .eq("key", key)
          .select()
          .single();

        if (error) {
          console.error(`Failed to update setting ${key}:`, error);
          results.push({ key, success: false, error: error.message });
        } else {
          results.push({ key, success: true, data });
        }
      }

      res.json({
        success: true,
        message: "Settings updated",
        results: results,
      });
    } catch (error) {
      console.error("Update settings error:", error);
      res.status(500).json({
        success: false,
        message: "Failed to update settings",
      });
    }
  },
);

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
