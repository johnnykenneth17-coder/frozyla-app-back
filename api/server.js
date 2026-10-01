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
const bcrypt = require('bcrypt');

// IMPORTANT: Fix the path to auth.js - it's now in ../middleware/auth.js
const {
  authMiddleware,
  adminMiddleware,
  staffMiddleware,
  signupUser,
  loginUser,
  loginWithPasscode,
  googleAuth,
  getProfile,
  changePassword,
  refreshToken,
  generateIdNumber,
} = require("../middleware/auth");

const analyticsRoutes = require("../lib/analytics-routes");
const opsRoutes = require("../lib/ops-routes");

const feecentPaymentsClient = require("../lib/feecent-payments-client");

const app = express();
const PORT = process.env.PORT || 5000;

app.set("trust proxy", 1);

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
  // Capacitor native webview origins (Android / iOS)
  "http://localhost",
  "https://localhost",
  "capacitor://localhost",
  "ionic://localhost",
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
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "Idempotency-Key",
    ],
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

const frozylaCronRouter = require("../lib/frozyla-cron-routes");
   app.use("/api/cron", frozylaCronRouter);

const { rawBodyJson, verifyFeecentSignature } = require("../lib/frozyla-feecent-auth-middleware");
   const frozylaIntegrationRouter = require("../lib/frozyla-integration-routes");
   app.use(
     "/api/v1/integrations/feecent/frozyla",
     rawBodyJson,
     verifyFeecentSignature,
     frozylaIntegrationRouter,
   );

// Admin routes - more lenient
app.use("/api/admin", (req, res, next) => {
  return adminLimiter(req, res, next);
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ===== ANALYTICS & OPERATIONS PLATFORMS =====
app.use("/api/admin/analytics", analyticsRoutes);
app.use("/api/admin/ops", opsRoutes);

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
app.post("/api/auth/login-passcode", loginWithPasscode);
app.post("/api/auth/google", googleAuth);
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

const pushRouter = require("../lib/push-routes");
app.use("/api/push", authMiddleware, pushRouter);

   const glAdminRouter = require("../lib/gl-admin-routes");
   app.use("/api/admin/gl", authMiddleware, adminMiddleware, glAdminRouter);

      const adminRiderRouter = require("../lib/admin-rider-routes");
  app.use("/api/admin/riders", authMiddleware, adminMiddleware, adminRiderRouter);

    const glReconciliationCronRouter = require("../lib/gl-reconciliation-cron-routes");
  app.use("/api/cron/gl-reconciliation", glReconciliationCronRouter);

     const riderMiddleware = require("../middleware/rider-middleware");
   const riderRouter = require("../lib/rider-routes");
   app.use("/api/rider", authMiddleware, riderMiddleware, riderRouter);

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
/*app.patch(
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
);*/

// Admin lifecycle helper. The state machine deliberately separates
// CONFIRMED (order accepted) from PREPARING, but the admin UI only has
// a "Preparing" action. If the order is still PAID, record the implicit
// confirmation as its own audited transition first, then do the
// requested one. Every hop still goes through transition_order_status(),
// so the state machine remains the single authority on what is legal;
// skipping further steps (e.g. PAID -> READY_FOR_DELIVERY) is still rejected.
async function adminTransitionOrder(orderId, newStatus, adminId, reason) {
  if (newStatus === "PREPARING") {
    const { data: current } = await supabase
      .from("orders")
      .select("status")
      .eq("id", orderId)
      .maybeSingle();
    if (current && current.status === "PAID") {
      const { data: confirmResult, error: confirmErr } = await supabase.rpc(
        "transition_order_status",
        {
          p_order_id: orderId,
          p_new_status: "CONFIRMED",
          p_actor_type: "admin",
          p_actor_id: adminId,
          p_reason: "Auto-confirmed when preparation started",
        },
      );
      if (confirmErr) return { data: null, error: confirmErr };
      if (!confirmResult.success) return { data: confirmResult, error: null };
    }
  }
  return supabase.rpc("transition_order_status", {
    p_order_id: orderId,
    p_new_status: newStatus,
    p_actor_type: "admin",
    p_actor_id: adminId,
    p_reason: reason || null,
  });
}

app.patch(
  "/api/admin/orders/:id/delivery-status",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { delivery_status, tracking_id, reason } = req.body;

      // Old delivery_status vocabulary -> new unified orders.status
      // vocabulary. Anything not in this map is rejected outright,
      // same as the old validStatuses array did.
      const STATUS_MAP = {
        preparing: "PREPARING",
        ready: "READY_FOR_DELIVERY",
        out_for_delivery: "OUT_FOR_DELIVERY",
        delivered: "DELIVERED",
        failed: "FULFILLMENT_FAILED",
      };
      const newStatus = STATUS_MAP[delivery_status];
      if (!newStatus) {
        return res.status(400).json({ success: false, message: "Invalid delivery status" });
      }

      const { data: result, error } = await adminTransitionOrder(id, newStatus, req.userId, reason);

      if (error) {
        console.error("transition_order_status RPC error:", error);
        return res.status(500).json({ success: false, message: "Failed to update delivery status" });
      }
      if (!result.success) {
        const statusCode = result.code === "ORDER_NOT_FOUND" ? 404 : 400;
        return res.status(statusCode).json(result);
      }

      // Metadata fields unrelated to the state machine — still just
      // plain column updates, same as before.
      const metadataUpdate = { updated_at: new Date().toISOString() };
      if (delivery_status === "out_for_delivery") {
        metadataUpdate.estimated_delivery_time = new Date(Date.now() + 30 * 60000);
      }
      if (delivery_status === "delivered") {
        metadataUpdate.actual_delivery_time = new Date().toISOString();
      }
      if (tracking_id) {
        metadataUpdate.delivery_tracking_id = tracking_id;
      }

      const { data, error: updateErr } = await supabase
        .from("orders")
        .update(metadataUpdate)
        .eq("id", id)
        .select()
        .single();

      if (updateErr) {
        console.error("Delivery metadata update failed:", updateErr);
        // Status transition already committed successfully at this
        // point — don't report this as a failure of the whole
        // request, the status change is real and correct either way.
      }

      res.json({ success: true, message: "Order updated", order: data, ...result });
    } catch (error) {
      console.error("Delivery status update error:", error);
      res.status(500).json({ success: false, message: "Failed to update delivery details" });
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

app.post("/api/admin/orders/:id/confirm", authMiddleware, adminMiddleware, async (req, res) => {
  const { data: result, error } = await supabase.rpc("transition_order_status", {
    p_order_id: req.params.id, p_new_status: "CONFIRMED",
    p_actor_type: "admin", p_actor_id: req.userId, p_reason: req.body.reason || null,
  });
  if (error) return res.status(500).json({ success: false, message: "Failed to confirm order" });
  if (!result.success) return res.status(result.code === "ORDER_NOT_FOUND" ? 404 : 400).json(result);
  res.json({ success: true, ...result });
});

app.post("/api/admin/orders/:id/start-preparing", authMiddleware, adminMiddleware, async (req, res) => {
  const { data: result, error } = await supabase.rpc("transition_order_status", {
    p_order_id: req.params.id, p_new_status: "PREPARING",
    p_actor_type: "admin", p_actor_id: req.userId, p_reason: req.body.reason || null,
  });
  if (error) return res.status(500).json({ success: false, message: "Failed to update order" });
  if (!result.success) return res.status(result.code === "ORDER_NOT_FOUND" ? 404 : 400).json(result);
  res.json({ success: true, ...result });
});

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



/*app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const { items, delivery_address, delivery_phone, delivery_instructions, notes } = req.body;

    // Idempotency key: header first (once app.js sends one — see the
    // frontend patch), falling back to a per-request UUID so this
    // route still works before that frontend change ships. A
    // fallback key protects nothing (it's different every call) but
    // costs nothing either — real double-tap protection starts
    // working the moment the frontend sends a stable key.
    const idempotencyKey = req.headers["idempotency-key"] || uuidv4();

    if (!items || !items.length) {
      return res.status(400).json({ success: false, message: "Order must contain items" });
    }

    // Client sends {id, quantity} per item (and, harmlessly, price/name —
    // ignored entirely). create_and_pay_order() re-fetches every price
    // from menu_items itself; nothing from req.body ever reaches the
    // ledger.
    const itemsForFn = items.map((i) => ({ id: i.id, quantity: i.quantity }));

    const { data: result, error } = await supabase.rpc("create_and_pay_order", {
      p_idempotency_key: idempotencyKey,
      p_user_id: req.userId,
      p_items: itemsForFn,
      p_delivery_address: delivery_address || null,
      p_delivery_phone: delivery_phone || null,
      p_delivery_instructions: delivery_instructions || null,
      p_notes: notes || null,
    });

    if (error) {
      console.error("create_and_pay_order RPC error:", error);
      return res.status(500).json({ success: false, message: "Failed to create order" });
    }

    if (!result.success) {
      const statusByCode = {
        EMPTY_CART: 400,
        INVALID_QUANTITY: 400,
        ITEM_NOT_FOUND: 400,
        INVALID_TOTAL: 400,
        USER_NOT_FOUND: 404,
        INSUFFICIENT_BALANCE: 400,
      };
      return res.status(statusByCode[result.code] || 500).json(result);
    }

    // Fire-and-forget notification — matches spec's "financial success
    // is independent of notification success." Not awaited critically:
    // if this insert fails, the order is still PAID and the response
    // below is unaffected. A real outbox/retry worker is a later phase;
    // this is the minimum viable version of "don't let this block or
    // fail the financial transaction."
    supabase
      .from("payment_notifications")
      .insert([
        {
          user_id: req.userId,
          type: "payment_success",
          title: "Order Placed Successfully 🎉",
          message: `Your order #${result.order.id} has been placed. ₦${Number(result.order.total).toFixed(2)} has been deducted from your wallet.`,
          reference: result.order.id,
          created_at: new Date().toISOString(),
        },
      ])
      .then(({ error: notifErr }) => {
        if (notifErr) console.error("Order notification insert failed (non-fatal):", notifErr);
      });

    res.status(result.duplicate ? 200 : 201).json({
      success: true,
      message: result.duplicate ? "Order already processed" : "Order created successfully",
      order: result.order,
      balance_after: result.balance_after,
      transaction_id: result.transaction_id,
      ledger_entry_id: result.ledger_entry_id,
    });
  } catch (error) {
    console.error("Order error:", error);
    res.status(500).json({ success: false, message: error.message || "Failed to create order" });
  }
});*/

app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const { items, delivery_address, delivery_phone, delivery_instructions, notes } = req.body;

    // Idempotency key: header first (once app.js sends one — see the
    // frontend patch), falling back to a per-request UUID so this
    // route still works before that frontend change ships. A
    // fallback key protects nothing (it's different every call) but
    // costs nothing either — real double-tap protection starts
    // working the moment the frontend sends a stable key.
    const idempotencyKey = req.headers["idempotency-key"] || uuidv4();

    if (!items || !items.length) {
      return res.status(400).json({ success: false, message: "Order must contain items" });
    }

    // Client sends {id, quantity} per item (and, harmlessly, price/name —
    // ignored entirely). create_and_pay_order() re-fetches every price
    // from menu_items itself; nothing from req.body ever reaches the
    // ledger.
    const itemsForFn = items.map((i) => ({ id: i.id, quantity: i.quantity }));

    const { data: result, error } = await supabase.rpc("create_and_pay_order", {
      p_idempotency_key: idempotencyKey,
      p_user_id: req.userId,
      p_items: itemsForFn,
      p_delivery_address: delivery_address || null,
      p_delivery_phone: delivery_phone || null,
      p_delivery_instructions: delivery_instructions || null,
      p_notes: notes || null,
    });

    if (error) {
      console.error("create_and_pay_order RPC error:", error);
      return res.status(500).json({ success: false, message: "Failed to create order" });
    }

    if (!result.success) {
      const statusByCode = {
        EMPTY_CART: 400,
        INVALID_QUANTITY: 400,
        ITEM_NOT_FOUND: 400,
        INVALID_TOTAL: 400,
        USER_NOT_FOUND: 404,
        INSUFFICIENT_BALANCE: 400,
      };
      return res.status(statusByCode[result.code] || 500).json(result);
    }

    // Notification is no longer inserted here directly — it's now a
    // retryable background_jobs row (send_push_notification), fanned
    // out from the ORDER_PAID outbox event create_and_pay_order()
    // writes atomically alongside the order itself (see 008 and
    // frozyla-job-worker.js). A cron-triggered worker batch picks it
    // up within seconds; no code in this route needs to know that.

    res.status(result.duplicate ? 200 : 201).json({
      success: true,
      message: result.duplicate ? "Order already processed" : "Order created successfully",
      order: result.order,
      balance_after: result.balance_after,
      transaction_id: result.transaction_id,
      ledger_entry_id: result.ledger_entry_id,
    });
  } catch (error) {
    console.error("Order error:", error);
    res.status(500).json({ success: false, message: error.message || "Failed to create order" });
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

/*app.patch("/api/orders/:id/status", authMiddleware, async (req, res) => {
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
});*/

app.patch("/api/orders/:id/status", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    let { status, reason } = req.body;
    const isAdmin = req.userRole === "admin";

    // The admin order table still sends the pre-state-machine lowercase
    // vocabulary ('preparing', 'ready', 'delivered'). Translate it for
    // admins so those buttons keep working. 'cancelled' is intentionally
    // NOT mapped: cancellation is now a refund flow (CANCELLATION_PENDING
    // -> approve-cancellation), not a one-click status.
    if (isAdmin && typeof status === "string") {
      const LEGACY_ADMIN_STATUS = {
        preparing: "PREPARING",
        ready: "READY_FOR_DELIVERY",
        delivered: "DELIVERED",
      };
      status = LEGACY_ADMIN_STATUS[status] || status;
    }

    // Customers may only ever request cancellation. Admins/staff get
    // the full lifecycle via the admin route below, not this one.
    if (!isAdmin && status !== "CANCELLATION_PENDING") {
      return res.status(403).json({
        success: false,
        message: "Customers can only request cancellation. Use the admin endpoint for other status changes.",
      });
    }

    if (!isAdmin) {
      // Ownership check stays — transition_order_status() itself
      // doesn't know or care who's asking, only whether the
      // FROM->TO transition is valid.
      const { data: order } = await supabase.from("orders").select("user_id").eq("id", id).maybeSingle();
      if (!order || order.user_id !== req.userId) {
        return res.status(404).json({ success: false, message: "Order not found" });
      }
    }

    const { data: result, error } = isAdmin
      ? await adminTransitionOrder(id, status, req.userId, reason)
      : await supabase.rpc("transition_order_status", {
          p_order_id: id,
          p_new_status: status,
          p_actor_type: "customer",
          p_actor_id: req.userId,
          p_reason: reason || null,
        });

    if (error) {
      console.error("transition_order_status RPC error:", error);
      return res.status(500).json({ success: false, message: "Failed to update order" });
    }
    if (!result.success) {
      const statusCode = result.code === "ORDER_NOT_FOUND" ? 404 : 400;
      return res.status(statusCode).json(result);
    }

    res.json({ success: true, message: "Order updated", ...result });
  } catch (error) {
    console.error("Order update error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
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
}*/

app.get("/api/wallet/balance", authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("balance, account_number, account_status, name, email, phone")
      .eq("id", req.userId)
      .single();

    if (error || !user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Stage 1 monitoring — compares against the new ledger on every
    // request, logs/flags disagreement, changes NOTHING about the
    // response. Remove this block (or flip WALLET_BALANCE_SOURCE, see
    // Stage 2) once you're confident. Never let a failure here affect
    // the response — this must degrade to "just return users.balance"
    // silently on any error.
    if (process.env.GL_WALLET_BALANCE_MONITOR === "true") {
      compareWalletBalanceToLedger(req.userId, user.balance).catch((err) =>
        console.error("[GL-MONITOR] Balance comparison failed (non-fatal):", err),
      );
    }

    res.json({
      success: true,
      balance: parseFloat(user.balance) || 0,
      account_number: user.account_number,
      account_status: user.account_status || "active",
      name: user.name,
      email: user.email,
      phone: user.phone,
    });
  } catch (error) {
    console.error("Get wallet balance error:", error);
    res.status(500).json({ success: false, message: "Failed to load wallet balance" });
  }
});

// Fire-and-forget — never awaited by the route above, never allowed
// to affect the response. Reuses the exact same
// createInvestigationCase() detection-only path Phase 2's
// reconciliation-engine.js already uses for its scheduled sweep; this
// is the same check, just triggered per-request instead of per-cron-run,
// so a live discrepancy surfaces the moment a real user hits it
// instead of waiting for the next scheduled sweep.
async function compareWalletBalanceToLedger(userId, usersBalanceValue) {
  const ledgerService = require("../lib/ledger-service");
  const glBalance = await ledgerService.getAccountBalance({ accountCode: "2000", ownerId: userId });
  const difference = Math.round((Number(usersBalanceValue) - Number(glBalance.ledger_balance)) * 100) / 100;

  if (Math.abs(difference) > 0.01) {
    console.warn(`[GL-MONITOR] Balance mismatch for user ${userId}: users.balance=${usersBalanceValue}, gl=${glBalance.ledger_balance}, diff=${difference}`);
    await ledgerService.createInvestigationCase({
      caseType: "WALLET_BALANCE_ENDPOINT_MISMATCH",
      severity: Math.abs(difference) > 10000 ? "CRITICAL" : Math.abs(difference) > 100 ? "HIGH" : "MEDIUM",
      accountCode: "2000",
      ownerId: userId,
      expectedAmount: glBalance.ledger_balance,
      actualAmount: usersBalanceValue,
      detectedBy: "SYSTEM",
    });
  }
}

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

// ------------------------------------------------------------
// Fund with Card (Flutterwave, via Feecent) — NEW, replaces the
// manual admin-approval "/api/wallet/fund" + payment_cards flow for
// end-user card payments. That old flow stored raw card numbers in
// payment_cards and required a human admin to approve before any real
// money had actually moved — see CARD_FUNDING_COMPLIANCE.md for why
// this is being retired in favor of an actual Flutterwave charge.
// This route and the one below never see a card number: Feecent
// returns a Flutterwave-hosted checkout URL, and this app only ever
// asks "what's the status of reference X" afterward.
// ------------------------------------------------------------
app.post("/api/wallet/fund-card", authMiddleware, async (req, res) => {
  try {
    const { amount } = req.body;
    const amountNum = parseFloat(amount);
    if (!amountNum || amountNum <= 0) {
      return res.status(400).json({ success: false, message: "Invalid amount" });
    }

    // Same min/max settings the old flow already enforced — reused
    // as-is rather than duplicated with different numbers.
    const { data: settings } = await supabase
      .from("payment_settings")
      .select("key, value")
      .in("key", ["min_funding_amount", "max_funding_amount"]);
    const minFunding = parseFloat(settings?.find((s) => s.key === "min_funding_amount")?.value || "10");
    const maxFunding = parseFloat(settings?.find((s) => s.key === "max_funding_amount")?.value || "100000");
    if (amountNum < minFunding) {
      return res.status(400).json({ success: false, message: `Minimum funding amount is ₦${minFunding.toFixed(2)}` });
    }
    if (amountNum > maxFunding) {
      return res.status(400).json({ success: false, message: `Maximum funding amount is ₦${maxFunding.toFixed(2)}` });
    }

    const { data: user, error: userError } = await supabase
      .from("users")
      .select("account_number")
      .eq("id", req.userId)
      .single();
    if (userError || !user || !user.account_number) {
      return res.status(500).json({ success: false, message: "Could not resolve your account for funding" });
    }

    const amountMinor = Math.round(amountNum * 100); // naira -> kobo, once, at this boundary
    const idempotencyKey = uuidv4();

    const checkout = await feecentPaymentsClient.createCheckout({
      frozylaUserId: user.account_number,
      amountMinor,
      currency: "NGN",
      idempotencyKey,
    });

    if (!checkout.success) {
      if (checkout.code === "CARD_FUNDING_DISABLED") {
        return res.status(503).json({ success: false, message: "Card funding is not available right now." });
      }
      console.error("Card funding checkout error:", checkout.error);
      return res.status(502).json({ success: false, message: "Could not start card funding. Please try again." });
    }

    res.json({
      success: true,
      reference: checkout.reference,
      checkoutUrl: checkout.checkoutUrl,
    });
  } catch (error) {
    console.error("Fund with card error:", error);
    res.status(500).json({ success: false, message: "Failed to start card funding" });
  }
});

app.get("/api/wallet/fund-card/status/:reference", authMiddleware, async (req, res) => {
  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("account_number")
      .eq("id", req.userId)
      .single();
    if (userError || !user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const result = await feecentPaymentsClient.getStatus(req.params.reference);
    if (result.notFound) {
      return res.status(404).json({ success: false, message: "Funding reference not found" });
    }
    if (!result.success) {
      console.error("Card funding status error:", result.error);
      return res.status(502).json({ success: false, message: "Could not check funding status" });
    }

    // Ownership check: this reference must belong to THIS user's
    // account_number. references are unguessable UUIDs, but this
    // closes the gap anyway rather than relying on that alone — see
    // CARD_FUNDING_COMPLIANCE.md.
    if (result.data.frozylaUserId !== user.account_number) {
      return res.status(404).json({ success: false, message: "Funding reference not found" });
    }

    res.json({
      success: true,
      status: result.data.status,
      amountMinor: result.data.amountMinor,
      currency: result.data.currency,
      failureReason: result.data.failureReason,
    });
  } catch (error) {
    console.error("Fund with card status error:", error);
    res.status(500).json({ success: false, message: "Failed to check funding status" });
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

app.post(
  "/api/admin/orders/:id/approve-cancellation",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    const { data: result, error } = await supabase.rpc("transition_order_status", {
      p_order_id: req.params.id,
      p_new_status: "REFUND_PENDING",
      p_actor_type: "admin",
      p_actor_id: req.userId,
      p_reason: req.body.reason || null,
    });
    if (error) return res.status(500).json({ success: false, message: "Failed to approve cancellation" });
    if (!result.success) return res.status(result.code === "ORDER_NOT_FOUND" ? 404 : 400).json(result);

    // Immediately execute the refund — for a wallet (instant, atomic)
    // this doesn't need to be a separate manual step; REFUND_PENDING
    // existing as its own audited transition above is what matters,
    // not making an admin click twice for something synchronous.
    const { data: refundResult, error: refundErr } = await supabase.rpc("refund_order", {
      p_order_id: req.params.id,
      p_actor_type: "admin",
      p_actor_id: req.userId,
      p_reason: req.body.reason || "Cancellation approved",
    });
    if (refundErr) {
      console.error("refund_order RPC error:", refundErr);
      return res.status(500).json({ success: false, message: "Cancellation approved but refund failed — order is now REFUND_PENDING, needs manual attention" });
    }
    res.json({ success: true, message: "Cancellation approved and refunded", ...refundResult });
  },
);

// Admin rejects a cancellation request — back to whatever normal
// fulfillment state makes sense. No money moves; nothing to be
// idempotent about beyond the state machine's own no-op handling.
app.post(
  "/api/admin/orders/:id/reject-cancellation",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    const { resume_status } = req.body; // e.g. "PREPARING" — whatever it actually was before
    const { data: result, error } = await supabase.rpc("transition_order_status", {
      p_order_id: req.params.id,
      p_new_status: resume_status || "CONFIRMED",
      p_actor_type: "admin",
      p_actor_id: req.userId,
      p_reason: req.body.reason || "Cancellation rejected",
    });
    if (error) return res.status(500).json({ success: false, message: "Failed to reject cancellation" });
    if (!result.success) return res.status(result.code === "ORDER_NOT_FOUND" ? 404 : 400).json(result);
    res.json({ success: true, message: "Cancellation rejected", ...result });
  },
);

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

// GET /api/admin/jobs?status=dead_letter&job_type=send_order_confirmation_email&limit=50&offset=0
app.get("/api/admin/jobs", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { status, job_type, limit, offset } = req.query;
    let query = supabase
      .from("background_jobs")
      .select("*", { count: "exact" })
      .order("created_at", { ascending: false })
      .range(Number(offset) || 0, (Number(offset) || 0) + (Math.min(Number(limit) || 50, 200) - 1));

    if (status) query = query.eq("status", status);
    if (job_type) query = query.eq("job_type", job_type);

    const { data, error, count } = await query;
    if (error) throw error;
    res.json({ success: true, jobs: data, total: count });
  } catch (error) {
    console.error("List jobs error:", error);
    res.status(500).json({ success: false, message: "Failed to load jobs" });
  }
});

// GET /api/admin/jobs/summary — counts per status, for a dashboard tile
app.get("/api/admin/jobs/summary", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from("background_jobs").select("status");
    if (error) throw error;
    const summary = data.reduce((acc, j) => {
      acc[j.status] = (acc[j.status] || 0) + 1;
      return acc;
    }, {});
    res.json({ success: true, summary });
  } catch (error) {
    console.error("Job summary error:", error);
    res.status(500).json({ success: false, message: "Failed to load job summary" });
  }
});

// POST /api/admin/jobs/:id/retry — resets to pending with a fresh
// attempt budget. Safe: none of today's job types touch money
// (notifications only) — see frozyla-job-worker.js's JOB_HANDLERS.
// If a future job type DOES move money, that job type should not be
// retryable through this generic endpoint without its own review.
app.post("/api/admin/jobs/:id/retry", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data: job, error: fetchErr } = await supabase
      .from("background_jobs")
      .select("id, status")
      .eq("id", req.params.id)
      .maybeSingle();
    if (fetchErr) throw fetchErr;
    if (!job) return res.status(404).json({ success: false, message: "Job not found" });
    if (job.status === "completed") {
      return res.status(400).json({ success: false, message: "Job already completed — nothing to retry" });
    }

    const { data, error } = await supabase
      .from("background_jobs")
      .update({ status: "pending", attempt_count: 0, next_retry_at: new Date().toISOString(), last_error: null, updated_at: new Date().toISOString() })
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, message: "Job requeued", job: data });
  } catch (error) {
    console.error("Retry job error:", error);
    res.status(500).json({ success: false, message: "Failed to retry job" });
  }
});

// POST /api/admin/jobs/:id/cancel — marks dead_letter/retrying job as
// permanently failed, no further attempts. "cancel where safe" per
// spec section 16 — safe here for the same reason retry is: no money
// involved in any job type that exists today.
app.post("/api/admin/jobs/:id/cancel", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("background_jobs")
      .update({ status: "failed", last_error: req.body.reason || "Cancelled by admin", updated_at: new Date().toISOString() })
      .eq("id", req.params.id)
      .select()
      .single();
    if (error) throw error;
    if (!data) return res.status(404).json({ success: false, message: "Job not found" });
    res.json({ success: true, message: "Job cancelled", job: data });
  } catch (error) {
    console.error("Cancel job error:", error);
    res.status(500).json({ success: false, message: "Failed to cancel job" });
  }
});

// ------------------------------------------------------------
// Refund / reconciliation queue — orders needing a human decision
// ------------------------------------------------------------

// GET /api/admin/orders/attention-queue — everything sitting in a
// state that needs an admin action to move forward. One endpoint
// covers all four "needs a human" states rather than four separate
// queue views.
app.get("/api/admin/orders/attention-queue", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("orders")
      .select("id, user_id, total, status, payment_status, created_at, updated_at")
      .in("status", ["CANCELLATION_PENDING", "REFUND_PENDING", "FULFILLMENT_FAILED", "RECONCILIATION_REQUIRED"])
      .order("updated_at", { ascending: true }); // oldest-waiting first
    if (error) throw error;

    const byStatus = data.reduce((acc, o) => {
      (acc[o.status] = acc[o.status] || []).push(o);
      return acc;
    }, {});
    res.json({ success: true, total: data.length, by_status: byStatus, orders: data });
  } catch (error) {
    console.error("Attention queue error:", error);
    res.status(500).json({ success: false, message: "Failed to load attention queue" });
  }
});

// GET /api/admin/orders/:id/history — full audit trail for one order,
// the transition-by-transition record transition_order_status() has
// been writing since Phase 3.
app.get("/api/admin/orders/:id/history", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data: order, error: orderErr } = await supabase
      .from("orders")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (orderErr) throw orderErr;
    if (!order) return res.status(404).json({ success: false, message: "Order not found" });

    const { data: transitions, error: transErr } = await supabase
      .from("order_status_transitions")
      .select("*")
      .eq("order_id", req.params.id)
      .order("created_at", { ascending: true });
    if (transErr) throw transErr;

    res.json({ success: true, order, transitions });
  } catch (error) {
    console.error("Order history error:", error);
    res.status(500).json({ success: false, message: "Failed to load order history" });
  }
});

// Approve funding request (admin)
app.patch(
  "/api/admin/funding-requests/:id/approve",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { admin_notes } = req.body;

      const { data: result, error } = await supabase.rpc("approve_card_funding_request", {
        p_funding_request_id: id,
        p_admin_id: req.userId,
        p_admin_notes: admin_notes || null,
      });

      if (error) {
        console.error("approve_card_funding_request RPC error:", error);
        return res.status(500).json({ success: false, message: "Failed to approve funding" });
      }

      if (!result.success) {
        const statusByCode = { NOT_FOUND: 404, ALREADY_PROCESSED: 400, USER_NOT_FOUND: 404 };
        return res.status(statusByCode[result.code] || 500).json({
          success: false,
          message: result.message || "Could not approve funding request",
        });
      }

      res.json({
        success: true,
        message: "Funding request approved",
        request: { id: result.funding_request_id, status: "approved" },
        ledger_entry_id: result.ledger_entry_id,
        gl_journal_entry_id: result.gl_journal_entry_id,
        gl_journal_reference: result.gl_journal_reference,
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