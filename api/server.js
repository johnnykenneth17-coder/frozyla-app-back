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
      });
    }

    if (!data || data.length === 0) {
      const mockMenu = [
        {
          id: "1",
          name: "Chicken Shawarma",
          description: "Grilled chicken with garlic sauce",
          price: 8.99,
          category: "shawarma",
          image_url: null,
        },
        {
          id: "2",
          name: "Beef Shawarma",
          description: "Tender beef with tahini",
          price: 9.99,
          category: "shawarma",
          image_url: null,
        },
        {
          id: "3",
          name: "Chocolate Cake",
          description: "Rich chocolate layer cake",
          price: 6.99,
          category: "cakes",
          image_url: null,
        },
        {
          id: "4",
          name: "Cheesecake",
          description: "Creamy New York style",
          price: 7.99,
          category: "cakes",
          image_url: null,
        },
        {
          id: "5",
          name: "Fresh Lemonade",
          description: "Hand-squeezed lemonade",
          price: 4.99,
          category: "beverages",
          image_url: null,
        },
        {
          id: "6",
          name: "Iced Coffee",
          description: "Cold brew with milk",
          price: 5.99,
          category: "beverages",
          image_url: null,
        },
        {
          id: "7",
          name: "Baklava",
          description: "Sweet pastry with nuts",
          price: 5.99,
          category: "desserts",
          image_url: null,
        },
        {
          id: "8",
          name: "Ice Cream Sundae",
          description: "Vanilla with hot fudge",
          price: 6.99,
          category: "desserts",
          image_url: null,
        },
      ];
      return res.json({ success: true, items: mockMenu });
    }

    res.json({ success: true, items: data });
  } catch (error) {
    console.error("Menu error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
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
