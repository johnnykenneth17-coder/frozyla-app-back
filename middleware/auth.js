// ============================================
// AUTH MIDDLEWARE - Production Ready
// ============================================

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { createClient } = require("@supabase/supabase-js");

// Initialize Supabase with service key for admin operations
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY,
);

const JWT_SECRET =
  process.env.JWT_SECRET || "frozyla_super_secret_key_change_in_production";

// ===== JWT HELPERS =====
function generateToken(userId, email, role = "user") {
  return jwt.sign({ userId, email, role }, JWT_SECRET, { expiresIn: "7d" });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// ===== AUTH MIDDLEWARE =====
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized: No token provided",
    });
  }

  const token = authHeader.split(" ")[1];
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized: Invalid token",
    });
  }

  req.userId = decoded.userId;
  req.userEmail = decoded.email;
  req.userRole = decoded.role || "user";
  next();
}

// ===== ADMIN MIDDLEWARE =====
function adminMiddleware(req, res, next) {
  if (!req.userRole || req.userRole !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Admin access required",
    });
  }
  next();
}

// ===== STAFF MIDDLEWARE =====
function staffMiddleware(req, res, next) {
  const allowedRoles = ["admin", "manager", "staff"];
  if (!req.userRole || !allowedRoles.includes(req.userRole)) {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Staff access required",
    });
  }
  next();
}

// ===== VALIDATION HELPERS =====
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePassword(password) {
  // At least 6 characters, 1 uppercase, 1 lowercase, 1 number
  const re = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
  return re.test(password);
}

function sanitizeInput(input) {
  if (!input) return "";
  return input.trim().replace(/[<>]/g, "");
}

// ===== AUTH FUNCTIONS =====
async function signupUser(req, res) {
  try {
    const { email, password, name } = req.body;

    // Validate input presence
    if (!email || !password || !name) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
        fields: { email: !email, password: !password, name: !name },
      });
    }

    // Sanitize inputs
    const sanitizedEmail = sanitizeInput(email.toLowerCase());
    const sanitizedName = sanitizeInput(name);

    // Validate email format
    if (!validateEmail(sanitizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email format",
      });
    }

    // Validate password strength
    if (!validatePassword(password)) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 6 characters with uppercase, lowercase, and a number",
      });
    }

    // Check if user exists
    const { data: existing, error: checkError } = await supabase
      .from("users")
      .select("id, email")
      .eq("email", sanitizedEmail)
      .single();

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "User already exists with this email",
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userId = require("uuid").v4();

    // Create user with default role 'user'
    const { data: user, error: createError } = await supabase
      .from("users")
      .insert([
        {
          id: userId,
          email: sanitizedEmail,
          password: hashedPassword,
          name: sanitizedName,
          role: "user",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ])
      .select("id, email, name, role, created_at")
      .single();

    if (createError) {
      console.error("Signup error:", createError);
      return res.status(500).json({
        success: false,
        message: "Failed to create user",
      });
    }

    // Generate token with role
    const token = generateToken(userId, sanitizedEmail, "user");

    // Return success
    res.status(201).json({
      success: true,
      message: "Account created successfully",
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role || "user",
        created_at: user.created_at,
      },
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

async function loginUser(req, res) {
  try {
    const { email, password } = req.body;

    // Validate input presence
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    // Sanitize email
    const sanitizedEmail = sanitizeInput(email.toLowerCase());

    // Validate email format
    if (!validateEmail(sanitizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email format",
      });
    }

    // Find user
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", sanitizedEmail)
      .single();

    if (error || !user) {
      // Use generic message for security
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      // Log failed attempt (for security monitoring)
      console.warn(`Failed login attempt for ${sanitizedEmail} from ${req.ip}`);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Update last login
    await supabase
      .from("users")
      .update({
        last_login: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq("id", user.id);

    // Generate token with role
    const token = generateToken(user.id, user.email, user.role || "user");

    // Return success with role info
    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role || "user",
        created_at: user.created_at,
        last_login: user.last_login,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

async function getProfile(req, res) {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, name, role, created_at, last_login")
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
      user: {
        ...user,
        role: user.role || "user",
      },
    });
  } catch (error) {
    console.error("Profile error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

async function changePassword(req, res) {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Both passwords are required",
      });
    }

    // Validate new password strength
    if (!validatePassword(newPassword)) {
      return res.status(400).json({
        success: false,
        message:
          "New password must be at least 6 characters with uppercase, lowercase, and a number",
      });
    }

    // Get current user with password
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("id", req.userId)
      .single();

    if (error || !user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password
    const { error: updateError } = await supabase
      .from("users")
      .update({
        password: hashedPassword,
        updated_at: new Date().toISOString(),
      })
      .eq("id", req.userId);

    if (updateError) {
      console.error("Password update error:", updateError);
      return res.status(500).json({
        success: false,
        message: "Failed to update password",
      });
    }

    res.json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

async function refreshToken(req, res) {
  try {
    const newToken = generateToken(req.userId, req.userEmail, req.userRole);
    res.json({
      success: true,
      token: newToken,
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

// Export all functions
module.exports = {
  authMiddleware,
  adminMiddleware,
  staffMiddleware,
  signupUser,
  loginUser,
  getProfile,
  changePassword,
  refreshToken,
  generateToken,
  verifyToken,
  validateEmail,
  validatePassword,
  sanitizeInput,
};
