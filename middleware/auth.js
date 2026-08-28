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

function validatePhone(phone) {
  // Digits only after stripping a leading +, 10-15 digits (E.164-ish)
  const digits = phone.replace(/[^\d]/g, "");
  return digits.length >= 10 && digits.length <= 15;
}

function normalizePhone(phone) {
  // Keep a leading + if present, strip everything else non-numeric
  const hasPlus = phone.trim().startsWith("+");
  const digits = phone.replace(/[^\d]/g, "");
  return hasPlus ? `+${digits}` : digits;
}

function validatePasscode(passcode) {
  // Exactly 6 digits
  return /^\d{6}$/.test(passcode);
}

function sanitizeInput(input) {
  if (!input) return "";
  return input.trim().replace(/[<>]/g, "");
}

// ===== ID NUMBER (was "account number") =====
// Rule: try to derive a 10-digit ID from the user's phone (dropping the
// leading 0 / country code). If that's taken, malformed, or missing
// (e.g. Google sign-up with no phone), fall back to a random unique
// 10-digit number instead. Never assign the same ID to two people.

function derivePhoneIdCandidate(phone) {
  if (!phone) return null;
  const digits = phone.replace(/[^\d]/g, "");
  if (digits.length === 13 && digits.startsWith("234")) {
    return digits.slice(3); // strip +234 country code
  }
  if (digits.length === 11 && digits.startsWith("0")) {
    return digits.slice(1); // strip leading 0
  }
  if (digits.length === 10) {
    return digits; // already bare 10 digits
  }
  return null; // not a shape we can cleanly derive from
}

function generateRandomIdCandidate() {
  let n = "";
  for (let i = 0; i < 10; i++) {
    n += Math.floor(Math.random() * 10);
  }
  return n;
}

async function isIdNumberTaken(idNumber) {
  const { data, error } = await supabase
    .from("users")
    .select("id")
    .eq("account_number", idNumber)
    .maybeSingle();
  if (error) throw error;
  return !!data;
}

// excludePhoneDerived: skip the phone-based attempt (used on retry after a
// DB-level unique-constraint race, where we already know that candidate lost)
async function generateIdNumber(phone, { excludePhoneDerived = false } = {}) {
  if (!excludePhoneDerived) {
    const phoneCandidate = derivePhoneIdCandidate(phone);
    if (phoneCandidate && !(await isIdNumberTaken(phoneCandidate))) {
      return phoneCandidate;
    }
  }

  // Phone-derived ID is unavailable, malformed, or already claimed by
  // someone else - assign a random unique 10-digit ID instead.
  for (let attempt = 0; attempt < 10; attempt++) {
    const candidate = generateRandomIdCandidate();
    if (!(await isIdNumberTaken(candidate))) {
      return candidate;
    }
  }

  throw new Error("Could not generate a unique ID number after 10 attempts");
}

// ===== AUTH FUNCTIONS =====
async function signupUser(req, res) {
  try {
    const { email, password, name, phone, passcode } = req.body;

    // Validate input presence
    if (!email || !password || !name || !phone || !passcode) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
        fields: {
          email: !email,
          password: !password,
          name: !name,
          phone: !phone,
          passcode: !passcode,
        },
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

    // Validate phone
    if (!validatePhone(phone)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid phone number (10-15 digits)",
      });
    }
    const normalizedPhone = normalizePhone(phone);

    // Validate passcode
    if (!validatePasscode(passcode)) {
      return res.status(400).json({
        success: false,
        message: "Passcode must be exactly 6 digits",
      });
    }

    // Check if user exists (email or phone)
    const { data: existing, error: checkError } = await supabase
      .from("users")
      .select("id, email, phone")
      .or(`email.eq.${sanitizedEmail},phone.eq.${normalizedPhone}`)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({
        success: false,
        message:
          existing.email === sanitizedEmail
            ? "User already exists with this email"
            : "User already exists with this phone number",
      });
    }

    // Hash password and passcode
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const hashedPasscode = await bcrypt.hash(passcode, saltRounds);
    const userId = require("uuid").v4();

    // Create user with default role 'user' - retry once if a concurrent
    // signup grabbed the same ID number between our check and this insert
    let user, createError;
    let idNumber = await generateIdNumber(normalizedPhone);
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await supabase
        .from("users")
        .insert([
          {
            id: userId,
            email: sanitizedEmail,
            password: hashedPassword,
            passcode_hash: hashedPasscode,
            name: sanitizedName,
            phone: normalizedPhone,
            role: "user",
            account_number: idNumber,
            auth_provider: "email",
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
        ])
        .select("id, email, name, phone, role, account_number, created_at")
        .single();

      user = result.data;
      createError = result.error;

      if (!createError) break;
      if (createError.code !== "23505" || attempt === 1) break;
      // Unique-constraint collision on account_number - regenerate and retry once
      idNumber = await generateIdNumber(normalizedPhone, {
        excludePhoneDerived: true,
      });
    }

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
        phone: user.phone,
        role: user.role || "user",
        account_number: user.account_number, // your ID Number
        id_number: user.account_number,
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

// ===== PASSCODE LOGIN =====
// identifier can be an email or a phone number
async function loginWithPasscode(req, res) {
  try {
    const { identifier, passcode } = req.body;

    if (!identifier || !passcode) {
      return res.status(400).json({
        success: false,
        message: "Email/phone number and passcode are required",
      });
    }

    if (!validatePasscode(passcode)) {
      return res.status(400).json({
        success: false,
        message: "Passcode must be exactly 6 digits",
      });
    }

    const trimmedIdentifier = identifier.trim();
    const isEmail = trimmedIdentifier.includes("@");

    let query = supabase.from("users").select("*");
    if (isEmail) {
      const sanitizedEmail = sanitizeInput(trimmedIdentifier.toLowerCase());
      if (!validateEmail(sanitizedEmail)) {
        return res.status(400).json({
          success: false,
          message: "Invalid email format",
        });
      }
      query = query.eq("email", sanitizedEmail);
    } else {
      if (!validatePhone(trimmedIdentifier)) {
        return res.status(400).json({
          success: false,
          message: "Invalid email or phone number",
        });
      }
      query = query.eq("phone", normalizePhone(trimmedIdentifier));
    }

    const { data: user, error } = await query.maybeSingle();

    if (error || !user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    if (!user.passcode_hash) {
      return res.status(400).json({
        success: false,
        message: "Passcode sign-in isn't set up for this account yet",
      });
    }

    const validPasscode = await bcrypt.compare(passcode, user.passcode_hash);
    if (!validPasscode) {
      console.warn(
        `Failed passcode login attempt for ${trimmedIdentifier} from ${req.ip}`,
      );
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    await supabase
      .from("users")
      .update({
        last_login: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq("id", user.id);

    const token = generateToken(user.id, user.email, user.role || "user");

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        role: user.role || "user",
        created_at: user.created_at,
        last_login: user.last_login,
      },
    });
  } catch (error) {
    console.error("Passcode login error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

// ===== GOOGLE OAUTH (sign-in + sign-up) =====
// Verifies a Google ID token from the client, then finds-or-creates the user.
// See the Google OAuth integration guide for how the client obtains idToken.
let googleClient = null;
function getGoogleClient() {
  if (!googleClient) {
    const { OAuth2Client } = require("google-auth-library");
    googleClient = new OAuth2Client();
  }
  return googleClient;
}

function googleAudiences() {
  return [
    process.env.GOOGLE_CLIENT_ID_WEB,
    process.env.GOOGLE_CLIENT_ID_ANDROID,
    process.env.GOOGLE_CLIENT_ID_IOS,
  ].filter(Boolean);
}

async function googleAuth(req, res) {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({
        success: false,
        message: "Google ID token is required",
      });
    }

    const audiences = googleAudiences();
    if (audiences.length === 0) {
      console.error(
        "Google OAuth is not configured: set GOOGLE_CLIENT_ID_WEB (and _ANDROID/_IOS if used)",
      );
      return res.status(500).json({
        success: false,
        message: "Google sign-in is not available right now",
      });
    }

    let payload;
    try {
      const ticket = await getGoogleClient().verifyIdToken({
        idToken,
        audience: audiences,
      });
      payload = ticket.getPayload();
    } catch (verifyError) {
      console.warn("Google token verification failed:", verifyError.message);
      return res.status(401).json({
        success: false,
        message: "Invalid Google sign-in token",
      });
    }

    if (!payload || !payload.email_verified) {
      return res.status(401).json({
        success: false,
        message: "Google account email is not verified",
      });
    }

    const googleId = payload.sub;
    const sanitizedEmail = sanitizeInput(payload.email.toLowerCase());
    const displayName = sanitizeInput(payload.name || sanitizedEmail.split("@")[0]);

    // 1) Already linked by google_id
    let { data: user, error: findError } = await supabase
      .from("users")
      .select("*")
      .eq("google_id", googleId)
      .maybeSingle();
    if (findError) throw findError;

    if (!user) {
      // 2) Existing email/password account with the same email -> link it
      const { data: existingByEmail, error: emailLookupError } = await supabase
        .from("users")
        .select("*")
        .eq("email", sanitizedEmail)
        .maybeSingle();
      if (emailLookupError) throw emailLookupError;

      if (existingByEmail) {
        const { data: linked, error: linkError } = await supabase
          .from("users")
          .update({
            google_id: googleId,
            updated_at: new Date().toISOString(),
          })
          .eq("id", existingByEmail.id)
          .select("*")
          .single();
        if (linkError) throw linkError;
        user = linked;
      } else {
        // 3) Brand new account via Google - no password/passcode set by the user,
        // so we store an unusable random hash to satisfy the NOT NULL constraint.
        // Google doesn't give us a phone number, so this always uses the
        // random-fallback branch of generateIdNumber.
        const randomSecret = require("uuid").v4() + require("uuid").v4();
        const hashedRandom = await bcrypt.hash(randomSecret, 12);
        const userId = require("uuid").v4();

        let created, createError;
        let idNumber = await generateIdNumber(null);
        for (let attempt = 0; attempt < 2; attempt++) {
          const result = await supabase
            .from("users")
            .insert([
              {
                id: userId,
                email: sanitizedEmail,
                password: hashedRandom,
                name: displayName,
                role: "user",
                account_number: idNumber,
                google_id: googleId,
                auth_provider: "google",
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
              },
            ])
            .select("*")
            .single();

          created = result.data;
          createError = result.error;

          if (!createError) break;
          if (createError.code !== "23505" || attempt === 1) break;
          idNumber = await generateIdNumber(null);
        }

        if (createError) throw createError;
        user = created;
      }
    }

    await supabase
      .from("users")
      .update({
        last_login: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq("id", user.id);

    const token = generateToken(user.id, user.email, user.role || "user");

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        role: user.role || "user",
        created_at: user.created_at,
        last_login: user.last_login,
      },
    });
  } catch (error) {
    console.error("Google auth error:", error);
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
  loginWithPasscode,
  googleAuth,
  getProfile,
  changePassword,
  refreshToken,
  generateToken,
  verifyToken,
  validateEmail,
  validatePassword,
  validatePhone,
  validatePasscode,
  normalizePhone,
  sanitizeInput,
  generateIdNumber,
};