// ============================================
// AUTH MIDDLEWARE - Production Ready
// ============================================

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const emailService = require("../lib/email-service");
const { createClient } = require("@supabase/supabase-js");

// Initialize Supabase with service key for admin operations
// SECURITY (F-01 / audit item 9): fail closed. The server must never start
// with a guessable JWT secret, and must never silently fall back to the
// public anon key (that would hide a misconfiguration and bypass the
// service-role model the whole backend is written for).
if (!process.env.SUPABASE_SERVICE_KEY) {
  throw new Error("SUPABASE_SERVICE_KEY is not set. Refusing to start.");
}
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || /change[_-]?(me|in[_-]?production)/i.test(JWT_SECRET)) {
  throw new Error(
    "JWT_SECRET is missing or is a placeholder value. Set a long random secret (>= 32 chars) in the environment. Refusing to start.",
  );
}
if (JWT_SECRET.length < 32) {
  console.error(
    "[AUTH] WARNING: JWT_SECRET is shorter than 32 characters. Rotate it to a long random value.",
  );
}

// ===== JWT HELPERS =====
// `tv` is the user's token_version at issue time. Changing/resetting a password increments the stored
// version, so every older token (including refresh) stops working; see authMiddleware.
function generateToken(userId, email, role = "user", tokenVersion = 0) {
  return jwt.sign({ userId, email, role, tv: tokenVersion }, JWT_SECRET, { expiresIn: "7d" });
}

function verifyToken(token) {
  try {
    // Pin the algorithm so a token can never be accepted under a different one.
    return jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
  } catch (error) {
    return null;
  }
}

// ===== ACCOUNT STATE (authoritative, short-lived cache) =====
// A signed JWT only proves who the caller WAS when the token was issued. The
// role and account status are re-read from the database (cached briefly, so
// the 5s polling does not become one query per request) which means:
//   - a demoted admin loses access within CACHE_TTL, not after 7 days
//   - a blocked/deleted account stops working immediately after the TTL
const ACCOUNT_CACHE_TTL_MS = 15000;
const ACCOUNT_CACHE_MAX = 5000;
const accountCache = new Map();

async function getAccountState(userId) {
  const hit = accountCache.get(userId);
  if (hit && Date.now() - hit.at < ACCOUNT_CACHE_TTL_MS) return hit.value;

  let { data, error } = await supabase
    .from("users")
    .select("id, role, account_status, token_version")
    .eq("id", userId)
    .maybeSingle();

  // Deploy-order safety: if migration 003 has not been applied the column does not exist (SQLSTATE 42703).
  // Fall back to the previous query instead of locking every user out; revocation simply is not active yet.
  if (error && (error.code === "42703" || /token_version/.test(error.message || ""))) {
    console.error("[AUTH] users.token_version missing: apply migrations/003_auth_recovery_legal.sql (session revocation inactive)");
    ({ data, error } = await supabase.from("users").select("id, role, account_status").eq("id", userId).maybeSingle());
  }

  if (error) {
    // Stale-on-error keeps a short DB blip from logging everyone out, but we
    // never invent a state we have not seen.
    if (hit) return hit.value;
    throw error;
  }

  const value = data
    ? { exists: true, role: data.role || "user", accountStatus: data.account_status || "active", tokenVersion: data.token_version || 0 }
    : { exists: false };
  if (accountCache.size >= ACCOUNT_CACHE_MAX) accountCache.clear();
  accountCache.set(userId, { at: Date.now(), value });
  return value;
}

function invalidateAccountCache(userId) {
  if (userId) accountCache.delete(userId);
  else accountCache.clear();
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

  let state;
  try {
    state = await getAccountState(decoded.userId);
  } catch (err) {
    console.error("[AUTH] account state lookup failed:", err.message);
    return res.status(503).json({
      success: false,
      message: "Service temporarily unavailable. Please try again.",
    });
  }

  if (!state.exists) {
    return res.status(401).json({ success: false, message: "Unauthorized: Invalid token" });
  }
  if (state.accountStatus === "blocked") {
    return res.status(403).json({
      success: false,
      code: "ACCOUNT_BLOCKED",
      message: "Your account has been blocked. Please contact support.",
    });
  }

  // Session revocation: a token issued before the last password change/reset carries an older version.
  if ((decoded.tv || 0) !== state.tokenVersion) {
    return res.status(401).json({
      success: false,
      code: "SESSION_REVOKED",
      message: "Your session has ended. Please sign in again.",
    });
  }

  req.userId = decoded.userId;
  req.userEmail = decoded.email;
  req.tokenVersion = state.tokenVersion;
  req.userRole = state.role; // DB is authoritative, not the token claim
  req.accountStatus = state.accountStatus;
  next();
}

// Money-moving routes additionally refuse restricted ("suspended") accounts.
// Reading history/profile and contacting support stay available so a
// restricted customer can still see their balance and ask for help.
function requireActiveAccount(req, res, next) {
  if (req.accountStatus && req.accountStatus !== "active") {
    return res.status(403).json({
      success: false,
      code: "ACCOUNT_RESTRICTED",
      message: "This action is unavailable while your account is restricted. Please contact support.",
    });
  }
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

// ===== LOGIN BRUTE-FORCE PROTECTION (F-07) =====
// A real bcrypt hash of a random string. Compared against when the account
// does not exist (or has no passcode) so "unknown account" costs the same time
// as "wrong password" and cannot be told apart by response time.
const DUMMY_HASH = "$2b$12$wozmGrZsx6B3DANPqm8Z/OZF7mTD03Rox0m5hGp8n6HDnKCmpyqIW";

function isLockedOut(user) {
  return !!(user && user.locked_until && new Date(user.locked_until) > new Date());
}

const lockedResponse = (res) =>
  res.status(429).json({
    success: false,
    code: "TOO_MANY_ATTEMPTS",
    message: "Too many failed attempts. Please try again in a few minutes.",
  });

// Atomic increment lives in SQL (migrations/001_auth_lockout.sql). If the
// migration has not been applied yet this logs and login keeps working
// exactly as before (the IP rate limiter still applies).
async function registerFailedLogin(userId) {
  try {
    const { error } = await supabase.rpc("register_failed_login", { p_user_id: userId });
    if (error) console.error("[AUTH] register_failed_login unavailable:", error.message);
  } catch (err) {
    console.error("[AUTH] register_failed_login failed:", err.message);
  }
}

async function clearFailedLogins(user) {
  // Only when there is something to clear; separate from the normal last_login
  // update so a missing column can never break a successful login.
  if (!user.failed_login_attempts && !user.locked_until) return;
  const { error } = await supabase
    .from("users")
    .update({ failed_login_attempts: 0, locked_until: null })
    .eq("id", user.id);
  if (error) console.error("[AUTH] could not clear failed-login counters:", error.message);
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
    // Legal acceptance must be an explicit, affirmative act (a ticked box), never implied by opening a page.
    // LEGAL_SIGNUP_ENFORCED=false lets already-published app builds (which cannot send the flag yet) keep
    // creating accounts during rollout. Those customers are still asked to accept at their first checkout.
    if (req.body.acceptedTerms !== true && process.env.LEGAL_SIGNUP_ENFORCED !== "false") {
      return res.status(400).json({
        success: false,
        code: "LEGAL_ACCEPTANCE_REQUIRED",
        message: "Please accept the Terms and Conditions and Privacy Policy to create an account.",
      });
    }

    // Two plain .eq() lookups instead of one .or("email.eq.<input>,...") string:
    // an email containing commas/parentheses could otherwise alter the filter.
    const { data: byEmail, error: emailCheckError } = await supabase
      .from("users")
      .select("id, email, phone")
      .eq("email", sanitizedEmail)
      .maybeSingle();
    const { data: byPhone, error: phoneCheckError } = await supabase
      .from("users")
      .select("id, email, phone")
      .eq("phone", normalizedPhone)
      .maybeSingle();
    const checkError = emailCheckError || phoneCheckError; // unchanged behaviour: the UNIQUE constraints are the backstop
    const existing = byEmail || byPhone;

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
    if (req.body.acceptedTerms === true) await recordSignupAcceptance(userId, req.ip);

    const token = generateToken(userId, sanitizedEmail, "user", 0);

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
    if (!email || !password || typeof email !== "string" || typeof password !== "string") {
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
      // Burn the same bcrypt time as a wrong password (no timing oracle).
      await bcrypt.compare(password, DUMMY_HASH);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    if (isLockedOut(user)) return lockedResponse(res);

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      // Log failed attempt (for security monitoring)
      console.warn(`Failed login attempt for ${sanitizedEmail} from ${req.ip}`);
      await registerFailedLogin(user.id);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    if (user.account_status === "blocked") {
      return res.status(403).json({
        success: false,
        code: "ACCOUNT_BLOCKED",
        message: "Your account has been blocked. Please contact support.",
      });
    }
    await clearFailedLogins(user);

    // Update last login
    await supabase
      .from("users")
      .update({
        last_login: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq("id", user.id);

    // Generate token with role
    const token = generateToken(user.id, user.email, user.role || "user", user.token_version || 0);

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

    if (!identifier || !passcode || typeof identifier !== "string" || typeof passcode !== "string") {
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

    // "No such account" and "account has no passcode" are deliberately
    // indistinguishable from "wrong passcode": same status, same body, same
    // bcrypt cost. (Previously a distinct 400 revealed which accounts exist.)
    if (error || !user || !user.passcode_hash) {
      await bcrypt.compare(passcode, DUMMY_HASH);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    if (isLockedOut(user)) return lockedResponse(res);

    const validPasscode = await bcrypt.compare(passcode, user.passcode_hash);
    if (!validPasscode) {
      console.warn(
        `Failed passcode login attempt for ${trimmedIdentifier} from ${req.ip}`,
      );
      await registerFailedLogin(user.id);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    if (user.account_status === "blocked") {
      return res.status(403).json({
        success: false,
        code: "ACCOUNT_BLOCKED",
        message: "Your account has been blocked. Please contact support.",
      });
    }
    await clearFailedLogins(user);

    await supabase
      .from("users")
      .update({
        last_login: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq("id", user.id);

    const token = generateToken(user.id, user.email, user.role || "user", user.token_version || 0);

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

    const token = generateToken(user.id, user.email, user.role || "user", user.token_version || 0);

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

// ===== LEGAL ACCEPTANCE =====
// Records acceptance of the CURRENT version of every document required at signup. The stored row
// carries user, document, version, context and timestamp (migrations/003).
async function recordSignupAcceptance(userId, ip) {
  try {
    const { data: missing, error } = await supabase.rpc("missing_legal_acceptances", { p_user_id: userId, p_context: "signup" });
    if (error) throw error;
    if (!missing || !missing.length) return;
    const { data, error: recErr } = await supabase.rpc("record_legal_acceptance", {
      p_user_id: userId, p_docs: missing.map((d) => ({ doc_type: d.doc_type, version: d.version })),
      p_context: "signup", p_ip: ip || null,
    });
    if (recErr || !data || !data.success) throw recErr || new Error(data && data.code);
  } catch (err) {
    // The account exists and the user did tick the box; do not strand them, but make the gap loud.
    console.error("[LEGAL] could not record signup acceptance:", err && err.message);
  }
}

// Gate for money-moving routes: the customer must have accepted the CURRENT version of every
// document required at checkout. 403 + the list of documents lets the app show a proper prompt.
function requireLegalAcceptance(context = "checkout") {
  return async (req, res, next) => {
    try {
      const { data, error } = await supabase.rpc("missing_legal_acceptances", { p_user_id: req.userId, p_context: context });
      if (error) {
        if (error.code === "42883" || error.code === "PGRST202") {
          console.error("[LEGAL] missing_legal_acceptances not found: apply migrations/003 (gate inactive)");
          return next();
        }
        throw error;
      }
      if (data && data.length) {
        return res.status(403).json({
          success: false, code: "LEGAL_ACCEPTANCE_REQUIRED",
          message: "Please review and accept our updated policies to continue.", documents: data,
        });
      }
      next();
    } catch (err) {
      console.error("[LEGAL] acceptance check failed:", err && err.message);
      res.status(503).json({ success: false, message: "Service temporarily unavailable. Please try again." });
    }
  };
}

// ===== PASSWORD RECOVERY =====
const RESET_TTL_MINUTES = 30;
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const GENERIC_RESET_RESPONSE = {
  success: true,
  message: "If an account exists for that email, we've sent password reset instructions.",
};

async function forgotPassword(req, res) {
  try {
    const email = req.body && req.body.email;
    if (typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || email.length > 254) {
      return res.status(400).json({ success: false, message: "Please enter a valid email address." });
    }
    const startedAt = Date.now();
    const raw = crypto.randomBytes(32).toString("base64url");   // 256-bit, unguessable
    const { data, error } = await supabase.rpc("create_password_reset", {
      p_email: email.trim(), p_token_hash: sha256(raw), p_ttl_minutes: RESET_TTL_MINUTES, p_ip: req.ip || null,
    });
    if (error) throw error;

    if (data && data.created) {
      const base = (process.env.FRONTEND_URL || "").replace(/\/+$/, "");
      if (!base || !emailService.isConfigured()) {
        console.error("[RECOVERY] FRONTEND_URL / Brevo not configured: reset email NOT sent");
      } else {
        const mail = emailService.passwordResetEmail({
          name: data.name, ttlMinutes: RESET_TTL_MINUTES,
          resetUrl: `${base}/reset-password.html?token=${encodeURIComponent(raw)}`,
        });
        const sent = await emailService.sendEmail({ to: data.email, name: data.name, ...mail });
        if (!sent.ok) console.error(`[RECOVERY] reset email failed (${sent.code}) for user ${data.user_id}`);
      }
    } else {
      // Even response time should not reveal whether the account exists: pad to roughly the cost of a send.
      await sleep(Math.max(0, 350 - (Date.now() - startedAt)) + Math.floor(Math.random() * 150));
    }
    // IDENTICAL answer whether or not the address is registered, blocked, throttled, or delivery failed.
    return res.json(GENERIC_RESET_RESPONSE);
  } catch (err) {
    console.error("[RECOVERY] forgot-password error:", err && err.message);
    return res.json(GENERIC_RESET_RESPONSE);   // an internal failure must not become an account oracle either
  }
}

async function resetPassword(req, res) {
  try {
    const { token, newPassword } = req.body || {};
    if (typeof token !== "string" || token.length < 20 || token.length > 200 || typeof newPassword !== "string") {
      return res.status(400).json({ success: false, code: "INVALID_OR_EXPIRED", message: "This reset link is invalid or has expired." });
    }
    if (!validatePassword(newPassword)) {
      return res.status(400).json({
        success: false, code: "WEAK_PASSWORD",
        message: "Password must be at least 6 characters with uppercase, lowercase, and a number",
      });
    }
    const hashed = await bcrypt.hash(newPassword, 12);
    const { data, error } = await supabase.rpc("consume_password_reset", { p_token_hash: sha256(token), p_new_password_hash: hashed });
    if (error) throw error;
    if (!data || !data.success) {
      return res.status(400).json({ success: false, code: "INVALID_OR_EXPIRED", message: "This reset link is invalid or has expired. Please request a new one." });
    }
    invalidateAccountCache(data.user_id);   // this instance sees the revocation immediately; others within the cache TTL
    emailService.sendEmail({ to: data.email, name: data.name, ...emailService.passwordChangedEmail({ name: data.name }) })
      .catch(() => {});   // confirmation is best-effort; the password HAS changed
    return res.json({ success: true, message: "Your password has been updated. Please sign in with your new password." });
  } catch (err) {
    console.error("[RECOVERY] reset-password error:", err && err.message);
    return res.status(500).json({ success: false, message: "Could not reset password. Please try again." });
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

    // Administrators are the highest-value accounts: stronger minimum, and no "change" to the same password.
    if (req.userRole === "admin" && newPassword.length < 10) {
      return res.status(400).json({ success: false, message: "Administrator passwords must be at least 10 characters." });
    }
    if (await bcrypt.compare(newPassword, user.password)) {
      return res.status(400).json({ success: false, message: "Your new password must be different from the current one." });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // One atomic statement: sets the hash, bumps token_version (revoking every existing session)
    // and voids any outstanding reset links.
    const { data: newVersion, error: updateError } = await supabase.rpc("set_user_password", {
      p_user_id: req.userId, p_new_password_hash: hashedPassword,
    });

    if (updateError) {
      console.error("Password update error:", updateError.message);
      return res.status(500).json({ success: false, message: "Failed to update password" });
    }
    invalidateAccountCache(req.userId);

    emailService.sendEmail({ to: user.email, name: user.name, ...emailService.passwordChangedEmail({ name: user.name }) })
      .catch(() => {});

    // The device that made the change stays signed in with a token at the NEW version.
    res.json({
      success: true,
      message: "Password updated successfully. Other devices have been signed out.",
      token: generateToken(user.id, user.email, user.role || "user", newVersion || 0),
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
    const newToken = generateToken(req.userId, req.userEmail, req.userRole, req.tokenVersion || 0);
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
  requireActiveAccount,
  requireLegalAcceptance,
  forgotPassword,
  resetPassword,
  invalidateAccountCache,
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