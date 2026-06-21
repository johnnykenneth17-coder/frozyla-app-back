// server.js - Update rate limiting

// ===== RATE LIMITING =====

// General rate limiter - for unauthenticated requests
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per 15 minutes
  message: {
    success: false,
    message: "Too many requests from this IP, please try again later."
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ✅ NEW: Less strict limiter for authenticated users
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute (1 per second)
  message: {
    success: false,
    message: "Too many requests, please slow down."
  },
  standardHeaders: true,
  legacyHeaders: false,
  // ✅ Skip rate limiting for admin users
  skip: (req) => {
    return req.userRole === 'admin';
  }
});

// ✅ NEW: Very lenient limiter for admin users
const adminLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 200, // 200 requests per minute
  message: {
    success: false,
    message: "Admin rate limit exceeded."
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply different limits based on route
app.use("/api/auth", authLimiter); // Auth routes - strict
app.use("/api", (req, res, next) => {
  // If authenticated, use auth limiter
  if (req.headers.authorization) {
    return authLimiter(req, res, next);
  }
  // Otherwise use general limiter
  return limiter(req, res, next);
});

// Admin routes - more lenient
app.use("/api/admin", (req, res, next) => {
  return adminLimiter(req, res, next);
});