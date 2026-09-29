// rider-middleware.js (Frozyla side)
//
// The rider equivalent of adminMiddleware — checks the AUTHENTICATED
// user (already resolved by the existing authMiddleware/JWT, same as
// every other Frozyla surface) actually has role='delivery', and that
// their account is in a state that allows delivery actions. Per spec
// section 5: never trust a client-side status; every rider route
// re-checks this on every request, not just at login.

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

async function riderMiddleware(req, res, next) {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("id, role, status, account_status, rider_availability_status")
      .eq("id", req.userId)
      .single();

    if (error || !user) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    if (user.role !== "delivery") {
      return res.status(403).json({ success: false, message: "Rider access required" });
    }
    if (user.account_status && user.account_status !== "active") {
      return res.status(403).json({
        success: false,
        code: "ACCOUNT_RESTRICTED",
        message: "Your account has been restricted. Contact Frozyla support.",
      });
    }
    if (user.status === "inactive") {
      return res.status(403).json({
        success: false,
        code: "ACCOUNT_DEACTIVATED",
        message: "Your rider account has been deactivated. Contact Frozyla support.",
      });
    }
    // 'on_leave' is intentionally NOT blocked here — a rider on leave
    // can still open the app to check history/earnings; they just
    // can't be assigned NEW runs (that's an admin-side assignment
    // check, not a route-access check).

    req.rider = user;
    next();
  } catch (err) {
    console.error("[RIDER-MIDDLEWARE] error:", err);
    res.status(500).json({ success: false, message: "Authorization check failed" });
  }
}

module.exports = riderMiddleware;