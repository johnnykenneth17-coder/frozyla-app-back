// push-routes.js (Frozyla side)
//
// Mount in server.js:
//   const pushRouter = require("./lib/push-routes");
//   app.use("/api/push", authMiddleware, pushRouter);
//   // (confirm this matches window.API_BASE + "/push/register" in
//   // capacitor-bridge.js — mount path here assumes API_BASE already
//   // includes "/api"; adjust the mount prefix if not)
//
// This closes the gap found while reading capacitor-bridge.js:
// handlePushToken() has always called an endpoint that didn't exist.
// Registration is real and complete. SENDING a push is an honest
// stub — no APNs/FCM credentials exist in this codebase, and per this
// project's own established convention (see frozyla-job-worker.js's
// send_order_confirmation_email — "NotImplementedError, loud and
// immediate, never fake success"), sendPushToUser() in
// push-sender.js follows the same philosophy rather than pretending
// to deliver notifications that don't actually go anywhere.

const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

router.post("/register", async (req, res) => {
  try {
    const { token, app } = req.body || {};
    if (!token) return res.status(400).json({ success: false, message: "token is required" });

    // Platform isn't sent by capacitor-bridge.js's handlePushToken()
    // today — inferred here from the User-Agent as a best effort;
    // exact enough for "which push service to call" once sending is
    // actually implemented, not load-bearing for anything security-sensitive.
    const userAgent = req.headers["user-agent"] || "";
    const platform = /android/i.test(userAgent) ? "android" : /iphone|ipad|ios/i.test(userAgent) ? "ios" : "unknown";

    const { error } = await supabase
      .from("push_tokens")
      .upsert(
        { user_id: req.userId, token, platform, app: app === "rider" ? "rider" : "customer", is_active: true, last_seen_at: new Date().toISOString() },
        { onConflict: "token" },
      );
    if (error) throw error;

    res.json({ success: true });
  } catch (error) {
    console.error("[PUSH] register error:", error);
    res.status(500).json({ success: false, message: "Failed to register push token" });
  }
});

router.post("/unregister", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ success: false, message: "token is required" });
    await supabase.from("push_tokens").update({ is_active: false }).eq("token", token).eq("user_id", req.userId);
    res.json({ success: true });
  } catch (error) {
    console.error("[PUSH] unregister error:", error);
    res.status(500).json({ success: false, message: "Failed to unregister push token" });
  }
});

module.exports = router;