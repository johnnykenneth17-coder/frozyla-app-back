// lib/legal-routes.js
//   GET  /api/legal/current   public: which version of each document is in force (for footers/links)
//   POST /api/legal/accept    authenticated: records an EXPLICIT acceptance of the current versions
// Acceptance is only ever recorded by this POST (or the signup flag), never by someone viewing a page.
const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const router = express.Router();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const CONTEXTS = ["checkout", "settings"];   // signup acceptance is recorded by the signup endpoint itself

router.get("/current", async (req, res) => {
  try {
    const { data, error } = await supabase.from("legal_documents").select("doc_type, version, title, path, required_at, effective_at").eq("is_current", true).order("doc_type");
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { console.error("[LEGAL] current:", e.message); res.status(500).json({ success: false, message: "Could not load documents" }); }
});

function acceptRouter(authMiddleware) {
  const r = express.Router();
  r.post("/accept", authMiddleware, async (req, res) => {
    try {
      const { documents, context } = req.body || {};
      if (!CONTEXTS.includes(context)) return res.status(400).json({ success: false, message: "invalid context" });
      if (!Array.isArray(documents) || documents.length === 0 || documents.length > 10 ||
          documents.some((d) => !d || typeof d.doc_type !== "string" || typeof d.version !== "string")) {
        return res.status(400).json({ success: false, message: "documents must list {doc_type, version}" });
      }
      const { data, error } = await supabase.rpc("record_legal_acceptance", {
        p_user_id: req.userId, p_docs: documents.map((d) => ({ doc_type: d.doc_type, version: d.version })), p_context: context, p_ip: req.ip || null,
      });
      if (error) throw error;
      if (!data.success) return res.status(409).json({ success: false, code: data.code, message: "These documents have been updated. Please review the latest version." });
      res.json({ success: true, recorded: data.recorded });
    } catch (e) { console.error("[LEGAL] accept:", e.message); res.status(500).json({ success: false, message: "Could not record acceptance" }); }
  });
  return r;
}
module.exports = { router, acceptRouter };
