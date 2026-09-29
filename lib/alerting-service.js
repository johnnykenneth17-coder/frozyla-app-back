// alerting-service.js (Frozyla side) — Phase 3
//
// Records alerts into system_alerts and (optionally) notifies a
// configured channel. Never performs a discretionary account action —
// same Rule 4 boundary as reconciliation-engine.js. This file's ONLY
// job is "make sure a human finds out," not "decide what to do."
//
// Notification delivery is a thin, swappable stub — wire in whatever
// this codebase already uses for outbound alerts (Slack webhook,
// email, PagerDuty, etc.) inside sendNotification() below. Left as an
// honest no-op with a console.warn if unconfigured, same philosophy
// as frozyla-job-worker.js's "no real email provider yet" stubs
// elsewhere in this project — never fake success.

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const ALERT_WEBHOOK_URL = process.env.GL_ALERT_WEBHOOK_URL; // e.g. a Slack incoming webhook

async function createAlert({ alertType, severity, message, caseId = null, metadata = {} }) {
  const { data, error } = await supabase
    .from("system_alerts")
    .insert({ alert_type: alertType, severity, message, case_id: caseId, metadata })
    .select()
    .single();
  if (error) throw error;

  if (severity === "CRITICAL" || severity === "HIGH") {
    await sendNotification(data);
  }

  return data;
}

async function sendNotification(alert) {
  if (!ALERT_WEBHOOK_URL) {
    console.warn(
      `[ALERTING] GL_ALERT_WEBHOOK_URL not configured — ${alert.severity} alert "${alert.alert_type}" ` +
        `was recorded in system_alerts but NOT pushed anywhere. Configure this before relying on alerting in production.`,
    );
    return;
  }

  try {
    await fetch(ALERT_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: `[${alert.severity}] ${alert.alert_type}: ${alert.message}`,
      }),
    });
  } catch (err) {
    // A failed notification must never fail the caller's own
    // operation (same fire-and-forget philosophy as
    // frozyla-webhook-sender.js elsewhere in this project) — the
    // alert row already exists in system_alerts regardless, so
    // nothing is lost, just not pushed in real time.
    console.error("[ALERTING] Failed to send notification:", err.message);
  }
}

async function acknowledgeAlert({ alertId, acknowledgedBy }) {
  const { data, error } = await supabase
    .from("system_alerts")
    .update({ acknowledged: true, acknowledged_by: acknowledgedBy, acknowledged_at: new Date().toISOString() })
    .eq("id", alertId)
    .select()
    .single();
  if (error) throw error;
  return data;
}

// Convenience wrapper for reconciliation-engine.js — fires an alert
// whenever a case is created at CRITICAL severity, without every call
// site in that file needing to remember to do this itself.
async function alertOnCriticalCase({ caseNumber, caseType, message }) {
  return createAlert({
    alertType: "CRITICAL_RECONCILIATION_CASE",
    severity: "CRITICAL",
    message: message || `Critical reconciliation case ${caseNumber} (${caseType}) requires immediate attention`,
    metadata: { case_number: caseNumber, case_type: caseType },
  });
}

module.exports = { createAlert, acknowledgeAlert, alertOnCriticalCase };