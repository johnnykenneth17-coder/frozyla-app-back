// lib/saved-cards-service.js (Frozyla side)
//
// The only code that turns what Feecent tells us about a saved card into a
// payment_cards row. Kept out of server.js so it can be tested on its own.
//
// What Frozyla keeps for a card: brand, last four digits, expiry, holder name
// and provider_ref (Feecent's OPAQUE card reference). Nothing here can charge
// a card by itself: only Feecent can, and only for the matching customer.

const ALLOWED_BRANDS = ["visa", "mastercard", "amex", "verve"]; // payment_cards.card_type CHECK, minus 'other'

function savingEnabled() {
  return String(process.env.CARD_SAVING_ENABLED || "").toLowerCase() === "true";
}

function mapBrand(raw) {
  const b = String(raw || "").toLowerCase().replace(/[^a-z]/g, "");
  if (b.startsWith("master")) return "mastercard";
  if (b.startsWith("americanexpress") || b === "amex") return "amex";
  return ALLOWED_BRANDS.includes(b) ? b : "other";
}

// Validates the `card` object from Feecent's status response. Returns a clean
// object, or null if anything needed is missing or malformed. Feecent is a
// trusted server, but this still refuses to store anything that looks like a
// card number: only the last four digits are accepted, in exactly that shape.
function parseFeecentCard(card) {
  if (!card || typeof card !== "object") return null;
  const ref = typeof card.ref === "string" ? card.ref.trim() : "";
  const last4 = String(card.last4 ?? "");
  const expMonth = String(card.expMonth ?? "").padStart(2, "0");
  let expYear = String(card.expYear ?? "");
  if (expYear.length === 2) expYear = "20" + expYear;

  if (!ref || ref.length > 200) return null;
  if (!/^[0-9]{4}$/.test(last4)) return null;
  if (!/^(0[1-9]|1[0-2])$/.test(expMonth)) return null;
  if (!/^20[0-9]{2}$/.test(expYear)) return null;

  const holder = typeof card.holderName === "string" ? card.holderName.trim().slice(0, 80) : "";
  return { ref, last4, expMonth, expYear, brand: mapBrand(card.brand), holderName: holder };
}

// Saves (or recognises) a card for a customer. Safe to call repeatedly: the
// status endpoint is polled, so the same successful payment is seen many times.
// Returns { saved: true|false, existed?: true, cardId?, reason? }.
async function persistSavedCard({ supabase, userId, userName, feecentCard }) {
  const card = parseFeecentCard(feecentCard);
  if (!card) return { saved: false, reason: "INVALID_CARD_DATA" };

  const { data: existing, error: findErr } = await supabase
    .from("payment_cards")
    .select("id")
    .eq("user_id", userId)
    .eq("provider_ref", card.ref)
    .maybeSingle();
  if (findErr) throw findErr;
  if (existing) return { saved: false, existed: true, cardId: existing.id };

  // First saved card becomes the default.
  const { count, error: countErr } = await supabase
    .from("payment_cards")
    .select("id", { count: "exact", head: true })
    .eq("user_id", userId)
    .not("provider_ref", "is", null);
  if (countErr) throw countErr;

  const now = new Date().toISOString();
  const { data: inserted, error: insErr } = await supabase
    .from("payment_cards")
    .insert([
      {
        user_id: userId,
        card_holder_name: card.holderName || userName || "Cardholder",
        expiry_month: card.expMonth,
        expiry_year: card.expYear,
        card_type: card.brand,
        last4: card.last4,
        provider: "flutterwave",
        provider_ref: card.ref,
        is_default: !count,
        is_verified: true, // it has already paid once through the provider
        created_at: now,
        updated_at: now,
      },
    ])
    .select("id")
    .single();

  if (insErr) {
    // Two polls racing: the unique index (user_id, provider_ref) rejects the
    // second insert. That is the card already being saved, not a failure.
    if (insErr.code === "23505") return { saved: false, existed: true };
    throw insErr;
  }
  return { saved: true, cardId: inserted.id };
}

module.exports = { savingEnabled, mapBrand, parseFeecentCard, persistSavedCard };