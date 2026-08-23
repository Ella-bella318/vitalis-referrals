const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Reserved so a generated slug can never collide with a real app route.
const RESERVED_SLUGS = new Set([
  "assets",
  "partner",
  "api",
  "admin",
  "index",
  "netlify",
  "_redirects",
]);

const RATE_LIMIT_WINDOW_MINUTES = 15;
const RATE_LIMIT_MAX_REQUESTS = 5;
const IP_HASH_SALT = "vitalis-referrals-signup-v1";
const PRODUCTION_ORIGIN = "https://vitalis-referrals.netlify.app";

const NAME_RE = /^[\p{L}\p{M}' -]{2,80}$/u;
const SLUG_LIKE_RE = /^[a-z0-9-]{1,60}$/;
const IDEMPOTENCY_KEY_RE = /^[a-zA-Z0-9-]{8,100}$/;

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "Method not allowed." });
  }
  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
    return json(500, { ok: false, error: "Server not configured." });
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { ok: false, error: "Invalid request." });
  }

  const rawName = typeof body.name === "string" ? body.name.trim() : "";
  const rawPhone = typeof body.phone === "string" ? body.phone : "";
  const recruitedBySlug =
    typeof body.recruitedBySlug === "string"
      ? body.recruitedBySlug.trim().toLowerCase()
      : "";
  const idempotencyKey =
    typeof body.idempotencyKey === "string" ? body.idempotencyKey.trim() : "";

  if (!NAME_RE.test(rawName)) {
    return json(400, { ok: false, error: "Please enter a valid name." });
  }

  const normalizedPhone = normalizePhone(rawPhone);
  if (!normalizedPhone) {
    return json(400, { ok: false, error: "Please enter a valid US phone number." });
  }

  if (!SLUG_LIKE_RE.test(recruitedBySlug)) {
    return json(400, { ok: false, error: "Invalid request." });
  }
  if (!IDEMPOTENCY_KEY_RE.test(idempotencyKey)) {
    return json(400, { ok: false, error: "Invalid request." });
  }

  const sb = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  const ipHash = hashIp(getClientIp(event));

  // --- rate limit: same IP, rolling window, counts every attempt ---
  const since = new Date(
    Date.now() - RATE_LIMIT_WINDOW_MINUTES * 60 * 1000,
  ).toISOString();
  const { count: recentCount, error: rateError } = await sb
    .from("referral_partner_signup_requests")
    .select("idempotency_key", { count: "exact", head: true })
    .eq("ip_hash", ipHash)
    .gte("created_at", since);

  if (!rateError && recentCount !== null && recentCount >= RATE_LIMIT_MAX_REQUESTS) {
    return json(429, {
      ok: false,
      error: "Too many attempts. Please try again in a little while.",
    });
  }

  // --- idempotency claim: exactly one request per key can win this insert ---
  const { error: claimError } = await sb
    .from("referral_partner_signup_requests")
    .insert({
      idempotency_key: idempotencyKey,
      phone: normalizedPhone,
      ip_hash: ipHash,
    });

  if (claimError) {
    if (claimError.code === "23505") {
      // This exact submission (same modal-open) was already processed, or
      // is being processed right now - never create a second row for it.
      const result = await findResultForKey(sb, idempotencyKey);
      if (result) return json(200, result);
      return json(202, {
        ok: false,
        error: "Your application is already being processed.",
      });
    }
    return json(500, { ok: false, error: "Could not process application." });
  }

  // --- soft duplicate signal by phone (no DB constraint - partners may
  // legitimately share a number). If we already have a partner at this
  // phone, hand back their existing page rather than creating another. ---
  const { data: existingByPhone } = await sb
    .from("referral_partners")
    .select("slug, referral_code")
    .eq("phone", normalizedPhone)
    .limit(1)
    .maybeSingle();

  if (existingByPhone) {
    return json(200, buildResult(existingByPhone));
  }

  // --- resolve recruiter slug -> uuid server-side (never trust/accept a
  // client-supplied uuid; the public view never exposes one anyway) ---
  const { data: recruiter } = await sb
    .from("referral_partners")
    .select("id")
    .eq("slug", recruitedBySlug)
    .eq("status", "active")
    .maybeSingle();

  const slug = await generateUniqueSlug(sb, rawName);
  const referralCode = await generateUniqueReferralCode(sb, rawName);

  const { data: created, error: insertError } = await sb
    .from("referral_partners")
    .insert({
      name: rawName,
      phone: normalizedPhone,
      slug,
      referral_code: referralCode,
      recruited_by_partner_id: recruiter ? recruiter.id : null,
      status: "active",
    })
    .select("id, slug, referral_code")
    .single();

  if (insertError) {
    return json(500, {
      ok: false,
      error: "Could not create your referral page. Please try again.",
    });
  }

  await sb
    .from("referral_partner_signup_requests")
    .update({ referral_partner_id: created.id })
    .eq("idempotency_key", idempotencyKey);

  return json(200, buildResult(created));
};

function buildResult(row) {
  return {
    ok: true,
    slug: row.slug,
    referralCode: row.referral_code,
    url: `${PRODUCTION_ORIGIN}/${row.slug}/`,
  };
}

async function findResultForKey(sb, idempotencyKey) {
  const { data: reqRow } = await sb
    .from("referral_partner_signup_requests")
    .select("referral_partner_id")
    .eq("idempotency_key", idempotencyKey)
    .maybeSingle();

  if (!reqRow || !reqRow.referral_partner_id) return null;

  const { data: partner } = await sb
    .from("referral_partners")
    .select("slug, referral_code")
    .eq("id", reqRow.referral_partner_id)
    .maybeSingle();

  return partner ? buildResult(partner) : null;
}

function normalizePhone(raw) {
  const digits = raw.replace(/\D/g, "");
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  return null;
}

function getClientIp(event) {
  const headers = event.headers || {};
  return (
    headers["x-nf-client-connection-ip"] ||
    (headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    "unknown"
  );
}

function hashIp(ip) {
  return crypto
    .createHash("sha256")
    .update(IP_HASH_SALT + ip)
    .digest("hex");
}

function slugify(input) {
  return input
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

async function slugTaken(sb, candidate) {
  if (RESERVED_SLUGS.has(candidate)) return true;
  const { data } = await sb
    .from("referral_partners")
    .select("slug")
    .ilike("slug", candidate)
    .limit(1)
    .maybeSingle();
  return !!data;
}

async function generateUniqueSlug(sb, fullName) {
  const parts = fullName.trim().split(/\s+/);
  const first = slugify(parts[0] || "");
  const last = slugify(parts.slice(1).join(" ") || "");
  const base = first || "partner";

  if (!(await slugTaken(sb, base))) return base;

  if (last) {
    const combined = `${base}-${last}`;
    if (!(await slugTaken(sb, combined))) return combined;

    for (let i = 2; i <= 25; i++) {
      const candidate = `${combined}-${i}`;
      if (!(await slugTaken(sb, candidate))) return candidate;
    }
  }

  // Extremely unlikely fallback - random suffix, still uniqueness-checked.
  for (let attempt = 0; attempt < 10; attempt++) {
    const candidate = `${base}-${crypto.randomBytes(3).toString("hex")}`;
    if (!(await slugTaken(sb, candidate))) return candidate;
  }
  throw new Error("Could not generate a unique slug.");
}

async function referralCodeTaken(sb, candidate) {
  const { data } = await sb
    .from("referral_partners")
    .select("referral_code")
    .eq("referral_code", candidate)
    .limit(1)
    .maybeSingle();
  return !!data;
}

async function generateUniqueReferralCode(sb, fullName) {
  const parts = fullName.trim().split(/\s+/);
  const first = slugify(parts[0] || "").replace(/-/g, "").toUpperCase();
  const last = slugify(parts.slice(1).join(" ") || "")
    .replace(/-/g, "")
    .toUpperCase();
  const base = (first || "PARTNER") + "10";

  if (!(await referralCodeTaken(sb, base))) return base;

  if (last) {
    const combined = first + last + "10";
    if (!(await referralCodeTaken(sb, combined))) return combined;

    const letters = "BCDEFGHJKLMNPQRSTUVWXYZ"; // skip A/I/O - avoid ambiguity
    for (const letter of letters) {
      const candidate = combined + letter;
      if (!(await referralCodeTaken(sb, candidate))) return candidate;
    }
  }

  // Extremely unlikely fallback - random suffix, still uniqueness-checked.
  for (let attempt = 0; attempt < 10; attempt++) {
    const candidate = base + "-" + crypto.randomBytes(2).toString("hex").toUpperCase();
    if (!(await referralCodeTaken(sb, candidate))) return candidate;
  }
  throw new Error("Could not generate a unique referral code.");
}

function json(statusCode, payload) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  };
}
