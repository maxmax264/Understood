"use strict";
/**
 * SIONYX billing - what each organization owes the platform owner.
 *
 * Data (Firebase RTDB, all written ONLY by this module via the Admin SDK):
 *   billing/config                         global settings (readable by any signed-in user)
 *   billing/secret/...                     owner-only: Nedarim ApiValid, per-invoice pay tokens
 *   billing/orgs/{orgId}/settings          per-org overrides (exempt, price, minimum, manualBlock, graceUntil, trialEndsAt)
 *   billing/orgs/{orgId}/status            computed: free | ok | warning | blocked (+ blockAt, daysLeft, amountDue)
 *   billing/orgs/{orgId}/invoices/{YYYY-MM}
 *   billing/orgs/{orgId}/contract          accepted contract record
 *   billing/orgs/{orgId}/audit/{id}        owner actions log
 *
 * Usage input: organizations/{orgId}/computers/{id}/usageDays/{YYYY-MM-DD}: true
 * (written by the kiosk heartbeat, once per day).
 *
 * Pricing rule per computer per month:
 *   active on >= fullMonthThresholdPct of the month's days -> full price
 *   active on at least one day                              -> half price
 *   never active                                            -> free
 * Org monthly total = max(minimumMonthly, sum of computers), 0 if exempt.
 */
const crypto = require("crypto");

const DAY = 86400000;

const DEFAULT_CONTRACT = [
  "הסכם שימוש בתוכנת SIONYX (טיוטה - יש לעדכן בהגדרות החיוב במסך המאסטר)",
  "",
  "1. התוכנה מוענקת לארגון לשימוש במחשביו בלבד, בתמורה לתשלום חודשי כמפורט להלן.",
  "2. התשלום מחושב לכל מחשב לפי פעילותו בחודש: מחשב שהיה פעיל רוב החודש - מחיר מלא; מחשב שהיה פעיל לפחות יום אחד - חצי מחיר; מחשב שלא פעל כלל - ללא תשלום.",
  "3. קיים מינימום חיוב חודשי לארגון, גם אם לא הייתה פעילות.",
  "4. החיוב מופק בתחילת כל חודש עבור החודש שחלף, והתשלום מבוצע דרך ממשק התשלומים בלוח הבקרה.",
  "5. אי תשלום עד מועד הפירעון עלול לגרום לחסימת הגישה ללוח הבקרה עד להסדרת התשלום. המחשבים עצמם ימשיכו לפעול.",
  "6. המחירים עשויים להתעדכן בהודעה מראש.",
].join("\n");

const DEFAULT_CONFIG = {
  pricePerComputer: 9.9,
  minimumMonthly: 200,
  fullMonthThresholdPct: 50,
  trialDays: 30,
  graceDays: 7,
  claimWindowDays: 3,
  firstBillableMonth: "2026-10",
  nedarimMosadId: "7009078",
  contractVersion: 1,
  contractText: DEFAULT_CONTRACT,
};

const r2 = (n) => Math.round(n * 100) / 100;
const pad = (n) => String(n).padStart(2, "0");
const num = (v, d) => (typeof v === "number" && isFinite(v) ? v : d);

const ymFmt = new Intl.DateTimeFormat("en-CA", {
  timeZone: "Asia/Jerusalem", year: "numeric", month: "2-digit",
});
const ilMonth = (ms) => ymFmt.format(new Date(ms)).slice(0, 7); // "2026-10"
const parseYM = (ym) => ({y: Number(ym.slice(0, 4)), m: Number(ym.slice(5, 7))});
const monthStartMs = (ym) => { const {y, m} = parseYM(ym); return Date.UTC(y, m - 1, 1); };
const nextYM = (ym) => { const {y, m} = parseYM(ym); return m === 12 ? `${y + 1}-01` : `${y}-${pad(m + 1)}`; };
const daysInMonth = (ym) => { const {y, m} = parseYM(ym); return new Date(Date.UTC(y, m, 0)).getUTCDate(); };

module.exports = function registerBillingRoutes(app, deps) {
  const {admin, verifyOwner} = deps;
  const db = () => admin.database();

  const fail = (res, code, error, extra) => res.status(code).json({success: false, error, ...(extra || {})});

  // ── config ──────────────────────────────────────────────────────────
  async function getConfig() {
    const snap = await db().ref("billing/config").once("value");
    const stored = snap.val() || {};
    return {...DEFAULT_CONFIG, ...stored};
  }
  const publicConfig = (c) => ({
    pricePerComputer: c.pricePerComputer, minimumMonthly: c.minimumMonthly,
    fullMonthThresholdPct: c.fullMonthThresholdPct, trialDays: c.trialDays,
    graceDays: c.graceDays, contractVersion: c.contractVersion, contractText: c.contractText,
  });

  // ── auth ────────────────────────────────────────────────────────────
  async function getCaller(req) {
    const h = req.headers.authorization || "";
    const t = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!t) return null;
    try { return await admin.auth().verifyIdToken(t); } catch (e) { return null; }
  }
  /** Returns {uid, isOwner} when caller may act on orgId (owner, or admin of that org), else null. */
  async function orgAccess(req, orgId) {
    const decoded = await getCaller(req);
    if (!decoded) return null;
    const own = await db().ref(`owners/${decoded.uid}`).once("value");
    if (own.exists()) return {uid: decoded.uid, isOwner: true};
    if (!orgId) return null;
    const u = (await db().ref(`organizations/${orgId}/users/${decoded.uid}`).once("value")).val();
    if (u && (u.isAdmin === true || u.role === "admin")) return {uid: decoded.uid, isOwner: false};
    return null;
  }

  // ── usage + charge ──────────────────────────────────────────────────
  function computeCharge(computers, ym, settings, cfg, nowMs) {
    const dim = daysInMonth(ym);
    const threshold = Math.max(1, Math.ceil((num(cfg.fullMonthThresholdPct, 50) / 100) * dim));
    const price = num(settings.pricePerComputer, cfg.pricePerComputer);
    const minimum = num(settings.minimumMonthly, cfg.minimumMonthly);
    const lines = [];
    let full = 0; let half = 0; let none = 0; let subtotal = 0;
    Object.entries(computers || {}).forEach(([id, c]) => {
      const days = Object.keys((c && c.usageDays) || {}).filter((d) => d.startsWith(ym)).length;
      let tier = "none"; let p = 0;
      if (days >= threshold) { tier = "full"; p = price; full++; }
      else if (days >= 1) { tier = "half"; p = price / 2; half++; }
      else none++;
      subtotal += p;
      lines.push({id, name: (c && c.computerName) || id, activeDays: days, tier, price: r2(p)});
    });
    subtotal = r2(subtotal);
    const exempt = settings.exempt === true;
    const total = exempt ? 0 : r2(Math.max(minimum, subtotal));
    return {
      month: ym, daysInMonth: dim, threshold, pricePerComputer: price, minimumMonthly: minimum,
      full, half, none, subtotal, minimumApplied: !exempt && subtotal < minimum, total, lines,
      provisional: ilMonth(nowMs) === ym,
    };
  }

  function evaluate(settings, invoices, cfg, nowMs) {
    if (settings.exempt === true) return {state: "free"};
    if (settings.manualBlock === true) {
      return {state: "blocked", reason: "manual", message: settings.blockMessage || ""};
    }
    const claimMs = num(cfg.claimWindowDays, 3) * DAY;
    const unpaid = [];
    Object.values(invoices || {}).forEach((inv) => {
      if (!inv || inv.status === "paid" || inv.status === "void") return;
      if (inv.status === "claimed" && nowMs < num(inv.claimedAt, 0) + claimMs) return;
      unpaid.push(inv);
    });
    if (!unpaid.length) return {state: "ok"};
    const graceUntil = num(settings.graceUntil, 0);
    let blockAt = Infinity; let due = 0; let first = null;
    unpaid.forEach((inv) => {
      const d = Math.max(num(inv.dueAt, 0), graceUntil);
      due += Math.max(0, r2(num(inv.amount, 0) - num(inv.paidAmount, 0)));
      if (d < blockAt) { blockAt = d; first = inv.month; }
    });
    if (nowMs > blockAt) return {state: "blocked", reason: "unpaid", blockAt, amountDue: r2(due), invoiceMonth: first};
    return {
      state: "warning", blockAt, amountDue: r2(due), invoiceMonth: first,
      daysLeft: Math.max(1, Math.ceil((blockAt - nowMs) / DAY)),
    };
  }

  /** Loads everything for one org, issues any missing closed-month invoices, persists status. */
  async function refreshOrg(orgId, cfg, nowMs, orgData) {
    const [metaS, compS, billS] = await Promise.all(orgData ? [null, null, db().ref(`billing/orgs/${orgId}`).once("value")] : [
      db().ref(`organizations/${orgId}/metadata`).once("value"),
      db().ref(`organizations/${orgId}/computers`).once("value"),
      db().ref(`billing/orgs/${orgId}`).once("value"),
    ]);
    const meta = orgData ? (orgData.metadata || {}) : (metaS.val() || {});
    const computers = orgData ? (orgData.computers || {}) : (compS.val() || {});
    const bill = billS.val() || {};
    const settings = bill.settings || {};
    const invoices = {...(bill.invoices || {})};
    const updates = {};

    let startedAt = num(bill.startedAt, 0);
    if (!startedAt) { startedAt = nowMs; updates[`billing/orgs/${orgId}/startedAt`] = startedAt; }
    const createdMs = meta.createdAt ? new Date(meta.createdAt).getTime() : 0;
    const base = createdMs && isFinite(createdMs) ? createdMs : startedAt;
    const trialEndsAt = num(settings.trialEndsAt, base + num(cfg.trialDays, 30) * DAY);

    // Issue invoices for closed months (never before firstBillableMonth, never inside the trial).
    if (settings.exempt !== true) {
      const cur = ilMonth(nowMs);
      let ym = cfg.firstBillableMonth || cur;
      for (let i = 0; i < 24 && ym < cur; i++, ym = nextYM(ym)) {
        if (invoices[ym]) continue;
        if (monthStartMs(nextYM(ym)) <= trialEndsAt) continue;
        const ch = computeCharge(computers, ym, settings, cfg, nowMs);
        const inv = {
          month: ym, issuedAt: nowMs, dueAt: nowMs + num(cfg.graceDays, 7) * DAY,
          amount: ch.total, status: "unpaid", paidAmount: 0,
          breakdown: {
            full: ch.full, half: ch.half, none: ch.none, subtotal: ch.subtotal,
            minimumApplied: ch.minimumApplied, pricePerComputer: ch.pricePerComputer,
            minimumMonthly: ch.minimumMonthly, lines: ch.lines,
          },
        };
        invoices[ym] = inv;
        updates[`billing/orgs/${orgId}/invoices/${ym}`] = inv;
      }
    }

    const status = evaluate(settings, invoices, cfg, nowMs);
    const prev = bill.status || {};
    const strip = (s) => JSON.stringify({...s, updatedAt: 0});
    const next = {...status, updatedAt: nowMs};
    if (strip(prev) !== strip(next)) updates[`billing/orgs/${orgId}/status`] = next;
    if (Object.keys(updates).length) await db().ref().update(updates);

    const estimate = computeCharge(computers, ilMonth(nowMs), settings, cfg, nowMs);
    return {meta, settings, invoices, status: next, estimate, contract: bill.contract || null, trialEndsAt, computerCount: Object.keys(computers).length};
  }

  const audit = (orgId, by, action, details) =>
    db().ref(`billing/orgs/${orgId}/audit`).push({at: Date.now(), by, action, details: details || null});

  async function listOrgIds() {
    try {
      const token = (await admin.app().options.credential.getAccessToken()).access_token;
      const base = (process.env.FIREBASE_DATABASE_URL || "").replace(/\/$/, "");
      const r = await fetch(`${base}/organizations.json?shallow=true&access_token=${token}`);
      if (r.ok) { const j = await r.json(); if (j) return Object.keys(j); }
    } catch (e) { /* fall through */ }
    const snap = await db().ref("organizations").once("value");
    return Object.keys(snap.val() || {});
  }

  // ── POST /billing/summary  (org admin or owner) ─────────────────────
  app.post("/billing/summary", async (req, res) => {
    try {
      const orgId = req.body && req.body.orgId;
      if (!orgId) return fail(res, 400, "orgId required");
      const who = await orgAccess(req, orgId);
      if (!who) return fail(res, 403, "Forbidden");
      const cfg = await getConfig();
      const now = Date.now();
      const o = await refreshOrg(orgId, cfg, now);
      const accepted = o.contract && o.contract.accepted;
      const invoices = Object.values(o.invoices)
          .map((i) => ({month: i.month, issuedAt: i.issuedAt, dueAt: i.dueAt, amount: i.amount, paidAmount: i.paidAmount || 0,
            status: i.status, paidAt: i.paidAt || null, claimedAt: i.claimedAt || null, breakdown: i.breakdown}))
          .sort((a, b) => (a.month < b.month ? 1 : -1));
      return res.json({
        success: true, status: o.status, estimate: o.estimate, invoices,
        config: publicConfig(cfg), exempt: o.settings.exempt === true, trialEndsAt: o.trialEndsAt,
        contract: {
          required: o.settings.exempt !== true && !!cfg.contractText,
          accepted: !!(accepted && accepted.version === cfg.contractVersion),
          acceptedAt: accepted ? accepted.acceptedAt : null, acceptedBy: accepted ? accepted.fullName : null,
        },
      });
    } catch (e) {
      console.error("billing/summary error:", e.message);
      return fail(res, 500, "Internal error");
    }
  });

  // ── POST /billing/overview  (owner) ─────────────────────────────────
  app.post("/billing/overview", async (req, res) => {
    try {
      if (!(await verifyOwner(req))) return fail(res, 403, "Owner access required");
      const cfg = await getConfig();
      const now = Date.now();
      const ids = await listOrgIds();
      const rows = [];
      for (const orgId of ids) {
        try {
          const o = await refreshOrg(orgId, cfg, now);
          const open = Object.values(o.invoices).filter((i) => i.status === "unpaid" || i.status === "claimed");
          rows.push({
            orgId, name: o.meta.name || orgId, computers: o.computerCount, state: o.status.state,
            reason: o.status.reason || null, blockAt: o.status.blockAt || null,
            exempt: o.settings.exempt === true, manualBlock: o.settings.manualBlock === true,
            pricePerComputer: o.settings.pricePerComputer ?? null, minimumMonthly: o.settings.minimumMonthly ?? null,
            graceUntil: o.settings.graceUntil || null, blockMessage: o.settings.blockMessage || "",
            estimate: o.estimate.total, estimateFull: o.estimate.full, estimateHalf: o.estimate.half, estimateNone: o.estimate.none,
            amountDue: r2(open.reduce((s, i) => s + (i.amount - (i.paidAmount || 0)), 0)),
            totalPaid: r2(Object.values(o.invoices).reduce((s, i) => s + (i.paidAmount || 0), 0)),
            invoices: Object.values(o.invoices).sort((a, b) => (a.month < b.month ? 1 : -1))
                .map((i) => ({month: i.month, amount: i.amount, paidAmount: i.paidAmount || 0, status: i.status, dueAt: i.dueAt})),
            contractAccepted: !!(o.contract && o.contract.accepted && o.contract.accepted.version === cfg.contractVersion),
            contractBy: o.contract && o.contract.accepted ? o.contract.accepted.fullName : null,
            trialEndsAt: o.trialEndsAt,
          });
        } catch (e) { console.error("billing overview org error:", orgId, e.message); }
      }
      const hasApi = !!(process.env.BILLING_NEDARIM_API_VALID ||
        (await db().ref("billing/secret/apiValid").once("value")).exists());
      return res.json({success: true, config: cfg, rows, apiValidConfigured: hasApi});
    } catch (e) {
      console.error("billing/overview error:", e.message);
      return fail(res, 500, "Internal error");
    }
  });

  // ── POST /billing/runAll  (owner, or cron with x-billing-cron-secret) ─
  app.post("/billing/runAll", async (req, res) => {
    try {
      const cronSecret = process.env.BILLING_CRON_SECRET;
      const okCron = cronSecret && req.headers["x-billing-cron-secret"] === cronSecret;
      if (!okCron && !(await verifyOwner(req))) return fail(res, 403, "Forbidden");
      const cfg = await getConfig();
      const now = Date.now();
      const ids = await listOrgIds();
      let n = 0;
      for (const orgId of ids) { try { await refreshOrg(orgId, cfg, now); n++; } catch (e) { /* skip */ } }
      return res.json({success: true, orgs: n});
    } catch (e) { return fail(res, 500, "Internal error"); }
  });

  // ── POST /billing/ownerAction  (owner) ──────────────────────────────
  app.post("/billing/ownerAction", async (req, res) => {
    try {
      const ownerUid = await verifyOwner(req);
      if (!ownerUid) return fail(res, 403, "Owner access required");
      const {action, orgId} = req.body || {};
      const p = (req.body && req.body.params) || {};
      const now = Date.now();

      if (action === "saveConfig") {
        const cur = await getConfig();
        const next = {...cur};
        const numField = (k, min, max) => {
          if (p[k] === undefined) return;
          const v = Number(p[k]);
          if (!isFinite(v) || v < min || v > max) throw new Error(`Invalid ${k}`);
          next[k] = v;
        };
        numField("pricePerComputer", 0, 100000); numField("minimumMonthly", 0, 1000000);
        numField("fullMonthThresholdPct", 1, 100); numField("trialDays", 0, 3650);
        numField("graceDays", 0, 365); numField("claimWindowDays", 0, 60);
        if (typeof p.firstBillableMonth === "string" && /^\d{4}-\d{2}$/.test(p.firstBillableMonth)) next.firstBillableMonth = p.firstBillableMonth;
        if (typeof p.nedarimMosadId === "string" && /^\d{3,12}$/.test(p.nedarimMosadId)) next.nedarimMosadId = p.nedarimMosadId;
        if (typeof p.contractText === "string" && p.contractText !== cur.contractText) {
          next.contractText = p.contractText.slice(0, 20000);
          next.contractVersion = num(cur.contractVersion, 1) + 1;
        }
        await db().ref("billing/config").set(next);
        await db().ref("billing/auditGlobal").push({at: now, by: ownerUid, action, details: {...p, contractText: p.contractText ? "(updated)" : undefined}});
        return res.json({success: true, config: next});
      }
      if (action === "saveApiValid") {
        if (typeof p.apiValid !== "string" || p.apiValid.trim().length < 4) return fail(res, 400, "Invalid apiValid");
        await db().ref("billing/secret/apiValid").set(p.apiValid.trim());
        return res.json({success: true});
      }

      if (!orgId) return fail(res, 400, "orgId required");
      const sRef = db().ref(`billing/orgs/${orgId}/settings`);
      const cfg = await getConfig();

      if (action === "saveSettings") {
        const s = {};
        if (p.exempt !== undefined) s.exempt = p.exempt === true;
        ["pricePerComputer", "minimumMonthly"].forEach((k) => {
          if (p[k] === undefined) return;
          if (p[k] === null || p[k] === "") { s[k] = null; return; }
          const v = Number(p[k]);
          if (!isFinite(v) || v < 0 || v > 1000000) throw new Error(`Invalid ${k}`);
          s[k] = v;
        });
        if (p.trialEndsAt !== undefined) s.trialEndsAt = p.trialEndsAt ? Number(p.trialEndsAt) : null;
        await sRef.update(s);
        await audit(orgId, ownerUid, action, s);
      } else if (action === "block") {
        await sRef.update({manualBlock: true, blockMessage: String(p.message || "").slice(0, 300)});
        await audit(orgId, ownerUid, action, {message: p.message || ""});
      } else if (action === "unblock") {
        await sRef.update({manualBlock: false, blockMessage: null});
        await audit(orgId, ownerUid, action);
      } else if (action === "extendGrace") {
        const days = Number(p.days);
        if (!isFinite(days) || days < 0 || days > 365) return fail(res, 400, "Invalid days");
        await sRef.update({graceUntil: days === 0 ? null : now + days * DAY});
        await audit(orgId, ownerUid, action, {days});
      } else if (action === "markPaid") {
        const ym = p.month;
        const inv = (await db().ref(`billing/orgs/${orgId}/invoices/${ym}`).once("value")).val();
        if (!inv) return fail(res, 404, "Invoice not found");
        await db().ref(`billing/orgs/${orgId}/invoices/${ym}`).update({
          status: "paid", paidAmount: inv.amount, paidAt: now, paidVia: "manual",
        });
        await audit(orgId, ownerUid, action, {month: ym, note: p.note || ""});
      } else if (action === "voidInvoice") {
        await db().ref(`billing/orgs/${orgId}/invoices/${p.month}`).update({status: "void", voidedAt: now});
        await audit(orgId, ownerUid, action, {month: p.month});
      } else if (action === "reissueInvoice") {
        // Recalculate an UNPAID invoice from the current settings/usage.
        const inv = (await db().ref(`billing/orgs/${orgId}/invoices/${p.month}`).once("value")).val();
        if (!inv || inv.status === "paid") return fail(res, 400, "Cannot reissue");
        await db().ref(`billing/orgs/${orgId}/invoices/${p.month}`).remove();
        await audit(orgId, ownerUid, action, {month: p.month});
      } else {
        return fail(res, 400, "Unknown action");
      }
      const o = await refreshOrg(orgId, cfg, Date.now());
      return res.json({success: true, status: o.status});
    } catch (e) {
      console.error("billing/ownerAction error:", e.message);
      return fail(res, e.message && e.message.startsWith("Invalid") ? 400 : 500, e.message && e.message.startsWith("Invalid") ? e.message : "Internal error");
    }
  });

  // ── POST /billing/acceptContract  (org admin) ───────────────────────
  app.post("/billing/acceptContract", async (req, res) => {
    try {
      const {orgId, fullName, idNumber, role, agree} = req.body || {};
      if (!orgId) return fail(res, 400, "orgId required");
      const who = await orgAccess(req, orgId);
      if (!who) return fail(res, 403, "Forbidden");
      if (agree !== true || typeof fullName !== "string" || fullName.trim().length < 2) {
        return fail(res, 400, "נא למלא שם מלא ולאשר את ההסכם");
      }
      const cfg = await getConfig();
      const rec = {
        version: cfg.contractVersion,
        hash: crypto.createHash("sha256").update(cfg.contractText || "").digest("hex"),
        acceptedAt: Date.now(), fullName: fullName.trim().slice(0, 100),
        idNumber: String(idNumber || "").slice(0, 20), role: String(role || "").slice(0, 60),
        uid: who.uid,
        ip: String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim(),
        userAgent: String(req.headers["user-agent"] || "").slice(0, 200),
      };
      await db().ref(`billing/orgs/${orgId}/contract`).update({
        accepted: rec, [`history/v${cfg.contractVersion}`]: {...rec, text: cfg.contractText},
      });
      return res.json({success: true});
    } catch (e) { return fail(res, 500, "Internal error"); }
  });

  // ── POST /billing/payConfig  (org admin) ────────────────────────────
  app.post("/billing/payConfig", async (req, res) => {
    try {
      const {orgId, month} = req.body || {};
      if (!orgId || !/^\d{4}-\d{2}$/.test(month || "")) return fail(res, 400, "orgId and month required");
      const who = await orgAccess(req, orgId);
      if (!who) return fail(res, 403, "Forbidden");
      const cfg = await getConfig();
      const o = await refreshOrg(orgId, cfg, Date.now());
      const inv = o.invoices[month];
      if (!inv || (inv.status !== "unpaid" && inv.status !== "claimed")) return fail(res, 400, "אין חיוב פתוח לחודש זה");
      const accepted = o.contract && o.contract.accepted;
      if (cfg.contractText && !(accepted && accepted.version === cfg.contractVersion)) {
        return fail(res, 409, "יש לחתום על ההסכם לפני התשלום", {code: "contract-required"});
      }
      const apiValid = process.env.BILLING_NEDARIM_API_VALID ||
        (await db().ref("billing/secret/apiValid").once("value")).val();
      if (!apiValid) return fail(res, 503, "התשלום טרם הוגדר (חסר ApiValid של נדרים)");
      const token = crypto.randomBytes(24).toString("hex");
      await db().ref(`billing/secret/payTokens/${orgId}/${month}`).set(token);
      const amountLeft = r2(inv.amount - (inv.paidAmount || 0));
      return res.json({
        success: true, mosadId: cfg.nedarimMosadId, apiValid, amount: amountLeft, month,
        callbackUrl: `${process.env.PUBLIC_BASE_URL || `https://${req.get("host")}`}/billingCallback?t=${token}`,
        comment: `SIONYX ${month} - ${o.meta.name || orgId}`,
      });
    } catch (e) {
      console.error("billing/payConfig error:", e.message);
      return fail(res, 500, "Internal error");
    }
  });

  // ── POST /billing/confirm  (org admin) - provisional unlock only ────
  // The authoritative paid-signal is /billingCallback. If Nedarim's webhook
  // is slow, the iframe's own OK lets the org through for claimWindowDays;
  // the owner sees the invoice as "claimed" until the webhook (or a manual
  // markPaid) settles it. One claim per invoice.
  app.post("/billing/confirm", async (req, res) => {
    try {
      const {orgId, month, transactionId} = req.body || {};
      const who = await orgAccess(req, orgId);
      if (!who) return fail(res, 403, "Forbidden");
      const iRef = db().ref(`billing/orgs/${orgId}/invoices/${month}`);
      const inv = (await iRef.once("value")).val();
      if (!inv) return fail(res, 404, "Invoice not found");
      if (inv.status === "unpaid" && !inv.claimedAt) {
        await iRef.update({status: "claimed", claimedAt: Date.now(), claimTx: String(transactionId || "").slice(0, 60)});
      }
      const o = await refreshOrg(orgId, await getConfig(), Date.now());
      return res.json({success: true, status: o.status});
    } catch (e) { return fail(res, 500, "Internal error"); }
  });

  // ── POST /billingCallback  (public webhook from Nedarim) ────────────
  // Param1 = month (YYYY-MM), Param2 = orgId, ?t= per-invoice secret token.
  app.post("/billingCallback", async (req, res) => {
    try {
      const body = req.body || {};
      const month = String(body.Param1 || "");
      const orgId = String(body.Param2 || "");
      const token = String(req.query.t || "");
      if (!/^\d{4}-\d{2}$/.test(month) || !orgId || !token) return fail(res, 400, "Bad request");
      const stored = (await db().ref(`billing/secret/payTokens/${orgId}/${month}`).once("value")).val();
      const a = Buffer.from(token); const b = Buffer.from(String(stored || ""));
      if (!stored || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return fail(res, 403, "Forbidden");
      const txId = body.TransactionId || body.KevaId;
      const status = body.Result || body.Status || (body.KevaId ? "OK" : undefined);
      const amount = Number(body.Amount);
      if (!txId || !status || !isFinite(amount) || amount <= 0) return fail(res, 400, "Missing fields");
      if (status !== "OK") return res.json({success: true, message: "Not a successful charge"});
      const iRef = db().ref(`billing/orgs/${orgId}/invoices/${month}`);
      const inv = (await iRef.once("value")).val();
      if (!inv) return fail(res, 404, "Invoice not found");
      if (inv.status === "paid" && inv.transactionId === String(txId)) return res.json({success: true, message: "Already processed"});
      const paid = r2(num(inv.paidAmount, 0) + amount);
      const done = paid + 0.01 >= inv.amount;
      await iRef.update({
        paidAmount: paid, transactionId: String(txId), lastPaymentAt: Date.now(),
        ...(done ? {status: "paid", paidAt: Date.now(), paidVia: "nedarim"} : {}),
      });
      if (done) await db().ref(`billing/secret/payTokens/${orgId}/${month}`).remove();
      await refreshOrg(orgId, await getConfig(), Date.now());
      return res.json({success: true});
    } catch (e) {
      console.error("billingCallback error:", e.message);
      return fail(res, 500, "Internal error");
    }
  });
};
