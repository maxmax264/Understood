/**
 * SIONYX payment bridge — runs on Render (or any Node host) instead of
 * Firebase Cloud Functions, because Cloud Functions gen2 (and any function
 * that makes outbound network calls) requires the Firebase Blaze plan to
 * deploy at all, regardless of what the function actually does.
 *
 * This service re-implements exactly two endpoints from functions/index.js:
 *   - POST /nedarimCallback     (public webhook Nedarim posts to on payment)
 *   - POST /chargeWithSavedCard (called by the kiosk client, auth required)
 *
 * Everything else (createPendingPurchase, org/user management, etc.) stays
 * as direct Realtime Database reads/writes from the client - those never
 * needed a Cloud Function and are unaffected by this migration.
 *
 * Auth model: the client already sends `Authorization: Bearer <Firebase ID
 * token>` for chargeWithSavedCard (see FirebaseClient.CallFunctionAsync in
 * the WPF app) - we verify that token with firebase-admin, same as Cloud
 * Functions' onCall did automatically via request.auth.
 *
 * Required environment variables (set these in the Render dashboard):
 *   FIREBASE_SERVICE_ACCOUNT_BASE64  - base64-encoded service account JSON
 *                                      (Project settings -> Service accounts
 *                                      -> Generate new private key, then
 *                                      `base64 -w0 key.json`)
 *   FIREBASE_DATABASE_URL            - e.g. https://sionyx-19636-default-rtdb.firebaseio.com
 *   ENCRYPTION_KEY                   - same value as in Firebase Functions config
 *   CALLBACK_SECRET                  - optional, same as before
 */

const express = require("express");
const admin = require("firebase-admin");
const crypto = require("crypto");

// This server's own public URL, used to build the CallBack= param sent to
// Nedarim on the saved-card recurring charge (TashlumBodedNew) - per the
// reference implementation, Nedarim expects CallBack on *every* charge
// request, not just relying on something pre-registered account-wide.
const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL || "https://understood-n5ok.onrender.com";

// ── Firebase Admin init ──────────────────────────────────────────────
const serviceAccountB64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;
if (!serviceAccountB64) {
  // eslint-disable-next-line no-console
  console.error("FATAL: FIREBASE_SERVICE_ACCOUNT_BASE64 is not set");
  process.exit(1);
}
const serviceAccount = JSON.parse(
    Buffer.from(serviceAccountB64, "base64").toString("utf8"),
);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
});

const app = express();
app.use(express.json());

// Every existing route here was only ever called from the WPF kiosk app
// (not a browser), so CORS was never relevant. Now that /registerOrganization
// is also called from sionyx-web (a real browser origin), the browser will
// enforce CORS on every request to this server - handle it globally rather
// than per-route. Allowing all origins is fine here: routes that need auth
// already verify a Firebase ID token themselves: this only affects whether
// a browser's JS is allowed to READ the response, not who can call the
// endpoint at all (a non-browser client, or curl, was never restricted by
// CORS in the first place).
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.urlencoded({extended: true}));

// ═══════════════════════════════════════════════════════════════════
// DIAGNOSTIC: log absolutely every incoming request, to ANY path, no
// matter what. This settles definitively whether Nedarim's servers ever
// reach us at all (vs. our own client-side reporting being the only
// thing that ever runs) - even if they hit a path we didn't expect.
// Safe to remove once nedarimCallback is confirmed reliably firing.
// ═══════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({
    level: "INFO",
    message: "[CATCH-ALL] Incoming request",
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.path,
    query: req.query,
    headers: {
      "user-agent": req.headers["user-agent"],
      "content-type": req.headers["content-type"],
      "x-forwarded-for": req.headers["x-forwarded-for"],
    },
    bodyPreview: JSON.stringify(req.body || {}).slice(0, 500),
  }));
  next();
});

// ── Logging / helper utilities (ported as-is from functions/index.js) ──
const createLogger = (context = {}) => {
  const baseContext = {
    timestamp: new Date().toISOString(),
    service: "sionyx-render-bridge",
    ...context,
  };
  const line = (level, message, data) =>
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({level, message, ...baseContext, ...data}));
  return {
    info: (message, data = {}) => line("INFO", message, data),
    warn: (message, data = {}) => line("WARN", message, data),
    error: (message, error = null, data = {}) => line("ERROR", message, {
      ...(error ? {
        errorMessage: error.message,
        errorStack: error.stack,
        errorName: error.name,
      } : {}),
      ...data,
    }),
    debug: (message, data = {}) => line("DEBUG", message, data),
  };
};

const generateCorrelationId = () =>
  `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

const createTimer = (operation) => {
  const start = Date.now();
  return {
    end: (logFn) => {
      const duration = Date.now() - start;
      logFn(`Operation '${operation}' completed`, {duration: `${duration}ms`});
      return duration;
    },
  };
};

const ALGORITHM = "aes-256-cbc";
const IV_LENGTH = 16;
const getEncryptionKey = () => {
  const key = process.env.ENCRYPTION_KEY;
  if (key && String(key).length >= 32) {
    return Buffer.from(String(key).slice(0, 32), "utf8");
  }
  return null;
};
const decryptData = (encrypted) => {
  const key = getEncryptionKey();
  if (key) {
    try {
      const [ivB64, dataB64] = encrypted.split(":");
      if (ivB64 && dataB64) {
        const iv = Buffer.from(ivB64, "base64");
        const data = Buffer.from(dataB64, "base64");
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        return JSON.parse(decipher.update(data) + decipher.final("utf8"));
      }
    } catch (e) {
      // Fall through to base64
    }
  }
  return JSON.parse(Buffer.from(encrypted, "base64").toString("utf8"));
};

// Card Tokef (expiry) is sensitive, PCI-adjacent data - encrypt it the same
// way as other Nedarim credentials before storing (mirrors decryptData's
// format so tryDecrypt can read it back). Falls back to plain base64 if
// ENCRYPTION_KEY isn't configured, same as decryptData's fallback path.
const encryptData = (value) => {
  const key = getEncryptionKey();
  const plaintext = JSON.stringify(value);
  if (key) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return `${iv.toString("base64")}:${encrypted.toString("base64")}`;
  }
  return Buffer.from(plaintext, "utf8").toString("base64");
};

// Small helper so responses look like the Firebase callable-function wire
// protocol ({result: ...} / {error: {status, message}}) - this means the
// existing WPF FirebaseClient.CallFunctionAsync code doesn't need to change
// at all beyond the base URL.
const callableOk = (res, result) => res.status(200).json({result});
const callableError = (res, httpStatus, status, message) =>
  res.status(httpStatus).json({error: {status, message}});

// ═══════════════════════════════════════════════════════════════════
// POST /nedarimCallback - public webhook, Nedarim posts payment results
// here directly (Param1=purchaseId, Param2=orgId, set via CallBack= in
// the iframe FinishTransaction2 call). Trimmed port of the same-named
// Cloud Function; behavior/field names unchanged.
// ═══════════════════════════════════════════════════════════════════
app.post("/nedarimCallback", async (req, res) => {
  const correlationId = generateCorrelationId();
  const log = createLogger({correlationId});
  const requestTimer = createTimer("nedarim-callback-request");
  let purchaseId;
  let orgId;

  try {
    const callbackSecret = process.env.CALLBACK_SECRET;
    if (callbackSecret) {
      const providedSecret = (req.query && req.query.secret) ||
          (req.headers && req.headers["x-callback-secret"]);
      if (providedSecret !== callbackSecret) {
        log.warn("Callback secret validation failed");
        return res.status(403).json({success: false, error: "Forbidden"});
      }
    }

    const paymentData = req.body || {};
    const {Amount, CreditCardNumber, Param1, Param2, Message} = paymentData;
    // Two different callback shapes hit this same endpoint:
    // - Ragil/CreateToken (iframe): includes explicit TransactionId + Status/Result.
    // - DebitKeva (saved-card charge): no TransactionId or Status/Result field
    //   at all - only KevaId. Nedarim only POSTs this notification when the
    //   standing order was actually created/executed, so KevaId's presence
    //   itself is the success signal for this shape.
    const TransactionId = paymentData.TransactionId || paymentData.KevaId;
    const Status = paymentData.Result || paymentData.Status ||
      (paymentData.KevaId ? "OK" : undefined);

    const amountNum = Amount != null ? Number(Amount) : NaN;
    if (Number.isNaN(amountNum) || amountNum < 0) {
      return res.status(400).json({success: false, error: "Invalid Amount"});
    }
    if (typeof Param1 !== "string" || !Param1.trim()) {
      return res.status(400).json({
        success: false, error: "Invalid Param1 (purchaseId)",
      });
    }
    if (typeof Param2 !== "string" || !Param2.trim()) {
      return res.status(400).json({
        success: false, error: "Invalid Param2 (orgId)",
      });
    }
    if (!TransactionId || !Status) {
      return res.status(400).json({
        success: false, error: "Missing required fields",
      });
    }

    purchaseId = Param1;
    orgId = Param2;

    const purchaseRef = admin.database()
        .ref(`organizations/${orgId}/purchases/${purchaseId}`);
    const purchaseSnapshot = await purchaseRef.once("value");
    const purchase = purchaseSnapshot.val();

    if (!purchase) {
      log.error("Purchase not found", null, {purchaseId, orgId});
      return res.status(404).json({success: false, error: "Purchase not found"});
    }

    // Idempotency
    if (purchase.status === "completed" && purchase.creditedAt) {
      return res.status(200).json({success: true, message: "Already processed"});
    }

    // SECURITY: never persist the full PAN - only last 4 digits.
    const maskedCardForStorage = CreditCardNumber ?
      `****${String(CreditCardNumber).slice(-4)}` : "";

    await purchaseRef.update({
      status: Status === "OK" ? "completed" : "failed",
      transactionId: TransactionId,
      amount: amountNum,
      creditCardNumber: maskedCardForStorage,
      message: Message || "",
      callbackReceivedAt: admin.database.ServerValue.TIMESTAMP,
      correlationId,
      processedAt: new Date().toISOString(),
    });

    if (Status === "OK" && purchase.userId) {
      const userRef = admin.database()
          .ref(`organizations/${orgId}/users/${purchase.userId}`);
      const userSnapshot = await userRef.once("value");
      const user = userSnapshot.val();

      if (user) {
        const currentTime = user.remainingTime || 0;
        const currentPrintBudget = user.printBalance || 0;
        const addingMinutes = purchase.minutes || 0;
        const addingPrintBudget = purchase.printBudget || 0;
        const validityDays = purchase.validityDays || 0;
        const newTime = currentTime + (addingMinutes * 60);
        const newPrintBudget = currentPrintBudget + addingPrintBudget;

        const updatePayload = {
          remainingTime: newTime,
          printBalance: newPrintBudget,
          updatedAt: new Date().toISOString(),
          lastCreditedAt: new Date().toISOString(),
          lastCreditedBy: "nedarim-callback-render",
          correlationId,
        };
        if (validityDays > 0) {
          const expiresAt = new Date();
          expiresAt.setDate(expiresAt.getDate() + validityDays);
          updatePayload.timeExpiresAt = expiresAt.toISOString();
        }
        // NOTE: previously overwrote user.savedCard here using KevaId/Token
        // from the callback payload. Removed - now that this webhook fires
        // for DebitKeva-triggered charges too, KevaId there is the
        // one-time standing order's own ID, not the reusable card token,
        // and this was silently corrupting savedCard.kevaId (and wiping
        // the stored tokef) on every successful callback. Token/tokef
        // persistence is handled exclusively by confirmPayment(tokenOnly)
        // now (see PaymentDialog.HandleTokenCreatedAsync).

        const atomicUpdate = {};
        const userPath = `organizations/${orgId}/users/${purchase.userId}`;
        for (const [key, val] of Object.entries(updatePayload)) {
          atomicUpdate[`${userPath}/${key}`] = val;
        }
        atomicUpdate[`organizations/${orgId}/purchases/${purchaseId}/creditedAt`] =
          new Date().toISOString();
        atomicUpdate[`organizations/${orgId}/purchases/${purchaseId}/creditedUserId`] =
          purchase.userId;
        await admin.database().ref().update(atomicUpdate);
        log.info("User credited successfully", {userId: purchase.userId, orgId});
      }
    }

    requestTimer.end(log.info);
    return res.status(200).json({success: true, correlationId});
  } catch (error) {
    log.error("Error processing callback", error, {purchaseId, orgId});
    return res.status(500).json({success: false, error: error.message, correlationId});
  }
});

// ═══════════════════════════════════════════════════════════════════
// POST /chargeWithSavedCard - REST equivalent of the onCall function.
// Body: {"data": {orgId, purchaseId, kevaId}}, matching the Firebase
// callable wire protocol so the existing WPF client code needs no
// changes beyond the base URL it points to.
// ═══════════════════════════════════════════════════════════════════
app.post("/chargeWithSavedCard", async (req, res) => {
  const correlationId = generateCorrelationId();
  const log = createLogger({correlationId, service: "charge-with-saved-card"});

  try {
    const authHeader = req.headers.authorization || "";
    const idToken = authHeader.startsWith("Bearer ") ?
      authHeader.slice(7) : null;
    if (!idToken) {
      log.warn("chargeWithSavedCard: no Authorization header");
      return callableError(res, 401, "unauthenticated", "Must be authenticated");
    }
    let decodedToken;
    try {
      decodedToken = await admin.auth().verifyIdToken(idToken);
    } catch (authErr) {
      log.warn("ID token verification failed", {error: authErr.message});
      return callableError(res, 401, "unauthenticated", "Invalid token");
    }
    const callerUid = decodedToken.uid;

    const {orgId, purchaseId, kevaId, tokef: requestTokef} = (req.body && req.body.data) || {};
    log.info("chargeWithSavedCard: request received", {
      orgId, purchaseId, callerUid,
      kevaIdPresent: !!kevaId, tokefPresentInRequest: !!requestTokef,
      bodyKeys: Object.keys((req.body && req.body.data) || {}),
    });
    if (!orgId || !purchaseId || !kevaId) {
      log.warn("chargeWithSavedCard: missing required fields", {
        hasOrgId: !!orgId, hasPurchaseId: !!purchaseId, hasKevaId: !!kevaId,
      });
      return callableError(res, 400, "invalid-argument",
          "Missing required fields: orgId, purchaseId, kevaId");
    }

    const purchaseRef = admin.database()
        .ref(`organizations/${orgId}/purchases/${purchaseId}`);
    const purchaseSnapshot = await purchaseRef.once("value");
    const purchase = purchaseSnapshot.val();
    if (!purchase) {
      log.warn("chargeWithSavedCard: purchase not found", {orgId, purchaseId});
      return callableError(res, 404, "not-found", "הרכישה לא נמצאה");
    }
    log.info("chargeWithSavedCard: purchase loaded", {
      orgId, purchaseId, purchaseStatus: purchase.status,
      purchaseUserId: purchase.userId, purchaseAmount: purchase.amount,
    });
    if (purchase.userId !== callerUid) {
      log.warn("chargeWithSavedCard: purchase belongs to a different user", {
        orgId, purchaseId, purchaseUserId: purchase.userId, callerUid,
      });
      return callableError(res, 403, "permission-denied", "אין הרשאה לרכישה זו");
    }
    if (purchase.status === "completed" && purchase.creditedAt) {
      log.info("chargeWithSavedCard: already completed (idempotent no-op)", {
        orgId, purchaseId,
      });
      return callableOk(res, {
        success: true, message: "כבר עובד (idempotent)", correlationId,
      });
    }

    const userRef = admin.database()
        .ref(`organizations/${orgId}/users/${callerUid}`);
    const userSnapshot = await userRef.once("value");
    const user = userSnapshot.val();
    if (!user) {
      log.warn("chargeWithSavedCard: user not found", {orgId, callerUid});
      return callableError(res, 404, "not-found", "המשתמש לא נמצא");
    }
    const storedKevaId = user.savedCard && user.savedCard.kevaId;
    log.info("chargeWithSavedCard: saved-card check", {
      orgId, callerUid,
      hasSavedCard: !!user.savedCard,
      storedKevaIdMasked: storedKevaId ? `${storedKevaId.slice(0, 3)}***` : null,
      requestKevaIdMasked: kevaId ? `${kevaId.slice(0, 3)}***` : null,
      match: storedKevaId === kevaId,
    });
    if (!storedKevaId || storedKevaId !== kevaId) {
      log.warn("KevaId mismatch or missing - possible tampering", {callerUid, orgId});
      return callableError(res, 403, "permission-denied", "כרטיס שמור לא תקין");
    }
    let tokef = requestTokef || "";
    if (user.savedCard && user.savedCard.tokef) {
      try {
        tokef = tryDecrypt(user.savedCard.tokef);
      } catch (e) {
        log.warn("chargeWithSavedCard: failed to decrypt stored tokef, falling back to request value", {orgId, callerUid});
      }
    }
    log.info("chargeWithSavedCard: tokef resolved", {orgId, callerUid, tokefPresent: !!tokef, source: (user.savedCard && user.savedCard.tokef) ? "stored" : "request"});
    if (!tokef) {
      log.warn("chargeWithSavedCard: no tokef available (stored or request) - DebitKeva requires it", {orgId, callerUid});
      return callableOk(res, {
        success: false,
        error: "לא נמצא תוקף כרטיס שמור - יש לשמור את הכרטיס מחדש",
        correlationId,
      });
    }

    const metaRef = admin.database()
        .ref(`organizations/${orgId}/metadata`);
    const metaSnapshot = await metaRef.once("value");
    const meta = metaSnapshot.val() || {};
    const mosadId = meta.nedarim_mosad_id ?
      (tryDecrypt(meta.nedarim_mosad_id)) : "";
    const apiPassword = meta.nedarim_api_valid ?
      (tryDecrypt(meta.nedarim_api_valid)) : "";
    log.info("chargeWithSavedCard: nedarim credentials loaded from metadata", {
      orgId,
      metaHasMosadIdField: "nedarim_mosad_id" in meta,
      metaHasApiValidField: "nedarim_api_valid" in meta,
      mosadIdResolved: !!mosadId,
      apiPasswordResolved: !!apiPassword,
    });
    if (!mosadId || !apiPassword) {
      log.error("chargeWithSavedCard: missing Nedarim credentials after lookup",
          null, {orgId});
      return callableError(res, 412, "failed-precondition", "חסרים פרטי התחברות לנדרים");
    }

    const amount = Number(purchase.amount) || 0;

    // ── DebitKeva.aspx - confirmed working live (16/08/2026): creates a
    // real one-time standing order (Month/Tashloumim=1) that Nedarim
    // executes IMMEDIATELY (same-minute, per their own admin panel:
    // "בוצעו: 1" right after creation), using the saved token instead of
    // re-entering card details. Replaced the old Manage3.aspx
    // "TashlumBodedNew" attempts entirely - those always returned either
    // wrong-credentials or "No Action" (that URL looks like a
    // reports/management endpoint, not a real charge one).
    //
    // Two things this recipe REQUIRES that took real trial-and-error to
    // find, both essential:
    // - StartFrom MUST be YYYY-MM-DD (ISO). DDMMYYYY or YYYYMMDD both get
    //   "תאריך לא תקין" even though Tokef is otherwise accepted.
    // - Avour/Comments must be unique per call. Nedarim silently dedupes
    //   "identical" standing orders (same card+amount+category+comment)
    //   created within a few minutes of each other - correlationId makes
    //   every purchase's order distinguishable.
    const callbackUrl = `${PUBLIC_BASE_URL}/nedarimCallback`;
    const today = new Date();
    const dd = String(today.getDate()).padStart(2, "0");
    const mm = String(today.getMonth() + 1).padStart(2, "0");
    const yyyy = String(today.getFullYear());
    const startFromIso = `${yyyy}-${mm}-${dd}`;
    const avour = `Purchase-${purchaseId}-${correlationId.slice(-8)}`;

    const debitKevaParams = {
      MosadId: mosadId, ClientName: "", Adresse: "", Mail: "",
      Phone: "", CardNumber: kevaId, Tokef: tokef, Amount: amount.toFixed(0),
      Tashloumim: "1", Groupe: "", Avour: avour, CVV: "",
      Day: String(today.getDate()), StartFrom: startFromIso, Zeout: "",
      Currency: "1", MasofId: "Online", Token: kevaId,
      ApiValid: apiPassword, CallBack: callbackUrl,
      Param1: purchaseId, Param2: orgId,
    };

    const maskedParams = {...debitKevaParams};
    maskedParams.ApiValid = `${String(apiPassword).slice(0, 2)}***`;
    maskedParams.Token = `${String(kevaId).slice(0, 3)}***`;
    maskedParams.CardNumber = `${String(kevaId).slice(0, 3)}***`;
    log.info("[SAVED-CARD DebitKeva] Sending", {
      orgId, purchaseId, callerUid, amount,
      url: "https://matara.pro/nedarimplus/V6/Files/WebServices/DebitKeva.aspx",
      paramsSent: maskedParams,
    });

    const attemptStart = Date.now();
    let responseText;
    let httpStatus = null;
    try {
      const nedarimResponse = await fetch(
          `https://matara.pro/nedarimplus/V6/Files/WebServices/DebitKeva.aspx?${new URLSearchParams(debitKevaParams)}`,
          {method: "GET"},
      );
      httpStatus = nedarimResponse.status;
      responseText = await nedarimResponse.text();
    } catch (fetchErr) {
      log.error("[SAVED-CARD DebitKeva] Network error", fetchErr, {
        orgId, purchaseId, durationMs: Date.now() - attemptStart,
      });
      await purchaseRef.update({
        status: "failed", message: "שגיאת רשת מול נדרים",
        callbackReceivedAt: admin.database.ServerValue.TIMESTAMP,
        correlationId,
      });
      return callableOk(res, {
        success: false, error: "שגיאת רשת מול נדרים", correlationId,
      });
    }
    const durationMs = Date.now() - attemptStart;

    log.info("[SAVED-CARD DebitKeva] Raw HTTP response from Nedarim", {
      orgId, purchaseId, httpStatus, durationMs,
      rawResponseFull: responseText.slice(0, 2000),
    });

    let parsed;
    try {
      parsed = JSON.parse(responseText);
    } catch (parseErr) {
      log.error("[SAVED-CARD DebitKeva] Failed to parse response as JSON", parseErr, {
        orgId, purchaseId, rawResponseSample: responseText.slice(0, 500),
      });
      await purchaseRef.update({
        status: "failed", message: "תגובה לא תקינה מנדרים",
        callbackReceivedAt: admin.database.ServerValue.TIMESTAMP,
        correlationId,
      });
      return callableOk(res, {
        success: false, error: "תגובה לא תקינה מנדרים", correlationId,
      });
    }

    const status = parsed.Status || parsed.Result;
    const transactionId = parsed.KevaId || correlationId;
    log.info("[SAVED-CARD DebitKeva] Parsed response", {
      orgId, purchaseId, status, message: parsed.Message,
      kevaId: parsed.KevaId, nextDate: parsed.NextDate, lastNum: parsed.LastNum,
      fullParsedResponse: parsed,
    });

    if (status !== "OK") {
      await purchaseRef.update({
        status: "failed", message: parsed.Message || "",
        callbackReceivedAt: admin.database.ServerValue.TIMESTAMP,
        correlationId,
      });
      return callableOk(res, {
        success: false, error: parsed.Message || "התשלום נכשל",
        correlationId,
      });
    }

    // Credit the user
    const currentTime = user.remainingTime || 0;
    const currentPrintBudget = user.printBalance || 0;
    const addingMinutes = purchase.minutes || 0;
    const addingPrintBudget = purchase.printBudget || 0;
    const validityDays = purchase.validityDays || 0;
    const newTime = currentTime + (addingMinutes * 60);
    const newPrintBudget = currentPrintBudget + addingPrintBudget;

    const updatePayload = {
      remainingTime: newTime,
      printBalance: newPrintBudget,
      updatedAt: new Date().toISOString(),
      lastCreditedAt: new Date().toISOString(),
      lastCreditedBy: "charge-with-saved-card-render",
      correlationId,
    };
    if (validityDays > 0) {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + validityDays);
      updatePayload.timeExpiresAt = expiresAt.toISOString();
    }

    const atomicUpdate = {};
    const userPath = `organizations/${orgId}/users/${callerUid}`;
    for (const [key, val] of Object.entries(updatePayload)) {
      atomicUpdate[`${userPath}/${key}`] = val;
    }
    const purchasePath = `organizations/${orgId}/purchases/${purchaseId}`;
    atomicUpdate[`${purchasePath}/status`] = "completed";
    atomicUpdate[`${purchasePath}/transactionId`] = transactionId;
    atomicUpdate[`${purchasePath}/amount`] = amount;
    atomicUpdate[`${purchasePath}/creditedAt`] = new Date().toISOString();
    atomicUpdate[`${purchasePath}/creditedUserId`] = callerUid;
    atomicUpdate[`${purchasePath}/creditedBy`] = "charge-with-saved-card-render";
    atomicUpdate[`${purchasePath}/correlationId`] = correlationId;
    atomicUpdate[`${purchasePath}/nedarimKevaId`] = parsed.KevaId || null;
    await admin.database().ref().update(atomicUpdate);

    log.info("User credited successfully via saved card", {
      orgId, callerUid, purchaseId, nedarimKevaId: parsed.KevaId,
    });

    return callableOk(res, {
      success: true, message: "התשלום הצליח", correlationId,
    });
  } catch (error) {
    log.error("Error charging saved card", error, {correlationId});
    return callableError(res, 500, "internal", error.message || "שגיאה בעיבוד תשלום");
  }
});

function tryDecrypt(value) {
  try {
    return decryptData(value);
  } catch (e) {
    return value; // already-plain fallback
  }
}

// ═══════════════════════════════════════════════════════════════════
// EXPERIMENTAL — POST /chargeWithSavedCardRegular
//
// חשוב: זו לא הוראת קבע! זו קריאה ל-DebitCard.aspx, שהוא ה-endpoint
// של נדרים פלוס לחיוב רגיל/חד-פעמי (או תשלומים, אבל בלי ליצור אובייקט
// "הוראת קבע" נמשך). זה שונה מ-DebitKeva.aspx (המשמש כרגע ב-
// /chargeWithSavedCard למעלה) שיוצר בפועל הוראת קבע ב-Tashloumim=1
// שרק "רצה" באותה דקה - עובד, אבל מבחינה טכנית זו עדיין הוראת קבע.
//
// DebitCard.aspx לא מקבל StartFrom/Day/Month בכלל (אלה פרמטרים
// ספציפיים ל-DebitKeva) - זה עוד סימן שזה מודול שונה לגמרי, לא עוד
// אופציה של אותו מודול.
//
// לפי דוגמאות API ציבוריות של נדרים פלוס (לא מתועד רשמית, נאסף
// מפורומים), הפרמטרים של DebitCard.aspx:
//   MosadId, ClientName, Adresse, Phone, ClientId, CardNumber, Tokef,
//   Amount, Tashloumim, Groupe, Avour, Token, CVV, Zeout, Currency,
//   MasofId, ApiValid, CallBack, Param1, Param2
// כשמחייבים כרטיס שמור (טוקן) ולא כרטיס גולמי: CardNumber ריק, CVV
// ריק, והטוקן השמור הולך בשדה Token. זה ההבדל המרכזי מהניסיון שכבר
// עובד עם DebitKeva, ששם קידדנו את kevaId גם ב-CardNumber וגם ב-
// Token (כי לא היה ברור אז מה הפורמט הנכון).
//
// לא ידוע איזו מהאסטרטגיות הבאות (אם בכלל) תעבוד מול נדרים - זה בדיוק
// למה יש כמה ניסיונות ברצף, כל אחד עם השדות ששונים, ולוגים מלאים על
// כל ניסיון בנפרד כדי שאפשר יהיה להשוות תגובות.
// ═══════════════════════════════════════════════════════════════════
app.post("/chargeWithSavedCardRegular", async (req, res) => {
  const correlationId = generateCorrelationId();
  const log = createLogger({correlationId, service: "charge-with-saved-card-regular"});

  try {
    const authHeader = req.headers.authorization || "";
    const idToken = authHeader.startsWith("Bearer ") ?
      authHeader.slice(7) : null;
    if (!idToken) {
      return callableError(res, 401, "unauthenticated", "Must be authenticated");
    }
    let decodedToken;
    try {
      decodedToken = await admin.auth().verifyIdToken(idToken);
    } catch (authErr) {
      return callableError(res, 401, "unauthenticated", "Invalid token");
    }
    const callerUid = decodedToken.uid;

    const {orgId, purchaseId, kevaId, tokef: requestTokef} = (req.body && req.body.data) || {};
    if (!orgId || !purchaseId || !kevaId) {
      return callableError(res, 400, "invalid-argument",
          "Missing required fields: orgId, purchaseId, kevaId");
    }

    const purchaseRef = admin.database()
        .ref(`organizations/${orgId}/purchases/${purchaseId}`);
    const purchaseSnapshot = await purchaseRef.once("value");
    const purchase = purchaseSnapshot.val();
    if (!purchase) {
      return callableError(res, 404, "not-found", "הרכישה לא נמצאה");
    }
    if (purchase.userId !== callerUid) {
      return callableError(res, 403, "permission-denied", "אין הרשאה לרכישה זו");
    }
    if (purchase.status === "completed" && purchase.creditedAt) {
      return callableOk(res, {success: true, message: "כבר עובד (idempotent)", correlationId});
    }

    const userRef = admin.database()
        .ref(`organizations/${orgId}/users/${callerUid}`);
    const userSnapshot = await userRef.once("value");
    const user = userSnapshot.val();
    if (!user) {
      return callableError(res, 404, "not-found", "המשתמש לא נמצא");
    }
    const storedKevaId = user.savedCard && user.savedCard.kevaId;
    if (!storedKevaId || storedKevaId !== kevaId) {
      log.warn("KevaId mismatch or missing - possible tampering", {callerUid, orgId});
      return callableError(res, 403, "permission-denied", "כרטיס שמור לא תקין");
    }
    let tokef = requestTokef || "";
    if (user.savedCard && user.savedCard.tokef) {
      try {
        tokef = tryDecrypt(user.savedCard.tokef);
      } catch (e) {
        log.warn("chargeWithSavedCardRegular: failed to decrypt stored tokef", {orgId, callerUid});
      }
    }
    if (!tokef) {
      return callableOk(res, {
        success: false,
        error: "לא נמצא תוקף כרטיס שמור - יש לשמור את הכרטיס מחדש",
        correlationId,
      });
    }

    const metaRef = admin.database().ref(`organizations/${orgId}/metadata`);
    const metaSnapshot = await metaRef.once("value");
    const meta = metaSnapshot.val() || {};
    const mosadId = meta.nedarim_mosad_id ? tryDecrypt(meta.nedarim_mosad_id) : "";
    const apiPassword = meta.nedarim_api_valid ? tryDecrypt(meta.nedarim_api_valid) : "";
    if (!mosadId || !apiPassword) {
      return callableError(res, 412, "failed-precondition", "חסרים פרטי התחברות לנדרים");
    }

    const amount = Number(purchase.amount) || 0;
    const callbackUrl = `${PUBLIC_BASE_URL}/nedarimCallback`;
    const debitCardUrl = "https://matara.pro/nedarimplus/V6/Files/WebServices/DebitCard.aspx";

    // כל אובייקט כאן הוא ניסיון נפרד - נרוץ עליהם בסדר, ונעצור בראשון
    // שמחזיר Status:OK. ה-label נכנס ללוגים כדי לדעת בדיעבד איזו
    // וריאציה בדיוק עבדה (אם עבדה).
    const attempts = [
      {
        label: "DebitCard.aspx - Token field only (no CardNumber/CVV) - חיוב רגיל",
        params: {
          MosadId: mosadId, ClientName: "", Adresse: "", Mail: "",
          Phone: "", ClientId: "", CardNumber: "", Tokef: tokef,
          Amount: amount.toFixed(0), Tashloumim: "1", Groupe: "",
          Avour: `Purchase-${purchaseId}-${correlationId.slice(-8)}`,
          Token: kevaId, CVV: "", Zeout: "", Currency: "1",
          MasofId: "Online", ApiValid: apiPassword, CallBack: callbackUrl,
          Param1: purchaseId, Param2: orgId,
        },
      },
      {
        label: "DebitCard.aspx - CardNumber+Token both = kevaId (מראה של DebitKeva שעובד)",
        params: {
          MosadId: mosadId, ClientName: "", Adresse: "", Mail: "",
          Phone: "", ClientId: "", CardNumber: kevaId, Tokef: tokef,
          Amount: amount.toFixed(0), Tashloumim: "1", Groupe: "",
          Avour: `Purchase-${purchaseId}-${correlationId.slice(-8)}-b`,
          Token: kevaId, CVV: "", Zeout: "", Currency: "1",
          MasofId: "Online", ApiValid: apiPassword, CallBack: callbackUrl,
          Param1: purchaseId, Param2: orgId,
        },
      },
      {
        label: "DebitCard.aspx - Tashloumim ריק (null=חד פעמי לפי אחת הדוגמאות בפורום)",
        params: {
          MosadId: mosadId, ClientName: "", Adresse: "", Mail: "",
          Phone: "", ClientId: "", CardNumber: "", Tokef: tokef,
          Amount: amount.toFixed(0), Tashloumim: "", Groupe: "",
          Avour: `Purchase-${purchaseId}-${correlationId.slice(-8)}-c`,
          Token: kevaId, CVV: "", Zeout: "", Currency: "1",
          MasofId: "Online", ApiValid: apiPassword, CallBack: callbackUrl,
          Param1: purchaseId, Param2: orgId,
        },
      },
    ];

    for (const attempt of attempts) {
      const maskedParams = {...attempt.params};
      maskedParams.ApiValid = `${String(apiPassword).slice(0, 2)}***`;
      maskedParams.Token = attempt.params.Token ? `${String(attempt.params.Token).slice(0, 3)}***` : "";
      maskedParams.CardNumber = attempt.params.CardNumber ? `${String(attempt.params.CardNumber).slice(0, 3)}***` : "";
      log.info(`[REGULAR-CHARGE] Trying: ${attempt.label}`, {
        orgId, purchaseId, correlationId, url: debitCardUrl, paramsSent: maskedParams,
      });

      let responseText;
      let httpStatus = null;
      const attemptStart = Date.now();
      try {
        const nedarimResponse = await fetch(
            `${debitCardUrl}?${new URLSearchParams(attempt.params)}`,
            {method: "GET"},
        );
        httpStatus = nedarimResponse.status;
        responseText = await nedarimResponse.text();
      } catch (fetchErr) {
        log.error(`[REGULAR-CHARGE] Network error on: ${attempt.label}`, fetchErr, {
          orgId, purchaseId, durationMs: Date.now() - attemptStart,
        });
        continue; // move to next attempt
      }
      const durationMs = Date.now() - attemptStart;
      log.info(`[REGULAR-CHARGE] Raw response for: ${attempt.label}`, {
        orgId, purchaseId, httpStatus, durationMs, rawResponseFull: responseText.slice(0, 2000),
      });

      let parsed;
      try {
        parsed = JSON.parse(responseText);
      } catch (parseErr) {
        log.error(`[REGULAR-CHARGE] Failed to parse JSON for: ${attempt.label}`, parseErr, {
          orgId, purchaseId, rawResponseSample: responseText.slice(0, 500),
        });
        continue;
      }

      const status = parsed.Status || parsed.Result;
      log.info(`[REGULAR-CHARGE] Parsed response for: ${attempt.label}`, {
        orgId, purchaseId, status, message: parsed.Message, fullParsedResponse: parsed,
      });

      if (status === "OK") {
        // מצאנו וריאציה שעובדת - זוכים את המשתמש בדיוק כמו בנתיב הרגיל.
        const transactionId = parsed.KevaId || parsed.TransactionId || correlationId;
        const currentTime = user.remainingTime || 0;
        const currentPrintBudget = user.printBalance || 0;
        const addingMinutes = purchase.minutes || 0;
        const addingPrintBudget = purchase.printBudget || 0;
        const validityDays = purchase.validityDays || 0;
        const newTime = currentTime + (addingMinutes * 60);
        const newPrintBudget = currentPrintBudget + addingPrintBudget;

        const updatePayload = {
          remainingTime: newTime,
          printBalance: newPrintBudget,
          updatedAt: new Date().toISOString(),
          lastCreditedAt: new Date().toISOString(),
          lastCreditedBy: `charge-with-saved-card-regular-render:${attempt.label}`,
          correlationId,
        };
        if (validityDays > 0) {
          const expiresAt = new Date();
          expiresAt.setDate(expiresAt.getDate() + validityDays);
          updatePayload.timeExpiresAt = expiresAt.toISOString();
        }

        const atomicUpdate = {};
        const userPath = `organizations/${orgId}/users/${callerUid}`;
        for (const [key, val] of Object.entries(updatePayload)) {
          atomicUpdate[`${userPath}/${key}`] = val;
        }
        const purchasePath = `organizations/${orgId}/purchases/${purchaseId}`;
        atomicUpdate[`${purchasePath}/status`] = "completed";
        atomicUpdate[`${purchasePath}/transactionId`] = transactionId;
        atomicUpdate[`${purchasePath}/amount`] = amount;
        atomicUpdate[`${purchasePath}/creditedAt`] = new Date().toISOString();
        atomicUpdate[`${purchasePath}/creditedUserId`] = callerUid;
        atomicUpdate[`${purchasePath}/creditedBy`] = "charge-with-saved-card-regular-render";
        atomicUpdate[`${purchasePath}/correlationId`] = correlationId;
        atomicUpdate[`${purchasePath}/nedarimWorkingAttempt`] = attempt.label;
        await admin.database().ref().update(atomicUpdate);

        log.info("User credited successfully via REGULAR (non-Keva) charge", {
          orgId, callerUid, purchaseId, workingAttempt: attempt.label,
        });

        return callableOk(res, {
          success: true, message: "התשלום הצליח (חיוב רגיל, לא הוראת קבע)",
          workingAttempt: attempt.label, correlationId,
        });
      }
      // status != OK -> log and try next attempt
    }

    // כל הניסיונות נכשלו
    await purchaseRef.update({
      status: "failed", message: "כל ניסיונות החיוב הרגיל נכשלו",
      callbackReceivedAt: admin.database.ServerValue.TIMESTAMP,
      correlationId,
    });
    return callableOk(res, {
      success: false, error: "כל ניסיונות החיוב הרגיל (DebitCard.aspx) נכשלו - בדוק לוגים",
      correlationId,
    });
  } catch (error) {
    log.error("Error in chargeWithSavedCardRegular", error, {correlationId});
    return callableError(res, 500, "internal", error.message || "שגיאה בעיבוד תשלום");
  }
});

// ═══════════════════════════════════════════════════════════════════
// POST /confirmPayment - client-attested fallback for the regular
// (non-saved-card) iframe flow.
//
// Why this exists: the iframe already tells the WPF client directly,
// via postMessage, that Nedarim returned Status=OK - that part always
// worked. The *separate* server-to-server webhook (nedarimCallback,
// via the CallBack= param sent to Nedarim) is what's supposed to credit
// the user - but if Nedarim never actually calls it (e.g. the callback
// URL isn't enabled/whitelisted yet on this Mosad's account), the
// purchase is stuck "pending" forever even though the card was charged.
//
// This endpoint lets the already-authenticated client say "the iframe
// told me this purchase succeeded, here's the transaction info" and the
// server credits the SAME way nedarimCallback would have - looking up
// amount/minutes/printBudget from the purchase record itself (never
// trusting client-supplied amounts), same idempotency check, same
// atomic update. It is NOT a substitute for fixing the real webhook
// with Nedarim - it's a stopgap so kiosks aren't stuck while that gets
// sorted out. Once nedarimCallback reliably fires, this becomes a
// redundant safety net rather than the only path (idempotency check
// below means whichever arrives first wins; the second is a no-op).
// ═══════════════════════════════════════════════════════════════════
app.post("/confirmPayment", async (req, res) => {
  const correlationId = generateCorrelationId();
  const log = createLogger({correlationId, service: "confirm-payment"});

  try {
    const authHeader = req.headers.authorization || "";
    const idToken = authHeader.startsWith("Bearer ") ?
      authHeader.slice(7) : null;
    if (!idToken) {
      log.warn("confirmPayment: no Authorization header");
      return callableError(res, 401, "unauthenticated", "Must be authenticated");
    }
    let decodedToken;
    try {
      decodedToken = await admin.auth().verifyIdToken(idToken);
    } catch (authErr) {
      log.warn("ID token verification failed", {error: authErr.message});
      return callableError(res, 401, "unauthenticated", "Invalid token");
    }
    const callerUid = decodedToken.uid;

    const {orgId, purchaseId, transactionId, lastFourDigits, tokenOnly, tokef} =
      (req.body && req.body.data) || {};
    log.info("confirmPayment: request received", {
      orgId, purchaseId, callerUid,
      transactionId, lastFourDigits, tokenOnly, tokefProvided: !!tokef,
      bodyKeys: Object.keys((req.body && req.body.data) || {}),
    });
    if (!orgId || !purchaseId) {
      log.warn("confirmPayment: missing required fields", {
        hasOrgId: !!orgId, hasPurchaseId: !!purchaseId,
      });
      return callableError(res, 400, "invalid-argument",
          "Missing required fields: orgId, purchaseId");
    }

    const purchaseRef = admin.database()
        .ref(`organizations/${orgId}/purchases/${purchaseId}`);
    const purchaseSnapshot = await purchaseRef.once("value");
    const purchase = purchaseSnapshot.val();
    if (!purchase) {
      log.warn("confirmPayment: purchase not found", {orgId, purchaseId});
      return callableError(res, 404, "not-found", "הרכישה לא נמצאה");
    }
    log.info("confirmPayment: purchase loaded", {
      orgId, purchaseId, purchaseStatus: purchase.status,
      purchaseUserId: purchase.userId, purchaseAmount: purchase.amount,
      purchaseMinutes: purchase.minutes, purchasePrintBudget: purchase.printBudget,
    });
    if (purchase.userId !== callerUid) {
      log.warn("confirmPayment: purchase belongs to a different user", {
        orgId, purchaseId, purchaseUserId: purchase.userId, callerUid,
      });
      return callableError(res, 403, "permission-denied", "אין הרשאה לרכישה זו");
    }
    if (purchase.status === "completed" && purchase.creditedAt) {
      log.info("Already credited (idempotent) - likely nedarimCallback " +
        "already fired for this purchase", {orgId, purchaseId});
      return callableOk(res, {success: true, message: "כבר עובד", correlationId});
    }

    const userRef = admin.database()
        .ref(`organizations/${orgId}/users/${callerUid}`);
    const userSnapshot = await userRef.once("value");
    const user = userSnapshot.val();
    if (!user) {
      log.warn("confirmPayment: user not found", {orgId, callerUid});
      return callableError(res, 404, "not-found", "המשתמש לא נמצא");
    }

    // ── tokenOnly: the iframe ran PaymentType=CreateToken (first payment +
    // "save card"). We've seen Nedarim return Status:OK with a real Token
    // here even when no charge actually lands on the card statement, so
    // this branch never credits anything - it just persists the token.
    // The caller (WPF) is expected to immediately follow up with a real
    // chargeWithSavedCard call using this token, which credits the user
    // only on an explicit, separately-verified TashlumBodedNew success.
    // This purchase record is left uncompleted; the follow-up charge
    // creates its own purchase record that actually gets credited.
    if (tokenOnly) {
      if (!transactionId) {
        log.warn("confirmPayment: tokenOnly=true but no transactionId given",
            {orgId, purchaseId, callerUid});
        return callableError(res, 400, "invalid-argument",
            "tokenOnly requires transactionId");
      }
      await userRef.update({
        savedCard: {
          kevaId: transactionId,
          savedAt: new Date().toISOString(),
          ...(tokef ? {tokef: encryptData(tokef)} : {}),
        },
      });
      await purchaseRef.update({
        status: "token-saved-not-charged",
        note: "CreateToken succeeded; awaiting explicit chargeWithSavedCard follow-up",
        updatedAt: new Date().toISOString(),
        correlationId,
      });
      log.info("confirmPayment: saved card token only, no credit issued",
          {orgId, callerUid, purchaseId});
      return callableOk(res, {success: true, tokenSaved: true, message: "כרטיס נשמר", correlationId});
    }

    const amount = Number(purchase.amount) || 0;
    const currentTime = user.remainingTime || 0;
    const currentPrintBudget = user.printBalance || 0;
    const addingMinutes = purchase.minutes || 0;
    const addingPrintBudget = purchase.printBudget || 0;
    const validityDays = purchase.validityDays || 0;
    const newTime = currentTime + (addingMinutes * 60);
    const newPrintBudget = currentPrintBudget + addingPrintBudget;
    log.info("confirmPayment: computed credit", {
      orgId, purchaseId, callerUid,
      currentTime, currentPrintBudget, addingMinutes, addingPrintBudget,
      newTime, newPrintBudget, amount,
    });

    const updatePayload = {
      remainingTime: newTime,
      printBalance: newPrintBudget,
      updatedAt: new Date().toISOString(),
      lastCreditedAt: new Date().toISOString(),
      lastCreditedBy: "confirm-payment-client-attested",
      correlationId,
    };
    if (validityDays > 0) {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + validityDays);
      updatePayload.timeExpiresAt = expiresAt.toISOString();
    }
    // Save the card token if one came back (CreateToken flow) - mirrors
    // nedarimCallback's identical logic. This has to be duplicated here
    // because nedarimCallback's webhook currently never arrives (see the
    // comment above this endpoint), so this is the only path that
    // actually runs today.
    if (transactionId) {
      updatePayload.savedCard = {
        kevaId: transactionId,
        savedAt: new Date().toISOString(),
      };
    }

    const atomicUpdate = {};
    const userPath = `organizations/${orgId}/users/${callerUid}`;
    for (const [key, val] of Object.entries(updatePayload)) {
      atomicUpdate[`${userPath}/${key}`] = val;
    }
    const purchasePath = `organizations/${orgId}/purchases/${purchaseId}`;
    atomicUpdate[`${purchasePath}/status`] = "completed";
    atomicUpdate[`${purchasePath}/transactionId`] = transactionId || correlationId;
    atomicUpdate[`${purchasePath}/creditCardNumber`] =
      lastFourDigits ? `****${String(lastFourDigits).slice(-4)}` : "";
    atomicUpdate[`${purchasePath}/amount`] = amount;
    atomicUpdate[`${purchasePath}/creditedAt`] = new Date().toISOString();
    atomicUpdate[`${purchasePath}/creditedUserId`] = callerUid;
    atomicUpdate[`${purchasePath}/creditedBy`] = "confirm-payment-client-attested";
    atomicUpdate[`${purchasePath}/correlationId`] = correlationId;
    await admin.database().ref().update(atomicUpdate);

    log.info("User credited via client-attested confirmPayment " +
      "(nedarimCallback webhook did not arrive)", {orgId, callerUid, purchaseId});

    return callableOk(res, {success: true, message: "התשלום אושר", correlationId});
  } catch (error) {
    log.error("Error confirming payment", error, {correlationId});
    return callableError(res, 500, "internal", error.message || "שגיאה באישור תשלום");
  }
});

// ═══════════════════════════════════════════════════════════════════
// POST /registerOrganization - moved here from Firebase Cloud
// Functions (functions/index.js still has the original for reference/
// rollback, but it's no longer called). Root cause of moving it: Gen2
// Cloud Functions run on Cloud Run under the hood, which requires the
// Firebase project to be on the Blaze (pay-as-you-go) plan - without
// it, deploys fail outright AND already-deployed functions can stop
// responding correctly (observed: CORS preflight failing with no
// Access-Control-Allow-Origin header at all, meaning the request never
// reached application code). User does not want to upgrade to Blaze,
// so this endpoint runs on Render instead - same Admin SDK, same
// logic, no Blaze dependency (matches why chargeWithSavedCard/
// confirmPayment/nedarimCallback already live here instead of Cloud
// Functions - Spark plan blocks outbound calls from Cloud Functions
// entirely, a related but different Spark-plan limitation).
// No auth check - this is the public "create a new org" signup flow,
// same as it was as an onCall function (callable functions don't
// require auth by default either; anyone can call registerOrganization
// today).
// ═══════════════════════════════════════════════════════════════════
app.post("/registerOrganization", async (req, res) => {
  const correlationId = generateCorrelationId();
  const log = createLogger({correlationId, service: "organization-registration"});

  const body = (req.body && req.body.data) || req.body || {};
  log.info("Organization registration request received", {
    hasData: !!body, dataKeys: Object.keys(body || {}),
  });

  try {
    const {
      organizationName, nedarimMosadId, nedarimApiValid,
      adminPhone, adminPassword, adminFirstName, adminLastName, adminEmail,
    } = body;

    // Nedarim credentials are optional at registration and can be
    // configured later from the dashboard settings screen.
    if (!organizationName || !adminPhone || !adminPassword ||
        !adminFirstName || !adminLastName) {
      return callableError(res, 400, "invalid-argument", "חסרים שדות חובה");
    }

    const cleanOrgName = organizationName.trim();
    const cleanMosadId = (nedarimMosadId || "").trim();
    const cleanApiValid = (nedarimApiValid || "").trim();
    const billingConfigured = !!(cleanMosadId && cleanApiValid);
    const cleanAdminPhone = adminPhone.replace(/\D/g, "");

    log.info("Processing registration", {
      orgNameLength: cleanOrgName.length, hasAdminPhone: !!cleanAdminPhone,
    });

    const orgId = cleanOrgName.toLowerCase()
        .replace(/[^a-z0-9\u0590-\u05FF]/g, "")
        .replace(/\s+/g, "");

    if (!orgId || orgId.length < 2) {
      return callableError(res, 400, "invalid-argument",
          "Organization name must contain valid characters");
    }

    const orgsRef = admin.database().ref("organizations");
    const orgsSnapshot = await orgsRef.once("value");
    if (orgsSnapshot.exists()) {
      const organizations = orgsSnapshot.val();
      if (organizations[orgId]) {
        log.warn("Organization ID already exists", {orgId, orgName: cleanOrgName});
        return callableError(res, 409, "already-exists", "Organization name already exists");
      }
    }
    log.info("Organization ID generated from name", {orgId, orgName: cleanOrgName});

    const phoneToEmail = (phone) => `${phone.replace(/\D/g, "")}@sionyx.app`;
    const adminFirebaseEmail = phoneToEmail(cleanAdminPhone);
    log.info("Creating admin user in Firebase Auth", {email: adminFirebaseEmail, phone: cleanAdminPhone});

    let adminUid;
    try {
      const userRecord = await admin.auth().createUser({
        email: adminFirebaseEmail,
        password: adminPassword,
        displayName: `${adminFirstName} ${adminLastName}`,
      });
      adminUid = userRecord.uid;
      log.info("Admin user created in Firebase Auth", {uid: adminUid});
    } catch (authError) {
      log.error("Failed to create admin user in Firebase Auth", authError);
      if (authError.code === "auth/email-already-exists") {
        return callableError(res, 409, "already-exists", "מספר הטלפון כבר רשום במערכת");
      }
      return callableError(res, 500, "internal", "Failed to create admin user: " + authError.message);
    }

    const metadata = {
      name: cleanOrgName,
      nedarim_mosad_id: encryptData(cleanMosadId),
      nedarim_api_valid: encryptData(cleanApiValid),
      billing_configured: billingConfigured,
      created_at: new Date().toISOString(),
      status: "active",
      created_by: "public-registration",
      admin_uid: adminUid,
      admin_phone: cleanAdminPhone,
      admin_email: adminEmail ? adminEmail.trim() : "",
      correlation_id: correlationId,
    };
    await admin.database().ref(`organizations/${orgId}/metadata`).set(metadata);
    log.info("Organization metadata saved", {orgId, orgName: cleanOrgName});

    const adminUserData = {
      firstName: adminFirstName.trim(),
      lastName: adminLastName.trim(),
      phoneNumber: cleanAdminPhone,
      email: adminEmail ? adminEmail.trim() : "",
      remainingTime: 0,
      printBalance: 0.0,
      isSessionActive: false,
      isAdmin: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      createdBy: "organization-registration",
      correlation_id: correlationId,
    };
    await admin.database().ref(`organizations/${orgId}/users/${adminUid}`).set(adminUserData);
    log.info("Admin user data saved to organization", {orgId, adminUid, isAdmin: true});

    return callableOk(res, {
      success: true, orgId, adminUid,
      message: "Organization and admin user registered successfully",
      correlationId,
    });
  } catch (error) {
    log.error("Error registering organization", error, {errorPhase: "organization-registration"});
    return callableError(res, 500, "internal", "Failed to register organization: " + error.message);
  }
});

app.get("/", (req, res) => res.status(200).send("SIONYX payment bridge is up"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`SIONYX payment bridge listening on port ${PORT}`);
});
