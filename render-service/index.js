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
app.use(express.urlencoded({extended: true}));

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
    const newCardToken = paymentData.Token || paymentData.KevaId || "";
    const TransactionId = paymentData.TransactionId;
    const Status = paymentData.Status;

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
      status: Status === "Error" ? "failed" : "completed",
      transactionId: TransactionId,
      amount: amountNum,
      creditCardNumber: maskedCardForStorage,
      message: Message || "",
      callbackReceivedAt: admin.database.ServerValue.TIMESTAMP,
      correlationId,
      processedAt: new Date().toISOString(),
    });

    if (Status !== "Error" && purchase.userId) {
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
        if (newCardToken) {
          updatePayload.savedCard = {
            kevaId: newCardToken,
            savedAt: new Date().toISOString(),
          };
        }

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

    const {orgId, purchaseId, kevaId} = (req.body && req.body.data) || {};
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
      return callableOk(res, {
        success: true, message: "כבר עובד (idempotent)", correlationId,
      });
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

    const metaRef = admin.database()
        .ref(`organizations/${orgId}/metadata`);
    const metaSnapshot = await metaRef.once("value");
    const meta = metaSnapshot.val() || {};
    const mosadId = meta.nedarim_mosad_id ?
      (tryDecrypt(meta.nedarim_mosad_id)) : "";
    const apiPassword = meta.nedarim_api_valid ?
      (tryDecrypt(meta.nedarim_api_valid)) : "";
    if (!mosadId || !apiPassword) {
      return callableError(res, 412, "failed-precondition", "חסרים פרטי התחברות לנדרים");
    }

    const amount = Number(purchase.amount) || 0;

    // ── Numbered fallback strategies - identical to functions/index.js ──
    const structuralFailureHints = [
      "מוסד", "לא נמצא", "not found", "פעולה לא מוכרת",
      "unrecognized", "invalid action", "פרמטר", "parameter",
      "לא מזוהה", "unauthorized",
    ];
    const isStructuralFailure = (message) => {
      const m = (message || "").toLowerCase();
      return structuralFailureHints.some(
          (hint) => m.includes(hint.toLowerCase()));
    };

    const strategies = [
      {
        option: 1,
        label: "MosadNumber/ApiPassword/KevaId/Tashloumim (original)",
        params: {
          Action: "TashlumBodedNew", MosadNumber: mosadId,
          ApiPassword: apiPassword, Currency: "1", KevaId: kevaId,
          Amount: amount.toFixed(0), Tashloumim: "1",
          JoinToKevaId: "NoJoin", Comments: `Purchase:${purchaseId}`,
        },
      },
      {
        option: 2,
        label: "Mosad/ApiValid/KevaId/Tashlumim (matches iframe naming)",
        params: {
          Action: "TashlumBodedNew", Mosad: mosadId, ApiValid: apiPassword,
          Currency: "1", KevaId: kevaId, Amount: amount.toFixed(0),
          Tashlumim: "1", JoinToKevaId: "NoJoin",
          Comment: `Purchase:${purchaseId}`, Param1: purchaseId, Param2: orgId,
        },
      },
      {
        option: 3,
        label: "MosadId/Token (DebitCard.aspx-style naming)",
        params: {
          Action: "TashlumBodedNew", MosadId: mosadId, ApiValid: apiPassword,
          Currency: "1", Token: kevaId, Amount: amount.toFixed(0),
          Tashloumim: "1", Avour: `Purchase:${purchaseId}`,
        },
      },
    ];

    let parsed = null;
    let optionUsed = null;
    const attemptsLog = [];

    for (const strategy of strategies) {
      const tag = `[SAVED-CARD OPTION ${strategy.option}]`;
      log.info(`${tag} Attempting Nedarim TashlumBodedNew`, {
        orgId, purchaseId, option: strategy.option, label: strategy.label,
      });

      let responseText;
      try {
        const nedarimResponse = await fetch(
            "https://matara.pro/nedarimplus/Reports/Manage3.aspx",
            {method: "POST", body: new URLSearchParams(strategy.params)},
        );
        responseText = await nedarimResponse.text();
      } catch (fetchErr) {
        log.error(`${tag} Network error`, fetchErr, {orgId, purchaseId});
        attemptsLog.push({option: strategy.option, error: "network-error"});
        continue;
      }

      let attemptParsed;
      try {
        attemptParsed = JSON.parse(responseText);
      } catch (parseErr) {
        log.error(`${tag} Failed to parse response`, parseErr, {
          orgId, purchaseId, rawResponseSample: responseText.slice(0, 200),
        });
        attemptsLog.push({option: strategy.option, error: "parse-error"});
        continue;
      }

      log.info(`${tag} Response received`, {
        orgId, purchaseId, status: attemptParsed.Status,
        message: attemptParsed.Message,
      });
      attemptsLog.push({
        option: strategy.option, status: attemptParsed.Status,
        message: attemptParsed.Message,
      });

      if (attemptParsed.Status === "OK") {
        log.info(`${tag} SUCCEEDED - this is the working option`);
        parsed = attemptParsed;
        optionUsed = strategy.option;
        break;
      }
      if (isStructuralFailure(attemptParsed.Message)) {
        log.warn(`${tag} Structural failure, trying next option`);
        continue;
      }
      log.warn(`${tag} Real decline - stopping, not trying more options`);
      parsed = attemptParsed;
      optionUsed = strategy.option;
      break;
    }

    if (!parsed) {
      log.error("All saved-card charge options failed structurally", null, {
        orgId, purchaseId, attempts: attemptsLog,
      });
      await purchaseRef.update({
        status: "failed",
        message: "כל אפשרויות החיוב נכשלו - ראה לוגים",
        callbackReceivedAt: admin.database.ServerValue.TIMESTAMP,
        correlationId,
      });
      return callableOk(res, {
        success: false, error: "לא ניתן לחייב את הכרטיס השמור",
        correlationId, attempts: attemptsLog,
      });
    }

    const status = parsed.Status;
    const transactionId = parsed.Id || parsed.TransactionId || correlationId;

    if (status !== "OK") {
      await purchaseRef.update({
        status: "failed", message: parsed.Message || "",
        callbackReceivedAt: admin.database.ServerValue.TIMESTAMP,
        correlationId, optionUsed,
      });
      return callableOk(res, {
        success: false, error: parsed.Message || "התשלום נכשל",
        correlationId, optionUsed, attempts: attemptsLog,
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
    atomicUpdate[`${purchasePath}/optionUsed`] = optionUsed;
    await admin.database().ref().update(atomicUpdate);

    log.info("User credited successfully via saved card", {
      orgId, callerUid, purchaseId, optionUsed,
    });

    return callableOk(res, {
      success: true, message: "התשלום הצליח", correlationId, optionUsed,
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

app.get("/", (req, res) => res.status(200).send("SIONYX payment bridge is up"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`SIONYX payment bridge listening on port ${PORT}`);
});
