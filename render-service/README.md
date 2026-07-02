# SIONYX Payment Bridge (Render)

Replaces two Firebase Cloud Functions that require the Blaze plan:
- `nedarimCallback` → `POST /nedarimCallback`
- `chargeWithSavedCard` → `POST /chargeWithSavedCard`

Everything else in the app (login, pending-purchase creation, org/user
data) stays exactly as-is — those are direct Realtime Database calls from
the client and were never Cloud Functions.

## 1. Deploy to Render

1. Push this repo to GitHub (already done).
2. In the Render dashboard: **New +** → **Web Service** → connect this repo.
3. **Root Directory**: `render-service`
4. **Build Command**: `npm install`
5. **Start Command**: `npm start`
6. **Instance Type**: Free is enough for a single kiosk.
7. Add the environment variables from `.env.example` under **Environment**.
8. Deploy. Render gives you a URL like `https://sionyx-payment-bridge.onrender.com`.

Note: Render's free tier spins down after 15 minutes of inactivity and
takes ~30-50s to wake up on the next request. For a kiosk that charges a
saved card once in a while, this means the *first* charge after idle time
will be slow (but will still work — the client just needs a reasonable
timeout, e.g. 60s, on that call). If that's not acceptable, Render's
cheapest paid tier ($7/mo) removes the spin-down.

## 2. Get a Firebase service account key

Firebase Console → Project Settings (gear icon) → Service accounts tab →
**Generate new private key**. This downloads a JSON file — **never commit
it to git**. Base64-encode it (see `.env.example` for the exact command)
and paste the result into Render's `FIREBASE_SERVICE_ACCOUNT_BASE64`.

This does **not** require Blaze — Admin SDK access (Realtime Database
reads/writes, Auth token verification) is free on any plan. Only Cloud
Functions/Cloud Run *hosting* requires Blaze.

## 3. Point the WPF client at the new URLs

Two places in the kiosk app currently hardcode
`https://us-central1-{projectId}.cloudfunctions.net/...`:

- `FirebaseClient.CallFunctionAsync` (for `chargeWithSavedCard`)
- `PaymentDialog.xaml.cs` (`callbackUrl` passed to Nedarim for `nedarimCallback`)

Add a `FUNCTIONS_BASE_URL` config value (registry key in production,
`.env` in development) set to your Render URL, e.g.:
```
FUNCTIONS_BASE_URL=https://sionyx-payment-bridge.onrender.com
```
See the accompanying patch for the exact code changes — `FirebaseClient`
now uses this URL if present, and falls back to the old
`cloudfunctions.net` pattern if it's empty (so nothing breaks if you
later move to Blaze and go back to Cloud Functions).

## 4. Testing

```
curl https://sionyx-payment-bridge.onrender.com/
# → "SIONYX payment bridge is up"
```

Then do a real save-card + saved-card-charge cycle from the kiosk and
check Render's **Logs** tab for `[SAVED-CARD OPTION N] SUCCEEDED` — same
as you'd have checked Cloud Functions logs.

## Limitations vs. Cloud Functions

- No `cleanupInactiveUsers` scheduled job here — that one function
  genuinely needs a scheduler; if you need it, either keep it on Blaze
  Cloud Functions on its own, or add a Render **Cron Job** service running
  a small script that does the same Realtime Database cleanup.
- `resetUserPassword`, `registerOrganization`, `deleteUser`,
  `cleanupTestOrganization` are admin/back-office functions used by the
  web app, not the kiosk — they weren't touched here. If they also need
  to move off Blaze, the same pattern (Express route + `verifyIdToken`)
  applies; ask and they can be added to this service.
