# SIONYX Remote Control (MeshCentral on Render)

Runs [MeshCentral](https://meshcentral.com/) - a free, open-source, fully
browser-based remote control server - as a second Render web service in
this repo, alongside `render-service/` (the payment bridge).

Kiosks will run a small MeshCentral agent (installed alongside the kiosk
app) that connects here automatically. From the SIONYX dashboard, an admin
clicks a computer under **Settings > Remote Control** and gets a full
remote-desktop session directly in the browser - no separate app needed on
the admin's side.

## Why MongoDB Atlas is required

Render's free tier has **no persistent disk** - anything MeshCentral
writes to its own filesystem (device list, credentials, sessions) would be
wiped every time the service restarts or spins down from inactivity. To
avoid that, this service is configured to store all of its state in
MongoDB Atlas (a separate free service) instead of local disk. The Render
filesystem itself stays fully disposable.

## 1. Create the MongoDB Atlas database (if not already done)

1. https://www.mongodb.com/cloud/atlas/register - free, no credit card
2. Create a free **M0** cluster
3. **Database Access** - create a database user (username + password)
4. **Network Access** - add `0.0.0.0/0` (allow from anywhere) so Render
   can connect - Render's outbound IPs aren't fixed on the free tier
5. **Connect > Drivers** - copy the connection string, it looks like:
   ```
   mongodb+srv://<user>:<password>@<cluster>.mongodb.net/sionyxremote?retryWrites=true&w=majority
   ```
   Make sure a database name is included in the path (`sionyxremote`
   above) - MeshCentral will create it automatically on first run.

## 2. Deploy this folder to Render

1. In the Render dashboard: **New +** → **Web Service** → connect this
   same repo (the one `render-service/` already deploys from)
2. **Root Directory**: `meshcentral-remote`
3. **Build Command**: `npm install`
4. **Start Command**: `npm start`
5. **Instance Type**: Free
6. Under **Environment**, add:
   - `MONGO_URL` = the full connection string from step 1.5 above
     (**never commit this to git** - Render env vars are the only place
     it should live)
7. Deploy. Render gives you a URL like
   `https://sionyx-remote-control.onrender.com` - this becomes the
   MeshCentral server URL used everywhere else (agent installer, dashboard
   links).

First boot takes a few minutes longer than usual - MeshCentral generates
its own certificates and initializes the MongoDB collections the first
time it starts.

## 3. Keep it awake (prevents cold-start delays)

Render's free tier spins the service down after 15 minutes of no
requests, and kiosk agents need a live connection to work properly. Use a
free pinger to keep it warm:

1. https://cron-job.org - free account, no credit card
2. Create a cronjob: URL = your Render URL from step 2.7, schedule =
   every 10 minutes
3. Save

## 4. Create the first admin account

Visit your Render URL once in a browser and create the first MeshCentral
admin account - this is separate from SIONYX's own admin accounts; it's
only used internally (by the dashboard integration) to manage devices.

## Next steps (not done in this commit)

- Bundle the MeshCentral agent installer into the kiosk build so it
  self-registers against this server on install
- Add the **Settings > Remote Control** tab to `sionyx-web`, listing
  connected computers and linking into MeshCentral's per-device remote
  session view
