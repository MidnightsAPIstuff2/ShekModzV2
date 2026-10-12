# Shek Modz (Vercel version)

Static site in `public/`, API in `api/index.js` (logic in `lib.js`), database = libSQL/Turso (SQLite-compatible).

## Deploy on Vercel
1. Create a free database at https://turso.tech -> copy its **URL** (libsql://...) and create an **auth token**.
2. In Vercel: Project -> Settings -> Environment Variables, add:
   - `TURSO_DATABASE_URL`  = libsql://your-db.turso.io
   - `TURSO_AUTH_TOKEN`    = (the token)
   - `ADMIN_PASSWORD`      = the admin password you want
   - `SESSION_SECRET`      = any long random string
3. Make sure the Vercel project's Root Directory is the folder containing package.json, then Redeploy.
Tables and sample posts are created automatically on first request.

## Run locally
    npm install
    set ADMIN_PASSWORD=your-password&& set SESSION_SECRET=anything&& npm start   (cmd)
Without TURSO_* vars it uses a local file `shek.db`.
