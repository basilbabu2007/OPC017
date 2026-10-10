# OPC017 Frontend (Astro)

This folder contains the **Astro** frontend for the OPC017 AI-Powered Digital Forensics Platform.
It was merged in from `automark-astro-main` and lives alongside the existing `backend/` and `app/`
stacks. Nothing in the existing backend was overwritten.

## How it fits together

```
OPC017/
  frontend/        <- Astro UI (this folder) — runs on :4321 (dev)
  backend/         <- Node + Express REST API + classic dashboard — runs on :4000
  app/             <- Python FastAPI investigation service — runs on :8000
  data/ test-data/ tests/ docs/
```

The frontend talks to the Node backend REST API. Point it at the backend with one env var:

```bash
# frontend/.env
PUBLIC_OPC_API=http://localhost:4000
```

Defaults to `http://localhost:4000` if the variable is not set.

> Note: `astro.config.mjs` also proxies `/api` -> `http://localhost:4000` in dev. The template's own
> server routes (`/api/lead`, `/api/contact`, `/api/checkout`) also live under `/api`, so this
> frontend calls the backend through the absolute `PUBLIC_OPC_API` base to avoid that clash.

## Pages

- `src/pages/dashboard.astro` — new OPC017 dashboard. Shows backend health, lists cases
  (`GET /api/analysis/cases`) and loads findings per case (`GET /api/analysis/findings?case_id=...`).
- The template's original marketing pages (Home, About, Features, Pricing, Blog, ...) are unchanged.

## Run it

1. Start the backend (serves REST API + classic dashboard on :4000):

   ```bash
   cd backend
   npm install
   node src/seed.js        # build synthetic demo cases
   node src/server.js
   ```

2. Start the Astro frontend (:4321):

   ```bash
   cd frontend
   pnpm install
   pnpm dev
   ```

3. Open the frontend dashboard:

   ```
   http://localhost:4321/dashboard
   ```

   Classic dashboard: `http://localhost:4000/`

## Backend endpoints used

| Endpoint | Purpose |
|----------|---------|
| `GET /api/health` | Service status + case count |
| `GET /api/analysis/cases` | Public case list |
| `GET /api/analysis/findings?case_id=` | Findings for a case |
| `GET /api/analysis/timeline?case_id=` | Chronological events |
| `GET /api/analysis/graph?case_id=` | Correlation graph |
| `POST /api/analysis/explain` | Evidence-grounded explanation |

## Next steps

- Rebrand the template pages (title, logo, content) for OPC017.
- Port the classic dashboard views (artifact explorer, graph, timeline, vault) into Astro pages.
- Point `site`/`base` in `astro.config.mjs` at the real deployment URL.
