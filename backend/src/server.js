// Minimal Express foundation (Phase 1). Full analysis routes land in Phase 2-4.
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

const { getDb } = require('./db');
const casesRouter = require('./routes/cases');
const evidenceRouter = require('./routes/evidence');
const authRouter = require('./routes/auth');
const analysisRouter = require('./routes/analysis');
const vaultRouter = require('./routes/vault');
const { authRequired } = require('./middleware/auth');
const path = require('path');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(morgan('dev'));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/health', (req, res) => {
  const db = getDb(false);
  const row = db.prepare('SELECT COUNT(*) AS c FROM cases').get();
  res.json({ ok: true, service: 'opc017-backend', cases: row.c, timeUtc: new Date().toISOString() });
});

// Forward dashboard questions to the Python investigation API.
app.post('/api/assistant/ask', async (req, res) => {
  try {
    const response = await fetch(
      `${process.env.PYTHON_API_URL || 'http://127.0.0.1:8000'}/ask`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body),
        signal: AbortSignal.timeout(120000)
      }
    );

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (error) {
    console.error('Python investigation API error:', error.message);

    res.status(502).json({
      error: 'investigation-api-unavailable',
      message: 'Could not reach the Python investigation service. Check that it is running.'
    });
  }
});

app.use('/api/auth', authRouter);
app.use('/api/cases', authRequired, casesRouter);
app.use('/api/evidence', authRequired, evidenceRouter);
// Demo-readable (case-scoped) analysis + vault; writes remain audit-logged.
app.use('/api/analysis', analysisRouter);
app.use('/api/vault', vaultRouter);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: 'internal-error', message: 'Something went wrong.' });
});

const PORT = process.env.PORT || 4000;
if (require.main === module) {
  getDb(true);
  app.listen(PORT, () => console.log(`OPC017 backend listening on :${PORT}`));
}
module.exports = app;
