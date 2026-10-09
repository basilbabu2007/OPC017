const jwt = require('jsonwebtoken');
function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'change-me-in-production-min-32-chars');
    next();
  } catch {
    return res.status(401).json({ error: 'unauthorized' });
  }
}
module.exports = { authRequired };
