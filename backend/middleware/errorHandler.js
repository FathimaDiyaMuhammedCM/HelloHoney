function errorHandler(err, req, res, next) {
  console.error('[API ERROR]', err.message);
  const status = err.status || 500;
  res.status(status).json({ error: err.message || 'Internal server error' });
}

function notFound(req, res) {
  res.status(404).json({ error: 'Not found: ' + req.originalUrl });
}

module.exports = { errorHandler, notFound };
