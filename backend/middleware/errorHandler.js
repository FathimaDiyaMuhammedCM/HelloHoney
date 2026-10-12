// Safe error messages — never leak stack traces or internal details to clients
function errorHandler(err, req, res, next) {
  console.error('[API ERROR]', err.message, err.stack);

  // Map known error types to appropriate client-safe statuses
  let status = err.status || err.statusCode || 500;
  let message;

  if (err.code === 'LIMIT_FILE_SIZE') {
    status = 413;
    message = 'File too large. Maximum upload size is 10MB.';
  } else if (err.type === 'entity.too.large') {
    status = 413;
    message = 'Request payload too large.';
  } else if (err.type === 'entity.parse.failed') {
    status = 400;
    message = 'Invalid JSON in request body.';
  } else if (err.name === 'MulterError') {
    status = 400;
    message = 'Invalid file upload: ' + (err.code || 'upload error');
  } else if (status < 500) {
    message = err.message || 'Bad request';
  } else {
    // Generic 500 errors return a non-descriptive message — no internal details
    message = 'Internal server error';
  }

  res.status(status).json({ error: message });
}

function notFound(req, res) {
  res.status(404).json({ error: 'Not found' });
}

module.exports = { errorHandler, notFound };
