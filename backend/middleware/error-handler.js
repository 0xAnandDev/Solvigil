const multer = require('multer');

function errorHandler(err, req, res, next) {
  // 1. Multer file size errors (LIMIT_FILE_SIZE)
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        error: 'File too large (max 2MB)',
        code: 'FILE_TOO_LARGE'
      });
    }
  }

  // 2. Invalid file type
  if (err.code === 'INVALID_FILE_TYPE' || err.message === 'Only Solidity (.sol) files are supported') {
    return res.status(400).json({
      error: 'Only Solidity (.sol) files are supported',
      code: 'INVALID_FILE_TYPE'
    });
  }

  // 3. Generic errors
  return res.status(500).json({
    error: err.message || 'Internal Server Error',
    code: 'INTERNAL_ERROR'
  });
}

module.exports = errorHandler;
