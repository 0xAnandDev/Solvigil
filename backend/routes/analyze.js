const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { analyzeContract } = require('../analyzer/index');

/**
 * Route middleware to handle file upload, analyze the contract, and return a standardized report.
 */
module.exports = async (req, res) => {
  const requestId = uuidv4();
  const startTime = Date.now();

  try {
    // 1. Validate file was uploaded
    if (!req.file || !req.file.path) {
      return res.status(400).json({ error: 'No file uploaded', code: 'NO_FILE' });
    }

    // 2. Read file content from req.file.path
    const code = fs.readFileSync(req.file.path, 'utf8');

    // 3. Validate file is not empty
    if (!code || code.trim() === '') {
      // Clean up the empty file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ error: 'File is empty', code: 'EMPTY_FILE' });
    }

    // 4. Call analyzeContract from analyzer/index.js
    const analysis = await analyzeContract(code);

    // 5. Delete temporary file
    if (fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    const processingTime = Date.now() - startTime;

    // 6. Return success response
    return res.status(200).json({
      success: true,
      requestId,
      timestamp: new Date().toISOString(),
      processingTime,
      file: {
        name: req.file.originalname,
        size: req.file.size
      },
      analysis
    });

  } catch (error) {
    // 7. On error: Delete temp file if exists
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (cleanupError) {
        console.error('Failed to clean up file:', cleanupError.message);
      }
    }

    return res.status(500).json({
      error: error.message || 'Internal analysis error',
      code: 'ANALYSIS_ERROR',
      requestId
    });
  }
};
