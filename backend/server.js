const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const errorHandler = require('./middleware/error-handler');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:5173']
}));
app.use(express.json());

// Multer setup for .sol file uploads (max 2MB)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'uploads/'));
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 2097152; // 2MB

const upload = multer({
  storage: storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: function (req, file, cb) {
    if (path.extname(file.originalname).toLowerCase() !== '.sol') {
      const error = new Error('Only Solidity (.sol) files are supported');
      error.code = 'INVALID_FILE_TYPE';
      return cb(error);
    }
    cb(null, true);
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Analysis endpoint
app.post('/api/analyze', upload.single('file'), require('./routes/analyze'));

// Error handling middleware
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
