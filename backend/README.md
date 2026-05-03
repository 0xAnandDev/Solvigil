# Solvigil Smart Contract Security Analyzer - Backend

## Overview
Backend for detecting vulnerabilities in Solidity smart contracts using AST parsing and pattern-based detection.

## Features
- **6 Vulnerability Detectors**:
  1. Reentrancy - External calls before state updates
  2. Access Control - Missing permission checks
  3. Unchecked Calls - External calls without return validation
  4. Overflow/Underflow - Arithmetic without SafeMath
  5. Denial of Service - External calls in loops
  6. Version Risk - Old Solidity versions

- **Precise Line Detection** - Know exactly where issues are
- **Confidence Ratings** - HIGH, MEDIUM, LOW
- **Attack Simulations** - Step-by-step exploit flows
- **Fix Suggestions** - Actionable remediation code
- **Security Scoring** - Overall contract safety (0-100)

## Installation

```bash
npm install
```

## Environment Setup

Create .env file:
```
PORT=5000
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
```

## Running the Server

```bash
npm start
```

Server runs on http://localhost:5000

## API Endpoints

### POST /api/analyze
Upload a Solidity contract for vulnerability analysis.

**Request:**
- Content-Type: multipart/form-data
- Field: file (.sol file, max 2MB)

**Response:**
```json
{
  "success": true,
  "requestId": "uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "processingTime": 250,
  "file": {
    "name": "Contract.sol",
    "size": 1024
  },
  "analysis": {
    "contractInfo": { ... },
    "securityScore": 72,
    "securityStatus": "Vulnerable",
    "vulnerabilities": [ ... ],
    "summary": { ... }
  }
}
```

### GET /api/health
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Vulnerability Detection Details

### Reentrancy
**Pattern**: External call → State update
**Severity**: CRITICAL
**Confidence**: HIGH

### Access Control
**Pattern**: Public critical function without permission check
**Severity**: HIGH
**Confidence**: MEDIUM

### Unchecked Calls
**Pattern**: .call()/.send() return not checked
**Severity**: MEDIUM
**Confidence**: HIGH

### Overflow/Underflow
**Pattern**: Old Solidity + arithmetic or unchecked block
**Severity**: CRITICAL or MEDIUM
**Confidence**: MEDIUM

### Denial of Service
**Pattern**: External calls in loops
**Severity**: MEDIUM
**Confidence**: MEDIUM

### Version Risk
**Pattern**: Old Solidity pragma (< 0.8.0)
**Severity**: LOW
**Confidence**: HIGH

## Testing with cURL

```bash
curl -X POST \
  -F "file=@Contract.sol" \
  http://localhost:5000/api/analyze
```

## Project Structure

```
backend/
├── server.js              # Express server
├── .env                   # Environment variables
├── analyzer/
│   ├── index.js          # Main analyzer
│   ├── ast-builder.js    # AST parsing
│   ├── vulnerability-scanner.js  # Scanner
│   ├── detectors/        # 6 vulnerability detectors
│   └── utils/
│       └── score-calculator.js
├── routes/
│   └── analyze.js        # API route
├── middleware/
│   └── error-handler.js  # Error handling
├── config/
│   └── detection-rules.js
└── uploads/              # Temp file storage
```

## Dependencies
- express: Web framework
- cors: Cross-origin requests
- multer: File upload handling
- solidity-parser-antlr: Solidity AST parsing
- dotenv: Environment variables
- uuid: Unique IDs
- lodash: Utility functions
- nodemon: Development tool

## Notes
- Only .sol files accepted (max 2MB)
- Automated detection is not a substitute for professional audits
- All files are analyzed within the request lifecycle
- CORS enabled for frontend integration

## License
MIT
