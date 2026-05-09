# Solvigil System Architecture

This document provides a comprehensive technical overview of the Solvigil platform, its internal subsystems, the vulnerability detection pipeline, and the security methodology driving the application.

---

## 1. Project Overview

**Solvigil** is an automated, AI-assisted smart contract vulnerability scanner designed specifically for Solidity codebases. 

The primary purpose of the platform is to democratize smart contract security by providing developers with an accessible, high-speed, and visually intuitive auditing tool. By leveraging a **static analysis approach**, Solvigil evaluates the source code without executing it. It parses the contract into an Abstract Syntax Tree (AST), identifying logical flaws, access control failures, and known attack vectors before the contract is ever deployed to the blockchain.

---

## 2. High-Level System Architecture

Solvigil follows a decoupled client-server architecture:

- **Frontend (Client):** A lightweight, browser-based user interface responsible for file uploads, data visualization, state management, and offline PDF rendering.
- **Backend (API Orchestrator):** A Node.js environment handling file ingestion, sanitization, and orchestration of the analysis payload.
- **Detection Engine:** The core static analysis engine running on the backend. It parses Solidity code and executes pattern-matching algorithms to detect vulnerabilities.
- **PDF Reporting System:** An isolated, client-side rendering pipeline utilizing `html2pdf.js` to convert structural DOM elements into a professional security audit document.

---

## 3. Frontend Architecture

The frontend is built using standard web technologies (HTML5, Vanilla JavaScript, Tailwind CSS) prioritizing speed and zero-dependency bloat. It is segmented into distinct application states:

- **Landing Page (`index.html`):** The highly optimized entry point featuring interactive CSS animations and smooth parallax scrolling. It serves as the marketing and product introduction layer.
- **Scanner/Upload Interface (`scanner.html`):** Handles drag-and-drop file interactions. It uses the `Fetch API` to securely transmit `.sol` files to the backend and handles loading states while the server processes the AST.
- **Results Dashboard (`analysis-results.html`):** Upon a successful scan, the JSON response is passed via `sessionStorage`. This dashboard parses the payload to render severity distributions, an overall security score, and expandable UI cards detailing each vulnerability line-by-line.
- **PDF Download Interface (`report-print.html`):** A hidden, specialized HTML structure. It strips away interactive web components (like flexbox/viewport units) in favor of strict CSS designed explicitly for A4 pagination.
- **UI Technologies:** HTML5, Vanilla JS, Tailwind CSS, PostCSS.

---

## 4. Backend Architecture

The backend serves as a stateless processing node designed for rapid, ephemeral execution.

- **API Handling:** Built on **Express.js**, exposing a secure REST API endpoint (e.g., `/api/analyze`) to accept file payloads.
- **File Processing Flow:** Uploaded files are temporarily cached in memory or isolated storage. The server extracts the raw source text and passes it to the parsing utility.
- **Vulnerability Analysis Pipeline:** The text is fed into a Solidity AST parser. The resulting JSON-like tree structure is traversed by the detection engine.
- **JSON Response Generation:** Findings are aggregated, deduplicated, and mapped to a standardized schema. A final JSON object containing a `contractInfo` block, a `summary` of severities, and a `details` array is returned to the frontend.

---

## 5. Vulnerability Detection Pipeline

The lifecycle of a single scan executes through the following deterministic flow:

1. **Upload Solidity File:** The client transmits a `.sol` file via a `multipart/form-data` POST request.
2. **Parse Source:** The backend parser converts the raw Solidity syntax into an Abstract Syntax Tree (AST).
3. **Run Detector Modules:** The rule engine iterates over the AST nodes, applying specific detector modules (e.g., Reentrancy, Access Control).
4. **Validate Exploitability:** The engine performs contextual checks (e.g., verifying if an external call is protected by a `nonReentrant` modifier) to discard false positives.
5. **Assign Severity/Confidence:** Confirmed patterns are tagged with a Severity (Critical, High, Medium, Low) and a Confidence level based on pattern strictness.
6. **Generate Structured Findings:** The data is compiled into a comprehensive JSON payload.
7. **Render Results:** The frontend reads the payload and builds the interactive UI dashboard.
8. **Export PDF Report:** If requested, the client injects the JSON data into `report-print.html` and triggers the PDF export module.

---

## 6. Detector Engine Design

The core intelligence of Solvigil lies in its custom detector engine.

- **Pattern-Based Detection:** The engine utilizes a visitor pattern to traverse the AST. It looks for specific node relationships, such as a `FunctionCall` to an external contract followed by an `Assignment` to state variables (Classic Reentrancy).
- **Severity Classification:** Findings are strictly classified. Critical/High severities denote direct risks of fund loss or unrecoverable state changes, while Medium/Low denote operational risks or poor practices.
- **Confidence Levels:** To maintain trust, findings are tagged with confidence levels. Exact pattern matches yield "High Confidence", while ambiguous edge cases yield "Medium Confidence."
- **False-Positive Reduction:** Detectors are context-aware. If an unprotected function is flagged, the engine traverses the AST upwards to check if it resides within an `onlyOwner` context.
- **Exploitability Validation:** Distinguishes between theoretical bugs and realistically exploitable vulnerabilities by tracing execution paths to public/external endpoints.

---

## 7. PDF Report Generation

Solvigil places heavy emphasis on actionable deliverables via its PDF engine.

- **HTML-Based Report Generation:** Instead of drawing primitives to a canvas, Solvigil utilizes `html2pdf.js` to take a snapshot of a meticulously crafted HTML DOM.
- **Styling System:** The report CSS is heavily restricted. Modern web paradigms like `vh/vw` or complex `flex` layouts are avoided to ensure consistent page breaks (`page-break-before: always`) and A4 dimension scaling.
- **Multi-Page Report Structure:** The document is systematically generated with a Cover Page, Executive Summary, Severity Breakdown chart, and an Appendix of detailed findings.
- **Findings Rendering:** The JavaScript iterates through the JSON vulnerability array, dynamically cloning and populating DOM templates with vulnerability names, descriptions, and code snippets before PDF compilation.

---

## 8. Security Methodology

- **Static Analysis Methodology:** Solvigil analyzes the codebase at rest. This provides immediate, cost-effective feedback without requiring complex local blockchain nodes, compiling, or state seeding.
- **Why Exploitability Validation Matters:** Raw static analysis is notoriously noisy. By enforcing exploitability validation (checking if the flaw is reachable by an attacker), developer fatigue is reduced.
- **Informational vs. Exploitable Findings:** Informational findings highlight deviations from best practices (e.g., outdated pragmas or missing emit statements). Exploitable findings indicate direct systemic compromise. Solvigil prioritizes the latter to focus developer attention on critical risks.

---

## 9. Current Limitations

As a static analysis tool, Solvigil currently operates within specific boundaries:

- **Static Analysis Limitations:** It cannot detect complex logical flaws, game-theory vulnerabilities, or multi-contract interaction bugs that only manifest during runtime.
- **No Symbolic Execution Yet:** The engine relies on AST pattern matching and lacks mathematical proofs (SMT solvers) of contract safety.
- **No Bytecode Analysis Yet:** Scans require raw `.sol` source code and cannot analyze compiled bytecode directly from the blockchain.
- **No On-Chain Simulation Yet:** Solvigil does not fork mainnet state to simulate transactions against the analyzed code.

---

## 10. Future Improvements

The engineering roadmap includes transitioning Solvigil from a static tool to a comprehensive security suite:

- **AI-Assisted Remediation:** Implementing LLM integration to automatically suggest and generate secure code patches for identified vulnerabilities.
- **Slither/Mythril Integration:** Wrapping industry-standard CLI engines into the backend pipeline as secondary fallback parsers to expand detector coverage.
- **Symbolic Execution:** Introducing deep path analysis using SMT solvers to prove the absence of specific overflow/underflow conditions.
- **Bytecode-Level Analysis:** Expanding ingestion to accept verified contract addresses to decompile and scan bytecode.
- **CI/CD Scanning:** Providing GitHub Actions and CLI binaries for automated pipeline integration.
- **SaaS Dashboard:** Implementing user authentication, project tracking, and team collaboration.
- **Historical Scan Tracking:** Analyzing code deltas between commits to track vulnerability resolution over time.

---

## 11. Tech Stack

- **Frontend:** HTML5, CSS3, Vanilla JavaScript, Tailwind CSS
- **Backend:** Node.js, Express.js
- **Analysis Engine:** Solidity AST Parsing (e.g., `@solidity-parser/parser`)
- **Reporting Engine:** `html2pdf.js`
- **Deployment:** Vercel (Frontend), Railway/Render (Backend API)
