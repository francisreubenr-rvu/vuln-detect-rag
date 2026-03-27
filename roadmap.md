# VulnDetectRAG Roadmap & Change Log

This document tracks the evolution of the VulnDetectRAG platform, highlighting major feature implementations, security patches, styling overhauls, and the specific errors we encountered and resolved during development.

---

## 🎯 v1.2.0 - The Polish & Security Update (Current)

**Focus:** Transforming the prototype into a production-ready, highly secure, and easily distributable application.

### New Features & Enhancements
1. **Universal Project Launcher (`Run_VulnDetect.bat`)**
   - **What we did:** Created a single `.bat` file for seamless project distribution.
   - **Benefit:** Auto-installs Python and Node environments, installs dependencies, runs both backend and frontend servers in separate terminal windows, and auto-launches the application in the user's default browser.
2. **Settings Hub & Live Backend Logs**
   - **What we did:** Introduced a `/settings` page with real-time log streaming from `backend.log` via the new `/api/logs` backend endpoint. Include a download option for forensics.
3. **Premium UI & Theming Overhaul**
   - **What we did:** Replaced flat backgrounds with a deep-space radial gradient mesh in `index.css`. 
   - **What we did:** Applied `.glass` (glassmorphism) utilities across `Sidebar.jsx` and `ScanConsole.jsx` for a sleek blur effect.
   - **What we did:** Color-coded `lucide-react` icons natively across components for improved reactive visual hierarchy (e.g., Emerald for Database, Cyan for Scanning).
4. **Pre-Project Dependency Tracker**
   - **What we did:** Added a root `requirements.txt` acting as both a Python dependency reference and a manual system prerequisite guide.

### 🛡️ Security Hardening & Patches
1. **Server-Side Request Forgery (SSRF) Prevention**
   - **What we did:** Analyzed target inputs in `backend/api/routes_scan.py`.
   - **The Bug:** The scanner orchestration regex allowed inputs like `127.0.0.1`, `localhost`, and internal metadata IPs (like `169.254.169.254`). This would have allowed attackers to map internal infrastructures.
   - **The Fix:** Implemented strict `ipaddress` validation filtering out loopback, link-local, private, and known metadata networks.
2. **Rate Limiting IP-Spoofing Block**
   - **What we did:** Audited `backend/main.py` middleware.
   - **The Bug:** Rate limiting solely relied on `request.client.host`, which is easily spoofed or unintentionally causes mass-blocks when deployed behind reverse proxies (like Nginx).
   - **The Fix:** Updated the middleware to extract the true client IP using `X-Forwarded-For` headers safely.

### 🐛 Errors Encountered & Fixed
- **Error:** *Vite Build Crash - `Identifier 'ScanConsole' has already been declared`*
  - **Context:** Occurred dynamically when verifying the React build via the new `Run_VulnDetect.bat`.
  - **Root Cause:** Duplicated duplicate JSX import lines existed inside `frontend/src/App.jsx` for `ScanConsole`, `RAGAssistant`, and `CVEDetail`.
  - **Resolution:** Removed the redundant import declarations, allowing the Babel parser to compile successfully.
- **Error:** *Initial Nmap Command Injection Risk*
  - **Context:** While checking `backend/scanners/nmap_scanner.py`, passing user input natively to `subprocess.run` was analyzed. 
  - **Root Cause & Resolution:** Discovered it natively evaded shell injection due to Python list mappings, and flag injection was already mitigated via our strict URL/IP regex (preventing inputs starting with `-`).

---

## 🎯 v1.0.0 - Foundation & Aggregation Framework 

**Focus:** Establishing the unified scanning backbone and RAG intelligence.

### Core Implemented Features
- **Multi-Scanner Aggregation:** Normalized outputs from actual `nmap` and `nuclei` binaries, standardizing them against mock `OpenVAS` and `Nessus` schemas into a unified CVSS database.
- **RAG Chat Assistant:** Built Python pipelines (`rag_engine.py`) powered by LangChain + ChromaDB for intelligent AI context queries.
- **Scan Orchestration UI:** Developed the baseline React frontend, complete with Chart visualizations (Recharts) for vulnerabilities and NetworkX integration for mapping attack vectors.
- **Evaluation Engine:** Built `run_eval.py` to benchmark Accuracy, F1, BLEU, and ROUGE metric calculations against reference results.

---

## 🚀 Future Roadmap (v1.3.0 & Beyond)

- [ ] **Full Native OpenVAS & Nessus Integation:** Transition away from generic mock data for comprehensive OpenVAS scanning.
- [ ] **Distributed Scanning Agents:** Allow lightweight worker nodes to process heavy `nmap` jobs via Celery or RabbitMQ.
- [ ] **Exportable PDF Reports:** Compile the current dashboard statistics into a formalized executive penetration test report.
