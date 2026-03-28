# Technical Documentation
## Centralized Vulnerability Detection & Intelligent Query Platform

**Version:** 1.3.0  
**Last Updated:** March 2026  
**Team:** The Last Commit  

---

## 1. System Architecture

### High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                          FRONTEND LAYER                              │
│  React + Tailwind CSS + Vite (http://localhost:5173)                │
│  ├── Dashboard (Real-time scan metrics & overview)                  │
│  ├── Scan Console (Target input, scanner selection, results view)   │
│  ├── RAG Assistant (Chat interface for vulnerability queries)       │
│  ├── CVE Browser (Search & filter vulnerabilities)                  │
│  └── Attack Path Visualization (Graph-based risk modeling)          │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ HTTP/WebSocket
┌──────────────────────────────▼──────────────────────────────────────┐
│                         FASTAPI BACKEND                              │
│              (http://localhost:8000)                                 │
├─────────────────────────────────────────────────────────────────────┤
│  API Routes:                                                         │
│  ├── routes_scan.py → /api/scans, /api/health                      │
│  ├── routes_rag.py → /api/rag/chat, /api/rag/index                 │
│  └── routes_cve.py → /api/cve/{id}, /api/stats                     │
├─────────────────────────────────────────────────────────────────────┤
│  Core Services:                                                      │
│  ├── Aggregator (Normalize Nmap/Nuclei/OpenVAS/Nessus outputs)     │
│  ├── Orchestrator (Schedule & manage scan workflows)                │
│  ├── RAG Engine (LangChain + ChromaDB vector search)                │
│  ├── Attack Path Analyzer (NetworkX graph modeling)                 │
│  └── Evaluators (F1, BLEU, ROUGE quality metrics)                  │
├─────────────────────────────────────────────────────────────────────┤
│  Scanner Adapters:                                                   │
│  ├── Nmap Scanner (Real scans + vulners script for CVE extraction)  │
│  ├── Nuclei Scanner (Real template-based scanning)                  │
│  ├── OpenVAS Adapter (Mock for demo)                                │
│  └── Nessus Adapter (Mock for demo)                                 │
└──────────────────────┬───────────────────────┬──────────────────────┘
                       │                       │
          ┌────────────▼────────┐  ┌──────────▼──────────┐
          │   DATA LAYER        │  │  VECTOR DATABASE    │
          ├─────────────────────┤  ├─────────────────────┤
          │  SQLite (Scan DB)   │  │  ChromaDB (CVE DB)  │
          │  ├── scans table    │  │  └── CVE embeddings │
          │  ├── results table  │  │     (OpenAI or      │
          │  ├── cves table     │  │      Sentence-      │
          │  └── assets table   │  │      Transformers)  │
          └─────────────────────┘  └─────────────────────┘
```

### Data Flow

1. **Scan Initiation:** User submits target + scanner selection in UI
2. **Orchestration:** Backend spawns scanner processes (Nmap, Nuclei)
3. **Aggregation:** Raw outputs (XML/JSON) normalized into CVE/CVSS schema
4. **Deduplication:** Merge identical CVEs across scanner outputs
5. **Enrichment:** Lookup CVSS scores, severity, attack vectors from NVD
6. **Persistence:** Store normalized results in SQLite
7. **Indexing:** CVE descriptions vectorized & stored in ChromaDB for RAG
8. **Visualization:** Frontend retrieves and displays attack paths, metrics

---

## 2. Technology Stack

### Backend

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| Framework | FastAPI | 0.104+ | REST API, async request handling |
| ORM | SQLAlchemy | 2.0+ | Database abstraction for SQLite |
| Validation | Pydantic | 2.0+ | Request/response schema validation |
| RAG Framework | LangChain | 0.1+ | Vector search, prompt chains |
| Embeddings | OpenAI / Sentence-Transformers | Latest | CVE text vectorization |
| Graph Analysis | NetworkX | 3.0+ | Attack path modeling |
| HTTP Client | httpx / requests | Latest | Scanner integration, NVD API calls |
| Database | SQLite3 | Built-in | Lightweight, file-based scan storage |
| Vector DB | ChromaDB | Latest | Semantic search for CVE data |
| CLI | Typer | Optional | Command-line utilities |
| Testing | Pytest | 7.0+ | Unit & integration tests |

### Frontend

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| Framework | React | 18+ | UI component library |
| Styling | Tailwind CSS | 3.0+ | Utility-first CSS framework |
| Build Tool | Vite | 4.0+ | Lightning-fast dev server & bundler |
| HTTP Client | Axios | 1.6+ | API communication |
| Charts | Recharts | 2.10+ | Data visualization (scan metrics) |
| Icons | Lucide React | 0.292+ | UI icons |
| State (Optional) | React Context / Zustand | - | Global state management |
| Markdown | React-Markdown | Optional | CVE details rendering |

### Scanners

| Scanner | Type | Integration | Status |
|---------|------|-------------|--------|
| Nmap | Network mapping | Real command execution | ✅ Real |
| Nuclei | Template-based scanning | Real command execution | ✅ Real |
| OpenVAS | Comprehensive scanning | Mocked (XML output simulation) | 🔵 Mock |
| Nessus | Proprietary scanner | Mocked (JSON output simulation) | 🔵 Mock |

### External APIs & Data Sources

| Source | Purpose | Integration |
|--------|---------|-------------|
| NVD (NIST) | CVE severity, CVSS scores | HTTP API / CSV download |
| OpenAI API | LLM-powered RAG responses | LangChain integration (optional) |
| Exploit-DB | Exploit information | Vector indexed into ChromaDB |

---

## 3. Database Schema

### SQLite Tables

#### `scans` Table
```sql
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    target TEXT NOT NULL,              -- Domain/IP scanned
    scanners TEXT NOT NULL,            -- JSON: ["nmap", "nuclei"]
    status TEXT,                       -- "pending", "running", "completed", "failed"
    start_time DATETIME,
    end_time DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### `scan_results` Table
```sql
CREATE TABLE scan_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    cve_id TEXT,                       -- CVE-YYYY-NNNNN
    asset_name TEXT,                   -- Hostname/IP
    port INT,                          -- Port number
    service TEXT,                      -- HTTP, SSH, etc.
    severity TEXT,                     -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score FLOAT,                  -- 0.0-10.0
    cvss_vector TEXT,                  -- CVSS v3.1 vector string
    description TEXT,
    remediation TEXT,
    scanner TEXT,                      -- Which scanner found this
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

#### `cves` Table
```sql
CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_v3_score FLOAT,
    cvss_v3_vector TEXT,
    published_date DATE,
    last_modified DATE,
    attack_vector TEXT,                -- NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity TEXT,            -- LOW, HIGH
    privileges_required TEXT,          -- NONE, LOW, HIGH
    user_interaction TEXT,             -- NONE, REQUIRED
    scope TEXT,                        -- UNCHANGED, CHANGED
    exploitability_rank INT,           -- Used for prioritization
    is_exploited BOOLEAN DEFAULT FALSE
);
```

#### `assets` Table
```sql
CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    ip_address TEXT,
    open_ports TEXT,                   -- JSON: [22, 80, 443, ...]
    services TEXT,                     -- JSON: {"22": "SSH", "80": "HTTP"}
    last_scanned DATETIME,
    vulnerabilities_count INT DEFAULT 0
);
```

#### `attack_paths` Table
```sql
CREATE TABLE attack_paths (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    source_cve TEXT,                   -- Starting CVE
    target_cve TEXT,                   -- Chained CVE
    chain_description TEXT,            -- e.g., "Web RCE → Privilege Escalation"
    risk_score FLOAT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

### ChromaDB Vector Collections

#### `cve-embeddings` Collection
```
Document: CVE description + related exploit info
Embedding: 1536-dim vector (OpenAI) or 384-dim (Sentence-Transformers)
Metadata: {
    "cve_id": "CVE-2023-12345",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "attack_vector": "NETWORK"
}
```

---

## 4. Core Services & Module Documentation

### 4.1 Aggregator Service
**File:** `backend/services/aggregator.py`

**Purpose:** Normalize heterogeneous scanner outputs into a unified CVE/CVSS schema.

**Key Functions:**
- `parse_nmap_output()` → Extracts CVEs from Nmap vulners script XML
- `parse_nuclei_output()` → Parses Nuclei JSON results
- `parse_openvas_output()` → Normalizes OpenVAS XML (mock)
- `parse_nessus_output()` → Processes Nessus JSON (mock)
- `normalize_to_schema()` → Converts all formats to standardized Pydantic model

**Example Flow:**
```
Nmap XML output
    ↓
[ScanResult(cve="CVE-2023-...", cvss=7.5, port=80, service="HTTP")]
    ↓
Stored in scan_results table with normalized schema
```

**Input Format (Nmap with Vulners):**
```xml
<script id="vulners" output="...">
  CVE-2023-12345 - 7.5 CVSS
</script>
```

**Output Format:**
```json
{
  "cve_id": "CVE-2023-12345",
  "severity": "HIGH",
  "cvss_score": 7.5,
  "asset_name": "scanme.nmap.org",
  "port": 443,
  "service": "HTTPS",
  "scanner": "nmap"
}
```

### 4.2 Orchestrator Service
**File:** `backend/services/orchestrator.py`

**Purpose:** Schedule, execute, and monitor scanner workflows.

**Key Functions:**
- `start_scan(target, scanners)` → Spawns scanner processes
- `monitor_scan(scan_id)` → Polls completion status
- `aggregate_results(scan_id)` → Collects outputs from all scanners
- `cancel_scan(scan_id)` → Gracefully stops running scans

**Workflow:**
```python
1. Receive target + scanner list from API
2. Create Scan record in DB (status="pending")
3. Spawn background tasks for each scanner
4. Update status to "running"
5. Poll scanner processes every 2 seconds
6. Aggregate results as they complete
7. Update status to "completed"
8. Trigger CVE enrichment & indexing
```

**Error Handling:**
- If Nmap not installed → Falls back to mock data
- If Nuclei timeout → Partial results still saved
- If scan is cancelled → Clean up child processes

### 4.3 RAG Engine Service
**File:** `backend/services/rag_engine.py`

**Purpose:** Answer vulnerability questions using semantic search + LLM.

**Key Components:**
- **Vector Store:** ChromaDB with OpenAI/Sentence-Transformers embeddings
- **Retriever:** Retrieves top-K relevant CVEs based on query embedding
- **LLM Chain:** LangChain prompt chain that synthesizes answers
- **Knowledge Base:** CVE descriptions, exploit techniques, remediation steps

**Query Flow:**
```
User: "How to fix CVE-2023-12345?"
    ↓
Embed query using same model as CVE vectors
    ↓
Search ChromaDB for top-5 similar CVEs
    ↓
Retrieve detailed CVE info from database
    ↓
Pass to LLM: "Given these CVEs, answer: [question]"
    ↓
LLM generates: "This vulnerability requires patching to version X..."
    ↓
Return response + sources
```

**Fallback Strategy:**
- If OpenAI API unavailable → Use local Sentence-Transformers
- If ChromaDB fails → Return direct DB lookup (no semantic search)
- If LLM unavailable → Return templated response with CVE details

### 4.4 Attack Path Analyzer
**File:** `backend/services/attack_path.py`

**Purpose:** Model real-world attack chains connecting vulnerabilities.

**Key Functions:**
- `build_graph(cves)` → Creates directed graph of CVE relationships
- `find_attack_paths(source_cve, max_depth=5)` → Breadth-first search for chains
- `calculate_risk_score(path)` → Weights by CVSS, exploitability, privilege gain

**Example Attack Chain:**
```
CVE-2023-1234 (Web RCE, CVSS 8.9)
    ↓ (gains shell access)
CVE-2023-5678 (Privilege Escalation, CVSS 7.0)
    ↓ (gains root)
CVE-2023-9012 (Lateral Movement, CVSS 6.0)
    ↓
Risk Score: 8.5 (weighted combination)
```

**Graph Construction:**
- Nodes = CVEs
- Edges = Attack relationships (weighted by severity delta)
- Metadata = Asset context, port, service

### 4.5 Evaluators Service
**File:** `backend/services/evaluators.py`

**Purpose:** Measure RAG response quality using multiple metrics.

**Metrics Implemented:**
1. **Accuracy:** % of correct answers vs. reference set
2. **F1 Score:** Precision/Recall balance for entity extraction
3. **BLEU Score:** N-gram overlap with reference answers
4. **ROUGE Score:** Longest common subsequence similarity

**Example Evaluation:**
```
Generated: "Update to version 2.5.1 to fix this RCE"
Reference: "Patch to 2.5.1 or later addresses the vulnerability"
BLEU: 0.45
F1: 0.67
```

---

## 5. API Endpoints & Routes

### Health & Metadata

```http
GET /api/health
Content-Type: application/json

Response:
{
  "status": "healthy",
  "scanners": {
    "nmap": { "available": true, "version": "7.93" },
    "nuclei": { "available": true, "version": "3.0.0" },
    "openvas": { "available": false, "reason": "mock mode" },
    "nessus": { "available": false, "reason": "mock mode" }
  },
  "databases": {
    "sqlite": "connected",
    "chromadb": "connected"
  }
}
```

### Scan Management

```http
POST /api/scans
Content-Type: application/json

Request:
{
  "target": "scanme.nmap.org",
  "scanners": ["nmap", "nuclei"],
  "title": "Full infrastructure scan"
}

Response:
{
  "scan_id": "scan-2026-03-28-abc123",
  "status": "running",
  "created_at": "2026-03-28T10:30:00Z"
}
```

```http
GET /api/scans/{scan_id}
Response:
{
  "id": "scan-2026-03-28-abc123",
  "target": "scanme.nmap.org",
  "status": "completed",
  "progress": 100,
  "start_time": "2026-03-28T10:30:00Z",
  "end_time": "2026-03-28T10:35:00Z",
  "total_vulnerabilities": 12,
  "critical_count": 2
}
```

```http
GET /api/scans/{scan_id}/results
Response:
{
  "scan_id": "scan-2026-03-28-abc123",
  "results": [
    {
      "cve_id": "CVE-2023-12345",
      "asset": "scanme.nmap.org:443",
      "service": "HTTPS",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "scanner": "nmap",
      "description": "Remote code execution in OpenSSL..."
    }
  ]
}
```

```http
GET /api/scans/{scan_id}/attack-paths
Response:
{
  "paths": [
    {
      "chain": [
        { "cve": "CVE-2023-1234", "severity": "CRITICAL" },
        { "cve": "CVE-2023-5678", "severity": "HIGH" }
      ],
      "risk_score": 8.9,
      "description": "RCE → Privilege Escalation"
    }
  ]
}
```

```http
GET /api/scans/{scan_id}/export?format=json
Response: File download (application/json or text/csv)
```

### CVE Lookup

```http
GET /api/cve/CVE-2023-12345
Response:
{
  "cve_id": "CVE-2023-12345",
  "description": "Remote code execution in OpenSSL...",
  "cvss_v3_score": 9.8,
  "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "published_date": "2023-10-15",
  "attack_vector": "NETWORK",
  "exploitability_rank": 1,
  "is_exploited": true,
  "remediation": "Update OpenSSL to version 3.0.7 or later"
}
```

```http
GET /api/cve/stats/severity
Response:
{
  "CRITICAL": 2,
  "HIGH": 5,
  "MEDIUM": 8,
  "LOW": 12,
  "INFO": 3
}
```

### Dashboard Statistics

```http
GET /api/stats
Response:
{
  "total_scans": 15,
  "total_vulnerabilities": 45,
  "critical_vulnerabilities": 3,
  "avg_scan_duration_seconds": 180,
  "recent_scans": [
    {
      "scan_id": "...",
      "target": "...",
      "timestamp": "...",
      "vulnerability_count": 5
    }
  ],
  "severity_distribution": {
    "CRITICAL": 3,
    "HIGH": 10,
    "MEDIUM": 20,
    "LOW": 12
  }
}
```

### RAG Chat

```http
POST /api/rag/chat
Content-Type: application/json

Request:
{
  "query": "How do I fix CVE-2023-12345?",
  "scan_id": "scan-2026-03-28-abc123"  // optional context
}

Response:
{
  "response": "This vulnerability requires updating OpenSSL to version 3.0.7 or later. Additionally, review access controls...",
  "sources": [
    {
      "cve_id": "CVE-2023-12345",
      "relevance": 0.95
    }
  ],
  "model_used": "gpt-3.5-turbo"  // or "sentence-transformers (local)"
}
```

```http
POST /api/rag/index
Body: {} (triggers reindexing of all CVEs into ChromaDB)
Response: { "indexed_count": 1240, "status": "success" }
```

---

## 6. Installation & Setup Guide

### 6.1 Prerequisites

- **Python 3.10+** — Check: `python --version`
- **Node.js 18+** — Check: `node --version`
- **Nmap** (optional for real scans)
  - **Windows:** Download from [nmap.org](https://nmap.org) or `winget install Insecure.Nmap`
  - **Linux:** `sudo apt-get install nmap`
  - **macOS:** `brew install nmap`
- **Nuclei** (optional for real scans)
  - **Windows:** Download from [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases)
  - **Linux/macOS:** `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

### 6.2 Backend Setup

```bash
# 1. Clone and navigate
git clone https://github.com/your-org/vuln-detect-rag.git
cd vuln-detect-rag/backend

# 2. Create virtual environment
python -m venv venv
# Activate:
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and set:
# NMAP_PATH=<full path to nmap executable>
# NUCLEI_PATH=<full path to nuclei executable>
# OPENAI_API_KEY=<your key> (optional, for LLM-powered RAG)

# 5. Initialize database (one-time)
python scripts/seed_cve_data.py
# This indexes ~1000 CVE descriptions into ChromaDB

# 6. Start backend
python main.py
# Backend ready at http://localhost:8000
```

### 6.3 Frontend Setup

```bash
# From repo root
cd frontend

# 1. Install dependencies
npm install

# 2. Start dev server
npm run dev
# Frontend ready at http://localhost:5173
```

### 6.4 Verify Installation

```bash
# Check backend health
curl http://localhost:8000/api/health

# Expected response:
# {
#   "status": "healthy",
#   "scanners": { "nmap": {"available": true}, ... }
# }

# Check frontend (open in browser)
# http://localhost:5173
```

---

## 7. Key Features & Implementation Details

### 7.1 Multi-Scanner Aggregation

**Problem Addressed:** Different scanners output different formats (XML, JSON) with inconsistent field names and severity ratings.

**Solution:**
- Unified Pydantic schema: `VulnerabilityResult`
- Scanner-specific parsers that map proprietary fields to standard schema
- CVSS score reconciliation (if multiple scanners find same CVE, use highest score)

**Example:**
```python
# Nmap output
{"port": 443, "service": "HTTPS", "cve": "CVE-2023-1234", "cvss": 7.5}

# Nuclei output
{"host": "scanme.nmap.org", "severity": "high", "id": "CVE-2023-1234", "score": 7.5}

# Normalized
{
  "cve_id": "CVE-2023-1234",
  "asset_name": "scanme.nmap.org",
  "port": 443,
  "service": "HTTPS",
  "severity": "HIGH",
  "cvss_score": 7.5
}
```

### 7.2 Real-World Attack Path Modeling

**Problem Addressed:** Tools show isolated vulnerabilities; analysts must manually connect them into exploitable chains.

**Solution:**
- Graph-based modeling (NetworkX DiGraph)
- Nodes = CVEs with CVSS scores
- Edges = Logical attack transitions (RCE → Priv Esc → Lateral Movement)
- Path weighting considers:
  - CVSS score of intermediate CVE
  - Privilege level gained/required
  - Asset context (service dependencies)

**Example Graph:**
```
OpenSSL RCE (CVE-2023-1234, CVSS 9.8)
    ↓
    (Gains unprivileged shell)
Linux Kernel PrivEsc (CVE-2023-5678, CVSS 7.0)
    ↓
    (Gains root)
Docker Escape (hypothetical)
    ↓
    (Gains host access)

Risk Score = avg(9.8, 7.0) + privilege_gain_bonus = 8.9
```

### 7.3 RAG Assistant with Semantic Search

**Problem Addressed:** Users need instant guidance on vulnerability remediation; generic help is not actionable.

**Solution:**
- **Embedding Model:** OpenAI (1536-dim) or local Sentence-Transformers (384-dim)
- **Vector DB:** ChromaDB stores 1000+ CVE descriptions with metadata
- **Retrieval:** User query embedded, top-5 similar CVEs returned via semantic search
- **Generation:** LangChain chain passes retrieved context to LLM

**Example:**
```
User Query: "How to fix an RCE in our web app?"

1. Embed query → [0.12, -0.45, 0.89, ...]
2. ChromaDB search → Top-5 RCE CVEs returned
3. Retrieve from DB → Full details (CVSS, exploitability, patches)
4. LLM Prompt:
   "Based on these CVEs: [context], answer: How to fix RCE?"
5. LLM Response:
   "Implement input validation, use prepared statements, 
    apply security patches for [specific CVEs], enable WAF..."
```

**Fallback Modes:**
- No OpenAI key → Uses local embeddings + templated responses
- Vector DB fails → Returns raw CVE lookup from database
- LLM unavailable → Provides static remediation hints

### 7.4 Real Scanner Integration

**Nmap + Vulners Script:**
```bash
nmap -sV -sC --script vulners -oX output.xml scanme.nmap.org
```
Extracts CVE IDs and CVSS scores from Nmap script output.

**Nuclei:**
```bash
nuclei -u http://example.com -json -o results.json
```
Parses JSON output with templated vulnerability findings.

**Mock Fallback:**
If scanners unavailable, backend returns realistic sample data for demo purposes.

### 7.5 Deduplication & Enrichment

**Deduplication:**
- Group results by CVE ID + asset (same CVE on same asset = one record)
- Conflict resolution: Keep highest CVSS score if multiple scanners report same CVE

**Enrichment:**
- NVD API lookup: Fetch official CVSS, severity, published date
- Attack vector extraction: CVSS string parsing
- Exploitability ranking: Track if CVE appears in exploit databases

---

## 8. Deployment & Scaling

### 8.1 Production Deployment

#### Docker Containerization
```dockerfile
# Dockerfile.backend
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y nmap
COPY backend/ .
CMD ["python", "main.py"]
```

```dockerfile
# Dockerfile.frontend
FROM node:18-alpine AS build
WORKDIR /app
COPY frontend/package*.json .
RUN npm ci
COPY frontend/ .
RUN npm run build

FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
```

#### Compose Setup
```yaml
version: '3.8'
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=sqlite:///./scans.db
      - CHROMADB_PATH=/data/chromadb
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./data:/data

  frontend:
    build: ./frontend
    ports:
      - "80:80"
    depends_on:
      - backend
```

### 8.2 Database Scaling

**SQLite → PostgreSQL Migration:**
- Change `SQLALCHEMY_DATABASE_URL` in `config.py`
- Update connection string: `postgresql://user:pass@localhost/vuln_db`
- Run migrations: `alembic upgrade head`

**ChromaDB Persistence:**
- Store in `/data/chromadb` volume
- Supports persistence across container restarts

### 8.3 Performance Optimization

**Caching:**
- Redis cache for frequently queried CVEs
- API response caching (5-minute TTL)

**Indexing:**
- SQLite: Index on `cve_id`, `asset_name`, `severity`
- ChromaDB: Automatic index on embeddings

**Query Optimization:**
- Batch insert results (1000 per transaction)
- Async scanner execution (don't block API)
- Limit attack path search depth

**Horizontal Scaling (Future):**
- Move SQLite → PostgreSQL for concurrency
- Deploy backend as microservices (orchestrator, RAG engine separate)
- Load balance with Nginx

---

## 9. Testing & Quality Assurance

### 9.1 Test Coverage

```bash
# Run all tests
pytest -v

# With coverage report
pytest --cov=backend tests/

# Example output:
# test_aggregator.py::test_nmap_xml_parsing PASSED
# test_rag_engine.py::test_query_embedding PASSED
# test_attack_path.py::test_graph_construction PASSED
```

### 9.2 Manual Testing Checklist

- [ ] **Scan Execution:** Launch Nmap scan against scanme.nmap.org
- [ ] **Results Aggregation:** Verify scanner outputs merged correctly
- [ ] **Deduplication:** Run same scan twice, confirm no duplicate CVEs
- [ ] **RAG Chat:** Ask "What is CVE-2023-1234?", verify accurate response
- [ ] **Attack Paths:** Confirm chains connect logically
- [ ] **Export:** Download results as JSON/CSV, verify data integrity
- [ ] **Error Handling:** Disconnect database, confirm graceful fallback

### 9.3 Evaluation Metrics

Run evaluation suite:
```bash
cd scripts
python run_eval.py
```

**Baseline Results:**
| Metric | Score |
|--------|-------|
| CVE Detection F1 | 0.67 |
| BLEU Score | 0.21 |
| ROUGE Score | 0.48 |
| Accuracy | 0.75 |

(Scores improve significantly when OpenAI API key is configured for LLM-powered responses.)

---

## 10. Troubleshooting & FAQs

### Common Issues

**Q: "Nmap command not found"**
- A: Set `NMAP_PATH` in `.env` to full executable path
  - Windows: `C:\Program Files (x86)\Nmap\nmap.exe`
  - Linux: `/usr/bin/nmap`

**Q: "ChromaDB fails to initialize"**
- A: Ensure write permissions on data directory; check disk space

**Q: "Scan results show 0 CVEs"**
- A: Verify target is reachable; check Nmap output manually
  - `nmap -sV scanme.nmap.org` (check if services detected)
  - If no services, target may be blocking scans

**Q: "RAG responses are generic/unhelpful"**
- A: Add OpenAI API key to `.env` for LLM-powered responses
  - Without it, responses are template-based

**Q: "Frontend can't connect to backend"**
- A: Check backend health: `curl http://localhost:8000/api/health`
  - Ensure CORS enabled in `main.py`
  - Check firewall (port 8000 accessible)

**Q: "How do I add a new scanner?"**
- A: Create new adapter in `backend/scanners/my_scanner.py`:
  ```python
  class MyScanner(BaseScannerAdapter):
      def scan(self, target):
          # Execute scanner
          # Return list of VulnerabilityResult
  ```
  - Register in `backend/services/orchestrator.py`

**Q: "Database getting too large"**
- A: Archive old scans:
  ```sql
  DELETE FROM scan_results WHERE scan_id IN (
    SELECT id FROM scans WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)
  );
  ```

---

## 11. Future Roadmap

- **Multi-tenant support:** Isolate scans by organization
- **Real OpenVAS/Nessus integration:** Direct API calls (currently mocked)
- **Advanced graph algorithms:** CVSS-weighted attack paths
- **ML-based false positive filtering:** Train classifier on historical data
- **Webhook notifications:** Alert on critical vulnerabilities
- **API authentication:** JWT-based access control
- **Scan scheduling:** Cron-like recurring scans

---

## 12. References & Resources

- **FastAPI Docs:** https://fastapi.tiangolo.com/
- **LangChain:** https://python.langchain.com/
- **NVD API:** https://nvd.nist.gov/developers/vulnerabilities
- **CVSS Calculator:** https://www.first.org/cvss/calculator/3.1
- **Nmap Documentation:** https://nmap.org/book/
- **Nuclei Templates:** https://github.com/projectdiscovery/nuclei-templates

---

**Document Version:** 1.3.0  
**Last Updated:** March 28, 2026  
**Maintainers:** The Last Commit Team  
