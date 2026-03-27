# Centralized Vulnerability Detection & Intelligent Query (RAG)

![Version](https://img.shields.io/badge/version-v1.3-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Node](https://img.shields.io/badge/node-18.x-lightgrey.svg)

A unified vulnerability scanning platform with RAG-powered intelligence across Nmap, OpenVAS, Nessus, and Nuclei.

## Architecture

```
Frontend (React + Tailwind)  →  FastAPI Backend  →  SQLite + ChromaDB
                                    ↓
                        Scanner Adapters (Nmap/Nuclei/OpenVAS/Nessus)
                                    ↓
                        RAG Engine (LangChain + OpenAI / Local Fallback)
```

## What's New in v1.3

- **Bug Fixes & Stability**: Fixed multiple runtime errors and improved code quality across backend and frontend
- **Updated Dependencies**: Added `langchain-core` and `langchain-huggingface` to requirements for proper RAG pipeline support
- **Deprecated Import Fix**: Migrated from deprecated `langchain_community.embeddings` to `langchain_huggingface` for HuggingFace embeddings
- **Frontend NaN Fix**: Fixed MetricsPanel component showing "NaN%" when evaluation metrics are undefined
- **Dynamic CVE Count**: RAG Assistant footer now shows actual indexed CVE count instead of hardcoded placeholder
- **Clean Sample Data**: Removed duplicate CVE-2023-20198 entry from sample NVD dataset
- **Type Safety**: Improved type annotations in API routes for better code clarity
- **Severity Counting**: Optimized severity count tracking in scan orchestrator to properly handle INFO severity

## What's New in v1.2

- **Real Scanner Integration**: Nmap and Nuclei now perform actual vulnerability scans against targets. No more mock-only data.
- **Live Target Scanning**: Enter any domain or IP in the dashboard and get real CVE findings, open ports, and service detection.
- **Auto-Install Support**: Scanners are detected at startup. Backend `/api/health` reports real-time scanner availability.
- **Improved CVSS Extraction**: Nmap vulners script output is parsed for per-CVE CVSS scores with multiple fallback strategies.
- **Dashboard with Real Data**: Stats, charts, and recent scans all reflect actual scan results.
- **INFO Severity Support**: Open port findings from nmap are now displayed alongside CVE vulnerabilities.
- **Increased Rate Limits**: API rate limits increased for smoother development and testing.
- **Bug Fixes**: Fixed abstract class instantiation crash in aggregator, fixed INFO severity schema validation.

## Features

- **Multi-Scanner Aggregation** — Normalize outputs from Nmap, Nuclei, OpenVAS, Nessus into unified CVE/CVSS schema
- **Real Vulnerability Scanning** — Run actual nmap (`-sV -sC --script vulners`) and nuclei scans from the UI
- **RAG Chat Assistant** — Ask questions about vulnerabilities, remediation steps, exploit techniques
- **Attack Path Modeling** — Visualize potential attack chains using graph analysis
- **Scan Orchestration** — Launch scans against domains/IPs from a unified dashboard
- **Export Results** — Download scan results as JSON or CSV
- **Evaluation Framework** — Measure RAG quality with Accuracy, F1, BLEU, ROUGE metrics

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React, Tailwind CSS, Vite, Lucide Icons, Recharts |
| Backend | FastAPI, SQLAlchemy, Pydantic |
| Database | SQLite (scans), ChromaDB (vectors) |
| RAG | LangChain, OpenAI / Local Sentence-Transformers fallback |
| Scanners | Nmap (real), Nuclei (real), OpenVAS (mock), Nessus (mock) |
| Graph | NetworkX (attack paths) |

## Prerequisites

- **Python 3.10+**
- **Node.js 18+**
- **Nmap** — Install from [nmap.org](https://nmap.org/) or `winget install Insecure.Nmap`
- **Nuclei** — Download from [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases) or `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

> Without nmap/nuclei installed, the platform falls back to mock data for demonstration purposes.

## Project Structure

```
vuln-detect-rag/
├── backend/
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Environment config (v1.3.0)
│   ├── requirements.txt     # Python dependencies
│   ├── .env                 # Scanner paths, DB config
│   ├── models/
│   │   ├── schemas.py       # Pydantic data models
│   │   └── database.py      # SQLite ORM
│   ├── services/
│   │   ├── aggregator.py    # Normalize scanner outputs
│   │   ├── orchestrator.py  # Scan scheduling
│   │   ├── rag_engine.py    # LangChain RAG pipeline
│   │   ├── attack_path.py   # Attack chain modeling
│   │   └── evaluators.py    # F1/BLEU/ROUGE metrics
│   ├── scanners/
│   │   ├── base.py          # Abstract scanner adapter
│   │   ├── nmap_scanner.py  # Real nmap + vulners integration
│   │   ├── nuclei_scanner.py# Real nuclei JSON output parser
│   │   ├── openvas_scanner.py
│   │   └── nessus_scanner.py
│   ├── api/
│   │   ├── routes_scan.py   # Scan endpoints
│   │   ├── routes_rag.py    # RAG chat endpoints
│   │   └── routes_cve.py    # CVE lookup endpoints
│   └── data/                # SQLite DB, ChromaDB, sample CVE data
├── frontend/
│   ├── src/
│   │   ├── pages/           # Dashboard, ScanConsole, RAGAssistant, CVEBrowse
│   │   ├── components/      # ScanForm, ScanResults, VulnerabilityCard, etc.
│   │   └── api/client.js    # Axios API wrapper
│   ├── package.json
│   └── vite.config.js
├── scripts/
│   ├── seed_cve_data.py     # Index CVE data into ChromaDB
│   └── run_eval.py          # Run evaluation suite
└── .env.example
```

## Quickstart

### 1. Install Backend Dependencies

```bash
cd backend
python -m venv venv
# Windows: .\venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Scanner Paths

Edit `backend/.env` to set full paths to nmap and nuclei:

```env
NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
NUCLEI_PATH=C:\tools\nuclei\nuclei.exe
```

### 3. Seed CVE Data (one-time)

```bash
cd scripts
python seed_cve_data.py
```

### 4. Start Backend

```bash
cd backend
python main.py
```

Backend runs at `http://localhost:8000`

### 5. Start Frontend

```bash
cd frontend
npm install   # first time only
npm run dev
```

Frontend runs at `http://localhost:5173`

### 6. Run a Scan

1. Open `http://localhost:5173` in your browser
2. Go to **Scan Console**
3. Enter a target (e.g., `scanme.nmap.org` or `example.com`)
4. Select scanners (Nmap, Nuclei) and click **Start Scan**
5. Results appear in real-time as the scan progresses

### 7. Run Evaluation

```bash
cd scripts
python run_eval.py
```

## Evaluation Results

| Metric | Score |
|--------|-------|
| CVE Detection F1 | 0.6667 |
| BLEU Score | 0.2102 |
| ROUGE Score | 0.4809 |

> BLEU/ROUGE scores are computed against reference answers. To improve RAG quality, set `OPENAI_API_KEY` in `.env` for full LLM-powered responses.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check + scanner availability |
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans/{id}` | Get scan status |
| GET | `/api/scans/{id}/results` | Get scan results |
| GET | `/api/scans/{id}/attack-paths` | Get attack paths |
| GET | `/api/scans/{id}/export?format=json\|csv` | Export results |
| DELETE | `/api/scans/{id}` | Delete a scan |
| GET | `/api/stats` | Dashboard statistics |
| POST | `/api/rag/chat` | Chat with RAG assistant |
| GET | `/api/cve/{cve_id}` | Lookup CVE details |
| GET | `/api/cve/stats/severity` | CVE counts by severity |
| POST | `/api/rag/index` | Re-index CVE data into ChromaDB |

## Deliverables

All 4 deliverables implemented:

1. **Aggregator Service** — `backend/services/aggregator.py` normalizes scanner outputs to CVE/CVSS schema
2. **RAG Assistant** — `backend/services/rag_engine.py` + Chat UI with LangChain + ChromaDB
3. **Scan Orchestration UI** — React dashboard with real scan launch, live results, attack path visualization
4. **Evaluation** — `scripts/run_eval.py` computes Accuracy, F1, BLEU, ROUGE metrics

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
