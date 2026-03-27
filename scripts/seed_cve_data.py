"""Seed CVE data from sample JSON files into SQLite and ChromaDB."""
import sys
import os
import json

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from models.database import init_db, CVEEntryDB, SessionLocal
from services.rag_engine import rag_engine


def seed_data():
    """Load sample CVE data into database and vector store."""
    init_db()

    # Load CVE data from backend/data
    data_dir = os.path.join(os.path.dirname(__file__), '..', 'backend', 'data')
    cve_file = os.path.join(data_dir, 'sample_nvd.json')

    if not os.path.exists(cve_file):
        print(f"Error: {cve_file} not found")
        return 0

    with open(cve_file, 'r') as f:
        cve_entries = json.load(f)

    # Deduplicate by cve_id
    seen = {}
    for entry in cve_entries:
        seen[entry['cve_id']] = entry
    cve_entries = list(seen.values())

    # Insert into SQLite
    db = SessionLocal()
    inserted = 0
    try:
        for entry in cve_entries:
            existing = db.query(CVEEntryDB).filter(
                CVEEntryDB.cve_id == entry['cve_id']
            ).first()

            if not existing:
                db_entry = CVEEntryDB(
                    cve_id=entry['cve_id'],
                    cvss_score=entry.get('cvss_score', 0.0),
                    severity=entry.get('severity', 'LOW'),
                    description=entry.get('description', ''),
                    solution=entry.get('solution', ''),
                    references=entry.get('references', []),
                    exploit_available=entry.get('exploit_available', False),
                    source=entry.get('source', 'NVD'),
                    raw_data=entry,
                )
                db.add(db_entry)
                try:
                    db.commit()
                    inserted += 1
                except Exception:
                    db.rollback()
    finally:
        db.close()

    # Index into ChromaDB for RAG
    rag_engine.index_cves(cve_entries)

    print(f"Seeded {inserted} new CVE entries ({len(cve_entries)} total in source)")
    print(f"Indexed {len(cve_entries)} entries into ChromaDB for RAG")
    return inserted


if __name__ == "__main__":
    seed_data()
