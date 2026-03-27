import logging

import chromadb

from config import settings

logger = logging.getLogger("vulndetect")


class RAGEngine:
    """RAG pipeline for vulnerability Q&A using ChromaDB + LLM."""

    def __init__(self):
        self.chroma_client = chromadb.PersistentClient(path=settings.CHROMA_PERSIST_DIR)
        self.collection = self.chroma_client.get_or_create_collection(
            name=settings.CHROMA_COLLECTION, metadata={"hnsw:space": "cosine"}
        )
        self._llm = None
        self._embeddings = None

    def _get_embeddings(self):
        if self._embeddings is None:
            if settings.USE_LOCAL_EMBEDDINGS or not settings.OPENAI_API_KEY:
                from langchain_huggingface import HuggingFaceEmbeddings

                self._embeddings = HuggingFaceEmbeddings(
                    model_name=settings.LOCAL_EMBEDDING_MODEL
                )
            else:
                from langchain_openai import OpenAIEmbeddings

                self._embeddings = OpenAIEmbeddings(
                    model=settings.EMBEDDING_MODEL,
                    api_key=settings.OPENAI_API_KEY,
                )
        return self._embeddings

    def _get_llm(self):
        if self._llm is None:
            if settings.OPENAI_API_KEY:
                from langchain_openai import ChatOpenAI

                self._llm = ChatOpenAI(
                    model=settings.OPENAI_MODEL,
                    api_key=settings.OPENAI_API_KEY,
                    temperature=0.1,
                )
            else:
                self._llm = None
        return self._llm

    def index_cves(self, cve_entries: list[dict]):
        """Index CVE entries into ChromaDB."""
        if not cve_entries:
            return

        documents = []
        metadatas = []
        ids = []

        for entry in cve_entries:
            cve_id = entry.get("cve_id", "")
            text = f"{cve_id}: {entry.get('description', '')} Solution: {entry.get('solution', '')}"
            documents.append(text)
            metadatas.append(
                {
                    "cve_id": cve_id,
                    "severity": entry.get("severity", "LOW"),
                    "cvss_score": entry.get("cvss_score", 0.0),
                    "exploit_available": entry.get("exploit_available", False),
                }
            )
            ids.append(cve_id or f"doc_{len(ids)}")

        # Upsert in batches
        batch_size = 100
        for i in range(0, len(documents), batch_size):
            self.collection.upsert(
                documents=documents[i : i + batch_size],
                metadatas=metadatas[i : i + batch_size],
                ids=ids[i : i + batch_size],
            )

    def query(self, question: str, n_results: int = 5) -> dict:
        """Query the RAG system."""
        try:
            results = self.collection.query(
                query_texts=[question],
                n_results=n_results,
            )
        except Exception:
            logger.exception("ChromaDB query failed")
            return {
                "answer": "Unable to query the vulnerability database. Please try again later.",
                "sources": [],
            }

        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        # Build context
        context_parts = []
        sources = []
        for doc, meta, dist in zip(documents, metadatas, distances):
            context_parts.append(doc)
            sources.append(
                {
                    "cve_id": meta.get("cve_id"),
                    "content": doc[:200],
                    "score": round(1 - dist, 4),
                }
            )

        context = "\n\n".join(context_parts)

        # Generate answer
        llm = self._get_llm()
        if llm:
            answer = self._generate_with_llm(question, context)
        else:
            answer = self._generate_fallback(question, context, metadatas)

        return {
            "answer": answer,
            "sources": sources,
        }

    def _generate_with_llm(self, question: str, context: str) -> str:
        """Generate answer using OpenAI LLM."""
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import StrOutputParser

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are a cybersecurity vulnerability expert assistant. 
Answer questions about vulnerabilities, CVEs, remediation steps, and exploit techniques.
Base your answers ONLY on the provided CVE context. If the context doesn't contain relevant information, say so.

Context:
{context}""",
                ),
                ("human", "{question}"),
            ]
        )

        llm = self._get_llm()
        chain = prompt | llm | StrOutputParser()

        return chain.invoke({"context": context, "question": question})

    def _generate_fallback(self, question: str, context: str, metadatas: list) -> str:
        """Generate a structured answer without LLM."""
        if not metadatas:
            return "No relevant vulnerabilities found in the knowledge base for your query."

        lines = [f"Based on the vulnerability database, here's what I found:\n"]
        for i, meta in enumerate(metadatas, 1):
            cve_id = meta.get("cve_id", "Unknown")
            severity = meta.get("severity", "LOW")
            cvss = meta.get("cvss_score", 0.0)
            exploit = "Yes" if meta.get("exploit_available") else "No"

            lines.append(f"**{i}. {cve_id}**")
            lines.append(f"   - Severity: {severity} (CVSS: {cvss})")
            lines.append(f"   - Exploit Available: {exploit}")

        lines.append(
            f"\nFor detailed remediation, please configure an OpenAI API key for full RAG responses."
        )
        return "\n".join(lines)


rag_engine = RAGEngine()
