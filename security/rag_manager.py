"""
Pramaan ADK - Database-Backed Vector RAG Manager
================================================
Stores documents, chunk metadata, and vector embeddings directly in PostgreSQL / Database
without relying on local ephemeral storage or local ChromaDB files.
"""

import os
import io
import uuid
import json
import math
import time
import hashlib
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pypdf import PdfReader
from security.db import db

logger = logging.getLogger(__name__)

def recursive_text_split(text: str, chunk_size: int = 1000, chunk_overlap: int = 200) -> List[str]:
    """Recursive character text splitter."""
    if len(text) <= chunk_size:
        return [text]
    
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        
        if end < len(text):
            break_point = text.rfind('\n\n', start, end)
            if break_point == -1 or break_point < start + chunk_size // 2:
                break_point = text.rfind('. ', start, end)
            if break_point == -1 or break_point < start + chunk_size // 2:
                break_point = text.rfind(' ', start, end)
                
            if break_point != -1 and break_point > start:
                end = break_point + 1
                
        chunks.append(text[start:end].strip())
        start = end - chunk_overlap
        
        if start >= end:
            start = end
            
    return chunks

def generate_local_embedding(text: str, dim: int = 768) -> List[float]:
    """Generate a deterministic normalized 768-dim pseudo-semantic vector from text tokens and n-grams."""
    vec = [0.0] * dim
    words = text.lower().split()
    if not words:
        return [0.0] * dim
    for word in words:
        h = int(hashlib.sha256(word.encode("utf-8")).hexdigest(), 16)
        idx = h % dim
        vec[idx] += 1.0
    for i in range(len(text) - 3):
        ngram = text[i:i+3]
        h = int(hashlib.md5(ngram.encode("utf-8")).hexdigest(), 16)
        idx = h % dim
        vec[idx] += 0.5
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [x / norm for x in vec]
    return vec

def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Compute cosine similarity between two float vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    norm_a = math.sqrt(sum(a * a for a in v1))
    norm_b = math.sqrt(sum(b * b for b in v2))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class VectorEmbeddingService:
    def __init__(self):
        pass

    def _get_api_key(self) -> Optional[str]:
        key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if not key:
            try:
                row = db.fetchone("SELECT gemini_api_key FROM users WHERE gemini_api_key IS NOT NULL AND gemini_api_key != '' ORDER BY last_login DESC LIMIT 1")
                if row:
                    key = row.get("gemini_api_key")
            except Exception:
                pass
        return key

    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        key = self._get_api_key()
        if key:
            try:
                from google.genai import Client
                client = Client(api_key=key)
                for attempt in range(3):
                    try:
                        response = client.models.embed_content(
                            model="text-embedding-004",
                            contents=texts
                        )
                        return [e.values for e in response.embeddings]
                    except Exception as e:
                        err_str = str(e)
                        logger.warning(f"Embedding API attempt {attempt+1}/3 failed ({err_str[:120]})")
                        if attempt < 2 and ("503" in err_str or "429" in err_str or "UNAVAILABLE" in err_str):
                            time.sleep(1.0 * (attempt + 1))
                            continue
                        break
            except Exception as e:
                logger.warning(f"Could not use Google GenAI embedding ({e}). Using normalized vector fallback.")

        # Fallback to normalized deterministic vector
        return [generate_local_embedding(t, 768) for t in texts]


class RAGManager:
    """Database-backed RAG Manager storing embeddings and documents in PostgreSQL."""

    def __init__(self):
        db.initialize()
        self.embed_service = VectorEmbeddingService()

    def extract_text(self, file_content: bytes, filename: str) -> str:
        """Extract text from supported file types."""
        if filename.endswith(".pdf"):
            reader = PdfReader(io.BytesIO(file_content))
            text = ""
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text += extracted + "\n"
            return text
        elif filename.endswith(".txt") or filename.endswith(".md"):
            return file_content.decode("utf-8", errors="replace")
        else:
            raise ValueError(f"Unsupported file type: {filename}")

    def ingest_document(self, filename: str, content: bytes = None, raw_text: str = None, user_id: Optional[str] = None) -> dict:
        """Parse, chunk, embed, and store document in PostgreSQL database."""
        try:
            text = raw_text if raw_text else self.extract_text(content, filename)
            if not text.strip():
                raise ValueError("No extractable text found in file.")
                
            doc_id = str(uuid.uuid4())
            chunks = recursive_text_split(text)
            
            # Generate vector embeddings
            embeddings = self.embed_service.get_embeddings(chunks)
            
            # Store document record in DB
            db.execute(
                """INSERT INTO rag_documents (doc_id, filename, chunks_count, status, full_text, user_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (doc_id, filename, len(chunks), "Indexed", text, user_id)
            )
            
            # Store chunk vectors in DB
            for idx, (chunk, emb) in enumerate(zip(chunks, embeddings)):
                chunk_id = str(uuid.uuid4())
                db.execute(
                    """INSERT INTO rag_chunks (chunk_id, doc_id, chunk_index, content, embedding, source)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (chunk_id, doc_id, idx, chunk, json.dumps(emb), filename)
                )
            
            doc_info = {
                "id": doc_id,
                "filename": filename,
                "chunks": len(chunks),
                "status": "Indexed"
            }
            return doc_info
        except Exception as e:
            logger.error(f"Failed to ingest {filename} into database: {e}")
            raise e

    def get_documents(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if user_id:
            rows = db.fetchall("SELECT doc_id as id, filename, chunks_count as chunks, status, created_at FROM rag_documents WHERE user_id = ? OR user_id IS NULL ORDER BY created_at DESC", (user_id,))
        else:
            rows = db.fetchall("SELECT doc_id as id, filename, chunks_count as chunks, status, created_at FROM rag_documents ORDER BY created_at DESC")
        return [dict(r) for r in rows]

    def get_document_text(self, doc_id: str) -> str:
        row = db.fetchone("SELECT full_text FROM rag_documents WHERE doc_id = ?", (doc_id,))
        if row and row.get("full_text"):
            return row["full_text"]
        return "Text not found."

    def delete_document(self, doc_id: str) -> bool:
        db.execute("DELETE FROM rag_chunks WHERE doc_id = ?", (doc_id,))
        db.execute("DELETE FROM rag_documents WHERE doc_id = ?", (doc_id,))
        return True

    def query(self, query_text: str, k: int = 3, user_id: Optional[str] = None) -> str:
        """Retrieve relevant context for a query using cosine similarity on DB vector embeddings."""
        query_embs = self.embed_service.get_embeddings([query_text])
        if not query_embs:
            return "No relevant information found in the knowledge base."
        
        query_vec = query_embs[0]
        
        # Retrieve chunks from DB
        chunks = db.fetchall("SELECT content, embedding, source FROM rag_chunks")
        if not chunks:
            return "No relevant information found in the knowledge base."
        
        scored_chunks = []
        for c in chunks:
            try:
                emb = json.loads(c["embedding"])
                score = cosine_similarity(query_vec, emb)
                scored_chunks.append((score, c["content"], c["source"]))
            except Exception:
                continue
                
        scored_chunks.sort(key=lambda x: x[0], reverse=True)
        top_k = scored_chunks[:k]
        
        if not top_k:
            return "No relevant information found in the knowledge base."
            
        context_parts = []
        for score, content, source in top_k:
            context_parts.append(f"Source: {source} (Relevance: {score:.2f})\n{content}")
            
        return "\n\n---\n\n".join(context_parts)

# Singleton instance
rag_manager = RAGManager()
