import os
import io
import uuid
import json
import logging
from typing import List, Dict, Any

from pypdf import PdfReader
import chromadb
from google.genai import Client

logger = logging.getLogger(__name__)

def recursive_text_split(text: str, chunk_size: int = 1000, chunk_overlap: int = 200) -> List[str]:
    """A simple recursive character text splitter."""
    if len(text) <= chunk_size:
        return [text]
    
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        
        # Try to find a good breaking point
        if end < len(text):
            # Look for paragraph break
            break_point = text.rfind('\n\n', start, end)
            if break_point == -1 or break_point < start + chunk_size // 2:
                # Look for sentence break
                break_point = text.rfind('. ', start, end)
            if break_point == -1 or break_point < start + chunk_size // 2:
                # Look for space
                break_point = text.rfind(' ', start, end)
                
            if break_point != -1 and break_point > start:
                end = break_point + 1 # Include the break character
                
        chunks.append(text[start:end].strip())
        start = end - chunk_overlap
        
        # Prevent infinite loop if we can't progress
        if start >= end:
            start = end
            
    return chunks

import hashlib
import math
import time

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

class GoogleGenAIEmbeddingFunction(chromadb.EmbeddingFunction):
    def __init__(self):
        self._client = None

    def _get_client(self):
        key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if key:
            try:
                return Client(api_key=key)
            except Exception as e:
                logger.warning(f"Could not initialize GenAI Client for embeddings: {e}")
        return None

    def __call__(self, input: chromadb.Documents) -> chromadb.Embeddings:
        client = self._get_client()
        if client:
            # Attempt with exponential backoff for high demand spikes (503 / 429)
            for attempt in range(3):
                try:
                    response = client.models.embed_content(
                        model="text-embedding-004",
                        contents=input
                    )
                    return [e.values for e in response.embeddings]
                except Exception as e:
                    err_str = str(e)
                    logger.warning(f"GenAI embed_content attempt {attempt + 1}/3 failed ({err_str[:120]})")
                    if attempt < 2 and ("503" in err_str or "429" in err_str or "UNAVAILABLE" in err_str):
                        time.sleep(1.0 * (attempt + 1))
                        continue
                    break

        # Fallback to deterministic normalized local embedding vectors
        logger.info(f"Using deterministic local embedding fallback for {len(input)} chunks")
        return [generate_local_embedding(doc, 768) for doc in input]

if os.environ.get("VERCEL"):
    DB_DIR = "/tmp/.ag_chroma"
else:
    DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".ag_chroma")

class RAGManager:
    def __init__(self):
        os.makedirs(DB_DIR, exist_ok=True)
        
        self.chroma_client = chromadb.PersistentClient(path=DB_DIR)
        self.embedding_function = GoogleGenAIEmbeddingFunction()
        
        self.collection = self.chroma_client.get_or_create_collection(
            name="knowledge_base",
            embedding_function=self.embedding_function
        )
        
        self.metadata_file = os.path.join(DB_DIR, "documents_metadata.json")
        self.texts_file = os.path.join(DB_DIR, "document_texts.json")
        
        self.documents_metadata = {} # In-memory map of ingested documents
        self.document_texts = {} # In-memory map of full texts for viewing
        self._load_persistence()

    def _load_persistence(self):
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, "r") as f:
                    self.documents_metadata = json.load(f)
            if os.path.exists(self.texts_file):
                with open(self.texts_file, "r", encoding="utf-8") as f:
                    self.document_texts = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load RAG persistence: {e}")

    def _save_persistence(self):
        try:
            with open(self.metadata_file, "w") as f:
                json.dump(self.documents_metadata, f)
            with open(self.texts_file, "w", encoding="utf-8") as f:
                json.dump(self.document_texts, f)
        except Exception as e:
            logger.error(f"Failed to save RAG persistence: {e}")
        
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
            return file_content.decode("utf-8")
        else:
            raise ValueError(f"Unsupported file type: {filename}")

    def ingest_document(self, filename: str, content: bytes = None, raw_text: str = None) -> dict:
        """Parse, chunk, and embed a document into the RAG store."""
        try:
            text = raw_text if raw_text else self.extract_text(content, filename)
            if not text.strip():
                raise ValueError("No extractable text found in file.")
                
            doc_id = str(uuid.uuid4())
            chunks = recursive_text_split(text)
            
            # Add to Chroma
            ids = [str(uuid.uuid4()) for _ in chunks]
            metadatas = [{"source": filename, "doc_id": doc_id} for _ in chunks]
            
            self.collection.add(
                documents=chunks,
                metadatas=metadatas,
                ids=ids
            )
            
            doc_info = {
                "id": doc_id,
                "filename": filename,
                "chunks": len(chunks),
                "status": "Indexed"
            }
            self.documents_metadata[doc_id] = doc_info
            self.document_texts[doc_id] = text
            self._save_persistence()
            
            return doc_info
        except Exception as e:
            logger.error(f"Failed to ingest {filename}: {e}")
            raise e

    def get_documents(self) -> List[Dict[str, Any]]:
        return list(self.documents_metadata.values())

    def get_document_text(self, doc_id: str) -> str:
        return self.document_texts.get(doc_id, "Text not found.")

    def delete_document(self, doc_id: str):
        if doc_id in self.documents_metadata:
            try:
                self.collection.delete(where={"doc_id": doc_id})
            except Exception as e:
                logger.error(f"Failed to delete vectors for {doc_id}: {e}")
            
            del self.documents_metadata[doc_id]
            if doc_id in self.document_texts:
                del self.document_texts[doc_id]
            self._save_persistence()
            return True
        return False

    def query(self, query_text: str, k: int = 3) -> str:
        """Retrieve relevant context for a query."""
        results = self.collection.query(
            query_texts=[query_text],
            n_results=k
        )
        
        if not results or not results['documents'] or not results['documents'][0]:
            return "No relevant information found in the knowledge base."
            
        context_parts = []
        for i, doc in enumerate(results['documents'][0]):
            meta = results['metadatas'][0][i] if results['metadatas'] and results['metadatas'][0] else {}
            source = meta.get('source', 'Unknown')
            context_parts.append(f"Source: {source}\n{doc}")
            
        return "\n\n---\n\n".join(context_parts)

# Singleton instance
rag_manager = RAGManager()
