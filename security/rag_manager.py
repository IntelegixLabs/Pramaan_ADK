import os
import io
import uuid
import json
import logging
from typing import List, Dict, Any

from pypdf import PdfReader
from langchain_chroma import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter

from langchain_openai import OpenAIEmbeddings

logger = logging.getLogger(__name__)

# Try to use OpenAI Embeddings if key exists, otherwise let Chroma use default (or throw if not configured properly)
def get_embeddings():
    if os.getenv("OPENAI_API_KEY"):
        return OpenAIEmbeddings(model="text-embedding-3-small")
    else:
        # Fallback to local sentence transformers if available, otherwise mock
        try:
            from langchain_community.embeddings import HuggingFaceEmbeddings
            return HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        except ImportError:
            # Fake embeddings for completely offline demo without dependencies
            from langchain_core.embeddings import Embeddings
            class FakeEmbeddings(Embeddings):
                def embed_documents(self, texts: List[str]) -> List[List[float]]:
                    return [[0.1] * 1536 for _ in texts]
                def embed_query(self, text: str) -> List[float]:
                    return [0.1] * 1536
            return FakeEmbeddings()

if os.environ.get("VERCEL"):
    DB_DIR = "/tmp/.ag_chroma"
else:
    DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".ag_chroma")

class RAGManager:
    def __init__(self):
        os.makedirs(DB_DIR, exist_ok=True)
        self.vector_store = Chroma(
            collection_name="knowledge_base",
            embedding_function=get_embeddings(),
            persist_directory=DB_DIR
        )
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            length_function=len,
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
            chunks = self.text_splitter.create_documents(
                [text], 
                metadatas=[{"source": filename, "doc_id": doc_id}]
            )
            
            # Add to Chroma
            ids = [str(uuid.uuid4()) for _ in chunks]
            self.vector_store.add_documents(documents=chunks, ids=ids)
            
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
            # Delete from Chroma using metadata filter
            # Note: chroma delete by metadata requires where clause
            # The chromadb client supports where clause directly via the vector store
            try:
                # We can fetch the chunks by doc_id to get their IDs and then delete by IDs
                results = self.vector_store.get(where={"doc_id": doc_id})
                if results and results.get("ids"):
                    self.vector_store.delete(ids=results["ids"])
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
        results = self.vector_store.similarity_search(query_text, k=k)
        if not results:
            return "No relevant information found in the knowledge base."
            
        context = "\n\n---\n\n".join([f"Source: {doc.metadata.get('source', 'Unknown')}\n{doc.page_content}" for doc in results])
        return context

# Singleton instance
rag_manager = RAGManager()
