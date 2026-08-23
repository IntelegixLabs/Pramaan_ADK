import os
import logging
from typing import Optional
import contextlib

logger = logging.getLogger(__name__)

def get_langfuse_handler() -> Optional[object]:
    """
    Initializes and returns the Langfuse CallbackHandler for Langchain if configured.
    Returns None if the required environment variables are not set or package is missing.
    """
    secret_key = os.getenv("LANGFUSE_SECRET_KEY", "").strip()
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY", "").strip()
    
    if not secret_key or not public_key:
        logger.info("Langfuse Observability: Not enabled (Missing keys)")
        return None
        
    try:
        from langfuse.langchain import CallbackHandler
        # In v4+, CallbackHandler automatically picks up keys from the environment.
        return CallbackHandler()
        
    except ImportError as e:
        logger.warning(
            f"Langfuse ImportError: {e}. Keys are set, but package failed to load. "
            "Run: pip install langfuse"
        )
        return None
    except Exception as e:
        logger.error(f"Failed to initialize Langfuse handler: {e}")
        return None

@contextlib.contextmanager
def langfuse_context(session_id: Optional[str] = None, user_id: Optional[str] = None, tags: Optional[list[str]] = None):
    """
    Context manager to propagate trace attributes (session_id, user_id, tags) 
    in Langfuse v4+. Safely yields even if Langfuse is not installed.
    """
    try:
        from langfuse import propagate_attributes
        with propagate_attributes(session_id=session_id, user_id=user_id, tags=tags):
            yield
    except ImportError:
        yield
