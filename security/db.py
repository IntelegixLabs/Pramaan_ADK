"""
Pramaan ADK - Database Abstraction Layer (PostgreSQL + SQLite)
==============================================================
Provides resilient database persistence using Cloud SQL / Managed PostgreSQL when
`DATABASE_URL` or `POSTGRES_URL` is set, with graceful fallback to local SQLite for
offline/standalone environments.
"""

import os
import re
import json
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from threading import Lock

logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        self._is_postgres = False
        self._pg_pool = None
        self._sqlite_conn = None
        self._lock = Lock()
        self._initialized = False

    def _get_db_url(self) -> Optional[str]:
        return (
            os.getenv("DATABASE_URL")
            or os.getenv("POSTGRES_URL")
            or os.getenv("POSTGRESQL_URL")
        )

    def initialize(self):
        with self._lock:
            if self._initialized:
                return

            db_url = self._get_db_url()
            if db_url and ("postgres" in db_url.lower() or "postgresql" in db_url.lower()):
                # Normalize postgres:// to postgresql://
                if db_url.startswith("postgres://"):
                    db_url = "postgresql://" + db_url[11:]
                
                try:
                    import psycopg2
                    from psycopg2 import pool
                    from psycopg2.extras import RealDictCursor

                    # Create connection pool
                    self._pg_pool = pool.ThreadedConnectionPool(
                        minconn=1,
                        maxconn=10,
                        dsn=db_url,
                        connect_timeout=10
                    )
                    # Test a connection
                    conn = self._pg_pool.getconn()
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1;")
                    self._pg_pool.putconn(conn)
                    
                    self._is_postgres = True
                    logger.info("Successfully connected to PostgreSQL database.")
                except Exception as e:
                    logger.warning(f"Could not connect to PostgreSQL ({e}). Falling back to local SQLite.")
                    self._is_postgres = False

            if not self._is_postgres:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                sqlite_path = os.path.join(base_dir, "handshakeos.db")
                if os.environ.get("VERCEL"):
                    sqlite_path = "/tmp/handshakeos.db"
                
                os.makedirs(os.path.dirname(os.path.abspath(sqlite_path)), exist_ok=True)
                self._sqlite_conn = sqlite3.connect(sqlite_path, check_same_thread=False)
                self._sqlite_conn.row_factory = sqlite3.Row
                logger.info(f"Using local SQLite database at {sqlite_path}")

            self._create_tables()
            self._initialized = True

    def _create_tables(self):
        """Create all required schema tables in PostgreSQL or SQLite."""
        if self._is_postgres:
            schema_statements = [
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id VARCHAR(128) PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    picture TEXT,
                    provider VARCHAR(64) DEFAULT 'google',
                    gemini_api_key TEXT,
                    gemini_model VARCHAR(128) DEFAULT 'gemini-2.5-flash',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS custom_agents (
                    id VARCHAR(128) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    system_prompt TEXT,
                    policies TEXT,
                    max_budget REAL DEFAULT 0,
                    tools TEXT,
                    a2a_agent_urls TEXT,
                    mcp_server_urls TEXT,
                    user_id VARCHAR(128),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS custom_mcps (
                    id VARCHAR(128) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    server_url TEXT,
                    transport VARCHAR(64) DEFAULT 'stdio',
                    tools TEXT,
                    resources TEXT,
                    prompts TEXT,
                    user_id VARCHAR(128),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS security_scans (
                    scan_id VARCHAR(128) PRIMARY KEY,
                    scan_type VARCHAR(64) NOT NULL,
                    target_name VARCHAR(255) NOT NULL,
                    findings_json TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    report_json TEXT,
                    user_id VARCHAR(128)
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS dashboard_agents (
                    agent_id VARCHAR(128) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    url TEXT NOT NULL,
                    scan_interval_minutes INTEGER NOT NULL,
                    last_scan_time TIMESTAMP WITH TIME ZONE,
                    next_scan_time TIMESTAMP WITH TIME ZONE,
                    last_score REAL,
                    agent_type VARCHAR(64) DEFAULT 'a2a',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id VARCHAR(128) PRIMARY KEY,
                    timestamp VARCHAR(128) NOT NULL,
                    category VARCHAR(64) NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    action VARCHAR(255) NOT NULL,
                    agent_did VARCHAR(255),
                    target_did VARCHAR(255),
                    source_ip VARCHAR(64),
                    details_json TEXT NOT NULL,
                    outcome VARCHAR(64) NOT NULL,
                    handshake_id VARCHAR(128),
                    previous_hash VARCHAR(128) NOT NULL,
                    event_hash VARCHAR(128) NOT NULL
                );
                """
            ]
            conn = self._pg_pool.getconn()
            try:
                with conn.cursor() as cur:
                    for stmt in schema_statements:
                        cur.execute(stmt)
                conn.commit()
            finally:
                self._pg_pool.putconn(conn)
        else:
            schema_statements = [
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    picture TEXT,
                    provider TEXT DEFAULT 'google',
                    gemini_api_key TEXT,
                    gemini_model TEXT DEFAULT 'gemini-2.5-flash',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS custom_agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    system_prompt TEXT,
                    policies TEXT,
                    max_budget REAL DEFAULT 0,
                    tools TEXT,
                    a2a_agent_urls TEXT,
                    mcp_server_urls TEXT,
                    user_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS custom_mcps (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    server_url TEXT,
                    transport TEXT DEFAULT 'stdio',
                    tools TEXT,
                    resources TEXT,
                    prompts TEXT,
                    user_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS security_scans (
                    scan_id TEXT PRIMARY KEY,
                    scan_type TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    report_json TEXT,
                    user_id TEXT
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS dashboard_agents (
                    agent_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    scan_interval_minutes INTEGER NOT NULL,
                    last_scan_time TIMESTAMP,
                    next_scan_time TIMESTAMP,
                    last_score REAL,
                    agent_type TEXT DEFAULT 'a2a',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """,
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action TEXT NOT NULL,
                    agent_did TEXT,
                    target_did TEXT,
                    source_ip TEXT,
                    details_json TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    handshake_id TEXT,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                """
            ]
            for stmt in schema_statements:
                self._sqlite_conn.execute(stmt)
            self._sqlite_conn.commit()

    def _convert_query(self, query: str) -> str:
        """Convert standard '?' parameter placeholders to '%s' for PostgreSQL."""
        if self._is_postgres:
            return query.replace("?", "%s")
        return query

    def execute(self, query: str, params: Optional[Tuple] = None):
        if not self._initialized:
            self.initialize()

        converted_query = self._convert_query(query)
        params = params or ()

        if self._is_postgres:
            conn = self._pg_pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute(converted_query, params)
                conn.commit()
            finally:
                self._pg_pool.putconn(conn)
        else:
            with self._lock:
                self._sqlite_conn.execute(converted_query, params)
                self._sqlite_conn.commit()

    def fetchone(self, query: str, params: Optional[Tuple] = None) -> Optional[Dict[str, Any]]:
        if not self._initialized:
            self.initialize()

        converted_query = self._convert_query(query)
        params = params or ()

        if self._is_postgres:
            from psycopg2.extras import RealDictCursor
            conn = self._pg_pool.getconn()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(converted_query, params)
                    row = cur.fetchone()
                    return dict(row) if row else None
            finally:
                self._pg_pool.putconn(conn)
        else:
            with self._lock:
                cursor = self._sqlite_conn.execute(converted_query, params)
                row = cursor.fetchone()
                return dict(row) if row else None

    def fetchall(self, query: str, params: Optional[Tuple] = None) -> List[Dict[str, Any]]:
        if not self._initialized:
            self.initialize()

        converted_query = self._convert_query(query)
        params = params or ()

        if self._is_postgres:
            from psycopg2.extras import RealDictCursor
            conn = self._pg_pool.getconn()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(converted_query, params)
                    rows = cur.fetchall()
                    return [dict(r) for r in rows]
            finally:
                self._pg_pool.putconn(conn)
        else:
            with self._lock:
                cursor = self._sqlite_conn.execute(converted_query, params)
                rows = cursor.fetchall()
                return [dict(r) for r in rows]

# Global database instance
db = Database()
