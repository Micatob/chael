"""
SQLite-backed agent persistence for reliable agent registration, heartbeat tracking,
and credential storage. Falls back to OpenSearch when configured.
"""
import json
import sqlite3
import os
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

log = logging.getLogger("identity-service.agent-store")

DB_PATH = os.environ.get("AGENT_DB_PATH", "/data/agents.db")


class AgentStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    machine_id TEXT UNIQUE,
                    hostname TEXT NOT NULL,
                    platform TEXT DEFAULT '',
                    platform_version TEXT DEFAULT '',
                    os_info TEXT DEFAULT '',
                    public_key_pem TEXT DEFAULT '',
                    client_cert_pem TEXT DEFAULT '',
                    ca_cert_pem TEXT DEFAULT '',
                    api_key_hash TEXT DEFAULT '',
                    agent_key_raw TEXT DEFAULT '',
                    agent_version TEXT DEFAULT '',
                    status TEXT DEFAULT 'pending',
                    last_seen TEXT,
                    registered_at TEXT NOT NULL,
                    revoked_at TEXT,
                    revoked_reason TEXT DEFAULT '',
                    metadata TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS agent_heartbeats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    status TEXT DEFAULT 'online',
                    version TEXT DEFAULT '',
                    metadata TEXT DEFAULT '{}',
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
                );

                CREATE INDEX IF NOT EXISTS idx_heartbeats_agent ON agent_heartbeats(agent_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
                CREATE INDEX IF NOT EXISTS idx_agents_machine ON agents(machine_id);
            """)
            conn.commit()
            # Migration: add agent_key_raw column if missing
            cols = [row[1] for row in conn.execute("PRAGMA table_info(agents)").fetchall()]
            if "agent_key_raw" not in cols:
                conn.execute("ALTER TABLE agents ADD COLUMN agent_key_raw TEXT DEFAULT ''")
                conn.commit()
                log.info("Migration: added agent_key_raw column to agents table")
        except Exception as e:
            log.error("DB init error: %s", e)
        finally:
            conn.close()

    def register_agent(self, agent_id: str, machine_id: str, hostname: str,
                       platform: str = "", platform_version: str = "",
                       os_info: str = "", public_key_pem: str = "",
                       client_cert_pem: str = "", ca_cert_pem: str = "",
                       api_key_hash: str = "", agent_key_raw: str = "",
                       agent_version: str = "", metadata: dict = None) -> bool:
        conn = self._get_conn()
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT OR REPLACE INTO agents
                (agent_id, machine_id, hostname, platform, platform_version, os_info,
                 public_key_pem, client_cert_pem, ca_cert_pem, api_key_hash, agent_key_raw,
                 agent_version, status, registered_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)
            """, (
                agent_id, machine_id, hostname, platform, platform_version, os_info,
                public_key_pem, client_cert_pem, ca_cert_pem, api_key_hash, agent_key_raw,
                agent_version, now, json.dumps(metadata or {}),
            ))
            conn.commit()
            log.info("Registered agent %s (machine: %s, hostname: %s)", agent_id, machine_id, hostname)
            return True
        except Exception as e:
            log.error("Failed to register agent %s: %s", agent_id, e)
            return False
        finally:
            conn.close()

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            log.error("Failed to get agent %s: %s", agent_id, e)
            return None
        finally:
            conn.close()

    def get_agent_by_machine_id(self, machine_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM agents WHERE machine_id = ?", (machine_id,)).fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            log.error("Failed to get agent by machine_id %s: %s", machine_id, e)
            return None
        finally:
            conn.close()

    def get_agent_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM agents WHERE hostname = ? AND status != 'revoked' ORDER BY registered_at DESC LIMIT 1",
                (hostname,)
            ).fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            log.error("Failed to get agent by hostname %s: %s", hostname, e)
            return None
        finally:
            conn.close()

    def update_agent_key(self, agent_id: str, api_key_hash: str, agent_key_raw: str = "") -> bool:
        conn = self._get_conn()
        try:
            conn.execute("UPDATE agents SET api_key_hash = ?, status = 'online', agent_key_raw = COALESCE(?, agent_key_raw) WHERE agent_id = ?",
                         (api_key_hash, agent_key_raw, agent_id))
            conn.commit()
            return True
        except Exception as e:
            log.error("Failed to update agent key for %s: %s", agent_id, e)
            return False
        finally:
            conn.close()

    def mark_online(self, agent_id: str) -> bool:
        conn = self._get_conn()
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("UPDATE agents SET status = 'online', last_seen = ? WHERE agent_id = ?", (now, agent_id))
            conn.commit()
            return True
        except Exception as e:
            log.error("Failed to mark agent %s as online: %s", agent_id, e)
            return False
        finally:
            conn.close()

    def list_agents(self, include_revoked: bool = False) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            if include_revoked:
                rows = conn.execute("SELECT * FROM agents ORDER BY registered_at DESC").fetchall()
            else:
                rows = conn.execute("SELECT * FROM agents WHERE status != 'revoked' ORDER BY registered_at DESC").fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            log.error("Failed to list agents: %s", e)
            return []
        finally:
            conn.close()

    def update_heartbeat(self, agent_id: str, status: str = "online",
                         version: str = "", metadata: dict = None):
        conn = self._get_conn()
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                UPDATE agents SET last_seen = ?, agent_version = ?, status = ?
                WHERE agent_id = ?
            """, (now, version, status, agent_id))
            conn.execute("""
                INSERT INTO agent_heartbeats (agent_id, status, version, metadata, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (agent_id, status, version, json.dumps(metadata or {}), now))
            conn.commit()
        except Exception as e:
            log.error("Failed to update heartbeat for %s: %s", agent_id, e)
        finally:
            conn.close()

    def revoke_agent(self, agent_id: str, reason: str = "") -> bool:
        conn = self._get_conn()
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                UPDATE agents SET status = 'revoked', revoked_at = ?, revoked_reason = ?
                WHERE agent_id = ?
            """, (now, reason, agent_id))
            conn.commit()
            log.info("Revoked agent %s: %s", agent_id, reason)
            return True
        except Exception as e:
            log.error("Failed to revoke agent %s: %s", agent_id, e)
            return False
        finally:
            conn.close()

    def delete_agent(self, agent_id: str) -> bool:
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM agent_heartbeats WHERE agent_id = ?", (agent_id,))
            conn.commit()
            return True
        except Exception as e:
            log.error("Failed to delete agent %s: %s", agent_id, e)
            return False
        finally:
            conn.close()

    def get_agent_status_summary(self) -> Dict[str, Any]:
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
            online = conn.execute("SELECT COUNT(*) FROM agents WHERE status = 'online'").fetchone()[0]
            offline = conn.execute("SELECT COUNT(*) FROM agents WHERE status = 'offline'").fetchone()[0]
            revoked = conn.execute("SELECT COUNT(*) FROM agents WHERE status = 'revoked'").fetchone()[0]
            pending = conn.execute("SELECT COUNT(*) FROM agents WHERE status = 'pending'").fetchone()[0]
            return {
                "total": total,
                "online": online,
                "offline": offline,
                "revoked": revoked,
                "pending": pending,
            }
        except Exception as e:
            log.error("Failed to get agent status summary: %s", e)
            return {"total": 0, "online": 0, "offline": 0, "revoked": 0, "pending": 0}
        finally:
            conn.close()

    def rotate_api_key(self, agent_id: str, new_api_key_hash: str) -> bool:
        conn = self._get_conn()
        try:
            conn.execute("UPDATE agents SET api_key_hash = ? WHERE agent_id = ?",
                         (new_api_key_hash, agent_id))
            conn.commit()
            return True
        except Exception as e:
            log.error("Failed to rotate key for %s: %s", agent_id, e)
            return False
        finally:
            conn.close()

    def get_recent_heartbeats(self, agent_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM agent_heartbeats WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            log.error("Failed to get heartbeats for %s: %s", agent_id, e)
            return []
        finally:
            conn.close()

    def mark_stale_agents_offline(self, stale_seconds: int = 120) -> int:
        conn = self._get_conn()
        try:
            from datetime import timedelta
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_seconds)).isoformat()
            cursor = conn.execute(
                "UPDATE agents SET status = 'offline' WHERE status = 'online' AND last_seen < ?",
                (cutoff,)
            )
            conn.commit()
            count = cursor.rowcount
            if count > 0:
                log.info("Marked %d stale agents as offline", count)
            return count
        except Exception as e:
            log.error("Failed to mark stale agents: %s", e)
            return 0
        finally:
            conn.close()
