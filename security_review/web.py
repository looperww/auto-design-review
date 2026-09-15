from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .service import (
    GitLabClient,
    LLM_DEFAULT_MODELS,
    LLM_PROVIDER_LABELS,
    LLM_PROVIDERS,
    RUNTIME_SETTINGS,
    Config,
    ReviewError,
    effective_runtime_settings,
    normalize_runtime_setting,
    test_llm_connection,
)


PASSWORD_ITERATIONS = 600_000
SESSION_LIFETIME_SECONDS = 12 * 60 * 60
LOGIN_WINDOW_SECONDS = 15 * 60
MAX_LOGIN_ATTEMPTS = 10
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
VAULT_ASSOCIATED_DATA = b"gitlab-security-review-vault-v1"
APP_JAVASCRIPT = b"""(() => {
  const provider = document.getElementById('llm_provider');
  const customField = document.getElementById('custom_api_url_field');
  const customInput = document.getElementById('llm_api_url');
  if (!provider || !customField || !customInput) return;
  const updateCustomField = () => {
    const visible = provider.value === 'custom';
    customField.hidden = !visible;
    customInput.disabled = !visible;
  };
  provider.addEventListener('change', updateCustomField);
  updateCustomField();
})();
"""


@dataclass(frozen=True)
class Credentials:
    gitlab_url: str
    gitlab_token: str
    llm_api_key: str
    llm_provider: str = "anthropic"
    llm_api_url: str = ""
    llm_model: str = ""


def credential_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS, dklen=32
    )


def credential_payload(credentials: Credentials) -> bytes:
    return json.dumps(
        {
            "gitlab_url": credentials.gitlab_url,
            "gitlab_token": credentials.gitlab_token,
            "llm_api_key": credentials.llm_api_key,
            "llm_provider": credentials.llm_provider,
            "llm_api_url": credentials.llm_api_url,
            "llm_model": credentials.llm_model,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def encrypt_credentials_with_key(
    credentials: Credentials, salt: bytes, key: bytes
) -> tuple[str, str, str]:
    if len(salt) != 16 or len(key) != 32:
        raise ReviewError("The in-memory credential encryption context is invalid.")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(
        nonce, credential_payload(credentials), VAULT_ASSOCIATED_DATA
    )
    return salt.hex(), nonce.hex(), ciphertext.hex()


def encrypt_credentials(credentials: Credentials, password: str) -> tuple[str, str, str]:
    salt = secrets.token_bytes(16)
    return encrypt_credentials_with_key(credentials, salt, credential_key(password, salt))


def decrypt_credentials_with_key(
    nonce_hex: str, ciphertext_hex: str, key: bytes
) -> Credentials:
    try:
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, VAULT_ASSOCIATED_DATA)
        payload = json.loads(plaintext)
        credentials = Credentials(
            gitlab_url=str(payload["gitlab_url"]),
            gitlab_token=str(payload["gitlab_token"]),
            llm_api_key=str(
                payload.get("llm_api_key", payload.get("anthropic_api_key", ""))
            ),
            llm_provider=str(payload.get("llm_provider", "anthropic")),
            llm_api_url=str(payload.get("llm_api_url", "")),
            llm_model=str(payload.get("llm_model", "")),
        )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, InvalidTag) as exc:
        raise ReviewError("The credential vault could not be unlocked.") from exc
    if not credentials.gitlab_url.strip() or not credentials.gitlab_token.strip():
        raise ReviewError("The credential vault does not contain GitLab access.")
    if credentials.llm_provider not in LLM_PROVIDERS:
        raise ReviewError("The credential vault contains an unsupported LLM provider.")
    return credentials


def decrypt_credentials(
    salt_hex: str, nonce_hex: str, ciphertext_hex: str, password: str
) -> Credentials:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise ReviewError("The credential vault could not be unlocked.") from exc
    return decrypt_credentials_with_key(
        nonce_hex, ciphertext_hex, credential_key(password, salt)
    )


class MemoryVault:
    def __init__(self):
        self.condition = threading.Condition()
        self.credentials: Credentials | None = None
        self.kdf_salt: bytes | None = None
        self.encryption_key: bytes | None = None
        self.version = 0

    def prepare(self, password: str, salt: bytes | None = None) -> None:
        selected_salt = salt or secrets.token_bytes(16)
        key = credential_key(password, selected_salt)
        with self.condition:
            self.kdf_salt = selected_salt
            self.encryption_key = key

    def set(
        self,
        credentials: Credentials,
        *,
        salt: bytes | None = None,
        encryption_key: bytes | None = None,
    ) -> None:
        with self.condition:
            if salt is not None:
                self.kdf_salt = salt
            if encryption_key is not None:
                self.encryption_key = encryption_key
            self.credentials = credentials
            self.version += 1
            self.condition.notify_all()

    def snapshot(self) -> tuple[Credentials | None, int]:
        with self.condition:
            return self.credentials, self.version

    def encryption_context(self) -> tuple[bytes, bytes]:
        with self.condition:
            if self.kdf_salt is None or self.encryption_key is None:
                raise ReviewError(
                    "The credential vault is locked. Sign in again to unlock it."
                )
            return self.kdf_salt, self.encryption_key

    def wait_for_credentials(self) -> tuple[Credentials, int]:
        with self.condition:
            while self.credentials is None:
                self.condition.wait(timeout=30)
            return self.credentials, self.version

    def wait_for_change(self, version: int, timeout: int) -> None:
        with self.condition:
            if self.version == version:
                self.condition.wait(timeout=timeout)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_record(password: str) -> tuple[str, str, int]:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return salt.hex(), digest.hex(), PASSWORD_ITERATIONS


def verify_password(password: str, salt_hex: str, digest_hex: str, iterations: int) -> bool:
    if iterations < 100_000 or iterations > 2_000_000:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validated_credentials(
    gitlab_url: str,
    gitlab_token: str,
    llm_api_key: str,
    llm_provider: str = "anthropic",
    llm_api_url: str = "",
    llm_model: str = "",
) -> Credentials:
    url = gitlab_url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ReviewError("GitLab URL must be a valid HTTPS address.")
    gitlab_token = gitlab_token.strip()
    llm_api_key = llm_api_key.strip()
    llm_provider = llm_provider.strip().lower()
    llm_api_url = llm_api_url.strip()
    llm_model = llm_model.strip() or LLM_DEFAULT_MODELS.get(llm_provider, "")
    if not 8 <= len(gitlab_token) <= 4096:
        raise ReviewError("GitLab token is missing or has an invalid length.")
    if llm_provider not in LLM_PROVIDERS:
        raise ReviewError("Select a supported LLM provider.")
    if llm_api_key and not 8 <= len(llm_api_key) <= 4096:
        raise ReviewError("LLM API key has an invalid length.")
    if llm_model and len(llm_model) > 256:
        raise ReviewError("LLM model name is too long.")
    if llm_api_key and not llm_model:
        raise ReviewError("Enter a model name for the selected LLM provider.")
    if llm_provider == "custom" and llm_api_key and not llm_api_url:
        raise ReviewError("Enter a custom LLM API URL when an API key is configured.")
    if llm_provider == "custom" and llm_api_url:
        parsed_llm = urllib.parse.urlparse(llm_api_url)
        if (
            parsed_llm.scheme != "https"
            or not parsed_llm.netloc
            or parsed_llm.username
            or parsed_llm.password
            or parsed_llm.fragment
        ):
            raise ReviewError("Custom LLM API URL must be a valid HTTPS address without a fragment.")
    elif llm_provider != "custom":
        llm_api_url = ""
    if len(llm_api_url) > 2048:
        raise ReviewError("Custom LLM API URL is too long.")
    return Credentials(
        url, gitlab_token, llm_api_key, llm_provider, llm_api_url, llm_model
    )


class WebStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.initialize()

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_salt TEXT NOT NULL,
                    password_digest TEXT NOT NULL,
                    password_iterations INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS web_sessions (
                    token_digest TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    csrf_token TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    remote_address TEXT NOT NULL,
                    attempted_at INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS login_attempts_address_time "
                "ON login_attempts(remote_address, attempted_at)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS credential_vault (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    kdf_salt TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS reviews (
                    project_id INTEGER NOT NULL,
                    mr_iid INTEGER NOT NULL,
                    head_sha TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    report_path TEXT,
                    report_content TEXT,
                    metadata_json TEXT,
                    discovered_at TEXT NOT NULL,
                    mr_created_at TEXT NOT NULL,
                    reviewed_at TEXT NOT NULL,
                    PRIMARY KEY (project_id, mr_iid, head_sha)
                )
                """
            )
            review_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(reviews)")
            }
            if "report_content" not in review_columns:
                connection.execute("ALTER TABLE reviews ADD COLUMN report_content TEXT")
            if "metadata_json" not in review_columns:
                connection.execute("ALTER TABLE reviews ADD COLUMN metadata_json TEXT")
            if "discovered_at" not in review_columns:
                connection.execute("ALTER TABLE reviews ADD COLUMN discovered_at TEXT")
                connection.execute(
                    "UPDATE reviews SET discovered_at = reviewed_at WHERE discovered_at IS NULL"
                )
            if "mr_created_at" not in review_columns:
                connection.execute(
                    "ALTER TABLE reviews ADD COLUMN "
                    "mr_created_at TEXT NOT NULL DEFAULT ''"
                )
                connection.execute(
                    "UPDATE reviews SET mr_created_at = discovered_at "
                    "WHERE mr_created_at = ''"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO metadata (key, value) VALUES ('deployment_started_at', ?)",
                (now_iso(),),
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS visible_projects (
                    project_id INTEGER PRIMARY KEY,
                    project_path TEXT NOT NULL,
                    web_url TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    is_visible INTEGER NOT NULL DEFAULT 1,
                    last_check_status TEXT NOT NULL DEFAULT 'unknown',
                    last_check_error TEXT NOT NULL DEFAULT ''
                )
                """
            )
            visible_project_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(visible_projects)")
            }
            if "last_check_status" not in visible_project_columns:
                connection.execute(
                    "ALTER TABLE visible_projects ADD COLUMN "
                    "last_check_status TEXT NOT NULL DEFAULT 'unknown'"
                )
            if "last_check_error" not in visible_project_columns:
                connection.execute(
                    "ALTER TABLE visible_projects ADD COLUMN "
                    "last_check_error TEXT NOT NULL DEFAULT ''"
                )

    def user_count(self) -> int:
        with self.connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def create_first_user(
        self,
        username: str,
        password: str,
        credentials: Credentials | None = None,
        runtime_settings: dict[str, str] | None = None,
    ) -> int:
        salt, digest, iterations = password_record(password)
        encrypted = encrypt_credentials(credentials, password) if credentials else None
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise ReviewError("The administrator account has already been created.")
            cursor = connection.execute(
                """
                INSERT INTO users
                    (username, password_salt, password_digest, password_iterations, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, salt, digest, iterations, now_iso()),
            )
            if encrypted:
                vault_salt, nonce, ciphertext = encrypted
                connection.execute(
                    """
                    INSERT INTO credential_vault
                        (id, kdf_salt, nonce, ciphertext, updated_at)
                    VALUES (1, ?, ?, ?, ?)
                    """,
                    (vault_salt, nonce, ciphertext, now_iso()),
                )
            for key, value in (runtime_settings or {}).items():
                connection.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, value, now_iso()),
                )
            return int(cursor.lastrowid)

    def authenticate(self, username: str, password: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
        if row is None:
            password_record(password)
            return None
        if not verify_password(
            password,
            str(row["password_salt"]),
            str(row["password_digest"]),
            int(row["password_iterations"]),
        ):
            return None
        return row

    def credentials_configured(self) -> bool:
        with self.connect() as connection:
            return connection.execute(
                "SELECT 1 FROM credential_vault WHERE id = 1"
            ).fetchone() is not None

    def save_encrypted_credentials(
        self, credentials: Credentials, salt: bytes, encryption_key: bytes
    ) -> None:
        salt_hex, nonce, ciphertext = encrypt_credentials_with_key(
            credentials, salt, encryption_key
        )
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO credential_vault
                    (id, kdf_salt, nonce, ciphertext, updated_at)
                VALUES (1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET kdf_salt = excluded.kdf_salt,
                                              nonce = excluded.nonce,
                                              ciphertext = excluded.ciphertext,
                                              updated_at = excluded.updated_at
                """,
                (salt_hex, nonce, ciphertext, now_iso()),
            )

    def save_credentials(self, credentials: Credentials, password: str) -> None:
        salt = secrets.token_bytes(16)
        self.save_encrypted_credentials(
            credentials, salt, credential_key(password, salt)
        )

    def unlock_credentials(self, password: str) -> Credentials:
        credentials, _, _ = self.unlock_credentials_with_key(password)
        return credentials

    def unlock_credentials_with_key(
        self, password: str
    ) -> tuple[Credentials, bytes, bytes]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT kdf_salt, nonce, ciphertext FROM credential_vault WHERE id = 1"
            ).fetchone()
        if row is None:
            raise ReviewError("GitLab credentials have not been configured.")
        try:
            salt = bytes.fromhex(str(row["kdf_salt"]))
        except ValueError as exc:
            raise ReviewError("The credential vault could not be unlocked.") from exc
        key = credential_key(password, salt)
        credentials = decrypt_credentials_with_key(
            str(row["nonce"]), str(row["ciphertext"]), key
        )
        return credentials, salt, key

    def login_blocked(self, remote_address: str) -> bool:
        cutoff = int(time.time()) - LOGIN_WINDOW_SECONDS
        with self.connect() as connection:
            connection.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
            count = connection.execute(
                "SELECT COUNT(*) FROM login_attempts "
                "WHERE remote_address = ? AND attempted_at >= ?",
                (remote_address, cutoff),
            ).fetchone()[0]
        return int(count) >= MAX_LOGIN_ATTEMPTS

    def record_failed_login(self, remote_address: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO login_attempts (remote_address, attempted_at) VALUES (?, ?)",
                (remote_address, int(time.time())),
            )

    def clear_failed_logins(self, remote_address: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM login_attempts WHERE remote_address = ?", (remote_address,)
            )

    def create_session(self, user_id: int) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self.connect() as connection:
            connection.execute("DELETE FROM web_sessions WHERE expires_at < ?", (int(time.time()),))
            connection.execute(
                """
                INSERT INTO web_sessions
                    (token_digest, user_id, csrf_token, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    token_digest(token),
                    user_id,
                    csrf,
                    int(time.time()) + SESSION_LIFETIME_SECONDS,
                    now_iso(),
                ),
            )
        return token, csrf

    def session(self, token: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                """
                SELECT users.id, users.username, web_sessions.csrf_token
                FROM web_sessions
                JOIN users ON users.id = web_sessions.user_id
                WHERE web_sessions.token_digest = ? AND web_sessions.expires_at >= ?
                """,
                (token_digest(token), int(time.time())),
            ).fetchone()

    def delete_session(self, token: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM web_sessions WHERE token_digest = ?", (token_digest(token),)
            )

    def settings(self) -> dict[str, str]:
        with self.connect() as connection:
            rows = connection.execute("SELECT key, value FROM settings").fetchall()
        return {str(row["key"]): str(row["value"]) for row in rows}

    def settings_configured(self) -> bool:
        saved = self.settings()
        return all(setting.key in saved for setting in RUNTIME_SETTINGS)

    def save_settings(self, values: dict[str, str]) -> None:
        with self.connect() as connection:
            for key, value in values.items():
                connection.execute(
                    """
                    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                                   updated_at = excluded.updated_at
                    """,
                    (key, value, now_iso()),
                )

    def dashboard(self) -> tuple[dict[str, int], list[sqlite3.Row]]:
        with self.connect() as connection:
            counts = {
                str(row["status"]): int(row["count"])
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM reviews GROUP BY status"
                ).fetchall()
            }
            recent = connection.execute(
                """
                SELECT project_id, project_path, mr_iid, head_sha, status,
                       report_path, report_content, reviewed_at
                FROM reviews ORDER BY reviewed_at DESC LIMIT 25
                """
            ).fetchall()
        return counts, recent

    def scan_status(self) -> dict[str, str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT key, value FROM metadata "
                "WHERE key LIKE 'last_gitlab_check_%' OR key = 'deployment_started_at'"
            ).fetchall()
        return {str(row["key"]): str(row["value"]) for row in rows}

    def visible_projects(self) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                """
                SELECT project_id, project_path, web_url, first_seen_at, last_seen_at,
                       last_check_status, last_check_error
                FROM visible_projects WHERE is_visible = 1
                ORDER BY project_path COLLATE NOCASE
                """
            ).fetchall()

    def repository_activity(
        self, period: str, selected_date: str = ""
    ) -> tuple[list[sqlite3.Row], datetime, datetime]:
        now = datetime.now(timezone.utc)
        if selected_date:
            try:
                start = datetime.strptime(selected_date, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
            except ValueError as exc:
                raise ReviewError("Choose a valid calendar date.") from exc
            end = start + timedelta(days=1)
        else:
            durations = {
                "day": timedelta(days=1),
                "week": timedelta(days=7),
                "month": timedelta(days=30),
            }
            start = now - durations.get(period, durations["week"])
            end = now
        with self.connect() as connection:
            rows = connection.execute(
                """
                WITH first_discovery AS (
                    SELECT project_id, mr_iid,
                           MIN(COALESCE(NULLIF(mr_created_at, ''), discovered_at)) AS mr_at
                    FROM reviews
                    GROUP BY project_id, mr_iid
                ), activity AS (
                    SELECT project_id, COUNT(*) AS mr_count,
                           MAX(mr_at) AS latest_mr_at
                    FROM first_discovery
                    WHERE mr_at >= ? AND mr_at < ?
                    GROUP BY project_id
                )
                SELECT projects.project_id, projects.project_path, projects.web_url,
                       projects.last_seen_at, projects.last_check_status,
                       projects.last_check_error,
                       COALESCE(activity.mr_count, 0) AS mr_count,
                       activity.latest_mr_at
                FROM visible_projects AS projects
                LEFT JOIN activity ON activity.project_id = projects.project_id
                WHERE projects.is_visible = 1
                ORDER BY projects.project_path COLLATE NOCASE
                """,
                (start.isoformat(), end.isoformat()),
            ).fetchall()
        return rows, start, end

    def repository_mrs(
        self, project_id: int, start: datetime, end: datetime
    ) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                """
                WITH ranked AS (
                    SELECT project_id, project_path, mr_iid, head_sha, status,
                           report_path, report_content, mr_created_at, reviewed_at,
                           ROW_NUMBER() OVER (
                               PARTITION BY project_id, mr_iid
                               ORDER BY reviewed_at DESC
                           ) AS revision_rank
                    FROM reviews
                    WHERE project_id = ?
                      AND COALESCE(NULLIF(mr_created_at, ''), discovered_at) >= ?
                      AND COALESCE(NULLIF(mr_created_at, ''), discovered_at) < ?
                )
                SELECT project_id, project_path, mr_iid, head_sha, status,
                       report_path, report_content, mr_created_at, reviewed_at
                FROM ranked
                WHERE revision_rank = 1
                ORDER BY mr_created_at DESC, mr_iid DESC
                """,
                (project_id, start.isoformat(), end.isoformat()),
            ).fetchall()

    def mr_activity(self, period: str) -> tuple[int, list[sqlite3.Row]]:
        durations = {
            "day": timedelta(days=1),
            "week": timedelta(days=7),
            "month": timedelta(days=30),
        }
        cutoff = (datetime.now(timezone.utc) - durations.get(period, durations["week"])).isoformat()
        with self.connect() as connection:
            count = connection.execute(
                """
                SELECT COUNT(*) FROM (
                    SELECT project_id, mr_iid FROM reviews
                    WHERE discovered_at >= ?
                    GROUP BY project_id, mr_iid
                )
                """,
                (cutoff,),
            ).fetchone()[0]
            recent = connection.execute(
                """
                SELECT project_id, project_path, mr_iid, head_sha, status,
                       report_path, report_content, discovered_at, reviewed_at
                FROM reviews WHERE discovered_at >= ?
                ORDER BY discovered_at DESC LIMIT 100
                """,
                (cutoff,),
            ).fetchall()
        return int(count), recent

    def report(self, project_id: int, mr_iid: int, head_sha: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                """
                SELECT project_path, mr_iid, head_sha, status, report_path, reviewed_at
                       , report_content, metadata_json
                FROM reviews WHERE project_id = ? AND mr_iid = ? AND head_sha = ?
                """,
                (project_id, mr_iid, head_sha),
            ).fetchone()


STYLE = """
:root{color-scheme:light;--ink:#14213d;--muted:#65758b;--line:#dbe3ed;--blue:#246bfd;--bg:#f5f8fc;--card:#fff;--red:#b42318;--green:#16803c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1120px;margin:0 auto;padding:38px 24px 72px}header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}h1{font-size:31px;margin:0}h2{font-size:21px;margin:0 0 18px}.sub{color:var(--muted);margin:7px 0 0}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px;box-shadow:0 8px 28px rgba(20,33,61,.05);margin-bottom:22px}.auth{max-width:480px;margin:8vh auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}.metric{padding:18px;border:1px solid var(--line);border-radius:12px}.metric strong{display:block;font-size:28px;margin-top:4px}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.field label,.date-filter label{display:block;font-weight:700;margin-bottom:7px}.field small{display:block;color:var(--muted);line-height:1.35;margin-top:6px}.field input,.field select,.date-filter input{width:100%;padding:11px 12px;border:1px solid #aebdce;border-radius:9px;background:#fff;font:inherit}.field input:focus,.field select:focus,.date-filter input:focus{outline:3px solid #d9e6ff;border-color:var(--blue)}[hidden]{display:none!important}button,.button{border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:700;padding:11px 16px;cursor:pointer;text-decoration:none;font:inherit}.secondary{background:#eaf0f8;color:var(--ink)}.actions{display:flex;gap:10px;align-items:center;margin-top:22px;flex-wrap:wrap}.filter-bar{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:18px}.date-filter{display:grid;grid-template-columns:minmax(170px,1fr) auto;gap:8px;align-items:end}.date-filter label{grid-column:1/-1}.notice,.error{padding:12px 14px;border-radius:9px;margin-bottom:18px}.notice{background:#eaf7ee;color:#116329}.error{background:#fff0ef;color:var(--red)}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:11px 9px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}.status{font-weight:700}.high_severity,.failed,.down{color:var(--red)}.completed,.up{color:var(--green)}.pending,.unknown{color:var(--blue)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#111827;color:#e5e7eb;padding:20px;border-radius:12px;line-height:1.5}.top-actions{display:flex;gap:10px;align-items:center}.top-actions form{margin:0}@media(max-width:760px){.grid,.form-grid{grid-template-columns:1fr}.filter-bar{align-items:stretch;flex-direction:column}.date-filter{grid-template-columns:1fr}header{align-items:flex-start;gap:20px;flex-direction:column}.table-wrap{overflow:auto}}
"""


def page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)} · Security Review</title><style>{STYLE}</style>"
        f"</head><body><main>{body}</main></body></html>"
    )


def form_field(key: str, value: str) -> str:
    setting = next(item for item in RUNTIME_SETTINGS if item.key == key)
    if setting.kind == "choice":
        options = "".join(
            f"<option value='{html.escape(choice)}'"
            f"{' selected' if choice == value else ''}>{html.escape(choice.title())}</option>"
            for choice in setting.choices
        )
        control = f"<select id='{key}' name='{key}'>{options}</select>"
    else:
        step = "1" if setting.kind == "integer" else "0.01"
        control = (
            f"<input id='{key}' name='{key}' type='number' value='{html.escape(value)}' "
            f"min='{setting.minimum}' max='{setting.maximum}' step='{step}' required>"
        )
    return (
        f"<div class='field'><label for='{key}'>{html.escape(setting.label)}</label>"
        f"{control}<small>{html.escape(setting.help_text)}</small></div>"
    )


def cookie_value(raw_header: str | None, name: str) -> str:
    jar = cookies.SimpleCookie()
    if raw_header:
        try:
            jar.load(raw_header)
        except cookies.CookieError:
            return ""
    morsel = jar.get(name)
    return morsel.value if morsel else ""


def handler_factory(
    store: WebStore,
    report_dir: Path,
    secure_cookies: bool,
    vault: MemoryVault,
):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecurityReviewUI/1"
        sys_version = ""

        def security_headers(self) -> None:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; "
                "base-uri 'none'; frame-ancestors 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")

        def send_page(
            self,
            status: int,
            content: str,
            extra_headers: list[tuple[str, str]] | None = None,
        ) -> None:
            encoded = content.encode("utf-8")
            self.send_response(status)
            self.security_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            for key, value in extra_headers or []:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(encoded)

        def send_javascript(self) -> None:
            self.send_response(200)
            self.security_headers()
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(APP_JAVASCRIPT)))
            self.end_headers()
            self.wfile.write(APP_JAVASCRIPT)

        def redirect(
            self, location: str, extra_headers: list[tuple[str, str]] | None = None
        ) -> None:
            self.send_response(303)
            self.security_headers()
            self.send_header("Location", location)
            for key, value in extra_headers or []:
                self.send_header(key, value)
            self.end_headers()

        def make_cookie(self, name: str, value: str, max_age: int) -> str:
            parts = [
                f"{name}={value}",
                "Path=/",
                f"Max-Age={max_age}",
                "HttpOnly",
                "SameSite=Strict",
            ]
            if secure_cookies:
                parts.append("Secure")
            return "; ".join(parts)

        def form(self) -> dict[str, str]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ReviewError("Invalid request length.") from exc
            if length < 1 or length > 65_536:
                raise ReviewError("Invalid form size.")
            body = self.rfile.read(length).decode("utf-8", errors="strict")
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            return {key: values[-1] for key, values in parsed.items()}

        def session(self) -> tuple[str, sqlite3.Row] | None:
            token = cookie_value(self.headers.get("Cookie"), "reviewer_session")
            if not token:
                return None
            row = store.session(token)
            return (token, row) if row is not None else None

        def require_session(self) -> tuple[str, sqlite3.Row] | None:
            session = self.session()
            if session is None:
                self.redirect("/login")
            return session

        def preauth_token(self) -> tuple[str, list[tuple[str, str]]]:
            token = cookie_value(self.headers.get("Cookie"), "reviewer_csrf")
            if token:
                return token, []
            token = secrets.token_urlsafe(32)
            return token, [("Set-Cookie", self.make_cookie("reviewer_csrf", token, 3600))]

        def valid_csrf(self, submitted: str, expected: str) -> bool:
            return bool(submitted and expected and hmac.compare_digest(submitted, expected))

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/healthz":
                payload = b'{"status":"ok"}\n'
                self.send_response(200)
                self.security_headers()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if parsed.path == "/app.js":
                self.send_javascript()
            elif parsed.path == "/setup":
                self.show_setup()
            elif parsed.path == "/login":
                self.show_login()
            elif parsed.path == "/report":
                self.show_report(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/repository":
                self.show_repository(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/":
                self.show_dashboard(urllib.parse.parse_qs(parsed.query))
            else:
                self.send_page(404, page("Not found", "<div class='card'><h1>Not found</h1></div>"))

        def do_POST(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            try:
                form = self.form()
                if parsed.path == "/setup":
                    self.create_admin(form)
                elif parsed.path == "/login":
                    self.login(form)
                elif parsed.path == "/logout":
                    self.logout(form)
                elif parsed.path == "/unlock":
                    self.unlock(form)
                elif parsed.path == "/credentials":
                    self.update_credentials(form)
                elif parsed.path == "/credentials/test-gitlab":
                    self.test_gitlab_credentials(form)
                elif parsed.path == "/credentials/test-llm":
                    self.test_llm_credentials(form)
                elif parsed.path == "/settings":
                    self.update_settings(form)
                else:
                    self.send_page(404, page("Not found", "<div class='card'><h1>Not found</h1></div>"))
            except (ReviewError, UnicodeDecodeError) as exc:
                self.send_page(
                    400,
                    page(
                        "Invalid request",
                        f"<div class='card auth'><h1>Invalid request</h1>"
                        f"<p class='error'>{html.escape(str(exc))}</p>"
                        "<a class='button secondary' href='/'>Return</a></div>",
                    ),
                )

        def show_setup(self, error: str = "") -> None:
            if store.user_count() > 0:
                self.redirect("/login")
                return
            csrf, headers = self.preauth_token()
            error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
            body = f"""
            <div class='card auth'><h1>Create administrator</h1>
            <p class='sub'>Create the local account first. You will sign in and configure the reviewer afterward.</p>
            {error_html}<form method='post' action='/setup'>
            <input type='hidden' name='csrf' value='{html.escape(csrf)}'>
            <div class='field'><label for='username'>Username</label><input id='username' name='username' autocomplete='username' required></div><br>
            <div class='field'><label for='password'>Password</label><input id='password' name='password' type='password' minlength='12' autocomplete='new-password' required><small>Use at least 12 characters.</small></div><br>
            <div class='field'><label for='confirm'>Confirm password</label><input id='confirm' name='confirm' type='password' minlength='12' autocomplete='new-password' required></div>
            <div class='actions'><button type='submit'>Create administrator</button></div>
            </form></div>"""
            self.send_page(200, page("Initial setup", body), headers)

        def create_admin(self, form: dict[str, str]) -> None:
            expected = cookie_value(self.headers.get("Cookie"), "reviewer_csrf")
            if not self.valid_csrf(form.get("csrf", ""), expected):
                raise ReviewError("The setup form expired. Reload the page and try again.")
            username = form.get("username", "").strip()
            password = form.get("password", "")
            if not USERNAME_PATTERN.fullmatch(username):
                self.show_setup("Username must be 3–64 letters, numbers, dots, dashes, or underscores.")
                return
            if len(password) < 12 or len(password) > 1024:
                self.show_setup("Password must contain between 12 and 1,024 characters.")
                return
            if password != form.get("confirm", ""):
                self.show_setup("The passwords do not match.")
                return
            store.create_first_user(username, password)
            self.redirect("/login")

        def show_login(self, error: str = "") -> None:
            if store.user_count() == 0:
                self.redirect("/setup")
                return
            csrf, headers = self.preauth_token()
            error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
            body = f"""
            <div class='card auth'><h1>Security Review</h1><p class='sub'>Sign in to manage review settings and see results.</p>
            {error_html}<form method='post' action='/login'>
            <input type='hidden' name='csrf' value='{html.escape(csrf)}'>
            <div class='field'><label for='username'>Username</label><input id='username' name='username' autocomplete='username' required></div><br>
            <div class='field'><label for='password'>Password</label><input id='password' name='password' type='password' autocomplete='current-password' required></div>
            <div class='actions'><button type='submit'>Sign in</button></div></form></div>"""
            self.send_page(200, page("Sign in", body), headers)

        def login(self, form: dict[str, str]) -> None:
            remote = self.client_address[0]
            expected = cookie_value(self.headers.get("Cookie"), "reviewer_csrf")
            if not self.valid_csrf(form.get("csrf", ""), expected):
                raise ReviewError("The login form expired. Reload the page and try again.")
            if store.login_blocked(remote):
                self.send_page(429, page("Try later", "<div class='card auth'><h1>Too many attempts</h1><p class='error'>Try again in 15 minutes.</p></div>"))
                return
            username = form.get("username", "")
            password = form.get("password", "")
            user = (
                store.authenticate(username, password)
                if len(username) <= 64 and len(password) <= 1024
                else None
            )
            if user is None:
                store.record_failed_login(remote)
                self.show_login("Invalid username or password.")
                return
            if store.credentials_configured():
                try:
                    credentials, salt, encryption_key = (
                        store.unlock_credentials_with_key(password)
                    )
                except ReviewError as exc:
                    self.show_login(str(exc))
                    return
                vault.set(credentials, salt=salt, encryption_key=encryption_key)
            else:
                vault.prepare(password)
            store.clear_failed_logins(remote)
            token, _ = store.create_session(int(user["id"]))
            headers = [("Set-Cookie", self.make_cookie("reviewer_session", token, SESSION_LIFETIME_SECONDS))]
            self.redirect("/", headers)

        def logout(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            token, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            store.delete_session(token)
            headers = [("Set-Cookie", self.make_cookie("reviewer_session", "", 0))]
            self.redirect("/login", headers)

        def unlock(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            password = form.get("password", "")
            authenticated = store.authenticate(str(user["username"]), password)
            if authenticated is None:
                self.redirect("/?message=" + urllib.parse.quote("The password was not accepted."))
                return
            credentials, salt, encryption_key = store.unlock_credentials_with_key(
                password
            )
            vault.set(credentials, salt=salt, encryption_key=encryption_key)
            message = (
                "Credential vault unlocked; GitLab discovery and LLM reviews can run."
                if credentials.llm_api_key
                else "Credential vault unlocked; GitLab discovery can run. Add an LLM API key to begin reviews."
            )
            self.redirect("/?message=" + urllib.parse.quote(message))

        def update_credentials(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            existing, salt, encryption_key = self.credential_context()
            credentials = self.merged_credentials(form, existing)
            store.save_encrypted_credentials(credentials, salt, encryption_key)
            vault.set(credentials)
            message = (
                "Credentials saved; GitLab discovery and LLM reviews are active."
                if credentials.llm_api_key
                else "GitLab access saved; MR discovery is active. Add an LLM API key later to review queued MRs."
            )
            self.redirect("/?message=" + urllib.parse.quote(message))

        def credential_context(self) -> tuple[Credentials, bytes, bytes]:
            existing, _ = vault.snapshot()
            salt, encryption_key = vault.encryption_context()
            if store.credentials_configured() and existing is None:
                raise ReviewError(
                    "The credential vault is locked. Sign in again before changing credentials."
                )
            return existing or Credentials("", "", ""), salt, encryption_key

        def merged_credentials(
            self, form: dict[str, str], existing: Credentials
        ) -> Credentials:
            submitted_gitlab_url = form.get("gitlab_url", "").strip()
            submitted_gitlab_token = form.get("gitlab_token", "").strip()
            submitted_provider = form.get("llm_provider", "anthropic").strip().lower()
            submitted_llm_key = form.get("llm_api_key", "").strip()
            retained_llm_key = (
                existing.llm_api_key
                if submitted_provider == existing.llm_provider
                else ""
            )
            return validated_credentials(
                submitted_gitlab_url or existing.gitlab_url,
                submitted_gitlab_token or existing.gitlab_token,
                submitted_llm_key or retained_llm_key,
                submitted_provider,
                form.get("llm_api_url", "").strip(),
                form.get("llm_model", "").strip(),
            )

        def test_gitlab_credentials(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            existing, _, _ = self.credential_context()
            credentials = self.merged_credentials(form, existing)
            projects = GitLabClient(
                credentials.gitlab_url, credentials.gitlab_token
            ).list_projects()
            self.redirect(
                "/?message="
                + urllib.parse.quote(
                    f"GitLab access test succeeded: {len(projects)} repositories are visible to this token."
                )
            )

        def test_llm_credentials(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            existing, _, _ = self.credential_context()
            credentials = self.merged_credentials(form, existing)
            config = Config.from_credentials(
                credentials.gitlab_url,
                credentials.gitlab_token,
                credentials.llm_api_key,
                store.settings(),
                llm_provider=credentials.llm_provider,
                llm_api_url=credentials.llm_api_url,
                llm_model=credentials.llm_model,
            )
            test_llm_connection(config)
            provider_label = LLM_PROVIDER_LABELS[credentials.llm_provider]
            self.redirect(
                "/?message="
                + urllib.parse.quote(
                    f"LLM connection test succeeded with {provider_label} using the {config.llm_model} model."
                )
            )

        def show_dashboard(self, query: dict[str, list[str]]) -> None:
            if store.user_count() == 0:
                self.redirect("/setup")
                return
            session = self.require_session()
            if session is None:
                return
            _, user = session
            saved = store.settings()
            try:
                settings = effective_runtime_settings(saved)
            except ReviewError:
                settings = effective_runtime_settings({})
            period = query.get("period", ["week"])[0]
            if period not in {"day", "week", "month"}:
                period = "week"
            selected_date = query.get("date", [""])[0].strip()
            period_labels = {
                "day": "last 24 hours",
                "week": "last 7 days",
                "month": "last 30 days",
            }
            counts, _ = store.dashboard()
            date_error = ""
            try:
                projects, _, _ = store.repository_activity(period, selected_date)
            except ReviewError as exc:
                date_error = str(exc)
                selected_date = ""
                projects, _, _ = store.repository_activity(period)
            fetched_mrs = sum(int(project["mr_count"]) for project in projects)
            filter_label = (
                f"{selected_date} UTC"
                if selected_date
                else period_labels[period]
            )
            scan_status = store.scan_status()
            active_credentials, _ = vault.snapshot()
            heartbeat = Path(os.environ.get("HEARTBEAT_FILE", "/data/heartbeat"))
            try:
                running = heartbeat.is_file() and time.time() - heartbeat.stat().st_mtime < 180
            except OSError:
                running = False
            if running and active_credentials is not None:
                reviewer_label = (
                    "Reviews active"
                    if active_credentials.llm_api_key
                    else "GitLab discovery active"
                )
                reviewer_class = "completed"
            elif running:
                reviewer_label = "Reviewer locked"
                reviewer_class = "failed"
            else:
                reviewer_label = "Waiting for reviewer heartbeat"
                reviewer_class = "failed"
            message = query.get("message", [""])[0]
            notice_text = message or date_error
            notice_class = "error" if date_error and not message else "notice"
            notice = (
                f"<p class='{notice_class}'>{html.escape(notice_text)}</p>"
                if notice_text
                else ""
            )
            check_state = scan_status.get("last_gitlab_check_status", "")
            check_time = scan_status.get("last_gitlab_check_at", "")[:19].replace("T", " ")
            if check_state == "success":
                try:
                    summary = json.loads(scan_status.get("last_gitlab_check_summary", "{}"))
                except json.JSONDecodeError:
                    summary = {}
                scan_panel = (
                    "<p class='notice'><strong>GitLab connection successful.</strong> "
                    f"Last checked {html.escape(check_time + ' UTC' if check_time else 'recently')}; "
                    f"found {int(summary.get('discovered', 0))} open MR revision(s), "
                    f"with {int(summary.get('pending', 0))} awaiting review.</p>"
                )
            elif check_state == "failed":
                scan_panel = (
                    "<p class='error'><strong>GitLab connection failed.</strong> "
                    f"Last checked {html.escape(check_time + ' UTC' if check_time else 'recently')}: "
                    f"{html.escape(scan_status.get('last_gitlab_check_error', 'Unknown error'))}</p>"
                )
            else:
                scan_panel = "<p class='sub'>No GitLab connection check has completed yet.</p>"
            deployment_time = scan_status.get("deployment_started_at", "")[:19].replace("T", " ")
            period_links = "".join(
                f"<a class='button {'primary' if choice == period else 'secondary'}' "
                f"href='/?period={choice}'>{label}</a>"
                for choice, label in (("day", "Day"), ("week", "Week"), ("month", "Month"))
            )
            activity_query = (
                {"date": selected_date} if selected_date else {"period": period}
            )
            project_rows = []
            for project in projects:
                project_path = html.escape(str(project["project_path"]))
                raw_url = str(project["web_url"])
                parsed_url = urllib.parse.urlparse(raw_url)
                if parsed_url.scheme == "https" and parsed_url.netloc:
                    project_name = (
                        f"<a href='{html.escape(raw_url)}' target='_blank' "
                        f"rel='noopener noreferrer'>{project_path}</a>"
                    )
                else:
                    project_name = project_path
                project_status = str(project["last_check_status"])
                if project_status not in {"up", "down"}:
                    project_status = "unknown"
                status_title = (
                    str(project["last_check_error"])
                    if project_status == "down"
                    else (
                        "Latest GitLab repository check succeeded."
                        if project_status == "up"
                        else "Awaiting the first repository check."
                    )
                )
                latest_mr = (
                    str(project["latest_mr_at"])[:19].replace("T", " ") + " UTC"
                    if project["latest_mr_at"]
                    else "—"
                )
                mr_count = int(project["mr_count"])
                detail_query = urllib.parse.urlencode(
                    {"project_id": int(project["project_id"]), **activity_query}
                )
                mr_count_display = (
                    f"<a href='/repository?{detail_query}'>{mr_count}</a>"
                    if mr_count
                    else "0"
                )
                project_rows.append(
                    "<tr>"
                    f"<td>{project_name}</td>"
                    f"<td><span class='status {html.escape(project_status)}' "
                    f"title='{html.escape(status_title)}'>{html.escape(project_status.title())}</span></td>"
                    f"<td>{mr_count_display}</td>"
                    f"<td>{html.escape(latest_mr)}</td>"
                    "</tr>"
                )
            visible_project_rows = "".join(project_rows) or (
                "<tr><td colspan='4'>No repositories discovered yet.</td></tr>"
            )
            fields = "".join(form_field(item.key, settings[item.key]) for item in RUNTIME_SETTINGS)
            credentials_configured = store.credentials_configured()
            if active_credentials is None and credentials_configured:
                vault_panel = f"""
                <section class='card'><h2>Reviewer locked</h2>
                <p class='error'>The encrypted credentials are safe in SQLite, but GitLab discovery must be unlocked after a restart.</p>
                <form method='post' action='/unlock'><input type='hidden' name='csrf' value='{html.escape(str(user['csrf_token']))}'>
                <div class='field'><label for='unlock_password'>Administrator password</label><input id='unlock_password' name='password' type='password' autocomplete='current-password' required></div>
                <div class='actions'><button type='submit'>Unlock service</button></div></form></section>"""
                gitlab_url = "https://gitlab.com"
            elif active_credentials is None:
                vault_panel = "<p class='error'>GitLab access is not configured. Enter it below to start MR discovery.</p>"
                gitlab_url = "https://gitlab.com"
            elif not active_credentials.llm_api_key:
                vault_panel = (
                    "<p class='notice'>GitLab discovery is unlocked. Open MR revisions are queued without downloading code. "
                    "Add an LLM API key to start reviewing the queue.</p>"
                )
                gitlab_url = active_credentials.gitlab_url
            else:
                provider_label = html.escape(LLM_PROVIDER_LABELS[active_credentials.llm_provider])
                vault_panel = f"<p class='notice'>GitLab discovery and {provider_label} security reviews are unlocked.</p>"
                gitlab_url = active_credentials.gitlab_url
            displayed_credentials = active_credentials or Credentials("", "", "")
            provider_options = "".join(
                f"<option value='{provider}' {'selected' if displayed_credentials.llm_provider == provider else ''}>"
                f"{html.escape(LLM_PROVIDER_LABELS[provider])}</option>"
                for provider in LLM_PROVIDERS
            )
            llm_model = displayed_credentials.llm_model or LLM_DEFAULT_MODELS[
                displayed_credentials.llm_provider
            ]
            llm_api_url = displayed_credentials.llm_api_url
            custom_url_hidden = "" if displayed_credentials.llm_provider == "custom" else " hidden"
            body = f"""
            <header><div><h1>Security Review</h1><p class='sub'>Signed in as {html.escape(str(user['username']))}</p></div>
            <div class='top-actions'><span class='status {reviewer_class}'>{reviewer_label}</span>
            <form method='post' action='/logout'><input type='hidden' name='csrf' value='{html.escape(str(user['csrf_token']))}'><button class='secondary'>Sign out</button></form></div></header>
            {notice}{vault_panel}<section class='card'><h2>GitLab connection</h2>{scan_panel}</section>
            <section class='card'><h2>Repositories and fetched MRs</h2>
            <p class='sub'>Shows every currently visible repository and distinct MRs first discovered after this deployment ({html.escape(deployment_time + ' UTC' if deployment_time else 'initializing')}). Current filter: {html.escape(filter_label)}.</p>
            <div class='filter-bar'><div class='actions'>{period_links}</div>
            <form class='date-filter' method='get' action='/'><label for='activity_date'>Specific date (UTC)</label><input id='activity_date' name='date' type='date' value='{html.escape(selected_date)}' max='{datetime.now(timezone.utc).date().isoformat()}'><button class='secondary' type='submit'>Apply date</button></form></div>
            <div class='grid activity-grid'><div class='metric'>Fetched MRs in {html.escape(filter_label)}<strong>{fetched_mrs}</strong></div><div class='metric'>Visible repositories<strong>{len(projects)}</strong></div></div>
            <div class='table-wrap'><table><thead><tr><th>Repository</th><th>Status</th><th>MRs</th><th>Latest MR</th></tr></thead><tbody>{visible_project_rows}</tbody></table></div></section>
            <section class='card'><h2>Review status</h2><div class='grid'>
            <div class='metric'>Queued<strong>{counts.get('pending', 0)}</strong></div>
            <div class='metric'>Completed<strong>{counts.get('completed', 0)}</strong></div>
            <div class='metric'>High severity<strong>{counts.get('high_severity', 0)}</strong></div>
            <div class='metric'>Manual review<strong>{counts.get('manual_review_required', 0)}</strong></div>
            <div class='metric'>Failed<strong>{counts.get('failed', 0)}</strong></div></div></section>
            <section class='card'><h2>Runtime settings</h2><p class='sub'>Saved in SQLite and applied automatically at the next polling cycle.</p>
            <form method='post' action='/settings'><input type='hidden' name='csrf' value='{html.escape(str(user['csrf_token']))}'><div class='form-grid'>{fields}</div><div class='actions'><button type='submit'>Save settings</button></div></form></section>
            <section class='card'><h2>Configure or rotate encrypted credentials</h2><p class='sub'>Save GitLab access first to test discovery. The LLM API key is optional and can be added later. Existing secrets are kept when their fields are left blank and the provider is unchanged.</p>
            <form method='post' action='/credentials'><input type='hidden' name='csrf' value='{html.escape(str(user['csrf_token']))}'><div class='form-grid'>
            <div class='field'><label for='rotate_gitlab_url'>GitLab URL</label><input id='rotate_gitlab_url' name='gitlab_url' type='url' value='{html.escape(gitlab_url)}' required></div>
            <div class='field'><label for='rotate_gitlab_token'>GitLab token</label><input id='rotate_gitlab_token' name='gitlab_token' type='password' autocomplete='off'><small>Required the first time; leave blank later to keep the stored token.</small></div>
            <div class='field'><label for='llm_provider'>LLM provider</label><select id='llm_provider' name='llm_provider'>{provider_options}</select><small>Anthropic is the default. Custom means an OpenAI-compatible Chat Completions endpoint.</small></div>
            <div class='field'><label for='llm_model'>Model</label><input id='llm_model' name='llm_model' value='{html.escape(llm_model)}' maxlength='256'><small>Use a model available to the selected provider account.</small></div>
            <div class='field' id='custom_api_url_field'{custom_url_hidden}><label for='llm_api_url'>Custom API URL</label><input id='llm_api_url' name='llm_api_url' type='url' value='{html.escape(llm_api_url)}' placeholder='https://llm.example.com/v1/chat/completions'><small>Enter the exact HTTPS Chat Completions endpoint.</small></div>
            <div class='field'><label for='llm_api_key'>LLM API key (optional)</label><input id='llm_api_key' name='llm_api_key' type='password' autocomplete='off'><small>Leave blank for discovery only. When changing provider, enter that provider's key.</small></div>
            </div><div class='actions'><button type='submit'>Save encrypted credentials</button>
            <button class='secondary' type='submit' formaction='/credentials/test-gitlab'>Test GitLab access</button>
            <button class='secondary' type='submit' formaction='/credentials/test-llm'>Test LLM connection</button></div>
            <p class='sub'>Tests do not save the entered values. The LLM test sends one minimal request using the selected provider and model and may incur a very small API charge.</p></form></section>
            <script src='/app.js' defer></script>"""
            self.send_page(200, page("Dashboard", body))

        def update_settings(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            normalized = {
                setting.key: normalize_runtime_setting(setting, form.get(setting.key, ""))
                for setting in RUNTIME_SETTINGS
            }
            store.save_settings(normalized)
            active_credentials, _ = vault.snapshot()
            if store.credentials_configured() and active_credentials is None:
                message = "Settings saved. Unlock the reviewer with your administrator password."
            else:
                message = "Settings saved. They will apply on the next polling cycle."
            self.redirect("/?message=" + urllib.parse.quote(message))

        def show_repository(self, query: dict[str, list[str]]) -> None:
            if self.require_session() is None:
                return
            try:
                project_id = int(query.get("project_id", [""])[0])
            except ValueError:
                self.send_page(
                    400,
                    page(
                        "Invalid repository",
                        "<div class='card'><h1>Invalid repository reference</h1>"
                        "<a class='button secondary' href='/'>Return</a></div>",
                    ),
                )
                return
            period = query.get("period", ["week"])[0]
            if period not in {"day", "week", "month"}:
                period = "week"
            selected_date = query.get("date", [""])[0].strip()
            try:
                projects, start, end = store.repository_activity(period, selected_date)
            except ReviewError as exc:
                self.send_page(
                    400,
                    page(
                        "Invalid date",
                        f"<div class='card'><h1>Invalid date</h1><p class='error'>{html.escape(str(exc))}</p>"
                        "<a class='button secondary' href='/'>Return</a></div>",
                    ),
                )
                return
            project = next(
                (row for row in projects if int(row["project_id"]) == project_id),
                None,
            )
            if project is None:
                self.send_page(
                    404,
                    page(
                        "Repository not found",
                        "<div class='card'><h1>Repository not found</h1>"
                        "<a class='button secondary' href='/'>Return</a></div>",
                    ),
                )
                return
            rows = []
            for row in store.repository_mrs(project_id, start, end):
                params = urllib.parse.urlencode(
                    {
                        "project_id": row["project_id"],
                        "mr_iid": row["mr_iid"],
                        "sha": row["head_sha"],
                    }
                )
                report_link = (
                    f"<a href='/report?{params}'>View report</a>"
                    if row["report_content"] or row["report_path"]
                    else "—"
                )
                rows.append(
                    "<tr>"
                    f"<td>!{int(row['mr_iid'])}</td>"
                    f"<td><code>{html.escape(str(row['head_sha'])[:12])}</code></td>"
                    f"<td class='status {html.escape(str(row['status']))}'>{html.escape(str(row['status']))}</td>"
                    f"<td>{html.escape(str(row['mr_created_at'])[:19].replace('T', ' '))} UTC</td>"
                    f"<td>{report_link}</td></tr>"
                )
            table_rows = "".join(rows) or (
                "<tr><td colspan='5'>No MRs in this period.</td></tr>"
            )
            filter_label = (
                f"{selected_date} UTC"
                if selected_date
                else {"day": "last 24 hours", "week": "last 7 days", "month": "last 30 days"}[period]
            )
            back_query = urllib.parse.urlencode(
                {"date": selected_date} if selected_date else {"period": period}
            )
            body = f"""
            <header><div><h1>{html.escape(str(project['project_path']))}</h1>
            <p class='sub'>Latest revision of each MR in {html.escape(filter_label)}</p></div>
            <a class='button secondary' href='/?{back_query}'>Back to repositories</a></header>
            <section class='card'><div class='table-wrap'><table><thead><tr>
            <th>MR</th><th>Latest commit</th><th>Review status</th><th>MR created</th><th>Report</th>
            </tr></thead><tbody>{table_rows}</tbody></table></div></section>"""
            self.send_page(200, page("Repository MRs", body))

        def show_report(self, query: dict[str, list[str]]) -> None:
            if self.require_session() is None:
                return
            try:
                project_id = int(query.get("project_id", [""])[0])
                mr_iid = int(query.get("mr_iid", [""])[0])
                head_sha = query.get("sha", [""])[0]
            except ValueError:
                self.send_page(400, page("Invalid report", "<div class='card'><h1>Invalid report reference</h1></div>"))
                return
            row = store.report(project_id, mr_iid, head_sha)
            if row is None or not (row["report_content"] or row["report_path"]):
                self.send_page(404, page("Report not found", "<div class='card'><h1>Report not found</h1></div>"))
                return
            if row["report_content"]:
                content = str(row["report_content"])[:1_000_000]
            else:
                path = Path(str(row["report_path"])).resolve()
                root = report_dir.resolve()
                try:
                    path.relative_to(root)
                except ValueError:
                    self.send_page(403, page("Report unavailable", "<div class='card'><h1>Report path rejected</h1></div>"))
                    return
                try:
                    content = path.read_text(encoding="utf-8")[:1_000_000]
                except OSError:
                    self.send_page(404, page("Report not found", "<div class='card'><h1>Report file not found</h1></div>"))
                    return
            body = (
                "<header><div><h1>Security report</h1>"
                f"<p class='sub'>{html.escape(str(row['project_path']))} !{int(row['mr_iid'])} · "
                f"{html.escape(str(row['head_sha'])[:12])}</p></div><a class='button secondary' href='/'>Back</a></header>"
                f"<section class='card'><pre>{html.escape(content)}</pre></section>"
            )
            self.send_page(200, page("Security report", body))

    return Handler


def run_web(managed: bool = False) -> int:
    state_db = Path(os.environ.get("STATE_DB", "/data/state/reviews.sqlite3"))
    report_dir = Path(os.environ.get("REPORT_DIR", "/data/reports"))
    host = os.environ.get("WEB_HOST", "0.0.0.0")
    port = int(os.environ.get("WEB_PORT", "8080"))
    secure_cookies = os.environ.get("WEB_SECURE_COOKIES", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    store = WebStore(state_db)
    vault = MemoryVault()
    if managed:
        from .service import run_managed_poll

        threading.Thread(
            target=run_managed_poll,
            args=(state_db, vault),
            daemon=True,
        ).start()
    server = ThreadingHTTPServer(
        (host, port), handler_factory(store, report_dir, secure_cookies, vault)
    )
    print(f"Security Review web console listening on {host}:{port}", flush=True)
    if store.user_count() == 0:
        print("Open /setup to create the first administrator account.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
