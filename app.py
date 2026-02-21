import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
import traceback

import jwt
from flask import Flask, Response, jsonify, render_template, request, send_from_directory, g, has_app_context
from psycopg import connect as pg_connect
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from psycopg_pool import ConnectionPool
except Exception:
    ConnectionPool = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
DB_PATH = os.path.join(DATA_DIR, "nebula.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
JWT_SECRET = os.environ.get("NEBULA_JWT_SECRET", "nebula-local-jwt-secret")
MSG_SECRET = os.environ.get("NEBULA_MSG_SECRET", "nebula-local-message-secret").encode("utf-8")
JWT_ALG = "HS256"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)

_event_counter = 0
_pg_pool = None


def _normalize_db_url(url: str) -> str:
    if not url:
        return url
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if "sslmode=" in url:
        return url
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}sslmode=require"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _adapt_sql(sql: str) -> str:
    if DATABASE_URL:
        return sql.replace("?", "%s")
    return sql


class CursorProxy:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, params=None):
        self._cursor.execute(_adapt_sql(sql), params or ())
        return self

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def lastrowid(self):
        return getattr(self._cursor, "lastrowid", None)

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class ConnectionProxy:
    def __init__(self, con, close_hook=None):
        self._con = con
        self._close_hook = close_hook
        self._closed = False

    def cursor(self):
        if DATABASE_URL:
            return CursorProxy(self._con.cursor(row_factory=dict_row))
        return CursorProxy(self._con.cursor())

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._con.commit()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._close_hook:
            self._close_hook(self._con)
        else:
            self._con.close()

    @property
    def closed(self):
        return self._closed

    def __getattr__(self, name):
        return getattr(self._con, name)


def get_db():
    if not has_app_context():
        if DATABASE_URL:
            return ConnectionProxy(pg_connect(_normalize_db_url(DATABASE_URL)))
        con = sqlite3.connect(DB_PATH, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA temp_store=MEMORY")
        con.execute("PRAGMA cache_size=-20000")
        return ConnectionProxy(con)
    if DATABASE_URL:
        db = getattr(g, "db", None)
        if db and not db.closed:
            return db
        global _pg_pool
        if _pg_pool is None and ConnectionPool:
            _pg_pool = ConnectionPool(
                conninfo=_normalize_db_url(DATABASE_URL),
                min_size=1,
                max_size=10,
                max_idle=300,
                timeout=5,
            )
        if _pg_pool:
            ctx = _pg_pool.connection()
            conn = ctx.__enter__()

            def _close(_):
                ctx.__exit__(None, None, None)

            g.db = ConnectionProxy(conn, close_hook=_close)
        else:
            g.db = ConnectionProxy(pg_connect(_normalize_db_url(DATABASE_URL)))
        return g.db
    db = getattr(g, "db", None)
    if db and not db.closed:
        return db
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA temp_store=MEMORY")
    con.execute("PRAGMA cache_size=-20000")
    g.db = ConnectionProxy(con)
    return g.db


@app.teardown_request
def close_db(_exc):
    db = getattr(g, "db", None)
    if db:
        db.close()
        g.db = None


@app.errorhandler(Exception)
def handle_exception(exc):
    traceback.print_exc()
    detail = ""
    if os.environ.get("NEBULA_DEBUG", "0") == "1" or os.environ.get("FLASK_DEBUG", "0") == "1":
        detail = f"{type(exc).__name__}: {exc}"
    return jsonify({"error": "server_error", "detail": detail}), 500


def encrypt_text(text: str) -> str:
    if not text:
        return "enc:v1:"
    key = hashlib.sha256(MSG_SECRET).digest()
    data = text.encode("utf-8")
    out = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
    return "enc:v1:" + base64.urlsafe_b64encode(out).decode("utf-8")


def decrypt_text(cipher: str) -> str:
    if not cipher:
        return ""
    if not cipher.startswith("enc:v1:"):
        return cipher
    key = hashlib.sha256(MSG_SECRET).digest()
    raw = base64.urlsafe_b64decode(cipher.replace("enc:v1:", "", 1).encode("utf-8"))
    out = bytes([b ^ key[i % len(key)] for i, b in enumerate(raw)])
    return out.decode("utf-8", errors="ignore")


def bump_event():
    global _event_counter
    _event_counter += 1


def init_db():
    con = get_db()
    cur = con.cursor()
    is_pg = bool(DATABASE_URL)
    if DATABASE_URL:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                login TEXT UNIQUE,
                username TEXT UNIQUE,
                nickname TEXT,
                password_hash TEXT,
                avatar_url TEXT,
                language TEXT DEFAULT 'ru',
                is_verified INTEGER DEFAULT 0,
                verified_at TEXT,
                is_admin INTEGER DEFAULT 0,
                is_banned INTEGER DEFAULT 0,
                banned_at TEXT,
                created_at TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id BIGSERIAL PRIMARY KEY,
                sender_id BIGINT,
                receiver_id BIGINT,
                content TEXT,
                is_e2e INTEGER DEFAULT 1,
                iv TEXT,
                created_at TEXT,
                edited_at TEXT,
                deleted_at TEXT,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS message_reactions (
                id BIGSERIAL PRIMARY KEY,
                message_id BIGINT,
                user_id BIGINT,
                reaction TEXT,
                created_at TEXT,
                UNIQUE(message_id, user_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS channels (
                id BIGSERIAL PRIMARY KEY,
                title TEXT,
                username TEXT UNIQUE,
                description TEXT,
                avatar_url TEXT,
                owner_id BIGINT,
                is_public INTEGER DEFAULT 1,
                is_verified INTEGER DEFAULT 0,
                verified_at TEXT,
                created_at TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS channel_members (
                id BIGSERIAL PRIMARY KEY,
                channel_id BIGINT,
                user_id BIGINT,
                role TEXT DEFAULT 'subscriber',
                created_at TEXT,
                UNIQUE(channel_id, user_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS channel_posts (
                id BIGSERIAL PRIMARY KEY,
                channel_id BIGINT,
                author_id BIGINT,
                content TEXT,
                created_at TEXT,
                FOREIGN KEY(channel_id) REFERENCES channels(id),
                FOREIGN KEY(author_id) REFERENCES users(id)
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_sr_id ON messages (sender_id, receiver_id, id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_rs_id ON messages (receiver_id, sender_id, id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_message_reactions_msg ON message_reactions (message_id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_channel_members_user ON channel_members (user_id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_channel_members_channel ON channel_members (channel_id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_channel_posts_channel ON channel_posts (channel_id, id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_channels_owner ON channels (owner_id)"
        )
    else:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE,
                username TEXT UNIQUE,
                nickname TEXT,
                password_hash TEXT,
                avatar_url TEXT,
                language TEXT DEFAULT 'ru',
                is_verified INTEGER DEFAULT 0,
                verified_at TEXT,
                is_admin INTEGER DEFAULT 0,
                is_banned INTEGER DEFAULT 0,
                banned_at TEXT,
                created_at TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                content TEXT,
                is_e2e INTEGER DEFAULT 1,
                iv TEXT,
                created_at TEXT,
                edited_at TEXT,
                deleted_at TEXT,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS message_reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                user_id INTEGER,
                reaction TEXT,
                created_at TEXT,
                UNIQUE(message_id, user_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                username TEXT UNIQUE,
                description TEXT,
                avatar_url TEXT,
                owner_id INTEGER,
                is_public INTEGER DEFAULT 1,
                is_verified INTEGER DEFAULT 0,
                verified_at TEXT,
                created_at TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS channel_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER,
                user_id INTEGER,
                role TEXT DEFAULT 'subscriber',
                created_at TEXT,
                UNIQUE(channel_id, user_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS channel_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER,
                author_id INTEGER,
                content TEXT,
                created_at TEXT,
                FOREIGN KEY(channel_id) REFERENCES channels(id),
                FOREIGN KEY(author_id) REFERENCES users(id)
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_sr_id ON messages (sender_id, receiver_id, id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_rs_id ON messages (receiver_id, sender_id, id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_message_reactions_msg ON message_reactions (message_id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_channel_members_user ON channel_members (user_id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_channel_members_channel ON channel_members (channel_id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_channel_posts_channel ON channel_posts (channel_id, id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_channels_owner ON channels (owner_id)"
        )

    def ensure_column(table: str, col: str, coldef: str):
        if is_pg:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {coldef}")
        else:
            try:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coldef}")
            except sqlite3.OperationalError:
                pass

    ensure_column("users", "login", "TEXT")
    ensure_column("users", "username", "TEXT")
    ensure_column("users", "nickname", "TEXT")
    ensure_column("users", "password_hash", "TEXT")
    ensure_column("users", "avatar_url", "TEXT")
    ensure_column("users", "language", "TEXT DEFAULT 'ru'")
    ensure_column("users", "is_verified", "INTEGER DEFAULT 0")
    ensure_column("users", "verified_at", "TEXT")
    ensure_column("users", "is_admin", "INTEGER DEFAULT 0")
    ensure_column("users", "is_banned", "INTEGER DEFAULT 0")
    ensure_column("users", "banned_at", "TEXT")
    ensure_column("users", "created_at", "TEXT")

    ensure_column("messages", "sender_id", "INTEGER")
    ensure_column("messages", "receiver_id", "INTEGER")
    ensure_column("messages", "content", "TEXT")
    ensure_column("messages", "is_e2e", "INTEGER DEFAULT 1")
    ensure_column("messages", "iv", "TEXT")
    ensure_column("messages", "created_at", "TEXT")
    ensure_column("messages", "edited_at", "TEXT")
    ensure_column("messages", "deleted_at", "TEXT")

    ensure_column("message_reactions", "message_id", "INTEGER")
    ensure_column("message_reactions", "user_id", "INTEGER")
    ensure_column("message_reactions", "reaction", "TEXT")
    ensure_column("message_reactions", "created_at", "TEXT")

    ensure_column("channels", "title", "TEXT")
    ensure_column("channels", "username", "TEXT")
    ensure_column("channels", "description", "TEXT")
    ensure_column("channels", "avatar_url", "TEXT")
    ensure_column("channels", "owner_id", "INTEGER")
    ensure_column("channels", "is_public", "INTEGER DEFAULT 1")
    ensure_column("channels", "is_verified", "INTEGER DEFAULT 0")
    ensure_column("channels", "verified_at", "TEXT")
    ensure_column("channels", "created_at", "TEXT")

    ensure_column("channel_members", "channel_id", "INTEGER")
    ensure_column("channel_members", "user_id", "INTEGER")
    ensure_column("channel_members", "role", "TEXT DEFAULT 'subscriber'")
    ensure_column("channel_members", "created_at", "TEXT")

    ensure_column("channel_posts", "channel_id", "INTEGER")
    ensure_column("channel_posts", "author_id", "INTEGER")
    ensure_column("channel_posts", "content", "TEXT")
    ensure_column("channel_posts", "created_at", "TEXT")
    con.commit()

    user_count = cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    admin_count = cur.execute("SELECT COUNT(*) AS c FROM users WHERE is_admin=1").fetchone()["c"]
    if user_count > 0 and admin_count == 0:
        row = cur.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
        cur.execute(
            "UPDATE users SET is_admin=1, is_verified=1, verified_at=? WHERE id=?",
            (now_iso(), row["id"]),
        )
        con.commit()
    con.close()


def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def parse_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        return None


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = ""
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
        elif request.args.get("token"):
            token = request.args.get("token")
        if not token:
            return jsonify({"error": "unauthorized"}), 401
        data = parse_token(token)
        if not data:
            return jsonify({"error": "bad_token"}), 401
        try:
            uid = int(data["sub"])
        except Exception:
            return jsonify({"error": "bad_token"}), 401
        con = get_db()
        user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not user:
            return jsonify({"error": "user_not_found"}), 401
        if user["is_banned"]:
            return jsonify({"error": "banned"}), 403
        request.user = user
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not request.user["is_admin"]:
            return jsonify({"error": "admin_only"}), 403
        return fn(*args, **kwargs)

    return wrapper


def user_payload(row):
    return {
        "id": row["id"],
        "login": row["login"],
        "username": row["username"],
        "nickname": row["nickname"],
        "avatar_url": row["avatar_url"],
        "language": row["language"] or "ru",
        "is_verified": bool(row["is_verified"]),
        "is_admin": bool(row["is_admin"]),
        "is_banned": bool(row["is_banned"]),
    }


def extract_data_url(name: str, value: str):
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not value.startswith("data:image/"):
        raise ValueError("bad_avatar")
    header, encoded = value.split(",", 1)
    ext = "png"
    if "image/jpeg" in header:
        ext = "jpg"
    elif "image/webp" in header:
        ext = "webp"
    fname = f"{name}_{int(time.time() * 1000)}.{ext}"
    fpath = os.path.join(UPLOAD_DIR, fname)
    with open(fpath, "wb") as f:
        f.write(base64.b64decode(encoded))
    return f"/static/uploads/{fname}"


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower().lstrip("@")
    nickname = (data.get("nickname") or username or "").strip()
    password = data.get("password") or ""
    language = (data.get("language") or "ru").strip().lower()

    if not username or len(username) < 3 or not re.fullmatch(r"[a-z0-9_]{3,32}", username):
        return jsonify({"error": "bad_username"}), 400
    if not nickname:
        return jsonify({"error": "bad_nickname"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "bad_password"}), 400

    con = get_db()
    cur = con.cursor()
    exists = cur.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if exists:
        if check_password_hash(exists["password_hash"], password) and not exists["is_banned"]:
            con.close()
            return jsonify({"token": create_token(exists["id"]), "user": user_payload(exists)})
        con.close()
        return jsonify({"error": "already_exists"}), 409

    is_first = cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0
    cur.execute(
        """
        INSERT INTO users(login, username, nickname, password_hash, language, is_admin, is_verified, verified_at, created_at)
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            username,
            username,
            nickname,
            generate_password_hash(password),
            language if language in {"ru", "en"} else "ru",
            1 if is_first else 0,
            1 if is_first else 0,
            now_iso() if is_first else None,
            now_iso(),
        ),
    )
    if DATABASE_URL:
        uid = cur.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
    else:
        uid = cur.lastrowid
    con.commit()
    user = cur.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    con.close()
    bump_event()
    return jsonify({"token": create_token(uid), "user": user_payload(user)})


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    identity = (data.get("identity") or data.get("username") or "").strip().lower().lstrip("@")
    password = data.get("password") or ""
    if not identity or not password:
        return jsonify({"error": "bad_credentials"}), 400
    con = get_db()
    user = con.execute("SELECT * FROM users WHERE username=? OR login=?", (identity, identity)).fetchone()
    con.close()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "bad_credentials"}), 401
    if user["is_banned"]:
        return jsonify({"error": "banned"}), 403
    return jsonify({"token": create_token(user["id"]), "user": user_payload(user)})


@app.get("/api/me")
@auth_required
def me():
    return jsonify({"user": user_payload(request.user)})


@app.get("/api/health")
def health():
    try:
        con = get_db()
        row = con.execute("SELECT 1 AS ok").fetchone()
        con.close()
        return jsonify({"ok": bool(row and row["ok"] == 1)})
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 500


@app.put("/api/profile")
@auth_required
def update_profile():
    data = request.get_json(silent=True) or {}
    nickname = (data.get("nickname") or request.user["nickname"] or "").strip()
    language = (data.get("language") or request.user["language"] or "ru").strip().lower()
    avatar = request.user["avatar_url"]
    if "avatar_url" in data:
        try:
            avatar = extract_data_url(f"user_{request.user['id']}", data.get("avatar_url"))
        except ValueError:
            return jsonify({"error": "bad_avatar"}), 400

    con = get_db()
    con.execute(
        "UPDATE users SET nickname=?, language=?, avatar_url=? WHERE id=?",
        (nickname, language if language in {"ru", "en"} else "ru", avatar, request.user["id"]),
    )
    con.commit()
    user = con.execute("SELECT * FROM users WHERE id=?", (request.user["id"],)).fetchone()
    con.close()
    bump_event()
    return jsonify({"user": user_payload(user)})


@app.get("/api/users/search")
@auth_required
def user_search():
    q = (request.args.get("q") or "").strip().lower()
    if not q:
        return jsonify({"items": []})
    con = get_db()
    rows = con.execute(
        """
        SELECT id, username, nickname, avatar_url, is_verified
        FROM users
        WHERE username LIKE ? AND id != ? AND is_banned=0
        ORDER BY username ASC
        LIMIT 20
        """,
        (f"%{q}%", request.user["id"]),
    ).fetchall()
    con.close()
    return jsonify(
        {
            "items": [
                {
                    "id": r["id"],
                    "username": r["username"],
                    "nickname": r["nickname"],
                    "avatar_url": r["avatar_url"],
                    "is_verified": bool(r["is_verified"]),
                }
                for r in rows
            ]
        }
    )


@app.get("/api/dialogs")
@auth_required
def dialogs():
    con = get_db()
    rows = con.execute(
        """
        SELECT u.id, u.username, u.nickname, u.avatar_url, u.is_verified,
               m.id AS last_message_id,
               m.created_at AS last_message_at,
               m.sender_id AS last_message_sender_id
        FROM (
            SELECT CASE WHEN sender_id=? THEN receiver_id ELSE sender_id END AS peer_id,
                   MAX(id) AS last_id
            FROM messages
            WHERE (sender_id=? OR receiver_id=?) AND deleted_at IS NULL
            GROUP BY peer_id
        ) lm
        JOIN messages m ON m.id=lm.last_id
        JOIN users u ON u.id=lm.peer_id
        ORDER BY m.id DESC
        """,
        (request.user["id"], request.user["id"], request.user["id"]),
    ).fetchall()

    channels = con.execute(
        """
        SELECT c.id, c.title, c.username, c.avatar_url, c.is_verified,
               c.owner_id,
               COALESCE(cm.role, 'not_subscribed') AS role,
               p.created_at AS last_post_at,
               p.author_id AS last_post_author_id
        FROM channels c
        LEFT JOIN channel_members cm ON cm.channel_id=c.id AND cm.user_id=?
        LEFT JOIN (
            SELECT channel_id, MAX(id) AS last_id
            FROM channel_posts
            GROUP BY channel_id
        ) lp ON lp.channel_id=c.id
        LEFT JOIN channel_posts p ON p.id=lp.last_id
        WHERE c.is_public=1 OR cm.user_id=? OR c.owner_id=?
        ORDER BY COALESCE(p.id, 0) DESC, c.id DESC
        """,
        (request.user["id"], request.user["id"], request.user["id"]),
    ).fetchall()
    con.close()

    return jsonify(
        {
            "dialogs": [
                {
                    "id": r["id"],
                    "username": r["username"],
                    "nickname": r["nickname"],
                    "avatar_url": r["avatar_url"],
                    "is_verified": bool(r["is_verified"]),
                    "last_message_at": r["last_message_at"],
                    "last_message_id": r["last_message_id"],
                    "last_message_sender_id": r["last_message_sender_id"],
                }
                for r in rows
            ],
            "channels": [
                {
                    "id": c["id"],
                    "title": c["title"],
                    "username": c["username"],
                    "avatar_url": c["avatar_url"],
                    "is_verified": bool(c["is_verified"]),
                    "owner_id": c["owner_id"],
                    "role": c["role"],
                    "last_post_at": c["last_post_at"],
                    "last_post_author_id": c["last_post_author_id"],
                }
                for c in channels
            ],
        }
    )


@app.post("/api/messages")
@auth_required
def send_message():
    data = request.get_json(silent=True) or {}
    to_username = (data.get("to_username") or "").strip().lower()
    content = (data.get("content") or "").strip()
    if not to_username or not content:
        return jsonify({"error": "bad_payload"}), 400

    con = get_db()
    to_user = con.execute(
        "SELECT id FROM users WHERE username=? AND is_banned=0", (to_username,)
    ).fetchone()
    if not to_user:
        con.close()
        return jsonify({"error": "user_not_found"}), 404
    con.execute(
        "INSERT INTO messages(sender_id, receiver_id, content, created_at) VALUES(?,?,?,?)",
        (request.user["id"], to_user["id"], encrypt_text(content), now_iso()),
    )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.get("/api/messages/<username>")
@auth_required
def get_messages(username):
    target = (username or "").strip().lower()
    con = get_db()
    other = con.execute(
        "SELECT id, username, nickname, avatar_url, is_verified FROM users WHERE username=?",
        (target,),
    ).fetchone()
    if not other:
        con.close()
        return jsonify({"error": "user_not_found"}), 404

    rows = con.execute(
        """
        SELECT m.*, su.username AS sender_username
        FROM messages m
        JOIN users su ON su.id=m.sender_id
        WHERE ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?))
        ORDER BY m.id ASC
        """,
        (request.user["id"], other["id"], other["id"], request.user["id"]),
    ).fetchall()

    mids = [r["id"] for r in rows]
    react_map = {}
    if mids:
        placeholders = ",".join("?" for _ in mids)
        reacts = con.execute(
            f"SELECT message_id, user_id, reaction FROM message_reactions WHERE message_id IN ({placeholders})",
            mids,
        ).fetchall()
        for r in reacts:
            react_map.setdefault(r["message_id"], []).append(
                {"user_id": r["user_id"], "reaction": r["reaction"]}
            )

    con.close()
    items = []
    for r in rows:
        reactions = react_map.get(r["id"], [])
        counts = {}
        my_reaction = None
        for rr in reactions:
            counts[rr["reaction"]] = counts.get(rr["reaction"], 0) + 1
            if rr["user_id"] == request.user["id"]:
                my_reaction = rr["reaction"]
        items.append(
            {
                "id": r["id"],
                "sender_id": r["sender_id"],
                "sender_username": r["sender_username"],
                "content": "[deleted]" if r["deleted_at"] else decrypt_text(r["content"]),
                "created_at": r["created_at"],
                "edited_at": r["edited_at"],
                "deleted_at": r["deleted_at"],
                "is_deleted": bool(r["deleted_at"]),
                "reactions": counts,
                "my_reaction": my_reaction,
            }
        )

    return jsonify(
        {
            "peer": {
                "id": other["id"],
                "username": other["username"],
                "nickname": other["nickname"],
                "avatar_url": other["avatar_url"],
                "is_verified": bool(other["is_verified"]),
            },
            "items": items,
        }
    )


@app.put("/api/messages/<int:msg_id>")
@auth_required
def edit_message(msg_id):
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "empty"}), 400
    con = get_db()
    row = con.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not row:
        con.close()
        return jsonify({"error": "not_found"}), 404
    if row["sender_id"] != request.user["id"] or row["deleted_at"]:
        con.close()
        return jsonify({"error": "forbidden"}), 403
    con.execute(
        "UPDATE messages SET content=?, edited_at=? WHERE id=?",
        (encrypt_text(content), now_iso(), msg_id),
    )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.delete("/api/messages/<int:msg_id>")
@auth_required
def delete_message(msg_id):
    con = get_db()
    row = con.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not row:
        con.close()
        return jsonify({"error": "not_found"}), 404
    if request.user["id"] not in (row["sender_id"], row["receiver_id"]):
        con.close()
        return jsonify({"error": "forbidden"}), 403
    con.execute("UPDATE messages SET deleted_at=? WHERE id=?", (now_iso(), msg_id))
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.post("/api/messages/<int:msg_id>/react")
@auth_required
def react(msg_id):
    data = request.get_json(silent=True) or {}
    reaction = (data.get("reaction") or "").strip()
    allowed = {"👍", "❤️", "🔥", "😂", "👏", "like", "love", "fire"}
    if reaction not in allowed:
        return jsonify({"error": "bad_reaction"}), 400
    con = get_db()
    row = con.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not row:
        con.close()
        return jsonify({"error": "not_found"}), 404
    if request.user["id"] not in (row["sender_id"], row["receiver_id"]):
        con.close()
        return jsonify({"error": "forbidden"}), 403
    exists = con.execute(
        "SELECT id,reaction FROM message_reactions WHERE message_id=? AND user_id=?",
        (msg_id, request.user["id"]),
    ).fetchone()
    if exists and exists["reaction"] == reaction:
        con.execute("DELETE FROM message_reactions WHERE id=?", (exists["id"],))
    elif exists:
        con.execute(
            "UPDATE message_reactions SET reaction=?, created_at=? WHERE id=?",
            (reaction, now_iso(), exists["id"]),
        )
    else:
        con.execute(
            "INSERT INTO message_reactions(message_id,user_id,reaction,created_at) VALUES(?,?,?,?)",
            (msg_id, request.user["id"], reaction, now_iso()),
        )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.post("/api/channels")
@auth_required
def create_channel():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    username = (data.get("username") or "").strip().lower()
    description = (data.get("description") or "").strip()
    avatar = data.get("avatar_url")
    if not title or not username:
        return jsonify({"error": "bad_payload"}), 400
    if avatar:
        try:
            avatar = extract_data_url(f"channel_u{request.user['id']}", avatar)
        except ValueError:
            return jsonify({"error": "bad_avatar"}), 400
    con = get_db()
    exists = con.execute("SELECT id FROM channels WHERE username=?", (username,)).fetchone()
    if exists:
        con.close()
        return jsonify({"error": "already_exists"}), 409
    cur = con.cursor()
    cur.execute(
        "INSERT INTO channels(title,username,description,avatar_url,owner_id,created_at) VALUES(?,?,?,?,?,?)",
        (title, username, description, avatar, request.user["id"], now_iso()),
    )
    if DATABASE_URL:
        cid = cur.execute("SELECT id FROM channels WHERE username=?", (username,)).fetchone()["id"]
    else:
        cid = cur.lastrowid
    con.execute(
        "INSERT INTO channel_members(channel_id,user_id,role,created_at) VALUES(?,?,?,?)",
        (cid, request.user["id"], "owner", now_iso()),
    )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.put("/api/channels/<username>")
@auth_required
def update_channel(username):
    data = request.get_json(silent=True) or {}
    uname = (username or "").strip().lower()
    con = get_db()
    ch = con.execute("SELECT * FROM channels WHERE username=?", (uname,)).fetchone()
    if not ch:
        con.close()
        return jsonify({"error": "not_found"}), 404
    if request.user["id"] != ch["owner_id"] and not request.user["is_admin"]:
        con.close()
        return jsonify({"error": "forbidden"}), 403
    title = (data.get("title") or ch["title"]).strip()
    description = (data.get("description") or ch["description"] or "").strip()
    avatar = ch["avatar_url"]
    if "avatar_url" in data:
        try:
            avatar = extract_data_url(f"channel_{ch['id']}", data.get("avatar_url"))
        except ValueError:
            return jsonify({"error": "bad_avatar"}), 400
    con.execute(
        "UPDATE channels SET title=?, description=?, avatar_url=? WHERE id=?",
        (title, description, avatar, ch["id"]),
    )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.delete("/api/channels/<username>")
@auth_required
def delete_channel(username):
    uname = (username or "").strip().lower()
    con = get_db()
    ch = con.execute("SELECT * FROM channels WHERE username=?", (uname,)).fetchone()
    if not ch:
        con.close()
        return jsonify({"error": "not_found"}), 404
    if request.user["id"] != ch["owner_id"] and not request.user["is_admin"]:
        con.close()
        return jsonify({"error": "forbidden"}), 403
    con.execute("DELETE FROM channel_members WHERE channel_id=?", (ch["id"],))
    con.execute("DELETE FROM channel_posts WHERE channel_id=?", (ch["id"],))
    con.execute("DELETE FROM channels WHERE id=?", (ch["id"],))
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.post("/api/channels/<username>/join")
@auth_required
def join_channel(username):
    uname = (username or "").strip().lower()
    con = get_db()
    ch = con.execute("SELECT * FROM channels WHERE username=?", (uname,)).fetchone()
    if not ch:
        con.close()
        return jsonify({"error": "not_found"}), 404
    if DATABASE_URL:
        con.execute(
            "INSERT INTO channel_members(channel_id,user_id,role,created_at) VALUES(?,?,?,?) ON CONFLICT(channel_id, user_id) DO NOTHING",
            (ch["id"], request.user["id"], "subscriber", now_iso()),
        )
    else:
        con.execute(
            "INSERT OR IGNORE INTO channel_members(channel_id,user_id,role,created_at) VALUES(?,?,?,?)",
            (ch["id"], request.user["id"], "subscriber", now_iso()),
        )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.get("/api/channels/<username>/posts")
@auth_required
def channel_posts(username):
    uname = (username or "").strip().lower()
    con = get_db()
    ch = con.execute("SELECT * FROM channels WHERE username=?", (uname,)).fetchone()
    if not ch:
        con.close()
        return jsonify({"error": "not_found"}), 404
    role_row = con.execute(
        "SELECT role FROM channel_members WHERE channel_id=? AND user_id=?",
        (ch["id"], request.user["id"]),
    ).fetchone()
    role = role_row["role"] if role_row else "not_subscribed"
    rows = con.execute(
        """
        SELECT p.id, p.content, p.created_at, u.username AS author_username, u.nickname AS author_nickname
        FROM channel_posts p
        JOIN users u ON u.id=p.author_id
        WHERE p.channel_id=?
        ORDER BY p.id DESC
        """,
        (ch["id"],),
    ).fetchall()
    con.close()
    return jsonify(
        {
            "channel": {
                "id": ch["id"],
                "title": ch["title"],
                "username": ch["username"],
                "description": ch["description"],
                "avatar_url": ch["avatar_url"],
                "is_verified": bool(ch["is_verified"]),
                "owner_id": ch["owner_id"],
                "role": role,
            },
            "items": [
                {
                    "id": r["id"],
                    "content": r["content"],
                    "created_at": r["created_at"],
                    "author_username": r["author_username"],
                    "author_nickname": r["author_nickname"],
                }
                for r in rows
            ],
        }
    )


@app.post("/api/channels/<username>/posts")
@auth_required
def create_post(username):
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "empty"}), 400
    uname = (username or "").strip().lower()
    con = get_db()
    ch = con.execute("SELECT * FROM channels WHERE username=?", (uname,)).fetchone()
    if not ch:
        con.close()
        return jsonify({"error": "not_found"}), 404
    if request.user["id"] != ch["owner_id"] and not request.user["is_admin"]:
        con.close()
        return jsonify({"error": "forbidden"}), 403
    con.execute(
        "INSERT INTO channel_posts(channel_id,author_id,content,created_at) VALUES(?,?,?,?)",
        (ch["id"], request.user["id"], content, now_iso()),
    )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.get("/api/admin/overview")
@auth_required
@admin_required
def admin_overview():
    q = (request.args.get("query") or "").strip().lower()
    con = get_db()
    if q:
        users = con.execute(
            """
            SELECT id, username, nickname, is_admin, is_verified, is_banned, created_at
            FROM users
            WHERE username LIKE ?
            ORDER BY id DESC
            LIMIT 100
            """,
            (f"%{q}%",),
        ).fetchall()
        channels = con.execute(
            """
            SELECT id, title, username, is_verified, owner_id, created_at
            FROM channels
            WHERE username LIKE ? OR title LIKE ?
            ORDER BY id DESC
            LIMIT 100
            """,
            (f"%{q}%", f"%{q}%"),
        ).fetchall()
    else:
        users = con.execute(
            "SELECT id, username, nickname, is_admin, is_verified, is_banned, created_at FROM users ORDER BY id DESC LIMIT 100"
        ).fetchall()
        channels = con.execute(
            "SELECT id, title, username, is_verified, owner_id, created_at FROM channels ORDER BY id DESC LIMIT 100"
        ).fetchall()

    stats = {
        "users": con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"],
        "channels": con.execute("SELECT COUNT(*) AS c FROM channels").fetchone()["c"],
        "messages": con.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"],
    }
    con.close()
    return jsonify(
        {
            "stats": stats,
            "users": [dict(r) for r in users],
            "channels": [dict(r) for r in channels],
        }
    )


@app.post("/api/admin/users/<int:user_id>/verify")
@auth_required
@admin_required
def admin_verify_user(user_id):
    con = get_db()
    con.execute(
        "UPDATE users SET is_verified = CASE WHEN is_verified=1 THEN 0 ELSE 1 END, verified_at=? WHERE id=?",
        (now_iso(), user_id),
    )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.post("/api/admin/users/<int:user_id>/admin")
@auth_required
@admin_required
def admin_toggle_admin(user_id):
    if user_id == request.user["id"]:
        return jsonify({"error": "cant_change_self"}), 400
    con = get_db()
    con.execute(
        "UPDATE users SET is_admin = CASE WHEN is_admin=1 THEN 0 ELSE 1 END WHERE id=?",
        (user_id,),
    )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.post("/api/admin/users/<int:user_id>/ban")
@auth_required
@admin_required
def admin_toggle_ban(user_id):
    if user_id == request.user["id"]:
        return jsonify({"error": "cant_ban_self"}), 400
    con = get_db()
    row = con.execute("SELECT is_banned FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        con.close()
        return jsonify({"error": "not_found"}), 404
    new_val = 0 if row["is_banned"] else 1
    con.execute(
        "UPDATE users SET is_banned=?, banned_at=? WHERE id=?",
        (new_val, now_iso() if new_val else None, user_id),
    )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.delete("/api/admin/users/<int:user_id>")
@auth_required
@admin_required
def admin_delete_user(user_id):
    if user_id == request.user["id"]:
        return jsonify({"error": "cant_delete_self"}), 400
    con = get_db()
    con.execute("DELETE FROM message_reactions WHERE user_id=?", (user_id,))
    con.execute("DELETE FROM messages WHERE sender_id=? OR receiver_id=?", (user_id, user_id))
    con.execute("DELETE FROM channel_posts WHERE author_id=?", (user_id,))
    con.execute("DELETE FROM channel_members WHERE user_id=?", (user_id,))
    con.execute("DELETE FROM channels WHERE owner_id=?", (user_id,))
    con.execute("DELETE FROM users WHERE id=?", (user_id,))
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.post("/api/admin/channels/<int:channel_id>/verify")
@auth_required
@admin_required
def admin_verify_channel(channel_id):
    con = get_db()
    con.execute(
        "UPDATE channels SET is_verified = CASE WHEN is_verified=1 THEN 0 ELSE 1 END, verified_at=? WHERE id=?",
        (now_iso(), channel_id),
    )
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.delete("/api/admin/channels/<int:channel_id>")
@auth_required
@admin_required
def admin_delete_channel(channel_id):
    con = get_db()
    con.execute("DELETE FROM channel_posts WHERE channel_id=?", (channel_id,))
    con.execute("DELETE FROM channel_members WHERE channel_id=?", (channel_id,))
    con.execute("DELETE FROM channels WHERE id=?", (channel_id,))
    con.commit()
    con.close()
    bump_event()
    return jsonify({"ok": True})


@app.get("/api/events")
@auth_required
def events():
    def gen():
        last = -1
        while True:
            global _event_counter
            if _event_counter != last:
                last = _event_counter
                yield f"data: {json.dumps({'counter': _event_counter})}\n\n"
            time.sleep(1)

    return Response(gen(), mimetype="text/event-stream")


with app.app_context():
    init_db()


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host=host, port=port, debug=debug)
