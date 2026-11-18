"""
Cloud Vault Bot — سحابة شخصية متعددة المستخدمين على تيليجرام
================================================================
المتطلبات:
    Python 3.10+
    pip install -U "aiogram>=3.7,<4" aiosqlite

التشغيل:
    python bot.py        (التوكن مكتوب داخل الكود في BOT_TOKEN)

متغيرات اختيارية:
    BOT_TOKEN          يستبدل التوكن المكتوب في الكود إن وُجد
    VAULT_DB           مسار قاعدة البيانات (الافتراضي vault.db)
    SESSION_TTL_HOURS  مدة الجلسة بالساعات (الافتراضي 24)

ملاحظة: الملفات تبقى على خوادم تيليجرام، والقاعدة تحفظ file_id فقط،
لذلك يجب استرجاعها بنفس البوت (نفس التوكن) الذي رُفعت إليه.
"""

import asyncio
import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import time
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import aiosqlite
from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.filters.callback_data import CallbackData
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BotCommand,
    CallbackQuery,
    ErrorEvent,
    InlineKeyboardMarkup,
    Message,
    TelegramObject,
)
from aiogram.utils.keyboard import InlineKeyboardBuilder

# ─────────────────────────────── الإعدادات ───────────────────────────────

# توكن البوت (سرّي: من يملكه يتحكم بالبوت كاملاً). متغير البيئة BOT_TOKEN له الأولوية إن وُجد.
BOT_TOKEN = "9282660989:AAHI8le1k6vdB0H3PU9019NobGIEV2x3i6c"
DB_PATH = os.getenv("VAULT_DB", "vault.db")
SESSION_TTL = int(float(os.getenv("SESSION_TTL_HOURS", "24")) * 3600)
PAGE_SIZE = 6
SEARCH_LIMIT = 20
PBKDF2_ITERATIONS = 200_000
MAX_LOGIN_ATTEMPTS = 5
LOCK_SECONDS = 300

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_MIN, PASSWORD_MAX = 6, 128

CATEGORIES: dict[str, str] = {
    "all": "📁 الكل",
    "photo": "🖼 الصور",
    "document": "📄 المستندات",
    "audio": "🎵 الصوتيات",
    "video": "🎬 الفيديوهات",
}
ICONS = {"photo": "🖼", "document": "📄", "audio": "🎵", "video": "🎬"}

log = logging.getLogger("vault")

# ───────────────────────────── كلمات المرور ──────────────────────────────


def hash_password(password: str) -> str:
    """PBKDF2-SHA256 مع ملح عشوائي لكل مستخدم."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(8))  # لتوحيد زمن الرد عند اسم غير موجود


class LoginThrottle:
    """قفل مؤقت بعد عدة محاولات دخول فاشلة من نفس حساب تيليجرام."""

    def __init__(self, max_attempts: int, lock_seconds: int) -> None:
        self._max, self._lock = max_attempts, lock_seconds
        self._fails: dict[int, int] = {}
        self._locked_until: dict[int, float] = {}

    def locked_for(self, tg_id: int) -> int:
        remaining = int(self._locked_until.get(tg_id, 0) - time.time())
        if remaining <= 0:
            self._locked_until.pop(tg_id, None)
            return 0
        return remaining

    def fail(self, tg_id: int) -> None:
        self._fails[tg_id] = self._fails.get(tg_id, 0) + 1
        if self._fails[tg_id] >= self._max:
            self._fails.pop(tg_id, None)
            self._locked_until[tg_id] = time.time() + self._lock

    def reset(self, tg_id: int) -> None:
        self._fails.pop(tg_id, None)
        self._locked_until.pop(tg_id, None)


# ───────────────────────────── قاعدة البيانات ────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    telegram_id INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_id        TEXT    NOT NULL,
    file_unique_id TEXT    NOT NULL,
    kind           TEXT    NOT NULL,
    category       TEXT    NOT NULL,
    file_name      TEXT    NOT NULL,
    mime_type      TEXT,
    file_size      INTEGER NOT NULL DEFAULT 0,
    uploaded_at    TEXT    NOT NULL,
    UNIQUE (owner_id, file_unique_id)
);
CREATE INDEX IF NOT EXISTS idx_files_owner_cat ON files (owner_id, category, id);
"""


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class Database:
    def __init__(self, path: str) -> None:
        self._path = path
        self._conn: aiosqlite.Connection | None = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database is not connected")
        return self._conn

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA foreign_keys = ON")
        await self._conn.execute("PRAGMA journal_mode = WAL")
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def _one(self, sql: str, params: tuple = ()) -> aiosqlite.Row | None:
        async with self.conn.execute(sql, params) as cur:
            return await cur.fetchone()

    async def _all(self, sql: str, params: tuple = ()) -> list[aiosqlite.Row]:
        async with self.conn.execute(sql, params) as cur:
            return list(await cur.fetchall())

    async def _run(self, sql: str, params: tuple = ()) -> int:
        async with self.conn.execute(sql, params) as cur:
            affected = cur.rowcount
        await self.conn.commit()
        return affected

    # ── المستخدمون ──
    async def create_user(self, username: str, password_hash: str) -> int | None:
        try:
            async with self.conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, now_str()),
            ) as cur:
                user_id = cur.lastrowid
            await self.conn.commit()
            return user_id
        except aiosqlite.IntegrityError:
            await self.conn.rollback()
            return None

    async def get_user(self, username: str) -> aiosqlite.Row | None:
        return await self._one("SELECT * FROM users WHERE username = ?", (username,))

    # ── الجلسات ──
    async def open_session(self, telegram_id: int, user_id: int) -> None:
        await self._run(
            "INSERT OR REPLACE INTO sessions (telegram_id, user_id, expires_at) VALUES (?, ?, ?)",
            (telegram_id, user_id, int(time.time()) + SESSION_TTL),
        )

    async def close_session(self, telegram_id: int) -> None:
        await self._run("DELETE FROM sessions WHERE telegram_id = ?", (telegram_id,))

    async def purge_sessions(self) -> None:
        await self._run("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))

    async def session_account(self, telegram_id: int) -> aiosqlite.Row | None:
        return await self._one(
            "SELECT u.id, u.username, u.created_at FROM sessions s "
            "JOIN users u ON u.id = s.user_id "
            "WHERE s.telegram_id = ? AND s.expires_at > ?",
            (telegram_id, int(time.time())),
        )

    # ── الملفات ──
    async def add_file(self, owner_id: int, f: dict[str, Any]) -> bool:
        try:
            await self.conn.execute(
                "INSERT INTO files (owner_id, file_id, file_unique_id, kind, category, "
                "file_name, mime_type, file_size, uploaded_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    owner_id, f["file_id"], f["file_unique_id"], f["kind"], f["category"],
                    f["file_name"], f["mime_type"], f["file_size"], now_str(),
                ),
            )
            await self.conn.commit()
            return True
        except aiosqlite.IntegrityError:
            await self.conn.rollback()
            return False

    async def count_files(self, owner_id: int, category: str) -> int:
        if category == "all":
            row = await self._one("SELECT COUNT(*) FROM files WHERE owner_id = ?", (owner_id,))
        else:
            row = await self._one(
                "SELECT COUNT(*) FROM files WHERE owner_id = ? AND category = ?",
                (owner_id, category),
            )
        return row[0] if row else 0

    async def list_files(
        self, owner_id: int, category: str, limit: int, offset: int
    ) -> list[aiosqlite.Row]:
        if category == "all":
            return await self._all(
                "SELECT * FROM files WHERE owner_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (owner_id, limit, offset),
            )
        return await self._all(
            "SELECT * FROM files WHERE owner_id = ? AND category = ? "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            (owner_id, category, limit, offset),
        )

    async def get_file(self, owner_id: int, file_pk: int) -> aiosqlite.Row | None:
        return await self._one(
            "SELECT * FROM files WHERE id = ? AND owner_id = ?", (file_pk, owner_id)
        )

    async def delete_file(self, owner_id: int, file_pk: int) -> bool:
        return await self._run(
            "DELETE FROM files WHERE id = ? AND owner_id = ?", (file_pk, owner_id)
        ) > 0

    async def search_files(self, owner_id: int, query: str, limit: int) -> list[aiosqlite.Row]:
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return await self._all(
            "SELECT * FROM files WHERE owner_id = ? AND file_name LIKE ? ESCAPE '\\' "
            "ORDER BY id DESC LIMIT ?",
            (owner_id, f"%{escaped}%", limit),
        )

    async def stats(self, owner_id: int) -> dict[str, tuple[int, int]]:
        rows = await self._all(
            "SELECT category, COUNT(*), COALESCE(SUM(file_size), 0) "
            "FROM files WHERE owner_id = ? GROUP BY category",
            (owner_id,),
        )
        return {r[0]: (r[1], r[2]) for r in rows}


# ───────────────────────── الحالات وبيانات الأزرار ───────────────────────


class Auth(StatesGroup):
    login_username = State()
    login_password = State()
    reg_username = State()
    reg_password = State()
    reg_confirm = State()


class Vault(StatesGroup):
    search = State()


class AuthCB(CallbackData, prefix="auth"):
    action: str  # login | register | cancel


class MenuCB(CallbackData, prefix="m"):
    action: str  # home | files | delete | search | stats | logout


class ListCB(CallbackData, prefix="ls"):
    mode: str  # v = عرض ، d = حذف
    cat: str
    page: int


class FileCB(CallbackData, prefix="f"):
    action: str  # open | get | del | yes
    id: int
    mode: str  # v | d | s (نتيجة بحث)
    cat: str
    page: int


# ─────────────────────────────── أدوات مساعدة ────────────────────────────


def human_size(size: int) -> str:
    value = float(size or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def short(text: str, limit: int = 38) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def extract_file(message: Message) -> dict[str, Any] | None:
    """يحوّل أي رسالة وسائط إلى سجل موحّد جاهز للتخزين."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def record(obj: Any, kind: str, category: str, name: str, mime: str | None) -> dict[str, Any]:
        return {
            "file_id": obj.file_id,
            "file_unique_id": obj.file_unique_id,
            "kind": kind,
            "category": category,
            "file_name": name,
            "mime_type": mime,
            "file_size": obj.file_size or 0,
        }

    if message.photo:
        return record(message.photo[-1], "photo", "photo", f"photo_{stamp}.jpg", "image/jpeg")
    if message.animation:  # يجب فحصها قبل document لأن تيليجرام يرسل الحقلين معاً
        a = message.animation
        return record(a, "animation", "video", a.file_name or f"animation_{stamp}.mp4", a.mime_type)
    if message.video:
        v = message.video
        return record(v, "video", "video", v.file_name or f"video_{stamp}.mp4", v.mime_type)
    if message.video_note:
        return record(message.video_note, "video_note", "video", f"video_note_{stamp}.mp4", "video/mp4")
    if message.audio:
        a = message.audio
        title = " - ".join(p for p in (a.performer, a.title) if p)
        return record(a, "audio", "audio", a.file_name or title or f"audio_{stamp}.mp3", a.mime_type)
    if message.voice:
        return record(message.voice, "voice", "audio", f"voice_{stamp}.ogg", message.voice.mime_type)
    if message.document:
        d = message.document
        return record(d, "document", "document", d.file_name or f"document_{stamp}", d.mime_type)
    return None


async def show(
    event: Message | CallbackQuery, text: str, markup: InlineKeyboardMarkup | None = None
) -> None:
    """يعدّل رسالة الزر إن أمكن، وإلا يرسل رسالة جديدة."""
    if isinstance(event, Message):
        await event.answer(text, reply_markup=markup)
        return
    if isinstance(event.message, Message):
        try:
            await event.message.edit_text(text, reply_markup=markup)
            return
        except TelegramBadRequest as exc:
            if "message is not modified" in str(exc):
                return
    await event.bot.send_message(event.from_user.id, text, reply_markup=markup)


# ─────────────────────────────── لوحات الأزرار ───────────────────────────


def auth_kb() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="🔑 تسجيل الدخول", callback_data=AuthCB(action="login"))
    kb.button(text="🆕 إنشاء حساب جديد", callback_data=AuthCB(action="register"))
    return kb.adjust(1).as_markup()


def cancel_auth_kb() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="✖️ إلغاء", callback_data=AuthCB(action="cancel"))
    return kb.as_markup()


def menu_kb() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="📂 ملفاتي", callback_data=MenuCB(action="files"))
    kb.button(text="🔎 بحث", callback_data=MenuCB(action="search"))
    kb.button(text="🗑 حذف ملفات", callback_data=MenuCB(action="delete"))
    kb.button(text="📊 الإحصائيات", callback_data=MenuCB(action="stats"))
    kb.button(text="🚪 تسجيل الخروج", callback_data=MenuCB(action="logout"))
    return kb.adjust(2, 2, 1).as_markup()


def home_kb() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="🏠 القائمة الرئيسية", callback_data=MenuCB(action="home"))
    return kb.as_markup()


def categories_kb(mode: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    for key, label in CATEGORIES.items():
        kb.button(text=label, callback_data=ListCB(mode=mode, cat=key, page=0))
    kb.button(text="🏠 القائمة الرئيسية", callback_data=MenuCB(action="home"))
    return kb.adjust(1, 2, 2, 1).as_markup()


def menu_text(username: str) -> str:
    return (
        "☁️ <b>سحابتك الشخصية</b>\n"
        f"👤 الحساب: <b>{html.escape(username)}</b>\n\n"
        "📤 أرسل أي ملف (صورة، مستند، صوت، فيديو) ليُحفظ تلقائياً."
    )


WELCOME = (
    "👋 أهلاً بك في <b>Cloud Vault</b>\n"
    "سحابة شخصية تصل إليها من أي حساب تيليجرام بعد تسجيل الدخول.\n\n"
    "اختر أحد الخيارين:"
)

# ─────────────────────────────── الموجّهات ───────────────────────────────

auth_router = Router(name="auth")
vault_router = Router(name="vault")
for _router in (auth_router, vault_router):
    _router.message.filter(F.chat.type == "private")


class AuthMiddleware(BaseMiddleware):
    """يمنع الوصول إلى السحابة دون جلسة صالحة ويمرّر الحساب إلى المعالجات."""

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        db: Database = data["db"]
        tg_user = data.get("event_from_user")
        account = await db.session_account(tg_user.id) if tg_user else None
        if account is None:
            text = "🔒 يجب تسجيل الدخول أولاً (أو انتهت جلستك)."
            if isinstance(event, CallbackQuery):
                await event.answer("🔒 الجلسة غير صالحة", show_alert=False)
                await show(event, text, auth_kb())
            elif isinstance(event, Message):
                await event.answer(text, reply_markup=auth_kb())
            return None
        data["account"] = account
        return await handler(event, data)


vault_router.message.middleware(AuthMiddleware())
vault_router.callback_query.middleware(AuthMiddleware())

# ───────────────────────────── المصادقة (FSM) ────────────────────────────


@auth_router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext, db: Database) -> None:
    await state.clear()
    account = await db.session_account(message.from_user.id)
    if account:
        await message.answer(menu_text(account["username"]), reply_markup=menu_kb())
    else:
        await message.answer(WELCOME, reply_markup=auth_kb())


@auth_router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext, db: Database) -> None:
    await state.clear()
    account = await db.session_account(message.from_user.id)
    if account:
        await message.answer("تم الإلغاء.", reply_markup=home_kb())
    else:
        await message.answer("تم الإلغاء.", reply_markup=auth_kb())


@auth_router.callback_query(AuthCB.filter(F.action == "cancel"))
async def cb_auth_cancel(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.answer()
    await show(callback, WELCOME, auth_kb())


@auth_router.callback_query(AuthCB.filter(F.action == "login"))
async def cb_login(callback: CallbackQuery, state: FSMContext, throttle: LoginThrottle) -> None:
    wait = throttle.locked_for(callback.from_user.id)
    if wait:
        await callback.answer(f"⏳ محاولات كثيرة. انتظر {wait} ثانية.", show_alert=True)
        return
    await state.set_state(Auth.login_username)
    await callback.answer()
    await show(callback, "🔑 <b>تسجيل الدخول</b>\nأرسل اسم المستخدم:", cancel_auth_kb())


@auth_router.callback_query(AuthCB.filter(F.action == "register"))
async def cb_register(callback: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(Auth.reg_username)
    await callback.answer()
    await show(
        callback,
        "🆕 <b>إنشاء حساب</b>\nأرسل اسم مستخدم (3–32 حرفاً: أحرف إنجليزية، أرقام، _ ):",
        cancel_auth_kb(),
    )


# ── تسجيل الدخول ──
@auth_router.message(Auth.login_username, F.text)
async def login_username(message: Message, state: FSMContext) -> None:
    username = message.text.strip()
    if not USERNAME_RE.fullmatch(username):
        await message.answer("⚠️ اسم مستخدم غير صالح. أعد الإرسال:", reply_markup=cancel_auth_kb())
        return
    await state.update_data(username=username)
    await state.set_state(Auth.login_password)
    await message.answer(
        "أرسل كلمة المرور (ستُحذف رسالتك فوراً):", reply_markup=cancel_auth_kb()
    )


@auth_router.message(Auth.login_password, F.text)
async def login_password(
    message: Message, state: FSMContext, db: Database, throttle: LoginThrottle
) -> None:
    password = message.text
    with suppress(TelegramBadRequest):
        await message.delete()

    tg_id = message.from_user.id
    wait = throttle.locked_for(tg_id)
    if wait:
        await state.clear()
        await message.answer(f"⏳ محاولات كثيرة. انتظر {wait} ثانية.", reply_markup=auth_kb())
        return

    data = await state.get_data()
    user = await db.get_user(data.get("username", ""))
    stored = user["password_hash"] if user else _DUMMY_HASH
    valid = await asyncio.to_thread(verify_password, password, stored)

    if not (user and valid):
        throttle.fail(tg_id)
        await state.clear()
        await message.answer("❌ اسم المستخدم أو كلمة المرور غير صحيحة.", reply_markup=auth_kb())
        return

    throttle.reset(tg_id)
    await state.clear()
    await db.open_session(tg_id, user["id"])
    await message.answer("✅ تم تسجيل الدخول.\n\n" + menu_text(user["username"]), reply_markup=menu_kb())


# ── إنشاء الحساب ──
@auth_router.message(Auth.reg_username, F.text)
async def reg_username(message: Message, state: FSMContext, db: Database) -> None:
    username = message.text.strip()
    if not USERNAME_RE.fullmatch(username):
        await message.answer(
            "⚠️ الاسم يجب أن يكون 3–32 حرفاً (أحرف إنجليزية، أرقام، _ ). أعد الإرسال:",
            reply_markup=cancel_auth_kb(),
        )
        return
    if await db.get_user(username):
        await message.answer("⚠️ هذا الاسم مستخدم. اختر اسماً آخر:", reply_markup=cancel_auth_kb())
        return
    await state.update_data(username=username)
    await state.set_state(Auth.reg_password)
    await message.answer(
        f"أرسل كلمة مرور ({PASSWORD_MIN} أحرف على الأقل، ستُحذف رسالتك فوراً):",
        reply_markup=cancel_auth_kb(),
    )


@auth_router.message(Auth.reg_password, F.text)
async def reg_password(message: Message, state: FSMContext) -> None:
    password = message.text
    with suppress(TelegramBadRequest):
        await message.delete()
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX or not password.strip():
        await message.answer(
            f"⚠️ كلمة المرور يجب أن تكون بين {PASSWORD_MIN} و{PASSWORD_MAX} حرفاً. أعد الإرسال:",
            reply_markup=cancel_auth_kb(),
        )
        return
    # نخزّن التجزئة فقط في الحالة المؤقتة، لا النص الصريح
    await state.update_data(password_hash=await asyncio.to_thread(hash_password, password))
    await state.set_state(Auth.reg_confirm)
    await message.answer("أعد إرسال كلمة المرور للتأكيد:", reply_markup=cancel_auth_kb())


@auth_router.message(Auth.reg_confirm, F.text)
async def reg_confirm(message: Message, state: FSMContext, db: Database) -> None:
    password = message.text
    with suppress(TelegramBadRequest):
        await message.delete()
    data = await state.get_data()
    username, password_hash = data.get("username"), data.get("password_hash")
    if not username or not password_hash:
        await state.clear()
        await message.answer("⚠️ انتهت العملية. ابدأ من جديد.", reply_markup=auth_kb())
        return
    if not await asyncio.to_thread(verify_password, password, password_hash):
        await state.set_state(Auth.reg_password)
        await message.answer(
            "❌ الكلمتان غير متطابقتين. أرسل كلمة المرور من جديد:", reply_markup=cancel_auth_kb()
        )
        return
    user_id = await db.create_user(username, password_hash)
    await state.clear()
    if user_id is None:  # سُجّل الاسم من شخص آخر في هذه الأثناء
        await message.answer("⚠️ الاسم حُجز للتو. ابدأ من جديد.", reply_markup=auth_kb())
        return
    await db.open_session(message.from_user.id, user_id)
    await message.answer("✅ تم إنشاء الحساب.\n\n" + menu_text(username), reply_markup=menu_kb())


# ─────────────────────────────── لوحة التحكم ─────────────────────────────


@vault_router.callback_query(MenuCB.filter())
async def cb_menu(
    callback: CallbackQuery,
    callback_data: MenuCB,
    state: FSMContext,
    db: Database,
    account: aiosqlite.Row,
) -> None:
    action = callback_data.action
    await state.clear()

    if action == "logout":
        await db.close_session(callback.from_user.id)
        await callback.answer("تم تسجيل الخروج")
        await show(callback, "🚪 تم تسجيل الخروج بأمان.\n\n" + WELCOME, auth_kb())
        return

    await callback.answer()
    if action == "files":
        await show(callback, "📂 اختر التصنيف:", categories_kb("v"))
    elif action == "delete":
        await show(callback, "🗑 اختر التصنيف ثم اضغط الملف المراد حذفه:", categories_kb("d"))
    elif action == "search":
        await state.set_state(Vault.search)
        await show(callback, "🔎 أرسل اسم الملف أو جزءاً منه:", home_kb())
    elif action == "stats":
        await show(callback, await stats_text(db, account), home_kb())
    else:
        await show(callback, menu_text(account["username"]), menu_kb())


async def stats_text(db: Database, account: aiosqlite.Row) -> str:
    stats = await db.stats(account["id"])
    total_count = sum(c for c, _ in stats.values())
    total_size = sum(s for _, s in stats.values())
    lines = [f"📊 <b>إحصائيات {html.escape(account['username'])}</b>", ""]
    for key, label in CATEGORIES.items():
        if key == "all":
            continue
        count, size = stats.get(key, (0, 0))
        lines.append(f"{label}: <b>{count}</b> — {human_size(size)}")
    lines += ["", f"📦 الإجمالي: <b>{total_count}</b> ملف — {human_size(total_size)} تقريباً"]
    lines.append(f"🗓 تاريخ إنشاء الحساب: {account['created_at']} UTC")
    return "\n".join(lines)


# ── تصفح الملفات مع ترقيم الصفحات ──
async def render_list(
    event: Message | CallbackQuery, db: Database, owner_id: int, mode: str, cat: str, page: int
) -> None:
    total = await db.count_files(owner_id, cat)
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(max(page, 0), pages - 1)
    rows = await db.list_files(owner_id, cat, PAGE_SIZE, page * PAGE_SIZE)

    title = "🗑 حذف" if mode == "d" else "📂 عرض"
    if total:
        text = f"{title} — {CATEGORIES[cat]}\nالعدد: <b>{total}</b> | صفحة {page + 1}/{pages}"
    else:
        text = f"{title} — {CATEGORIES[cat]}\n\nلا توجد ملفات هنا بعد."

    kb = InlineKeyboardBuilder()
    action = "del" if mode == "d" else "open"
    for row in rows:
        prefix = "❌ " if mode == "d" else ""
        kb.button(
            text=f"{prefix}{ICONS.get(row['category'], '📄')} {short(row['file_name'])}",
            callback_data=FileCB(action=action, id=row["id"], mode=mode, cat=cat, page=page),
        )
    sizes = [1] * len(rows)
    nav = 0
    if page > 0:
        kb.button(text="◀️ السابق", callback_data=ListCB(mode=mode, cat=cat, page=page - 1))
        nav += 1
    if page < pages - 1:
        kb.button(text="التالي ▶️", callback_data=ListCB(mode=mode, cat=cat, page=page + 1))
        nav += 1
    if nav:
        sizes.append(nav)
    kb.button(text="🗂 التصنيفات", callback_data=MenuCB(action="delete" if mode == "d" else "files"))
    kb.button(text="🏠 الرئيسية", callback_data=MenuCB(action="home"))
    sizes.append(2)
    await show(event, text, kb.adjust(*sizes).as_markup())


@vault_router.callback_query(ListCB.filter())
async def cb_list(
    callback: CallbackQuery, callback_data: ListCB, db: Database, account: aiosqlite.Row
) -> None:
    if callback_data.cat not in CATEGORIES or callback_data.mode not in ("v", "d"):
        await callback.answer("زر غير صالح", show_alert=True)
        return
    await callback.answer()
    await render_list(
        callback, db, account["id"], callback_data.mode, callback_data.cat, callback_data.page
    )


def back_button(kb: InlineKeyboardBuilder, cd: FileCB) -> None:
    if cd.mode == "s":
        kb.button(text="🏠 الرئيسية", callback_data=MenuCB(action="home"))
    else:
        kb.button(text="↩️ رجوع", callback_data=ListCB(mode=cd.mode, cat=cd.cat, page=cd.page))


@vault_router.callback_query(FileCB.filter())
async def cb_file(
    callback: CallbackQuery, callback_data: FileCB, db: Database, account: aiosqlite.Row
) -> None:
    cd = callback_data
    if cd.cat not in CATEGORIES or cd.mode not in ("v", "d", "s"):
        await callback.answer("زر غير صالح", show_alert=True)
        return

    row = await db.get_file(account["id"], cd.id)
    if row is None:
        await callback.answer("⚠️ الملف غير موجود أو حُذف.", show_alert=True)
        if cd.mode != "s":
            await render_list(callback, db, account["id"], cd.mode, cd.cat, cd.page)
        return
    name = html.escape(row["file_name"])

    if cd.action == "open":
        await callback.answer()
        text = (
            f"{ICONS.get(row['category'], '📄')} <b>{name}</b>\n\n"
            f"التصنيف: {CATEGORIES[row['category']]}\n"
            f"الحجم: {human_size(row['file_size'])}\n"
            f"تاريخ الرفع: {row['uploaded_at']} UTC"
        )
        kb = InlineKeyboardBuilder()
        kb.button(text="📥 استرجاع", callback_data=cd.model_copy(update={"action": "get"}))
        kb.button(text="🗑 حذف", callback_data=cd.model_copy(update={"action": "del"}))
        back_button(kb, cd)
        await show(callback, text, kb.adjust(2, 1).as_markup())

    elif cd.action == "get":
        sender = getattr(callback.bot, f"send_{row['kind']}", None)
        if sender is None:
            await callback.answer("نوع ملف غير مدعوم", show_alert=True)
            return
        kwargs = {} if row["kind"] == "video_note" else {"caption": f"📎 {name}"}
        try:
            await sender(callback.from_user.id, row["file_id"], **kwargs)
            await callback.answer("تم الإرسال ✅")
        except TelegramBadRequest:
            log.warning("Failed to send file id=%s", row["id"], exc_info=True)
            await callback.answer("⚠️ تعذّر استرجاع الملف من تيليجرام.", show_alert=True)

    elif cd.action == "del":
        await callback.answer()
        kb = InlineKeyboardBuilder()
        kb.button(text="✅ نعم، احذف", callback_data=cd.model_copy(update={"action": "yes"}))
        if cd.mode == "d":
            kb.button(text="✖️ إلغاء", callback_data=ListCB(mode="d", cat=cd.cat, page=cd.page))
        else:
            kb.button(text="✖️ إلغاء", callback_data=cd.model_copy(update={"action": "open"}))
        await show(
            callback,
            f"⚠️ حذف <b>{name}</b> نهائياً من سحابتك؟",
            kb.adjust(2).as_markup(),
        )

    elif cd.action == "yes":
        deleted = await db.delete_file(account["id"], cd.id)
        await callback.answer("🗑 تم الحذف" if deleted else "⚠️ لم يُحذف")
        if cd.mode == "s":
            await show(callback, "🗑 تم حذف الملف.", home_kb())
        else:
            await render_list(callback, db, account["id"], cd.mode, cd.cat, cd.page)
    else:
        await callback.answer("زر غير صالح", show_alert=True)


# ── البحث ──
@vault_router.message(Vault.search, F.text)
async def do_search(
    message: Message, state: FSMContext, db: Database, account: aiosqlite.Row
) -> None:
    query = message.text.strip()
    if not query or query.startswith("/"):
        await message.answer("⚠️ أرسل نصاً للبحث عنه:", reply_markup=home_kb())
        return
    if len(query) > 64:
        await message.answer("⚠️ نص البحث طويل (64 حرفاً كحد أقصى).", reply_markup=home_kb())
        return
    await state.clear()
    rows = await db.search_files(account["id"], query, SEARCH_LIMIT)
    kb = InlineKeyboardBuilder()
    for row in rows:
        kb.button(
            text=f"{ICONS.get(row['category'], '📄')} {short(row['file_name'])}",
            callback_data=FileCB(action="open", id=row["id"], mode="s", cat="all", page=0),
        )
    kb.button(text="🔎 بحث جديد", callback_data=MenuCB(action="search"))
    kb.button(text="🏠 الرئيسية", callback_data=MenuCB(action="home"))
    safe_query = html.escape(query)
    if rows:
        note = f" (أول {SEARCH_LIMIT})" if len(rows) == SEARCH_LIMIT else ""
        text = f"🔎 نتائج «{safe_query}»: <b>{len(rows)}</b>{note}"
    else:
        text = f"🔎 لا توجد نتائج لـ «{safe_query}»."
    await message.answer(text, reply_markup=kb.adjust(*([1] * len(rows)), 2).as_markup())


# ── الرفع التلقائي ──
@vault_router.message(
    F.photo | F.document | F.audio | F.voice | F.video | F.video_note | F.animation
)
async def upload(message: Message, db: Database, account: aiosqlite.Row) -> None:
    record = extract_file(message)
    if record is None:
        await message.reply("⚠️ نوع الملف غير مدعوم.")
        return
    if await db.add_file(account["id"], record):
        await message.reply(
            f"✅ حُفظ في سحابتك\n"
            f"{ICONS[record['category']]} <b>{html.escape(record['file_name'])}</b>\n"
            f"الحجم: {human_size(record['file_size'])} | {now_str()} UTC",
            reply_markup=home_kb(),
        )
    else:
        await message.reply("ℹ️ هذا الملف موجود مسبقاً في سحابتك.", reply_markup=home_kb())


@vault_router.message()
async def fallback(message: Message, account: aiosqlite.Row) -> None:
    await message.answer(
        "أرسل ملفاً لحفظه، أو استخدم القائمة:\n\n" + menu_text(account["username"]),
        reply_markup=menu_kb(),
    )


@vault_router.callback_query()
async def unknown_callback(callback: CallbackQuery) -> None:
    await callback.answer("زر قديم أو غير صالح. أرسل /start", show_alert=True)


# ───────────────────────────── الأخطاء والتشغيل ──────────────────────────


async def on_error(event: ErrorEvent) -> bool:
    log.error("Unhandled error", exc_info=event.exception)
    update = event.update
    with suppress(Exception):
        if update.callback_query:
            await update.callback_query.answer("⚠️ حدث خطأ غير متوقع. حاول مجدداً.", show_alert=True)
        elif update.message:
            await update.message.answer("⚠️ حدث خطأ غير متوقع. أرسل /start للمتابعة.")
    return True


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    token = os.getenv("BOT_TOKEN") or BOT_TOKEN

    db = Database(DB_PATH)
    await db.connect()
    await db.purge_sessions()

    bot = Bot(token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp["db"] = db
    dp["throttle"] = LoginThrottle(MAX_LOGIN_ATTEMPTS, LOCK_SECONDS)
    dp.errors.register(on_error)
    dp.include_routers(auth_router, vault_router)

    try:
        await bot.set_my_commands(
            [
                BotCommand(command="start", description="القائمة الرئيسية / تسجيل الدخول"),
                BotCommand(command="cancel", description="إلغاء العملية الحالية"),
            ]
        )
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        await db.close()
        await bot.session.close()


if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        asyncio.run(main())
