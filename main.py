import os, json, uuid, time, asyncio, random, hashlib, logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from telethon import TelegramClient
from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest
from telethon.tl.functions.channels import InviteToChannelRequest, GetParticipantsRequest
from telethon.tl.types import (
    InputPhoneContact, InputUser, ChannelParticipantsSearch,
    UserStatusRecently, UserStatusOnline, UserStatusLastWeek,
    InputPeerChannel
)
from telethon.errors import (
    FloodWaitError, PeerFloodError, ChatAdminRequiredError,
    UserPrivacyRestrictedError, UserNotMutualContactError,
    ChatWriteForbiddenError, SessionPasswordNeededError,
    PhoneCodeInvalidError, PhoneCodeExpiredError
)
from telethon.sessions import StringSession

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("relay")

SERVICE_KEY = os.environ.get("SERVICE_KEY", "change-me-in-production")
API_ID = int(os.environ.get("API_ID", "2040"))
API_HASH = os.environ.get("API_HASH", "b18441a1ff607e10a989891a5462e627")

# Robust persistent volume auto-detection
def _init_session_dirs() -> tuple[Path, list[Path]]:
    candidates: list[Path] = []
    # 1. Explicit env var
    env_dir = os.environ.get("SESSION_DIR")
    if env_dir:
        candidates.append(Path(env_dir))
    # 2. Check /proc/mounts for Railway/Docker attached volumes
    try:
        if Path("/proc/mounts").exists():
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        mp = parts[1]
                        if mp in ("/", "/etc", "/dev", "/sys", "/proc", "/run", "/tmp", "/var", "/etc/hosts", "/etc/resolv.conf", "/etc/hostname"):
                            continue
                        if mp.startswith(("/dev", "/sys", "/proc", "/etc", "/run")):
                            continue
                        candidates.append(Path(mp) / "relay_sessions")
    except Exception as e:
        log.warning(f"Could not inspect /proc/mounts: {e}")
    # 3. Known Railway defaults
    for fallback in [Path("/data/relay_sessions"), Path("/app/data/relay_sessions"), Path("/data"), Path("/tmp/relay_sessions")]:
        if fallback not in candidates:
            candidates.append(fallback)

    writable_dirs: list[Path] = []
    primary: Optional[Path] = None
    for c in candidates:
        try:
            c.mkdir(parents=True, exist_ok=True)
            test_file = c / ".mount_test"
            test_file.write_text("ok")
            test_file.unlink()
            if primary is None:
                primary = c
            if c not in writable_dirs:
                writable_dirs.append(c)
        except Exception:
            pass

    if primary is None:
        primary = Path("/tmp/relay_sessions")
        primary.mkdir(parents=True, exist_ok=True)
        writable_dirs.append(primary)

    return primary, writable_dirs

SESSION_DIR, ALL_SESSION_DIRS = _init_session_dirs()
log.info(f"Initialized SESSION_DIR: {SESSION_DIR} (all search dirs: {[str(d) for d in ALL_SESSION_DIRS]})")

# Anti-limit configuration
MIN_DELAY = float(os.environ.get("MIN_DELAY", "30"))
MAX_DELAY = float(os.environ.get("MAX_DELAY", "120"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "20"))
BATCH_PAUSE_MIN = float(os.environ.get("BATCH_PAUSE_MIN", "300"))
BATCH_PAUSE_MAX = float(os.environ.get("BATCH_PAUSE_MAX", "600"))
ROTATION_THRESHOLD = int(os.environ.get("ROTATION_THRESHOLD", "20"))

app = FastAPI()


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    log.exception(f"Unhandled error on {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"detail": f"{type(exc).__name__}: {str(exc)[:300]}"})

# In-memory job store (use Redis/DB in production)
jobs: dict[str, dict] = {}
clients: dict[str, TelegramClient] = {}
pending_logins: dict[str, dict] = {}


def verify_key(request: Request):
    key = request.headers.get("X-Service-Key", "")
    user_id = request.headers.get("X-User-Id", "")
    if key != SERVICE_KEY:
        raise HTTPException(401, "Invalid service key")
    if not user_id:
        raise HTTPException(400, "Missing X-User-Id header")
    return user_id


def id_variants(account_id: str) -> list[str]:
    """Return all representations of an account ID: canonical UUID (with hyphens), clean hex (no hyphens), and raw."""
    if not account_id:
        return []
    raw = str(account_id).strip()
    variants = [raw]
    try:
        u = uuid.UUID(raw)
        canonical = str(u)
        clean_hex = u.hex
        if canonical not in variants:
            variants.append(canonical)
        if clean_hex not in variants:
            variants.append(clean_hex)
    except Exception:
        no_hyphens = raw.replace("-", "").lower()
        if no_hyphens not in variants:
            variants.append(no_hyphens)
    return variants


def get_candidate_meta_paths(user_id: str, account_id: str) -> list[Path]:
    safe = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    paths: list[Path] = []
    variants = id_variants(account_id)
    for base in ALL_SESSION_DIRS:
        user_folder = base / safe
        for var in variants:
            p = user_folder / f"{var}.json"
            if p not in paths:
                paths.append(p)
    return paths


def user_dir(user_id: str) -> Path:
    safe = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    d = SESSION_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def account_meta_path(user_id: str, account_id: str) -> Path:
    # Return existing candidate if one exists, otherwise default to primary
    for p in get_candidate_meta_paths(user_id, account_id):
        if p.exists():
            return p
    # Default to canonical format
    try:
        canonical = str(uuid.UUID(str(account_id).strip()))
        return user_dir(user_id) / f"{canonical}.json"
    except Exception:
        return user_dir(user_id) / f"{account_id}.json"


def load_meta(user_id: str, account_id: str) -> Optional[dict]:
    for p in get_candidate_meta_paths(user_id, account_id):
        if p.exists():
            try:
                data = json.loads(p.read_text())
                if data.get("string_session"):
                    return data
            except Exception:
                continue
    return None


def save_meta(user_id: str, account_id: str, meta: dict):
    safe = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    content = json.dumps(meta)
    variants = id_variants(account_id)
    for base in ALL_SESSION_DIRS:
        try:
            folder = base / safe
            folder.mkdir(parents=True, exist_ok=True)
            for var in variants:
                (folder / f"{var}.json").write_text(content)
        except Exception as e:
            log.warning(f"Could not save meta to {base}: {e}")


def get_cached_client(user_id: str, account_id: str) -> Optional[TelegramClient]:
    for var in id_variants(account_id):
        c = clients.get(f"{user_id}:{var}")
        if c:
            return c
    return None


def set_cached_client(user_id: str, account_id: str, client: TelegramClient):
    for var in id_variants(account_id):
        clients[f"{user_id}:{var}"] = client


def remove_cached_client(user_id: str, account_id: str):
    for var in id_variants(account_id):
        clients.pop(f"{user_id}:{var}", None)


def build_proxy(proxy: Optional[dict]):
    if not proxy:
        return None
    import socks
    scheme = socks.SOCKS5 if proxy.get("type", "socks5") == "socks5" else socks.HTTP
    return (scheme, proxy["host"], int(proxy["port"]), True, proxy.get("user"), proxy.get("pass"))


async def get_client(user_id: str, account_id: str, proxy: Optional[dict] = None) -> TelegramClient:
    cached = get_cached_client(user_id, account_id)
    if cached and cached.is_connected() and await cached.is_user_authorized():
        return cached
    if cached:
        try:
            await cached.disconnect()
        except Exception:
            pass
        remove_cached_client(user_id, account_id)

    meta = load_meta(user_id, account_id)
    if not meta or not meta.get("string_session"):
        raise HTTPException(401, f"Account '{str(account_id)[:8]}' has no saved session (searched in {SESSION_DIR}). Delete it and re-add it via Accounts.")

    client = TelegramClient(StringSession(meta["string_session"]), API_ID, API_HASH, proxy=build_proxy(proxy))
    await client.connect()
    if not await client.is_user_authorized():
        await client.disconnect()
        raise HTTPException(401, f"Account '{meta.get('name', str(account_id)[:8])}' session was rejected by Telegram (session revoked or 2FA changed). Delete it and re-add it via Accounts.")
    set_cached_client(user_id, account_id, client)
    return client


def add_job_log(job: Optional[dict], level: str, message: str):
    if not job:
        return
    if "logs" not in job:
        job["logs"] = []
    entry = {
        "time": now_iso(),
        "level": level,  # "info" | "success" | "delay" | "warn" | "error"
        "message": message,
    }
    job["logs"].append(entry)
    if len(job["logs"]) > 250:
        job["logs"] = job["logs"][-250:]


async def human_delay(job: Optional[dict] = None, min_s: float = MIN_DELAY, max_s: float = MAX_DELAY):
    delay = random.uniform(min_s, max_s)
    jitter = random.uniform(-2, 5)
    delay = max(8, delay + jitter)
    msg = f"Human delay: waiting {delay:.1f}s before next operation..."
    log.info(msg)
    if job:
        add_job_log(job, "delay", msg)
    await asyncio.sleep(delay)


async def batch_pause(job: Optional[dict] = None):
    pause = random.uniform(BATCH_PAUSE_MIN, BATCH_PAUSE_MAX)
    msg = f"Batch pause safety threshold reached: cooling down for {pause:.0f}s..."
    log.info(msg)
    if job:
        add_job_log(job, "delay", msg)
    await asyncio.sleep(pause)


@app.get("/")
async def root():
    return {"ok": True, "service": "relay-telegram"}


@app.post("/v1/health")
async def health(request: Request):
    verify_key(request)
    return {"ok": True, "service": "relay-telegram"}


@app.post("/v1/login/start")
async def login_start(request: Request):
    user_id = verify_key(request)
    body = await request.json()
    phone = body.get("phone", "").strip()
    if not phone:
        raise HTTPException(400, "Phone number required")

    tmp_id = uuid.uuid4().hex[:12]
    # Standard canonical UUID with hyphens matching PostgreSQL / Supabase
    account_id = str(uuid.uuid4())
    client = TelegramClient(StringSession(), API_ID, API_HASH)
    await client.connect()

    try:
        result = await client.send_code_request(phone)
        set_cached_client(user_id, account_id, client)
        pending_logins[tmp_id] = {"user_id": user_id, "phone": phone, "phone_code_hash": result.phone_code_hash, "account_id": account_id}
        return {"hash": result.phone_code_hash, "tmp_id": tmp_id}
    except FloodWaitError as e:
        await client.disconnect()
        raise HTTPException(429, f"Flood wait: retry after {e.seconds}s")
    except Exception as e:
        await client.disconnect()
        raise HTTPException(400, str(e))


@app.post("/v1/login/complete")
async def login_complete(request: Request):
    user_id = verify_key(request)
    body = await request.json()
    tmp_id = body.get("tmp_id", "")
    code = body.get("code", "")
    password = body.get("password")
    name = body.get("name", "default")

    pending = pending_logins.get(tmp_id)
    if not pending or pending["user_id"] != user_id:
        raise HTTPException(400, "Login session expired. Start over.")

    account_id = pending["account_id"]
    client = get_cached_client(user_id, account_id)
    if not client:
        raise HTTPException(400, "Login session expired. Start over.")

    try:
        if pending.get("authenticated"):
            me = await client.get_me()
        elif password:
            await client.sign_in(password=password)
            me = await client.get_me()
        else:
            await client.sign_in(phone=pending["phone"], code=code, phone_code_hash=pending["phone_code_hash"])
            me = await client.get_me()

        if not name or name == "default":
            pending["authenticated"] = True
            return {"requires_name": True}

        # Export StringSession (embeds auth key + correct DC) and persist meta
        string_session = client.session.save()
        meta = {
            "id": account_id,
            "name": name,
            "username": me.username,
            "phone_hint": f"+{me.phone[-4:]}" if me.phone else None,
            "string_session": string_session,
            "created_at": time.time(),
        }
        save_meta(user_id, account_id, meta)
        set_cached_client(user_id, account_id, client)  # keep connected
        pending_logins.pop(tmp_id, None)

        return {
            "accounts": [{
                "id": account_id,
                "name": name,
                "username": me.username,
                "phone_hint": f"+{me.phone[-4:]}" if me.phone else None,
                "status": "connected"
            }]
        }
    except SessionPasswordNeededError:
        return {"requires_password": True}
    except (PhoneCodeInvalidError, PhoneCodeExpiredError) as e:
        raise HTTPException(400, f"Verification failed: {type(e).__name__}. Start over.")
    except Exception as e:
        err = str(e).lower()
        if "two-step" in err or "password" in err:
            return {"requires_password": True}
        raise HTTPException(400, str(e))


@app.post("/v1/accounts")
async def list_accounts(request: Request):
    user_id = verify_key(request)
    accounts = []
    seen_ids = set()
    safe = hashlib.sha256(user_id.encode()).hexdigest()[:16]

    for base in ALL_SESSION_DIRS:
        ud = base / safe
        if not ud.exists():
            continue
        for p in sorted(ud.glob("*.json")):
            try:
                meta = json.loads(p.read_text())
            except Exception:
                continue
            account_id = meta.get("id") or p.stem
            try:
                account_id = str(uuid.UUID(str(account_id).strip()))
            except Exception:
                pass
            if account_id in seen_ids:
                continue
            seen_ids.add(account_id)

            status = "disconnected"
            username = meta.get("username")
            try:
                client = await get_client(user_id, account_id)
                me = await client.get_me()
                username = me.username or username
                status = "connected"
            except Exception:
                pass
            accounts.append({
                "id": account_id,
                "name": (meta.get("name") or username or account_id)[:20],
                "username": username,
                "phone_hint": meta.get("phone_hint"),
                "status": status,
            })
    return {"accounts": accounts}


@app.post("/v1/accounts/sync")
async def sync_accounts(request: Request):
    """Check which account IDs still have valid session files on disk or live in memory."""
    user_id = verify_key(request)
    body = await request.json()
    account_ids = body.get("account_ids", [])
    results = {}
    for aid in account_ids:
        # First check in-memory client
        c = get_cached_client(user_id, aid)
        if c and c.is_connected():
            results[aid] = "ok"
            continue
        # Then check disk meta across all dirs and ID variants
        meta = load_meta(user_id, aid)
        if meta and meta.get("string_session"):
            results[aid] = "ok"
        else:
            results[aid] = "session_lost"
    return {"accounts": results}


@app.post("/v1/accounts/delete")
async def delete_account(request: Request):
    user_id = verify_key(request)
    body = await request.json()
    account_id = body.get("account_id", "")
    cached = get_cached_client(user_id, account_id)
    if cached:
        try:
            await cached.disconnect()
        except Exception:
            pass
    remove_cached_client(user_id, account_id)

    safe = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    for p in get_candidate_meta_paths(user_id, account_id):
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass
    for base in ALL_SESSION_DIRS:
        ud = base / safe
        for var in id_variants(account_id):
            for legacy in (ud / f"{var}.session", ud / f"{var}.session-journal"):
                if legacy.exists():
                    try:
                        legacy.unlink()
                    except Exception:
                        pass
    return {"ok": True}


@app.post("/v1/groups")
async def list_groups(request: Request):
    user_id = verify_key(request)
    body = await request.json()
    account_id = body.get("account_id", "")
    client = await get_client(user_id, account_id)

    groups = []
    try:
        async for dialog in client.iter_dialogs(limit=300):
            if dialog.is_group or dialog.is_channel:
                groups.append({"id": str(dialog.entity.id), "title": dialog.entity.title})
    except FloodWaitError as e:
        raise HTTPException(429, f"Flood wait: retry after {e.seconds}s")
    return {"groups": groups}


@app.post("/v1/jobs/start")
async def start_job(request: Request):
    user_id = verify_key(request)
    body = await request.json()
    account_id = body.get("account_id", "")
    group_id = body.get("group_id", "")
    kind = body.get("kind", "scrape")
    source_job_id = body.get("source_job_id")
    filters = body.get("filters", {}) or {}
    
    limit = body.get("limit") or filters.get("limit")
    parsed_limit = None
    if limit is not None:
        try:
            parsed_limit = int(limit)
            if parsed_limit <= 0:
                parsed_limit = None
        except (ValueError, TypeError):
            parsed_limit = None
    if parsed_limit:
        filters["limit"] = parsed_limit

    proxy = body.get("proxy")

    job_id = str(uuid.uuid4())
    job = {
        "id": job_id, "user_id": user_id, "account_id": account_id,
        "kind": kind, "group_name": group_id, "status": "running",
        "progress": 0, "total": parsed_limit or 0, "added": 0, "skipped": 0, "failed": 0,
        "error": None, "settings": filters, "members": [],
        "logs": [],
        "created_at": now_iso(), "completed_at": None,
        "cancelled": False
    }
    jobs[job_id] = job

    if kind == "scrape":
        asyncio.create_task(run_scrape(job_id, user_id, account_id, group_id, filters, proxy, parsed_limit))
    elif kind == "add":
        asyncio.create_task(run_add(job_id, user_id, account_id, group_id, source_job_id, proxy, parsed_limit))

    return {"job": {k: v for k, v in job.items() if k != "members"}}


@app.post("/v1/jobs/status")
async def job_status(request: Request):
    verify_key(request)
    body = await request.json()
    job_id = body.get("job_id", "")
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {"job": {k: v for k, v in job.items() if k != "members"}}


@app.post("/v1/jobs/cancel")
async def cancel_job(request: Request):
    verify_key(request)
    body = await request.json()
    job_id = body.get("job_id", "")
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    job["cancelled"] = True
    job["status"] = "cancelled"
    job["completed_at"] = now_iso()
    add_job_log(job, "warn", "Operation cancelled by user.")
    return {"ok": True, "job": {k: v for k, v in job.items() if k != "members"}}


@app.post("/v1/jobs/results")
async def job_results(request: Request):
    verify_key(request)
    body = await request.json()
    job_id = body.get("job_id", "")
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    members = [
        {
            "id": str(uuid.uuid4()),
            "telegram_id": m["id"],
            "username": m.get("username"),
            "first_name": m.get("first_name", ""),
            "last_name": m.get("last_name", ""),
            "is_bot": m.get("bot", False),
            "is_premium": m.get("premium", False),
        }
        for m in job.get("members", [])
    ]
    return {"members": members}


async def run_scrape(job_id: str, user_id: str, account_id: str, group_id: str, filters: dict, proxy: Optional[dict], limit: Optional[int] = None):
    job = jobs[job_id]
    if limit is None:
        raw_limit = filters.get("limit")
        if raw_limit is not None:
            try:
                limit = int(raw_limit)
                if limit <= 0:
                    limit = None
            except (ValueError, TypeError):
                limit = None

    limit_desc = f"{limit} members" if limit else "All members"
    add_job_log(job, "info", f"Starting member collection for group '{group_id}' (target: {limit_desc})...")

    try:
        client = await get_client(user_id, account_id, proxy)
        entity = await client.get_entity(int(group_id) if group_id.lstrip("-").isdigit() else group_id)
        group_title = getattr(entity, "title", str(group_id))
        job["group_name"] = group_title
        add_job_log(job, "info", f"Connected to Telegram group '{group_title}'. Fetching member roster...")

        offset = 0
        all_members = []
        batch_num = 1
        while True:
            if job["cancelled"]:
                add_job_log(job, "warn", "Collection cancelled by user.")
                return
            participants = await client(GetParticipantsRequest(
                channel=entity, filter=ChannelParticipantsSearch(""), offset=offset, limit=200, hash=0
            ))
            if not participants.users:
                add_job_log(job, "info", "Reached the end of group member directory.")
                break

            matched_in_batch = 0
            for u in participants.users:
                member = {
                    "id": str(u.id),
                    "username": u.username,
                    "first_name": getattr(u, "first_name", "") or "",
                    "last_name": getattr(u, "last_name", "") or "",
                    "bot": getattr(u, "bot", False),
                    "premium": getattr(u, "premium", False),
                    "access_hash": str(getattr(u, "access_hash", 0)),
                    "status": type(getattr(u, "status", None)).__name__,
                }
                # Smart filtering: recently active only
                if filters.get("activeOnly"):
                    status = getattr(u, "status", None)
                    if not isinstance(status, (UserStatusRecently, UserStatusOnline, UserStatusLastWeek)):
                        continue
                if filters.get("usernameOnly") and not u.username:
                    continue
                if filters.get("excludeBots") and getattr(u, "bot", False):
                    continue
                if filters.get("premiumOnly") and not getattr(u, "premium", False):
                    continue
                pattern = filters.get("pattern")
                if pattern:
                    import re
                    text = f"{member['first_name']} {member['last_name']} {u.username or ''}"
                    if not re.search(pattern, text, re.I):
                        continue

                all_members.append(member)
                matched_in_batch += 1

                if limit and len(all_members) >= limit:
                    all_members = all_members[:limit]
                    break

            offset += len(participants.users)
            job["progress"] = len(all_members)
            if limit:
                job["total"] = limit
            else:
                job["total"] = max(job["total"], len(all_members))

            add_job_log(
                job,
                "info",
                f"Batch #{batch_num}: processed {len(participants.users)} participants ({matched_in_batch} matched filters). Total collected: {len(all_members)}{f' / {limit}' if limit else ''}."
            )
            batch_num += 1

            if limit and len(all_members) >= limit:
                add_job_log(job, "info", f"Target limit of {limit} members reached. Ending collection.")
                break

            await asyncio.sleep(random.uniform(1, 2.5))

        job["members"] = all_members
        job["total"] = len(all_members)
        job["progress"] = len(all_members)
        job["status"] = "completed"
        job["completed_at"] = now_iso()
        add_job_log(job, "success", f"Collection successfully completed! Total members saved: {len(all_members)}.")
        log.info(f"Scrape {job_id}: {len(all_members)} members collected")

    except FloodWaitError as e:
        job["status"] = "failed"
        job["error"] = f"Flood wait: retry after {e.seconds}s"
        job["completed_at"] = now_iso()
        add_job_log(job, "error", f"Telegram FloodWait encountered: must wait {e.seconds}s.")
    except ChatAdminRequiredError:
        job["status"] = "failed"
        job["error"] = "Admin access required for this group"
        job["completed_at"] = now_iso()
        add_job_log(job, "error", "Telegram error: Admin access is required to view members of this group.")
    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)[:500]
        job["completed_at"] = now_iso()
        add_job_log(job, "error", f"Collection failed: {str(e)[:300]}")
        log.error(f"Scrape {job_id} failed: {e}")


async def run_add(job_id: str, user_id: str, account_id: str, target_group: str, source_job_id: str, proxy: Optional[dict], limit: Optional[int] = None):
    job = jobs[job_id]
    try:
        source_job = jobs.get(source_job_id)
        if not source_job or not source_job.get("members"):
            job["status"] = "failed"
            job["error"] = "Source collection not found or empty"
            job["completed_at"] = now_iso()
            add_job_log(job, "error", "Source collection not found or contains 0 members.")
            return

        members = list(source_job["members"])
        if limit and limit > 0:
            members = members[:limit]
            add_job_log(job, "info", f"Applying custom limit: targeting {len(members)} members out of {len(source_job['members'])} available.")
        else:
            add_job_log(job, "info", f"Targeting all {len(members)} available members from source collection.")

        job["total"] = len(members)
        add_job_log(job, "info", f"Connecting account to Telegram for target group '{target_group}'...")

        client = await get_client(user_id, account_id, proxy)
        entity = await client.get_entity(int(target_group) if target_group.lstrip("-").isdigit() else target_group)
        group_title = getattr(entity, "title", str(target_group))
        job["group_name"] = group_title
        add_job_log(job, "info", f"Connected to group '{group_title}'. Beginning member addition sequence...")

        added_count = 0
        adds_since_pause = 0

        for i, member in enumerate(members):
            if job["cancelled"]:
                job["status"] = "cancelled"
                job["completed_at"] = now_iso()
                add_job_log(job, "warn", f"Operation cancelled by user after processing {i} members.")
                return

            member_label = f"@{member['username']}" if member.get("username") else f"{member.get('first_name', '')} {member.get('last_name', '')} (ID: {member.get('id')})".strip()
            add_job_log(job, "info", f"[{i + 1}/{len(members)}] Inviting {member_label}...")

            try:
                # Strategy 4: Use ID + AccessHash for direct matching
                access_hash = int(member.get("access_hash", 0))
                user_id_tg = int(member["id"])

                if access_hash:
                    input_user = InputUser(user_id=user_id_tg, access_hash=access_hash)
                else:
                    input_user = await client.get_input_entity(member.get("username") or user_id_tg)

                # Strategy 1 & 2: Contact-add trick with human delays
                contact = InputPhoneContact(
                    client_id=random.randint(100000, 999999),
                    phone=f"+{random.randint(1000000000, 9999999999)}",
                    first_name=member.get("first_name", "User") or "User",
                    last_name=member.get("last_name", "") or ""
                )

                # Try direct invite first (uses AccessHash — lower friction)
                try:
                    await client(InviteToChannelRequest(channel=entity, users=[input_user]))
                    added_count += 1
                    job["added"] = added_count
                    add_job_log(job, "success", f"Successfully added {member_label} directly! (Total added: {added_count})")
                except (UserNotMutualContactError, UserPrivacyRestrictedError):
                    # Fall back to contact-add trick
                    add_job_log(job, "warn", f"{member_label} has privacy restrictions. Attempting contact bypass...")
                    try:
                        import_result = await client(ImportContactsRequest([contact]))
                        if import_result.imported:
                            imported_user = import_result.users[0]
                            await client(InviteToChannelRequest(channel=entity, users=[imported_user]))
                            await client(DeleteContactsRequest(id=[imported_user]))
                            added_count += 1
                            job["added"] = added_count
                            add_job_log(job, "success", f"Successfully added {member_label} via contact bypass! (Total added: {added_count})")
                        else:
                            job["skipped"] += 1
                            add_job_log(job, "warn", f"Skipped {member_label}: privacy settings prohibit group invites.")
                    except Exception as exc:
                        job["skipped"] += 1
                        add_job_log(job, "warn", f"Skipped {member_label}: {str(exc)[:120]}")
                except ChatWriteForbiddenError:
                    job["status"] = "failed"
                    job["error"] = "Cannot write to this group. Check admin permissions."
                    job["completed_at"] = now_iso()
                    add_job_log(job, "error", "Fatal error: Admin permissions required to invite members to this group.")
                    return

                adds_since_pause += 1
                job["progress"] = i + 1

                # Strategy 1: Rotation threshold — stop and signal rotation needed
                if adds_since_pause >= ROTATION_THRESHOLD:
                    await batch_pause(job)
                    adds_since_pause = 0

                # Strategy 2: Human-like micro-delay with jitter
                await human_delay(job)

            except PeerFloodError as e:
                job["status"] = "failed"
                job["error"] = f"Peer flood: account restricted. Wait {getattr(e, 'seconds', '?')}s before retrying."
                job["completed_at"] = now_iso()
                add_job_log(job, "error", f"Telegram PeerFlood restriction: account temporarily throttled by Telegram.")
                log.warning(f"PeerFlood on job {job_id} after {added_count} adds")
                return
            except FloodWaitError as e:
                add_job_log(job, "warn", f"Telegram FloodWait: pausing for {e.seconds + 5}s before resuming...")
                log.info(f"FloodWait {e.seconds}s on job {job_id}, sleeping...")
                await asyncio.sleep(e.seconds + 5)
                continue
            except (UserPrivacyRestrictedError, ChatWriteForbiddenError):
                job["skipped"] += 1
                add_job_log(job, "warn", f"Skipped {member_label} due to permission restrictions.")
                continue
            except Exception as e:
                job["failed"] += 1
                add_job_log(job, "error", f"Failed to add {member_label}: {str(e)[:150]}")
                log.warning(f"Add failed for {member.get('username', member['id'])}: {e}")
                continue

        job["status"] = "completed"
        job["completed_at"] = now_iso()
        add_job_log(job, "success", f"Operation finished! Summary: {added_count} added, {job['skipped']} skipped, {job['failed']} failed out of {len(members)} targeted.")
        log.info(f"Add {job_id}: {added_count} added, {job['skipped']} skipped, {job['failed']} failed")

    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)[:500]
        job["completed_at"] = now_iso()
        add_job_log(job, "error", f"Operation encountered an unexpected error: {str(e)[:300]}")
        log.error(f"Add {job_id} failed: {e}")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
