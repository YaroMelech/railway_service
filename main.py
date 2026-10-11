import os, json, uuid, time, asyncio, random, hashlib, logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from telethon import TelegramClient
from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest
from telethon.tl.functions.channels import InviteToChannelRequest, GetParticipantsRequest
from telethon.tl.functions.messages import GetDialogsRequest
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
SESSION_DIR = Path(os.environ.get("SESSION_DIR", "/tmp/relay_sessions"))
SESSION_DIR.mkdir(parents=True, exist_ok=True)

# Anti-limit configuration
MIN_DELAY = float(os.environ.get("MIN_DELAY", "30"))
MAX_DELAY = float(os.environ.get("MAX_DELAY", "120"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "20"))
BATCH_PAUSE_MIN = float(os.environ.get("BATCH_PAUSE_MIN", "300"))
BATCH_PAUSE_MAX = float(os.environ.get("BATCH_PAUSE_MAX", "600"))
ROTATION_THRESHOLD = int(os.environ.get("ROTATION_THRESHOLD", "20"))

app = FastAPI()

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


def user_dir(user_id: str) -> Path:
    safe = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    d = SESSION_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def session_path(user_id: str, account_id: str) -> Path:
    return user_dir(user_id) / f"{account_id}.session"


async def get_client(user_id: str, account_id: str, proxy: Optional[dict] = None) -> TelegramClient:
    cache_key = f"{user_id}:{account_id}"
    if cache_key in clients and clients[cache_key].is_connected():
        return clients[cache_key]

    sp = session_path(user_id, account_id)
    proxy_tuple = None
    if proxy:
        import socks
        proxy_tuple = (socks.SOCKS5, proxy["host"], proxy["port"], True, proxy.get("user"), proxy.get("pass"))

    client = TelegramClient(str(sp), API_ID, API_HASH, proxy=proxy_tuple)
    await client.connect()
    if not await client.is_user_authorized():
        await client.disconnect()
        raise HTTPException(401, f"Account {account_id} is not authorized. Re-login required.")
    clients[cache_key] = client
    return client


async def human_delay(min_s: float = MIN_DELAY, max_s: float = MAX_DELAY):
    delay = random.uniform(min_s, max_s)
    jitter = random.uniform(-2, 5)
    delay = max(8, delay + jitter)
    log.info(f"Human delay: {delay:.1f}s")
    await asyncio.sleep(delay)


async def batch_pause():
    pause = random.uniform(BATCH_PAUSE_MIN, BATCH_PAUSE_MAX)
    log.info(f"Batch pause: {pause:.0f}s")
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
    sp = session_path(user_id, tmp_id)
    client = TelegramClient(str(sp), API_ID, API_HASH)
    await client.connect()

    try:
        result = await client.send_code_request(phone)
        clients[f"{user_id}:{tmp_id}"] = client
        pending_logins[tmp_id] = {"user_id": user_id, "phone": phone, "phone_code_hash": result.phone_code_hash}
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

    cache_key = f"{user_id}:{tmp_id}"
    client = clients.get(cache_key)
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

        account_id = str(uuid.uuid4())
        old_path = session_path(user_id, tmp_id)
        new_path = session_path(user_id, account_id)
        await client.disconnect()

        if old_path.exists():
            old_path.rename(new_path)
        journal = old_path.parent / f"{old_path.name}-journal"
        if journal.exists():
            journal.unlink()

        del clients[cache_key]
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
    for p in user_dir(user_id).glob("*.session"):
        account_id = p.stem
        try:
            client = await get_client(user_id, account_id)
            me = await client.get_me()
            accounts.append({
                "id": account_id, "name": (me.first_name or me.username or account_id)[:20],
                "username": me.username,
                "phone_hint": f"+{me.phone[-4:]}" if me.phone else None,
                "status": "connected"
            })
        except Exception:
            accounts.append({"id": account_id, "name": account_id[:8], "username": None, "phone_hint": None, "status": "disconnected"})
    return {"accounts": accounts}


@app.post("/v1/accounts/delete")
async def delete_account(request: Request):
    user_id = verify_key(request)
    body = await request.json()
    account_id = body.get("account_id", "")
    cache_key = f"{user_id}:{account_id}"
    if cache_key in clients:
        await clients[cache_key].disconnect()
        del clients[cache_key]
    sp = session_path(user_id, account_id)
    if sp.exists():
        sp.unlink()
    journal = sp.parent / f"{sp.name}-journal"
    if journal.exists():
        journal.unlink()
    return {"ok": True}


@app.post("/v1/groups")
async def list_groups(request: Request):
    user_id = verify_key(request)
    body = await request.json()
    account_id = body.get("account_id", "")
    client = await get_client(user_id, account_id)

    result = await client(GetDialogsRequest(offset_date=None, offset_id=0, offset_peer=None, limit=200, hash=0))
    groups = []
    for chat in result.chats:
        if hasattr(chat, 'megagroup') and chat.megagroup:
            groups.append({"id": str(chat.id), "title": chat.title})
    return {"groups": groups}


@app.post("/v1/jobs/start")
async def start_job(request: Request):
    user_id = verify_key(request)
    body = await request.json()
    account_id = body.get("account_id", "")
    group_id = body.get("group_id", "")
    kind = body.get("kind", "scrape")
    source_job_id = body.get("source_job_id")
    filters = body.get("filters", {})
    proxy = body.get("proxy")

    job_id = str(uuid.uuid4())
    job = {
        "id": job_id, "user_id": user_id, "account_id": account_id,
        "kind": kind, "group_name": group_id, "status": "running",
        "progress": 0, "total": 0, "added": 0, "skipped": 0, "failed": 0,
        "error": None, "settings": filters, "members": [],
        "created_at": time.time(), "completed_at": None,
        "cancelled": False
    }
    jobs[job_id] = job

    if kind == "scrape":
        asyncio.create_task(run_scrape(job_id, user_id, account_id, group_id, filters, proxy))
    elif kind == "add":
        asyncio.create_task(run_add(job_id, user_id, account_id, group_id, source_job_id, proxy))

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
    job["completed_at"] = time.time()
    return {"ok": True}


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


async def run_scrape(job_id: str, user_id: str, account_id: str, group_id: str, filters: dict, proxy: Optional[dict]):
    job = jobs[job_id]
    try:
        client = await get_client(user_id, account_id, proxy)
        entity = await client.get_entity(int(group_id) if group_id.lstrip("-").isdigit() else group_id)

        offset = 0
        all_members = []
        while True:
            if job["cancelled"]:
                return
            participants = await client(GetParticipantsRequest(
                channel=entity, filter=ChannelParticipantsSearch(""), offset=offset, limit=200, hash=0
            ))
            if not participants.users:
                break
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
            offset += len(participants.users)
            job["progress"] = len(all_members)
            await asyncio.sleep(random.uniform(1, 3))

        job["members"] = all_members
        job["total"] = len(all_members)
        job["progress"] = len(all_members)
        job["status"] = "completed"
        job["completed_at"] = time.time()
        log.info(f"Scrape {job_id}: {len(all_members)} members collected")

    except FloodWaitError as e:
        job["status"] = "failed"
        job["error"] = f"Flood wait: retry after {e.seconds}s"
        job["completed_at"] = time.time()
    except ChatAdminRequiredError:
        job["status"] = "failed"
        job["error"] = "Admin access required for this group"
        job["completed_at"] = time.time()
    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)[:500]
        job["completed_at"] = time.time()
        log.error(f"Scrape {job_id} failed: {e}")


async def run_add(job_id: str, user_id: str, account_id: str, target_group: str, source_job_id: str, proxy: Optional[dict]):
    job = jobs[job_id]
    try:
        source_job = jobs.get(source_job_id)
        if not source_job or not source_job.get("members"):
            job["status"] = "failed"
            job["error"] = "Source collection not found or empty"
            job["completed_at"] = time.time()
            return

        members = source_job["members"]
        job["total"] = len(members)

        client = await get_client(user_id, account_id, proxy)
        entity = await client.get_entity(int(target_group) if target_group.lstrip("-").isdigit() else target_group)

        added_count = 0
        adds_since_pause = 0

        for i, member in enumerate(members):
            if job["cancelled"]:
                job["status"] = "cancelled"
                job["completed_at"] = time.time()
                return

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
                    first_name=member.get("first_name", "User"),
                    last_name=member.get("last_name", "")
                )

                # Try direct invite first (uses AccessHash — lower friction)
                try:
                    await client(InviteToChannelRequest(channel=entity, users=[input_user]))
                    added_count += 1
                    job["added"] = added_count
                except (UserNotMutualContactError, UserPrivacyRestrictedError):
                    # Fall back to contact-add trick
                    try:
                        import_result = await client(ImportContactsRequest([contact]))
                        if import_result.imported:
                            imported_user = import_result.users[0]
                            await client(InviteToChannelRequest(channel=entity, users=[imported_user]))
                            await client(DeleteContactsRequest(id=[imported_user]))
                            added_count += 1
                            job["added"] = added_count
                        else:
                            job["skipped"] += 1
                    except Exception:
                        job["skipped"] += 1
                except ChatWriteForbiddenError:
                    job["status"] = "failed"
                    job["error"] = "Cannot write to this group. Check admin permissions."
                    job["completed_at"] = time.time()
                    return

                adds_since_pause += 1
                job["progress"] = i + 1

                # Strategy 1: Rotation threshold — stop and signal rotation needed
                if adds_since_pause >= ROTATION_THRESHOLD:
                    log.info(f"Rotation threshold reached ({ROTATION_THRESHOLD}). Pausing for account rotation.")
                    await batch_pause()
                    adds_since_pause = 0

                # Strategy 2: Human-like micro-delay with jitter
                await human_delay()

            except PeerFloodError as e:
                job["status"] = "failed"
                job["error"] = f"Peer flood: account restricted. Wait {getattr(e, 'seconds', '?')}s before retrying."
                job["completed_at"] = time.time()
                log.warning(f"PeerFlood on job {job_id} after {added_count} adds")
                return
            except FloodWaitError as e:
                log.info(f"FloodWait {e.seconds}s on job {job_id}, sleeping...")
                await asyncio.sleep(e.seconds + 5)
                continue
            except (UserPrivacyRestrictedError, ChatWriteForbiddenError):
                job["skipped"] += 1
                continue
            except Exception as e:
                job["failed"] += 1
                log.warning(f"Add failed for {member.get('username', member['id'])}: {e}")
                continue

        job["status"] = "completed"
        job["completed_at"] = time.time()
        log.info(f"Add {job_id}: {added_count} added, {job['skipped']} skipped, {job['failed']} failed")

    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)[:500]
        job["completed_at"] = time.time()
        log.error(f"Add {job_id} failed: {e}")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
