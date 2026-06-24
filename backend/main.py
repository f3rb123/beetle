from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
import asyncio
import logging
import os

# Suppress androguard's loguru-based DEBUG spam before any analyzer imports it.
# Under heavy AXML parsing it emits tens of thousands of lines per APK and can
# stall the scan through Docker's log driver.
os.environ.setdefault("LOGURU_LEVEL", "ERROR")
try:
    from loguru import logger as _loguru
    _loguru.remove()
    _loguru.add(lambda _m: None, level="ERROR")
except Exception:
    pass
for _name in ("androguard", "androguard.core", "androguard.core.axml",
              "androguard.core.apk", "androguard.core.analysis"):
    logging.getLogger(_name).setLevel(logging.ERROR)
from pathlib import Path
from queue import Queue
from threading import Lock, Thread
import traceback
import uuid

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from analyzers.android_analyzer import analyze_apk
from analyzers.ios_analyzer import analyze_ipa
from json_utils import safe_results
from report.pdf_generator import generate_pdf
from report.compliance_pdf import generate_compliance_pdf, FRAMEWORKS as COMPLIANCE_FRAMEWORKS
from report.sbom_generator import generate_sbom_json
from policy import check_policy, get_policy, init_policy_db, set_policy
init_policy_db()
from audit import get_audit_log, init_audit_db, log_event as _audit
init_audit_db()
from custom_rules import (
    create_rule, delete_rule, get_rule, get_rules_for_scanner,
    init_custom_rules_db, list_rules, update_rule,
)
init_custom_rules_db()
from sarif_exporter import results_to_sarif_json
from webhooks import (
    build_scan_summary, create_webhook, delete_webhook, fire_scan_event,
    init_webhooks_db, list_webhooks, update_webhook,
)
init_webhooks_db()

try:
    from ai_enrichment import AI_AVAILABLE, enrich_finding, enrich_findings_batch, init_ai_db
    init_ai_db()
except Exception as _ai_err:
    AI_AVAILABLE = False
    def enrich_finding(*a, **kw): return {"error": f"AI module unavailable: {_ai_err}", "cached": False}
    def enrich_findings_batch(*a, **kw): return []

try:
    import ai_actions
    ai_actions.init_ai_actions_db()
except Exception as _aia_err:
    ai_actions = None
    logging.getLogger("cortex").warning("ai_actions unavailable: %s", _aia_err)

try:
    import ai_chat
    from database import (
        create_conversation, list_conversations, get_conversation,
        rename_conversation, delete_conversation,
    )
except Exception as _chat_err:
    ai_chat = None
    logging.getLogger("cortex").warning("ai_chat unavailable: %s", _chat_err)
    log_msg = f"[main] AI enrichment unavailable: {_ai_err}"

try:
    from auth import (
        AUTH_AVAILABLE,
        authenticate_user,
        change_password,
        create_access_token,
        create_api_key,
        create_user,
        get_current_user_from_token,
        init_auth_db,
        list_api_keys,
        list_users,
        revoke_api_key,
        role_at_least,
        set_user_active,
    )
    if AUTH_AVAILABLE:
        init_auth_db()
except Exception as _auth_err:
    AUTH_AVAILABLE = False
    print(f"[main] Auth unavailable: {_auth_err}")
    def role_at_least(role, minimum): return True  # fail-open only when auth itself is down

try:
    from database import (
        add_scan_note,
        compare_scans,
        delete_scan,
        delete_scan_note,
        get_scan_findings,
        get_scan_history,
        get_scan_notes,
        get_scan_results,
        get_triage,
        set_triage,
        init_db,
        save_scan,
        update_scan_note,
        restore_scans_on_startup,
        cleanup_workspace,
        export_workspace,
        import_workspace,
    )

    DB_AVAILABLE = True
except Exception as db_error:
    DB_AVAILABLE = False
    print(f"[main] DB unavailable: {db_error}")
    def get_triage(scan_id): return {}
    def set_triage(scan_id, finding_key, state, note="", triaged_by=""): return {}

try:
    import collaboration as collab
    COLLAB_AVAILABLE = DB_AVAILABLE
except Exception as _collab_err:
    COLLAB_AVAILABLE = False
    print(f"[main] Collaboration layer unavailable: {_collab_err}")

try:
    from decompiler import decompile_apk, get_file_content, inspect_file, list_source_files

    DECOMPILER_AVAILABLE = True
except Exception as decompiler_error:
    DECOMPILER_AVAILABLE = False
    print(f"[main] Decompiler unavailable: {decompiler_error}")

try:
    from analyzers.scan_storage import cleanup_expired as _scan_cleanup_expired
except Exception:
    def _scan_cleanup_expired(*a, **kw): return 0

logging.basicConfig(level=logging.INFO, format="[%(name)s] %(levelname)s %(message)s")
log = logging.getLogger("cortex")

app = FastAPI(
    title="Beetle API",
    description="Mobile Recon Framework",
    version="3.2.0",
)

# CORS — explicit allow-list when credentials are on. The old `["*"]` combined
# with `allow_credentials=True` is rejected by browsers AND is a CSRF footgun.
# Override via `CORTEX_CORS_ORIGINS` (comma-separated) in production.
_cors_env = os.environ.get("CORTEX_CORS_ORIGINS", "").strip()
if _cors_env:
    _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
else:
    _cors_origins = [
        "http://localhost:9005",
        "http://localhost:5173",
        "http://127.0.0.1:9005",
        "http://127.0.0.1:5173",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)

UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/tmp/cortex/uploads"))
REPORT_DIR = Path(os.environ.get("REPORT_DIR", "/tmp/cortex/reports"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SCAN_JOBS: dict[str, dict] = {}
SCAN_JOBS_LOCK = Lock()

# Bounded concurrent scan queue
_MAX_CONCURRENT_SCANS = int(os.environ.get("CORTEX_MAX_CONCURRENT_SCANS", "3"))
_SCAN_QUEUE: list[str] = []          # ordered list of queued scan_ids
_SCAN_QUEUE_LOCK = Lock()
_SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=_MAX_CONCURRENT_SCANS, thread_name_prefix="cortex-scan")


def _queue_position(scan_id: str) -> int | None:
    """Return 1-based queue position, or None if not queued."""
    with _SCAN_QUEUE_LOCK:
        try:
            return _SCAN_QUEUE.index(scan_id) + 1
        except ValueError:
            return None


def _submit_scan(scan_id: str, *args) -> None:
    """Enqueue scan_id, submit to executor, update job with queue position."""
    with _SCAN_QUEUE_LOCK:
        _SCAN_QUEUE.append(scan_id)

    def _run():
        with _SCAN_QUEUE_LOCK:
            try:
                _SCAN_QUEUE.remove(scan_id)
            except ValueError:
                pass
        _run_scan_job(scan_id, *args)

    _SCAN_EXECUTOR.submit(_run)

    pos = _queue_position(scan_id)
    if pos:
        _update_scan_job(scan_id, queue_position=pos, message=f"Queued — position {pos}")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "")


def _update_scan_job(scan_id: str, **changes) -> dict:
    with SCAN_JOBS_LOCK:
        current = dict(SCAN_JOBS.get(scan_id, {}))
        if "created_at" not in current:
            current["created_at"] = _utcnow()
        current.update(changes)
        current["scan_id"] = scan_id
        current["updated_at"] = _utcnow()
        SCAN_JOBS[scan_id] = current
        return dict(current)


def _get_scan_job(scan_id: str) -> dict | None:
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        return dict(job) if job else None


def _scan_status_response(scan_id: str) -> dict | None:
    job = _get_scan_job(scan_id)
    if job:
        return job

    if DB_AVAILABLE:
        try:
            results = get_scan_results(scan_id)
            if results:
                safe = safe_results(results)
                return {
                    "scan_id": scan_id,
                    "status": "completed",
                    "stage": "completed",
                    "progress": 100,
                    "message": "Analysis complete",
                    "app_name": safe.get("app_name") or safe.get("filename") or scan_id,
                    "filename": safe.get("filename"),
                    "platform": safe.get("platform"),
                    "findings_count": len(safe.get("findings", [])),
                    "result": safe,
                    "created_at": safe.get("scan_time") or _utcnow(),
                    "updated_at": _utcnow(),
                }
        except Exception as e:
            log.warning(f"[{scan_id}] Failed to read completed scan from DB: {e}")

    return None


# ─── Auth helpers ─────────────────────────────────────────────────────────────
_bearer = HTTPBearer(auto_error=False)


def _require_auth(credentials: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    if not AUTH_AVAILABLE:
        # Fail closed. If the operator intentionally wants an unauthenticated
        # deployment (local dev, CI container), they must opt in explicitly.
        if os.environ.get("CORTEX_ALLOW_ANONYMOUS", "").lower() not in ("1", "true", "yes"):
            raise HTTPException(status_code=503,
                detail="Authentication subsystem unavailable. Set CORTEX_ALLOW_ANONYMOUS=1 to permit anonymous access for local dev.")
        return {"username": "anonymous", "role": "analyst"}
    header = f"Bearer {credentials.credentials}" if credentials else None
    user = get_current_user_from_token(header)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or missing authentication token")
    return user


def _require_admin(user: dict = Depends(_require_auth)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def _require_writer(user: dict = Depends(_require_auth)) -> dict:
    """Any role except read-only may mutate collaboration data
    (triage, comments, assignments)."""
    if not role_at_least(user.get("role"), "analyst"):
        raise HTTPException(status_code=403, detail="Read-only role cannot modify findings")
    return user


def _require_manager(user: dict = Depends(_require_auth)) -> dict:
    """Manager+ for workspace-wide controls (suppressions, sharing)."""
    if not role_at_least(user.get("role"), "manager"):
        raise HTTPException(status_code=403, detail="Manager or admin role required")
    return user


def _collab_unavailable():
    raise HTTPException(status_code=503, detail="Collaboration layer unavailable")


def _auth_unavailable():
    raise HTTPException(status_code=503, detail="Auth dependencies not installed on server")


# ─── Auth endpoints ───────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(request: Request):
    if not AUTH_AVAILABLE:
        _auth_unavailable()
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password required")
    user = authenticate_user(username, password)
    if not user:
        _audit("auth.login", actor=username, detail={"outcome": "failure"}, ip=_client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user["username"], user["role"])
    _audit("auth.login", actor=user["username"], detail={"outcome": "success", "role": user["role"]}, ip=_client_ip(request))
    return {"access_token": token, "token_type": "bearer", "role": user["role"], "username": user["username"]}


@app.get("/api/auth/me")
async def get_me(user: dict = Depends(_require_auth)):
    return user


@app.post("/api/auth/change-password")
async def api_change_password(request: Request, user: dict = Depends(_require_auth)):
    if not AUTH_AVAILABLE:
        _auth_unavailable()
    body = await request.json()
    new_password = body.get("new_password", "")
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    try:
        change_password(user["username"], new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"message": "Password updated"}


# ─── User management (admin only) ─────────────────────────────────────────────
@app.get("/api/users")
async def api_list_users(_admin: dict = Depends(_require_admin)):
    if not AUTH_AVAILABLE:
        _auth_unavailable()
    return list_users()


@app.post("/api/users")
async def api_create_user(request: Request, _admin: dict = Depends(_require_admin)):
    if not AUTH_AVAILABLE:
        _auth_unavailable()
    body = await request.json()
    try:
        user = create_user(
            username=body.get("username", ""),
            password=body.get("password", ""),
            role=body.get("role", "analyst"),
            email=body.get("email", ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit("user.created", actor=_admin.get("username",""),
           detail={"new_user": user.get("username",""), "role": user.get("role","")})
    return user


@app.patch("/api/users/{username}/active")
async def api_set_user_active(username: str, request: Request, _admin: dict = Depends(_require_admin)):
    if not AUTH_AVAILABLE:
        _auth_unavailable()
    body = await request.json()
    active = bool(body.get("active", True))
    set_user_active(username, active)
    _audit("user.activated", actor=_admin.get("username",""),
           detail={"target": username, "active": active})
    return {"username": username, "active": active}


# ─── API key management ────────────────────────────────────────────────────────
@app.post("/api/auth/api-keys")
async def api_create_key(request: Request, user: dict = Depends(_require_auth)):
    if not AUTH_AVAILABLE:
        _auth_unavailable()
    body = await request.json()
    label = body.get("label", "")
    role = body.get("role", user.get("role", "analyst"))
    # Analysts can only create analyst-role keys
    if user.get("role") != "admin":
        role = "analyst"
    raw = create_api_key(user["username"], label=label, role=role)
    _audit("auth.key_created", actor=user["username"],
           detail={"label": label, "role": role, "prefix": raw[:8]})
    return {"key": raw, "label": label, "note": "Store this key — it will not be shown again"}


@app.get("/api/auth/api-keys")
async def api_list_keys(user: dict = Depends(_require_auth)):
    if not AUTH_AVAILABLE:
        _auth_unavailable()
    return list_api_keys(user["username"])


@app.delete("/api/auth/api-keys/{key_id}")
async def api_revoke_key(key_id: int, user: dict = Depends(_require_auth)):
    if not AUTH_AVAILABLE:
        _auth_unavailable()
    revoke_api_key(key_id, user["username"])
    _audit("auth.key_revoked", actor=user["username"], detail={"key_id": key_id})
    return {"message": "Key revoked"}


# ─── Webhook endpoints (admin only) ───────────────────────────────────────────
@app.get("/api/webhooks")
async def api_list_webhooks(_admin: dict = Depends(_require_admin)):
    return list_webhooks()


@app.post("/api/webhooks")
async def api_create_webhook(request: Request, _admin: dict = Depends(_require_admin)):
    body = await request.json()
    try:
        wh = create_webhook(
            label=body.get("label", ""),
            url=body.get("url", ""),
            type_=body.get("type", "generic"),
            events=body.get("events", ["scan.completed"]),
            secret=body.get("secret", ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return wh


@app.patch("/api/webhooks/{wid}")
async def api_update_webhook(wid: int, request: Request, _admin: dict = Depends(_require_admin)):
    body = await request.json()
    try:
        wh = update_webhook(wid, **body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if wh is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return wh


@app.delete("/api/webhooks/{wid}")
async def api_delete_webhook(wid: int, _admin: dict = Depends(_require_admin)):
    delete_webhook(wid)
    return {"message": "Webhook deleted"}


@app.post("/api/webhooks/{wid}/test")
async def api_test_webhook(wid: int, _admin: dict = Depends(_require_admin)):
    """Send a test payload to a webhook."""
    wh_list = list_webhooks()
    wh = next((w for w in wh_list if w["id"] == wid), None)
    if wh is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    # Fetch full row including secret (list_webhooks strips it)
    from webhooks import _conn as _wh_conn, _deliver
    with _wh_conn() as _c:
        _row = _c.execute("SELECT * FROM webhooks WHERE id = ?", (wid,)).fetchone()
    if not _row:
        raise HTTPException(status_code=404, detail="Webhook not found")
    wh_full = dict(_row)

    test_summary = {
        "scan_id":   "test-00000000",
        "app_name":  "TestApp",
        "platform":  "android",
        "status":    "completed",
        "score":     72,
        "grade":     "C",
        "findings_by_severity": {"critical": 0, "high": 2, "medium": 5, "low": 3},
        "report_url": "",
    }
    try:
        _deliver(wh_full, "scan.completed", test_summary)
        return {"message": "Test payload delivered successfully"}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Delivery failed: {str(e)}")


# ─── AI Enrichment endpoints ──────────────────────────────────────────────────
@app.get("/api/ai/status")
async def ai_status(_user: dict = Depends(_require_auth)):
    """Check whether AI enrichment is available."""
    return {"available": AI_AVAILABLE, "model": "claude-haiku-4-5-20251001"}


@app.get("/api/ai/providers")
async def ai_providers(_user: dict = Depends(_require_auth)):
    """List AI providers and their availability (drives the UI selector).
    Unavailable providers are returned too, so the UI can disable them."""
    if ai_actions is None:
        return {"providers": [], "any_available": False}
    provs = ai_actions.list_providers()
    return {"providers": provs, "any_available": any(p.get("available") for p in provs)}


@app.post("/api/ai/action")
async def ai_action(request: Request, _user: dict = Depends(_require_auth)):
    """Run one AI finding-action.
    Body: { action, provider?, model?, finding?, results? }
    action ∈ explain | verify | worth_testing | generate_poc | generate_fix | summary

    Offline-safe: with no provider configured it returns a deterministic,
    evidence-only result (mode='deterministic'). Never suppresses a finding."""
    if ai_actions is None:
        raise HTTPException(503, detail="AI actions module unavailable")
    body = await request.json()
    action = (body.get("action") or "").strip()
    if action not in ai_actions.ACTIONS:
        raise HTTPException(400, detail=f"Unknown action. Valid: {list(ai_actions.ACTIONS)}")
    result = ai_actions.run_action(
        action,
        finding=body.get("finding") or {},
        results=body.get("results") or {},
        provider_name=body.get("provider"),
        model=body.get("model"),
        use_cache=bool(body.get("use_cache", True)),
    )
    return JSONResponse(content=result)


# ─── Ask-AI conversational workspace (Phase 11.98) ───────────────────────────
def _load_results_for(scan_id: str) -> dict:
    """Resolve a scan's full results from the persistent store, then in-memory."""
    res = get_scan_results(scan_id) if DB_AVAILABLE else None
    if not res:
        payload = _scan_status_response(scan_id)
        res = (payload or {}).get("result") if payload else None
    return res or {}


@app.post("/api/ai/chat")
async def ai_chat_message(request: Request, _user: dict = Depends(_require_auth)):
    """Send a conversational question about a scan.
    Body: { scan_id, question, chat_id?, finding_ids?, provider?, model? }
    Offline-safe: returns a deterministic, evidence-only answer when no provider
    is configured. Persists the conversation (survives restart)."""
    if ai_chat is None:
        raise HTTPException(503, detail="AI chat module unavailable")
    body = await request.json()
    scan_id = (body.get("scan_id") or "").strip()
    question = (body.get("question") or "").strip()
    if not scan_id or not question:
        raise HTTPException(400, detail="scan_id and question are required")
    results = _load_results_for(scan_id)
    if not results:
        raise HTTPException(404, detail=f"Scan {scan_id} not found")
    from starlette.concurrency import run_in_threadpool
    env = await run_in_threadpool(
        ai_chat.send_message,
        scan_id=scan_id, question=question, results=results,
        chat_id=body.get("chat_id"), finding_ids=body.get("finding_ids") or [],
        provider_name=body.get("provider"), model=body.get("model"),
    )
    return JSONResponse(content=env)


@app.get("/api/ai/chats")
async def ai_list_chats(scan_id: str = Query(...), _user: dict = Depends(_require_auth)):
    if ai_chat is None:
        return JSONResponse(content={"conversations": []})
    return JSONResponse(content={"conversations": list_conversations(scan_id)})


@app.get("/api/ai/chats/{chat_id}")
async def ai_get_chat(chat_id: str, _user: dict = Depends(_require_auth)):
    if ai_chat is None:
        raise HTTPException(503, detail="AI chat module unavailable")
    convo = get_conversation(chat_id)
    if not convo:
        raise HTTPException(404, detail="Conversation not found")
    return JSONResponse(content=convo)


@app.patch("/api/ai/chats/{chat_id}")
async def ai_rename_chat(chat_id: str, request: Request, _user: dict = Depends(_require_auth)):
    if ai_chat is None:
        raise HTTPException(503, detail="AI chat module unavailable")
    body = await request.json()
    rename_conversation(chat_id, (body.get("title") or "").strip())
    return JSONResponse(content={"chat_id": chat_id, "title": body.get("title")})


@app.delete("/api/ai/chats/{chat_id}")
async def ai_delete_chat(chat_id: str, _user: dict = Depends(_require_auth)):
    if ai_chat is None:
        raise HTTPException(503, detail="AI chat module unavailable")
    delete_conversation(chat_id)
    return JSONResponse(content={"deleted": chat_id})


@app.post("/api/ai/enrich")
async def ai_enrich_finding(request: Request, _user: dict = Depends(_require_auth)):
    """
    Enrich a single finding with AI-generated exploit scenario and remediation.
    Body: { finding: {...}, app_context: { platform, framework, package } }
    """
    body = await request.json()
    finding     = body.get("finding")
    app_context = body.get("app_context", {})

    if not finding:
        raise HTTPException(400, detail="Missing 'finding' in request body")

    result = enrich_finding(finding, app_context)

    if "error" in result and not result.get("cached"):
        # Don't 500 — return the error in the response body so the UI can handle it
        return JSONResponse(status_code=200, content=result)

    return result


@app.post("/api/ai/enrich-batch")
async def ai_enrich_batch(request: Request, _user: dict = Depends(_require_auth)):
    """
    Enrich up to 20 findings (prioritised by severity).
    Body: { findings: [...], app_context: {...}, max_findings: 10 }
    """
    body        = await request.json()
    findings    = body.get("findings", [])
    app_context = body.get("app_context", {})
    max_f       = min(int(body.get("max_findings", 10)), 20)

    if not findings:
        return []

    results = enrich_findings_batch(findings, app_context, max_findings=max_f)
    return results


# ─── Policy / CI Gate endpoints ──────────────────────────────────────────────

@app.get("/api/audit")
async def api_get_audit(
    limit: int = Query(100, ge=1, le=500),
    event: str = Query(""),
    actor: str = Query(""),
    _user: dict = Depends(_require_admin),
):
    """Return recent audit log entries (admin only)."""
    entries = get_audit_log(limit=limit, event_filter=event, actor_filter=actor)
    return JSONResponse(content={"entries": entries, "count": len(entries)})


@app.get("/api/rules")
async def api_list_rules(
    platform: str = Query(""),
    enabled_only: bool = Query(False),
    _user: dict = Depends(_require_auth),
):
    """List custom SAST rules."""
    return list_rules(platform=platform, enabled_only=enabled_only)


@app.post("/api/rules")
async def api_create_rule(request: Request, _user: dict = Depends(_require_admin)):
    """Create a custom SAST rule (admin only)."""
    body = await request.json()
    try:
        rule = create_rule(body, created_by=_user.get("username", ""))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    _audit("rule.created", actor=_user.get("username", ""), detail={"rule_id": rule["rule_id"], "title": rule["title"]})
    return rule


@app.get("/api/rules/{rule_id}")
async def api_get_rule(rule_id: str, _user: dict = Depends(_require_auth)):
    """Get a single custom SAST rule."""
    rule = get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@app.put("/api/rules/{rule_id}")
async def api_update_rule(rule_id: str, request: Request, _user: dict = Depends(_require_admin)):
    """Update a custom SAST rule (admin only)."""
    body = await request.json()
    try:
        rule = update_rule(rule_id, body)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    _audit("rule.updated", actor=_user.get("username", ""), detail={"rule_id": rule_id})
    return rule


@app.delete("/api/rules/{rule_id}")
async def api_delete_rule(rule_id: str, _user: dict = Depends(_require_admin)):
    """Delete a custom SAST rule (admin only)."""
    if not delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    _audit("rule.deleted", actor=_user.get("username", ""), detail={"rule_id": rule_id})
    return {"deleted": True}


@app.get("/api/policy")
async def api_get_policy(_user: dict = Depends(_require_auth)):
    """Return the current scan policy thresholds."""
    return get_policy()


@app.put("/api/policy")
async def api_set_policy(request: Request, _user: dict = Depends(_require_admin)):
    """Update scan policy thresholds (admin only)."""
    body = await request.json()
    updated = set_policy(body)
    _audit("policy.updated", actor=_user.get("username",""), detail={"changes": body})
    return updated


@app.post("/api/policy/check")
async def api_check_policy(request: Request, _user: dict = Depends(_require_auth)):
    """
    Evaluate scan results against the current policy.
    Body: { results: {...}, overrides: { max_critical: 0, ... } }
    Returns: { passed, verdict, score, reasons, policy, summary }
    """
    body      = await request.json()
    results   = body.get("results") or body
    overrides = body.get("overrides") or {}
    verdict   = check_policy(results, overrides if overrides else None)
    status    = 200 if verdict["passed"] else 422
    return JSONResponse(content=verdict, status_code=status)


def _run_scan_job(
    scan_id: str,
    file_path: Path,
    filename: str,
    ext: str,
    use_jadx: bool,
    use_apktool: bool,
):
    try:
        _update_scan_job(
            scan_id,
            status="running",
            stage="preparing",
            progress=10,
            message="Preparing package",
            filename=filename,
            platform="ios" if ext == ".ipa" else "android",
        )

        jadx_dir = None
        apktool_dir = None
        decompile_info = {"tools_used": [], "errors": [], "jadx_dir": None, "apktool_dir": None}

        if ext == ".apk" and DECOMPILER_AVAILABLE and (use_jadx or use_apktool):
            try:
                _update_scan_job(
                    scan_id,
                    stage="decompiling",
                    progress=34,
                    message="Decompiling and indexing",
                )
                log.info(f"[{scan_id}] Decompiling...")
                info = decompile_apk(str(file_path), scan_id)
                jadx_dir = info.get("jadx_dir")
                apktool_dir = info.get("apktool_dir")
                decompile_info = info
                log.info(f"[{scan_id}] Decompile done: {info.get('tools_used', [])}")
            except Exception as e:
                log.warning(f"[{scan_id}] Decompile error: {e}")
                decompile_info["errors"].append(str(e))

        _update_scan_job(
            scan_id,
            stage="analyzing",
            progress=68,
            message="Running static analysis",
        )

        if ext == ".apk":
            results = analyze_apk(
                str(file_path),
                scan_id,
                filename,
                jadx_dir=jadx_dir,
                apktool_dir=apktool_dir,
            )
        else:
            results = analyze_ipa(str(file_path), scan_id, filename)

        results["decompile_info"] = decompile_info

        _update_scan_job(
            scan_id,
            stage="finalizing",
            progress=92,
            message="Finalizing results",
        )

        clean = safe_results(results)

        if DB_AVAILABLE:
            try:
                save_scan(clean)
            except Exception as e:
                log.warning(f"[{scan_id}] DB save failed: {e}")

        _update_scan_job(
            scan_id,
            status="completed",
            stage="completed",
            progress=100,
            message="Analysis complete",
            result=clean,
            findings_count=len(clean.get("findings", [])),
            app_name=clean.get("app_name") or filename,
        )
        log.info(f"[{scan_id}] Done - {len(clean.get('findings', []))} findings")
        _audit("scan.completed", scan_id=scan_id, detail={
            "score": clean.get("score", {}).get("score"),
            "findings": len(clean.get("findings", [])),
            "platform": clean.get("platform", ""),
        })
        try:
            fire_scan_event("scan.completed", build_scan_summary(clean))
        except Exception:
            pass
    except Exception as e:
        detail = f"Analysis error: {str(e)}"
        log.error(f"[{scan_id}] Analysis failed: {e}\n{traceback.format_exc()}")
        _update_scan_job(
            scan_id,
            status="failed",
            stage="failed",
            message=detail,
            detail=detail,
        )
        try:
            fire_scan_event("scan.failed", {"scan_id": scan_id, "status": "failed", "error": detail})
        except Exception:
            pass
    finally:
        try:
            file_path.unlink(missing_ok=True)
        except Exception:
            pass
        # Opportunistic cleanup of stale scan dirs. Cheap (just stats dir mtimes).
        try:
            _scan_cleanup_expired()
        except Exception:
            pass


@app.on_event("startup")
async def startup():
    if DB_AVAILABLE:
        try:
            init_db()
            log.info("Database initialized")
        except Exception as e:
            log.warning(f"DB init failed: {e}")
        # Phase 11.99: restore persisted scans; mark any with a missing
        # results.json as BROKEN (never crash on startup).
        try:
            summary = restore_scans_on_startup()
            log.info(f"Restored {summary['ok']}/{summary['total']} scans "
                     f"({summary['broken']} broken)")
        except Exception as e:
            log.warning(f"Scan restore failed: {e}")
        if COLLAB_AVAILABLE:
            try:
                collab.init_collab_db()
                log.info("Collaboration layer initialized")
            except Exception as e:
                log.warning(f"Collab init failed: {e}")
    # Best-effort cleanup of stale scan extractions at startup. This also runs
    # after each scan completes (see _run_scan_job's finally clause).
    try:
        removed = _scan_cleanup_expired()
        if removed:
            log.info(f"Cleaned up {removed} expired scan directories")
    except Exception as e:
        log.warning(f"Scan cleanup failed: {e}")

    # User-facing access banner. The backend binds 0.0.0.0:9005; nginx serves the
    # SPA on the same port and reverse-proxies /api to it. Print the real URL last
    # so `docker compose logs backend` ends with the address users should open.
    log.info("=" * 56)
    log.info("  Beetle is ready  →  open  http://localhost:9005")
    log.info("=" * 56)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log full traceback server-side; return an opaque error to the client
    # so we don't leak file paths, internal class names, or stack details.
    log.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}\n{traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.exception_handler(HTTPException)
async def custom_http_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/api/health")
async def health():
    tools = {}
    if DECOMPILER_AVAILABLE:
        try:
            from decompiler import apktool_available, jadx_available

            tools = {"jadx": jadx_available(), "apktool": apktool_available()}
        except Exception:
            tools = {"jadx": False, "apktool": False}
    return JSONResponse(
        content={
            "status": "ok",
            "tool": "Beetle",
            "version": "3.2.0",
            "db": DB_AVAILABLE,
            "tools": tools,
        }
    )


@app.post("/api/analyze")
async def analyze(
    request: Request,
    file: UploadFile = File(...),
    use_jadx: bool = Query(True),
    use_apktool: bool = Query(True),
    _user: dict = Depends(_require_auth),
):
    if not file.filename:
        raise HTTPException(400, detail="No file provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in [".apk", ".ipa"]:
        raise HTTPException(400, detail="Only APK and IPA files are supported")

    scan_id = str(uuid.uuid4())
    file_path = UPLOAD_DIR / f"{scan_id}{ext}"

    try:
        content = await file.read()
        if not content:
            raise HTTPException(400, detail="Empty file uploaded")
        if len(content) > 200 * 1024 * 1024:
            raise HTTPException(400, detail="File exceeds 200MB limit")

        with open(file_path, "wb") as f:
            f.write(content)

        log.info(f"[{scan_id}] Queued {file.filename} ({len(content)//1024}KB)")
        job = _update_scan_job(
            scan_id,
            status="queued",
            stage="queued",
            progress=6,
            message="Upload received",
            filename=file.filename,
            platform="ios" if ext == ".ipa" else "android",
        )

        _submit_scan(scan_id, file_path, file.filename, ext, use_jadx, use_apktool)
        # Refresh job dict to pick up queue_position if set by _submit_scan
        with SCAN_JOBS_LOCK:
            job = dict(SCAN_JOBS.get(scan_id, job))
        _audit("scan.started", actor=_user.get("username",""), scan_id=scan_id,
               detail={"filename": file.filename, "platform": job.get("platform","")},
               ip=_client_ip(request))
        return JSONResponse(status_code=202, content=job)
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"[{scan_id}] Queue failed: {e}\n{traceback.format_exc()}")
        raise HTTPException(500, detail=f"Failed to queue analysis: {str(e)}")


@app.get("/api/queue")
async def get_queue_status(_user: dict = Depends(_require_auth)):
    """Return current scan queue state."""
    with _SCAN_QUEUE_LOCK:
        queued = list(_SCAN_QUEUE)
    running = [
        sid for sid, job in list(SCAN_JOBS.items())
        if job.get("status") not in ("completed", "failed", "queued")
    ]
    return {
        "max_concurrent": _MAX_CONCURRENT_SCANS,
        "queued_count":   len(queued),
        "running_count":  len(running),
        "queued":  queued,
        "running": running,
    }


@app.get("/api/scans/{scan_id}/status")
async def get_scan_status(scan_id: str, _user: dict = Depends(_require_auth)):
    payload = _scan_status_response(scan_id)
    if not payload:
        raise HTTPException(404, detail=f"Scan {scan_id} not found")
    return JSONResponse(content=payload)


@app.get("/api/scans/{scan_id}/stream")
async def stream_scan_status(scan_id: str, _user: dict = Depends(_require_auth)):
    """
    Server-Sent Events stream for real-time scan progress.

    Emits data frames at ~400ms intervals while the scan is running.
    Sends a heartbeat comment (': ping') every 5 s to keep the connection
    alive through proxies and load-balancers.
    Closes automatically when status reaches 'completed' or 'failed'.
    """
    import json as _json

    async def _generate():
        heartbeat_counter = 0
        _SSE_INTERVAL   = 0.4   # seconds between data frames
        _HEARTBEAT_EVERY = 12   # frames between heartbeat pings (≈5 s)
        _MAX_FRAMES     = 900   # ~6 min hard cap

        for _ in range(_MAX_FRAMES):
            payload = _scan_status_response(scan_id)

            if payload is None:
                yield f"data: {_json.dumps({'status': 'not_found', 'scan_id': scan_id})}\n\n"
                return

            # Strip full result blob from streaming frames to keep payload small.
            # The client fetches the full result separately once 'completed'.
            frame = {k: v for k, v in payload.items() if k != "result"}
            pos = _queue_position(scan_id)
            if pos:
                frame["queue_position"] = pos
            yield f"data: {_json.dumps(frame)}\n\n"

            if payload.get("status") in ("completed", "failed"):
                return

            heartbeat_counter += 1
            if heartbeat_counter >= _HEARTBEAT_EVERY:
                yield ": ping\n\n"
                heartbeat_counter = 0

            await asyncio.sleep(_SSE_INTERVAL)

        # Emit a timeout sentinel so the client can fall back to a regular fetch.
        yield f"data: {_json.dumps({'status': 'timeout', 'scan_id': scan_id})}\n\n"

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx proxy buffering
            "Connection":       "keep-alive",
        },
    )


@app.get("/api/scans")
async def list_scans(limit: int = Query(20, ge=1, le=100), _user: dict = Depends(_require_auth)):
    if not DB_AVAILABLE:
        return JSONResponse(content={"scans": [], "db_available": False})
    try:
        hist = get_scan_history(limit)
        return JSONResponse(content={"scans": hist["items"], "total": hist["total"], "db_available": True})
    except Exception as e:
        log.error(f"list_scans error: {e}")
        return JSONResponse(content={"scans": [], "error": str(e)})


@app.get("/api/scans/history")
async def scans_history(
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
    search: str = Query(""),
    sort: str = Query("created_at"),
    order: str = Query("desc"),
    _user: dict = Depends(_require_auth),
):
    """Paginated, searchable, sortable scan history (metadata only)."""
    if not DB_AVAILABLE:
        return JSONResponse(content={"items": [], "total": 0, "db_available": False})
    hist = get_scan_history(limit=limit, offset=offset, search=search, sort=sort, order=order)
    return JSONResponse(content={**hist, "db_available": True, "limit": limit, "offset": offset})


@app.get("/api/scans/compare")
async def compare_scans_endpoint(a: str = Query(...), b: str = Query(...), _user: dict = Depends(_require_auth)):
    """Diff two persisted scans (a=baseline, b=current)."""
    if not DB_AVAILABLE:
        raise HTTPException(503, detail="Database not available")
    return JSONResponse(content=compare_scans(a, b))


@app.post("/api/scans/cleanup")
async def scans_cleanup(_user: dict = Depends(_require_admin)):
    """Remove orphaned result dirs + broken records. Never deletes active scans."""
    if not DB_AVAILABLE:
        raise HTTPException(503, detail="Database not available")
    with SCAN_JOBS_LOCK:
        active = {sid for sid, job in SCAN_JOBS.items()
                  if job.get("status") not in ("completed", "failed")}
    return JSONResponse(content=cleanup_workspace(active_ids=active))


@app.post("/api/scans/export")
def scans_export(_user: dict = Depends(_require_auth)):
    """Export the whole workspace (results + reports + metadata) as a zip.

    Sync def so FastAPI runs the blocking zip build in a worker thread (never on
    the event loop). The zip is written to UPLOAD_DIR — NOT inside the results or
    reports dirs it bundles — so it can't recursively include itself."""
    if not DB_AVAILABLE:
        raise HTTPException(503, detail="Database not available")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    out = UPLOAD_DIR / f"workspace_{uuid.uuid4().hex}.zip"
    try:
        export_workspace(str(out), reports_dir=str(REPORT_DIR))
    except Exception as e:
        log.error(f"workspace export failed: {e}")
        raise HTTPException(500, detail="Workspace export failed")
    return FileResponse(str(out), media_type="application/zip", filename="workspace.zip")


@app.post("/api/scans/import")
async def scans_import(file: UploadFile = File(...), _user: dict = Depends(_require_admin)):
    """Import a previously-exported workspace.zip (idempotent — no duplicates)."""
    if not DB_AVAILABLE:
        raise HTTPException(503, detail="Database not available")
    from starlette.concurrency import run_in_threadpool
    tmp = UPLOAD_DIR / f"import_{uuid.uuid4().hex}.zip"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    try:
        content = await file.read()
        with open(tmp, "wb") as fh:
            fh.write(content)
        report = await run_in_threadpool(import_workspace, str(tmp))
        return JSONResponse(content=report)
    except Exception as e:
        log.error(f"workspace import failed: {e}")
        raise HTTPException(400, detail="Workspace import failed")
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, _user: dict = Depends(_require_auth)):
    if not DB_AVAILABLE:
        payload = _scan_status_response(scan_id)
        if payload and payload.get("result"):
            return JSONResponse(content=payload["result"])
        raise HTTPException(503, detail="Database not available")

    # Workspace sharing (point 6): a 'private' scan is visible only to its owner
    # or a manager/admin. 'shared'/'team' stay visible to all authenticated users
    # (preserving prior single-tenant behaviour).
    if COLLAB_AVAILABLE and not collab.can_view(scan_id, _user):
        raise HTTPException(403, detail="This workspace is private")

    results = get_scan_results(scan_id)
    if not results:
        payload = _scan_status_response(scan_id)
        if payload and payload.get("result"):
            return JSONResponse(content=payload["result"])
        raise HTTPException(404, detail=f"Scan {scan_id} not found")
    return JSONResponse(content=safe_results(results))


@app.get("/api/scans/{scan_id}/findings")
async def get_findings(scan_id: str, severity: str = None, _user: dict = Depends(_require_auth)):
    if not DB_AVAILABLE:
        raise HTTPException(503, detail="Database not available")
    findings = get_scan_findings(scan_id, severity)
    return JSONResponse(content={"findings": findings, "count": len(findings)})


@app.get("/api/scans/{scan_id}/triage")
async def get_scan_triage(scan_id: str, _user: dict = Depends(_require_auth)):
    """Return all triage states for a scan as {finding_key: {state, note, triaged_by, updated_at}}."""
    return JSONResponse(content=get_triage(scan_id))


@app.put("/api/scans/{scan_id}/triage/{finding_key:path}")
async def set_scan_triage(
    scan_id: str,
    finding_key: str,
    request: Request,
    user: dict = Depends(_require_auth),
):
    """
    Upsert triage state for one finding.
    Body: { state: 'open'|'in_progress'|'fixed'|'accepted_risk'|'false_positive', note?: str }
    """
    body  = await request.json()
    state = body.get("state", "open")
    note  = body.get("note", "")
    valid = {"open", "in_progress", "fixed", "accepted_risk", "false_positive"}
    if state not in valid:
        raise HTTPException(400, detail=f"state must be one of: {', '.join(sorted(valid))}")
    result = set_triage(
        scan_id, finding_key, state, note=note,
        triaged_by=user.get("username", ""),
    )
    _audit("triage.set", actor=user.get("username",""), scan_id=scan_id,
           detail={"finding_key": finding_key, "state": state})
    return JSONResponse(content=result)


@app.get("/api/scans/{scan_id}/notes")
async def get_notes(scan_id: str, _user: dict = Depends(_require_auth)):
    """Return all analyst notes for a scan."""
    if not DB_AVAILABLE:
        return JSONResponse(content=[])
    return JSONResponse(content=get_scan_notes(scan_id))


@app.post("/api/scans/{scan_id}/notes")
async def add_note(scan_id: str, request: Request, user: dict = Depends(_require_auth)):
    """Append an analyst note to a scan."""
    body = await request.json()
    text = (body.get("note") or "").strip()
    if not text:
        raise HTTPException(400, detail="note is required")
    if not DB_AVAILABLE:
        raise HTTPException(503, detail="Database not available")
    note = add_scan_note(scan_id, text, author=user.get("username", ""))
    return JSONResponse(content=note)


@app.put("/api/scans/{scan_id}/notes/{note_id}")
async def edit_note(scan_id: str, note_id: int, request: Request, _user: dict = Depends(_require_auth)):
    """Edit an existing analyst note."""
    body = await request.json()
    text = (body.get("note") or "").strip()
    if not text:
        raise HTTPException(400, detail="note is required")
    if not DB_AVAILABLE:
        raise HTTPException(503, detail="Database not available")
    updated = update_scan_note(note_id, text)
    if not updated:
        raise HTTPException(404, detail="Note not found")
    return JSONResponse(content=updated)


@app.delete("/api/scans/{scan_id}/notes/{note_id}")
async def delete_note(scan_id: str, note_id: int, _user: dict = Depends(_require_auth)):
    """Delete an analyst note."""
    if DB_AVAILABLE:
        delete_scan_note(note_id)
    return JSONResponse(content={"deleted": note_id})


# ─── Collaboration: finding states, assignment, comments ─────────────────────
# Everything below is keyed by the scan's app_id (package/bundle id) inside the
# collaboration layer, so states/comments/assignments survive a rescan of the
# same app (a new scan_id inherits them automatically).
def _app_id_for_scan(scan_id: str) -> str:
    res = get_scan_results(scan_id) or {}
    return collab.app_id_for(res) if res else "unknown-app"


@app.get("/api/scans/{scan_id}/collab")
async def get_collab(scan_id: str, _user: dict = Depends(_require_auth)):
    """One-shot snapshot: states, comments, suppressions, sharing + vocab."""
    if not COLLAB_AVAILABLE:
        return JSONResponse(content={"meta": {}, "comments": {}, "suppressions": [],
                                     "states": list(getattr(collab, "FINDING_STATES", [])),
                                     "priorities": [], "share": {"share_mode": "team"}})
    return JSONResponse(content=collab.collab_for_scan(scan_id))


@app.put("/api/scans/{scan_id}/findings/{finding_key:path}/state")
async def set_finding_state(scan_id: str, finding_key: str, request: Request,
                            user: dict = Depends(_require_writer)):
    if not COLLAB_AVAILABLE:
        _collab_unavailable()
    body = await request.json()
    try:
        result = collab.set_finding_state(
            _app_id_for_scan(scan_id), finding_key, body.get("state", "open"),
            by=user.get("username", ""))
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("finding.state", actor=user.get("username", ""), scan_id=scan_id,
           detail={"finding_key": finding_key, "state": body.get("state")})
    return JSONResponse(content=result)


@app.put("/api/scans/{scan_id}/findings/{finding_key:path}/assign")
async def assign_finding(scan_id: str, finding_key: str, request: Request,
                         user: dict = Depends(_require_writer)):
    if not COLLAB_AVAILABLE:
        _collab_unavailable()
    body = await request.json()
    try:
        result = collab.assign_finding(
            _app_id_for_scan(scan_id), finding_key,
            assignee=body.get("assignee", ""), priority=body.get("priority", ""),
            by=user.get("username", ""))
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("finding.assign", actor=user.get("username", ""), scan_id=scan_id,
           detail={"finding_key": finding_key, "assignee": body.get("assignee"),
                   "priority": body.get("priority")})
    return JSONResponse(content=result)


@app.get("/api/scans/{scan_id}/findings/{finding_key:path}/comments")
async def list_finding_comments(scan_id: str, finding_key: str, _user: dict = Depends(_require_auth)):
    if not COLLAB_AVAILABLE:
        return JSONResponse(content=[])
    return JSONResponse(content=collab.list_comments(_app_id_for_scan(scan_id), finding_key))


@app.post("/api/scans/{scan_id}/findings/{finding_key:path}/comments")
async def add_finding_comment(scan_id: str, finding_key: str, request: Request,
                              user: dict = Depends(_require_writer)):
    if not COLLAB_AVAILABLE:
        _collab_unavailable()
    body = await request.json()
    try:
        result = collab.add_comment(
            _app_id_for_scan(scan_id), finding_key, body.get("body", ""),
            author=user.get("username", ""))
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    return JSONResponse(content=result)


@app.delete("/api/comments/{comment_id}")
async def delete_finding_comment(comment_id: int, _user: dict = Depends(_require_writer)):
    if COLLAB_AVAILABLE:
        collab.delete_comment(comment_id)
    return JSONResponse(content={"deleted": comment_id})


# ─── Persistent suppressions (manager+) ──────────────────────────────────────
@app.get("/api/suppressions")
async def list_suppressions(scan_id: str = Query(None), _user: dict = Depends(_require_auth)):
    """Active suppressions. With ?scan_id=, scopes to that app + globals."""
    if not COLLAB_AVAILABLE:
        return JSONResponse(content=[])
    app_id = _app_id_for_scan(scan_id) if scan_id else None
    return JSONResponse(content=collab.list_suppressions(app_id))


@app.post("/api/suppressions")
async def create_suppression(request: Request, user: dict = Depends(_require_manager)):
    if not COLLAB_AVAILABLE:
        _collab_unavailable()
    body = await request.json()
    app_id = _app_id_for_scan(body["scan_id"]) if body.get("scan_id") else (body.get("app_id") or "")
    try:
        result = collab.add_suppression(
            rule_id=body.get("rule_id", ""), file_pattern=body.get("file_pattern", ""),
            reason=body.get("reason", ""), app_id=app_id,
            created_by=user.get("username", ""))
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("suppression.create", actor=user.get("username", ""),
           detail={"rule_id": body.get("rule_id"), "file_pattern": body.get("file_pattern")})
    return JSONResponse(content=result)


@app.delete("/api/suppressions/{supp_id}")
async def remove_suppression(supp_id: int, user: dict = Depends(_require_manager)):
    if COLLAB_AVAILABLE:
        collab.delete_suppression(supp_id)
    _audit("suppression.delete", actor=user.get("username", ""), detail={"id": supp_id})
    return JSONResponse(content={"deleted": supp_id})


# ─── Workspace sharing (manager+) ────────────────────────────────────────────
@app.put("/api/scans/{scan_id}/share")
async def set_scan_share(scan_id: str, request: Request, user: dict = Depends(_require_manager)):
    if not COLLAB_AVAILABLE:
        _collab_unavailable()
    body = await request.json()
    try:
        result = collab.set_share_mode(scan_id, body.get("share_mode", "team"))
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("scan.share", actor=user.get("username", ""), scan_id=scan_id,
           detail={"share_mode": body.get("share_mode")})
    return JSONResponse(content=result)


@app.delete("/api/scans/{scan_id}")
async def remove_scan(scan_id: str, _user: dict = Depends(_require_auth)):
    if DB_AVAILABLE:
        try:
            delete_scan(scan_id)
        except Exception as e:
            log.warning(f"delete_scan error: {e}")
    _audit("scan.deleted", actor=_user.get("username",""), scan_id=scan_id)
    return JSONResponse(content={"deleted": scan_id})


@app.get("/api/compare")
async def compare(
    scan_a: str = Query(...),
    scan_b: str = Query(...),
    _user: dict = Depends(_require_auth),
):
    if not DB_AVAILABLE:
        raise HTTPException(503, detail="Database not available")
    diff = compare_scans(scan_a, scan_b)
    return JSONResponse(content=diff)


@app.get("/api/scans/{scan_id}/files")
async def list_files(scan_id: str, _user: dict = Depends(_require_auth)):
    if not DECOMPILER_AVAILABLE:
        return JSONResponse(content={"files": {}, "available": False})
    try:
        files = list_source_files(scan_id)
        return JSONResponse(content={"files": files, "available": True})
    except Exception as e:
        log.exception("list_files failed")
        # Do NOT leak str(e) — it can contain internal paths / stack details.
        return JSONResponse(content={"files": {}, "error": "listing unavailable"})


@app.get("/api/scans/{scan_id}/file")
async def get_file(
    scan_id: str,
    path: str = Query(..., description="Relative file path within decompiled output"),
    _user: dict = Depends(_require_auth),
):
    # Defense-in-depth: decode, normalize, and block any path that tries to
    # escape the scan root. `get_file_content` also re-validates before reading.
    from urllib.parse import unquote
    decoded = unquote(path or "")
    # Reject NUL bytes, backslashes, and any parent-dir segment
    if "\x00" in decoded or "\\" in decoded:
        raise HTTPException(400, detail="Invalid file path")
    normalized = os.path.normpath(decoded).replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith(".."):
        raise HTTPException(400, detail="Invalid file path")
    # Stricter: reject ANY `..` segment and any empty segment (double slash).
    for seg in normalized.split("/"):
        if seg in ("..", ""):
            raise HTTPException(400, detail="Invalid file path")

    # Final containment check: resolved path must be inside the scan root.
    from pathlib import Path as _P
    scan_root = _P(os.environ.get("CORTEX_SCAN_DIR", "/tmp/cortex/scans")) / scan_id
    try:
        _ = scan_root.resolve()  # ensure parent exists for resolve semantics
    except Exception:
        pass

    if not DECOMPILER_AVAILABLE:
        raise HTTPException(503, detail="Decompiler not available")

    # Classify first: compiled artifacts are returned as a structured JSON
    # envelope (rendered as a "binary" card) instead of decoded-to-garbage text.
    payload = inspect_file(scan_id, normalized)
    if payload is None:
        raise HTTPException(404, detail="File not found")

    if payload.get("kind") == "binary":
        return JSONResponse(content={"binary": True, "info": payload["info"]})

    return PlainTextResponse(content=payload.get("content", ""))


@app.get("/api/scans/{scan_id}/manifest")
async def get_manifest(scan_id: str, _user: dict = Depends(_require_auth)):
    manifest_xml = ""

    if DB_AVAILABLE:
        try:
            results = get_scan_results(scan_id)
            if results:
                manifest_xml = results.get("manifest_xml", "")
        except Exception:
            pass

    if not manifest_xml and DECOMPILER_AVAILABLE:
        try:
            manifest_xml = get_file_content(scan_id, "AndroidManifest.xml") or ""
        except Exception:
            pass

    if not manifest_xml:
        raise HTTPException(404, detail="Manifest not available for this scan")

    return PlainTextResponse(content=manifest_xml, media_type="application/xml")


@app.post("/api/report")
async def generate_report(payload: dict, _user: dict = Depends(_require_auth)):
    try:
        results = payload.get("results")
        theme = payload.get("theme", "light")
        prepared_by = payload.get("prepared_by", "")
        # Phase 3: default to the high-signal, application-only report. Clients
        # can request the full export with findings_scope="all".
        findings_scope = payload.get("findings_scope", "application")

        if not results:
            raise HTTPException(400, detail="Missing results payload")

        scan_id = results.get("scan_id", str(uuid.uuid4()))
        report_path = REPORT_DIR / f"beetle_{scan_id}.pdf"
        generate_pdf(results, str(report_path), theme=theme, prepared_by=prepared_by,
                     findings_scope=findings_scope)

        app_name = results.get("app_name", "report")
        filename = f"beetle_{app_name}_{theme}.pdf"
        return FileResponse(str(report_path), media_type="application/pdf", filename=filename)
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Report error: {e}")
        raise HTTPException(500, detail=f"Report generation failed: {str(e)}")


# ─── Compliance PDF ──────────────────────────────────────────────────────────
@app.post("/api/report/compliance")
async def generate_compliance_report(payload: dict, _user: dict = Depends(_require_auth)):
    """
    Generate a compliance-mapped PDF.
    Body: { results, framework, theme, prepared_by }
    framework: 'masvs' | 'pci_dss' | 'owasp_mobile'
    """
    try:
        results     = payload.get("results")
        framework   = payload.get("framework", "masvs")
        theme       = payload.get("theme", "light")
        prepared_by = payload.get("prepared_by", "")

        if not results:
            raise HTTPException(400, detail="Missing results payload")
        if framework not in COMPLIANCE_FRAMEWORKS:
            raise HTTPException(400, detail=f"Unknown framework '{framework}'. Valid: {list(COMPLIANCE_FRAMEWORKS)}")

        scan_id     = results.get("scan_id", str(uuid.uuid4()))
        report_path = REPORT_DIR / f"beetle_compliance_{framework}_{scan_id}.pdf"
        generate_compliance_pdf(results, str(report_path), framework=framework, theme=theme, prepared_by=prepared_by)

        app_name = results.get("app_name", "report")
        fw_name  = COMPLIANCE_FRAMEWORKS[framework]["name"].replace(" ", "_").replace("/", "-")
        filename = f"beetle_{app_name}_{fw_name}.pdf"
        return FileResponse(str(report_path), media_type="application/pdf", filename=filename)
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Compliance report error")
        raise HTTPException(500, detail="Compliance report generation failed")


# ─── SARIF Export ─────────────────────────────────────────────────────────────
@app.get("/api/scans/{scan_id}/sarif")
async def export_sarif(scan_id: str, _user: dict = Depends(_require_auth)):
    """
    Export scan results as SARIF 2.1.0.

    Compatible with:
      - GitHub Code Scanning (upload-sarif action)
      - VS Code SARIF Viewer extension
      - Any CI/CD tool supporting SARIF
    """
    if not DB_AVAILABLE:
        raise HTTPException(503, detail="Database unavailable")

    results = get_scan_results(scan_id)
    if not results:
        raise HTTPException(404, detail=f"Scan {scan_id} not found")

    try:
        sarif_json = results_to_sarif_json(results)
        app_name   = results.get("app_name", "scan")
        filename   = f"beetle_{app_name}_{scan_id[:8]}.sarif.json"
        return Response(
            content=sarif_json,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Beetle-Scan-Id":    scan_id,
            },
        )
    except Exception as e:
        log.error(f"SARIF export error: {e}")
        raise HTTPException(500, detail=f"SARIF export failed: {str(e)}")


@app.post("/api/sbom")
async def export_sbom(request: Request, _user: dict = Depends(_require_auth)):
    """
    Generate a CycloneDX 1.5 JSON SBOM from a results payload.
    Body: { results: {...} }
    """
    try:
        payload  = await request.json()
        results  = payload.get("results") or payload
        sbom_str = generate_sbom_json(results)
        app_name = results.get("app_name", "scan")
        scan_id  = (results.get("scan_id") or "unknown")[:8]
        filename = f"beetle_{app_name}_{scan_id}.cdx.json"
        return Response(
            content=sbom_str,
            media_type="application/vnd.cyclonedx+json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception as e:
        log.error(f"SBOM export error: {e}")
        raise HTTPException(500, detail=f"SBOM export failed: {str(e)}")


@app.post("/api/sarif")
async def export_sarif_from_payload(request: Request, _user: dict = Depends(_require_auth)):
    """
    Generate SARIF from a results payload directly (no DB lookup).
    Used by the frontend to download SARIF from the current scan.
    """
    try:
        payload = await request.json()
        results = payload.get("results") or payload
        sarif_json = results_to_sarif_json(results)
        app_name   = results.get("app_name", "scan")
        scan_id    = results.get("scan_id", "unknown")
        filename   = f"beetle_{app_name}_{scan_id[:8]}.sarif.json"
        return Response(
            content=sarif_json,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception as e:
        log.error(f"SARIF payload export error: {e}")
        raise HTTPException(500, detail=f"SARIF export failed: {str(e)}")
