"""Auth API endpoints."""

import structlog
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from vindicara.config.settings import VindicaraSettings
from vindicara.dashboard.auth.mfa import generate_qr_base64, generate_secret, get_provisioning_uri, verify_totp
from vindicara.dashboard.auth.passwords import validate_password
from vindicara.dashboard.auth.store import get_user_store
from vindicara.dashboard.auth.tokens import create_access_token, create_csrf_token, create_refresh_token

logger = structlog.get_logger()

router = APIRouter(prefix="/api/auth")


def _set_auth_cookies(response: Response, access: str, refresh: str, csrf: str) -> None:
    """Set auth cookies. Secure flag based on stage (off in dev/test for HTTP)."""
    settings = VindicaraSettings()
    secure = settings.stage not in ("dev", "test")
    response.set_cookie("vnd_access", access, httponly=True, secure=secure, samesite="strict", max_age=900)
    response.set_cookie("vnd_refresh", refresh, httponly=True, secure=secure, samesite="strict", max_age=604800)
    response.set_cookie("vnd_csrf", csrf, httponly=False, secure=secure, samesite="strict", max_age=604800)


@router.post("/signup")
async def signup(
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
) -> Response:
    if password != confirm_password:
        return HTMLResponse('<div style="color:#E63946;padding:8px;">Passwords do not match</div>')

    validation = validate_password(password)
    if not validation.valid:
        errors = "<br>".join(validation.errors)
        return HTMLResponse(f'<div style="color:#E63946;padding:8px;">{errors}</div>')

    store = get_user_store()
    try:
        user = store.create_user(email, password)
    except ValueError as exc:
        return HTMLResponse(f'<div style="color:#E63946;padding:8px;">{exc}</div>')

    session = store.create_session(user.user_id)
    access = create_access_token(user.user_id, user.email)
    refresh = create_refresh_token(user.user_id, session.session_id)
    csrf = create_csrf_token()

    response = RedirectResponse(url="/dashboard/", status_code=303)
    _set_auth_cookies(response, access, refresh, csrf)
    logger.info("auth.signup.success", user_id=user.user_id, email=email)
    return response


@router.post("/login")
async def login(
    email: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(default=""),
) -> Response:
    store = get_user_store()

    if store.check_lockout(email):
        return HTMLResponse('<div style="color:#E63946;padding:8px;">Account locked. Try again in 15 minutes.</div>')

    user = store.authenticate(email, password)
    if user is None:
        return HTMLResponse('<div style="color:#E63946;padding:8px;">Invalid email or password</div>')

    if user.mfa_enabled:
        if not totp_code:
            return HTMLResponse(
                '<div style="padding:8px;">'
                '<label style="font-size:11px;color:#444458;display:block;margin-bottom:4px;">MFA CODE</label>'
                '<input type="text" name="totp_code" placeholder="000000" style="width:120px;" autofocus>'
                '<input type="hidden" name="email" value="' + email + '">'
                '<input type="hidden" name="password" value="' + password + '">'
                '</div>'
            )
        if not verify_totp(user.mfa_secret, totp_code):
            return HTMLResponse('<div style="color:#E63946;padding:8px;">Invalid MFA code</div>')

    session = store.create_session(user.user_id)
    access = create_access_token(user.user_id, user.email)
    refresh = create_refresh_token(user.user_id, session.session_id)
    csrf = create_csrf_token()

    response = RedirectResponse(url="/dashboard/", status_code=303)
    _set_auth_cookies(response, access, refresh, csrf)
    logger.info("auth.login.success", user_id=user.user_id)
    return response


@router.post("/logout")
async def logout(request: Request) -> Response:
    store = get_user_store()
    refresh = request.cookies.get("vnd_refresh", "")
    from vindicara.dashboard.auth.tokens import decode_token
    payload = decode_token(refresh)
    if payload and payload.get("sid"):
        store.revoke_session(payload["sid"])

    response = RedirectResponse(url="/dashboard/login", status_code=303)
    response.delete_cookie("vnd_access")
    response.delete_cookie("vnd_refresh")
    response.delete_cookie("vnd_csrf")
    logger.info("auth.logout")
    return response


@router.post("/mfa/setup")
async def mfa_setup(request: Request) -> HTMLResponse:
    store = get_user_store()
    user_id = getattr(request.state, "user_id", "")
    user = store.get_by_id(user_id)
    if not user:
        return HTMLResponse('<div style="color:#E63946;">Not authenticated</div>')

    secret = generate_secret()
    uri = get_provisioning_uri(secret, user.email)
    qr_b64 = generate_qr_base64(uri)

    store.update_user(user.model_copy(update={"mfa_secret": secret}))

    return HTMLResponse(
        f'<div class="card p-16">'
        f'<div style="font-size:13px;font-weight:600;color:#EFEFEF;margin-bottom:12px;">Scan with Authenticator App</div>'
        f'<img src="data:image/png;base64,{qr_b64}" style="width:200px;height:200px;margin-bottom:12px;">'
        f'<div class="mono" style="font-size:11px;color:#9090A8;word-break:break-all;margin-bottom:16px;">Manual key: {secret}</div>'
        f'<form hx-post="/dashboard/api/auth/mfa/verify" hx-target="#mfa-result" hx-swap="innerHTML">'
        f'<div class="flex-row"><input type="text" name="code" placeholder="000000" style="width:120px;">'
        f'<button type="submit" class="btn-red">Verify & Enable</button></div>'
        f'</form><div id="mfa-result"></div></div>'
    )


@router.post("/mfa/verify")
async def mfa_verify(request: Request, code: str = Form(...)) -> HTMLResponse:
    store = get_user_store()
    user_id = getattr(request.state, "user_id", "")
    user = store.get_by_id(user_id)
    if not user or not user.mfa_secret:
        return HTMLResponse('<div style="color:#E63946;">MFA not set up</div>')

    if verify_totp(user.mfa_secret, code):
        store.update_user(user.model_copy(update={"mfa_enabled": True}))
        return HTMLResponse('<div style="color:#4ADE80;padding:8px;">MFA enabled successfully</div>')
    return HTMLResponse('<div style="color:#E63946;padding:8px;">Invalid code. Try again.</div>')
