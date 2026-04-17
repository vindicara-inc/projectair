"""Auth middleware for dashboard routes."""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from vindicara.dashboard.auth.tokens import decode_token, verify_csrf

_PUBLIC_PATHS = {
    "/dashboard/login",
    "/dashboard/signup",
    "/dashboard/api/auth/signup",
    "/dashboard/api/auth/login",
    "/dashboard/demo",
    "/dashboard/api/demo/start",
    "/dashboard/api/demo/status",
}


class DashboardAuthMiddleware(BaseHTTPMiddleware):
    """Protects dashboard routes with JWT cookie auth and CSRF."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        if not path.startswith("/dashboard"):
            return await call_next(request)

        if path in _PUBLIC_PATHS:
            return await call_next(request)

        access_token = request.cookies.get("vnd_access", "")
        payload = decode_token(access_token)

        if not payload or payload.get("type") != "access":
            if path.startswith("/dashboard/api/"):
                return Response(status_code=401, content="Unauthorized")
            return RedirectResponse(url="/dashboard/login", status_code=302)

        if request.method in ("POST", "PUT", "DELETE") and path.startswith("/dashboard/api/") and not path.startswith("/dashboard/api/auth/"):
                csrf_cookie = request.cookies.get("vnd_csrf", "")
                csrf_header = request.headers.get("X-CSRF-Token", "")
                if not verify_csrf(csrf_cookie, csrf_header):
                    csrf_form = ""
                    if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                        form = await request.form()
                        csrf_form = str(form.get("_csrf", ""))
                    if not verify_csrf(csrf_cookie, csrf_form):
                        return Response(status_code=403, content="CSRF validation failed")

        request.state.user_id = payload.get("sub", "")
        request.state.email = payload.get("email", "")
        return await call_next(request)
