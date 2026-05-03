"""Shared-token authentication middleware.

The token is read from /data/settings.json (set via the Settings tab) and
falls back to the AUTH_TOKEN env var. Empty token = no auth (dev mode).
Tokens may be presented as:
  - Authorization: Bearer <token> header
  - ?token=<token> query parameter
  - ctfmanager_token cookie
"""
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from modules.settings_io import get_setting

PUBLIC_PATHS = ("/api/health", "/login", "/static/", "/favicon.ico")


class TokenAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = str(get_setting("auth_token") or "").strip()
        if not token:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(p) for p in PUBLIC_PATHS):
            return await call_next(request)

        # Accept token from header / query / cookie
        provided = None
        auth_h = request.headers.get("Authorization", "")
        if auth_h.lower().startswith("bearer "):
            provided = auth_h[7:].strip()
        if not provided:
            provided = request.query_params.get("token")
        if not provided:
            provided = request.cookies.get("ctfmanager_token")

        if provided != token:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "auth required"}, status_code=401)
            # For root/HTML requests, send to login page
            return RedirectResponse(url="/login")

        return await call_next(request)
