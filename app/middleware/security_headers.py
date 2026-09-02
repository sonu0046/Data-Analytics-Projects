# app/middleware/security_headers.py - Production Security Hardening Middleware (Step 9 PRD v1.1)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class ProductionSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects enterprise fintech HTTP security headers into every response.
    Enforces HSTS, strict CSP, frame protection, and MIME type sniffing prevention.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # 1. Strict Transport Security (HSTS) - 2 Years with preload
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )

        # 2. Frame Protection (Anti-Clickjacking)
        response.headers["X-Frame-Options"] = "DENY"

        # 3. MIME Sniffing Prevention
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 4. Strict Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 5. Content Security Policy (CSP)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        # 6. Permissions Policy
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # 7. Cache-Control for sensitive financial data
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, max-age=0"
            )
            response.headers["Pragma"] = "no-cache"

        return response
