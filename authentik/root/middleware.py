"""Dynamically set SameSite depending if the upstream connection is TLS or not"""

from collections.abc import Callable
from hashlib import sha512
from ipaddress import ip_address
from time import perf_counter, time
from typing import Any

from channels.exceptions import DenyConnection
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.exceptions import SessionInterrupted
from django.contrib.sessions.middleware import SessionMiddleware as UpstreamSessionMiddleware
from django.http.request import HttpRequest
from django.http.response import HttpResponse, HttpResponseServerError
from django.middleware.csrf import CSRF_SESSION_KEY
from django.middleware.csrf import CsrfViewMiddleware as UpstreamCsrfViewMiddleware
from django.utils.cache import patch_vary_headers
from django.utils.http import http_date
from django.utils.timezone import now as timezone_now
from jwt import PyJWTError, decode, encode
from sentry_sdk import Scope
from structlog.stdlib import get_logger

from authentik.core.models import Session, Token, TokenIntents, User, UserTypes
from authentik.lib.config import CONFIG

LOGGER = get_logger("authentik.asgi")
ACR_AUTHENTIK_SESSION = "goauthentik.io/core/default"
SIGNING_HASH = sha512(settings.SECRET_KEY.encode()).hexdigest()
ACCOUNT_SESSION_COOKIE_NAME = "authentik_account_sessions"
ACCOUNT_SESSION_COOKIE_SCHEMA = 1
REQUEST_ATTR_ACCOUNT_SESSIONS = "authentik_account_sessions"
REQUEST_ATTR_ACCOUNT_SESSIONS_MODIFIED = "authentik_account_sessions_modified"
REQUEST_ATTR_SESSION_COOKIE_OVERRIDE = "authentik_session_cookie_override"


def _normalise_account_session_entry(entry: Any) -> dict[str, Any] | None:
    if isinstance(entry, str):
        return {"sid": entry}
    if not isinstance(entry, dict):
        return None
    session_key = entry.get("sid")
    if not isinstance(session_key, str) or session_key == "":
        return None
    normalised: dict[str, Any] = {"sid": session_key}
    user_pk = entry.get("user_pk")
    if isinstance(user_pk, int):
        normalised["user_pk"] = user_pk
    browser_close = entry.get("browser_close")
    if isinstance(browser_close, bool):
        normalised["browser_close"] = browser_close
    return normalised


def decode_account_sessions(value: str | None) -> list[dict[str, Any]]:
    """Decode the connected account session cookie."""
    if not value:
        return []
    try:
        payload = decode(value, SIGNING_HASH, algorithms=["HS256"])
    except PyJWTError:
        return []
    if payload.get("schema") != ACCOUNT_SESSION_COOKIE_SCHEMA:
        return []
    entries = payload.get("sessions", [])
    if not isinstance(entries, list):
        return []
    seen: set[str] = set()
    normalised = []
    for entry in entries:
        normalised_entry = _normalise_account_session_entry(entry)
        if not normalised_entry:
            continue
        session_key = normalised_entry["sid"]
        if session_key in seen:
            continue
        seen.add(session_key)
        normalised.append(normalised_entry)
    return normalised


def encode_account_sessions(entries: list[dict[str, Any]]) -> str:
    """Encode connected account sessions into a signed cookie payload."""
    return encode(
        payload={
            "iss": "authentik",
            "schema": ACCOUNT_SESSION_COOKIE_SCHEMA,
            "sessions": entries,
        },
        key=SIGNING_HASH,
    )


def get_account_session_entries(request: HttpRequest) -> list[dict[str, Any]]:
    """Get connected account session entries from the request."""
    return list(getattr(request, REQUEST_ATTR_ACCOUNT_SESSIONS, []))


def set_account_session_entries(request: HttpRequest, entries: list[dict[str, Any]]):
    """Update connected account session entries for the response cookie."""
    setattr(request, REQUEST_ATTR_ACCOUNT_SESSIONS, entries)
    setattr(request, REQUEST_ATTR_ACCOUNT_SESSIONS_MODIFIED, True)


def add_account_session(
    request: HttpRequest,
    session_key: str,
    user: User,
    browser_close: bool | None = None,
):
    """Connect a user's authenticated session to this browser."""
    if not session_key or not user.is_authenticated:
        return
    entries = [
        entry
        for entry in get_account_session_entries(request)
        if entry.get("sid") != session_key and entry.get("user_pk") != user.pk
    ]
    if browser_close is None:
        browser_close = request.session.get_expire_at_browser_close()
    entries.append(
        {
            "sid": session_key,
            "user_pk": user.pk,
            "browser_close": browser_close,
        }
    )
    set_account_session_entries(request, entries)


def ensure_current_account_session(request: HttpRequest):
    """Ensure the active authenticated session is present in the connected account cookie."""
    authenticated_session = request.session.get("authenticatedsession", None)
    user = authenticated_session.user if authenticated_session else getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return
    add_account_session(request, request.session.session_key, user)


def set_session_cookie_override(
    request: HttpRequest,
    session_key: str,
    user: User | AnonymousUser,
    browser_close: bool = True,
    expires: Any | None = None,
):
    """Set the active session cookie to a different session after this request."""
    setattr(
        request,
        REQUEST_ATTR_SESSION_COOKIE_OVERRIDE,
        {
            "session_key": session_key,
            "user": user,
            "browser_close": browser_close,
            "expires": expires,
        },
    )


class SessionMiddleware(UpstreamSessionMiddleware):
    """Dynamically set SameSite depending if the upstream connection is TLS or not"""

    @staticmethod
    def is_secure(request: HttpRequest) -> bool:
        """Check if request is TLS'd or localhost"""
        if request.is_secure():
            return True
        host, _, _ = request.get_host().partition(":")
        if host == "localhost" and settings.DEBUG:
            # Since go does not consider localhost with http a secure origin
            # we can't set the secure flag.
            user_agent = request.META.get("HTTP_USER_AGENT", "")
            if user_agent.startswith("goauthentik.io/outpost/") or (
                "safari" in user_agent.lower() and "chrome" not in user_agent.lower()
            ):
                return False
            return True
        return False

    @staticmethod
    def decode_session_key(key: str | None) -> str | None:
        """Decode raw session cookie, and parse JWT"""
        # We need to support the standard django format of just a session key
        # for testing setups, where the session is directly set
        session_key = key if settings.TEST else None
        try:
            session_payload = decode(key, SIGNING_HASH, algorithms=["HS256"])
            session_key = session_payload["sid"]
        except KeyError, PyJWTError:
            pass
        return session_key

    @staticmethod
    def encode_session(session_key: str, user: User):
        payload = {
            "sid": session_key,
            "iss": "authentik",
            "sub": "anonymous",
            "authenticated": user.is_authenticated,
            "acr": ACR_AUTHENTIK_SESSION,
        }
        if user.is_authenticated:
            payload["sub"] = user.uid
        value = encode(payload=payload, key=SIGNING_HASH)
        if settings.TEST:
            value = session_key
        return value

    def process_request(self, request: HttpRequest):
        raw_session = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        session_key = SessionMiddleware.decode_session_key(raw_session)
        setattr(
            request,
            REQUEST_ATTR_ACCOUNT_SESSIONS,
            decode_account_sessions(request.COOKIES.get(ACCOUNT_SESSION_COOKIE_NAME)),
        )
        setattr(request, REQUEST_ATTR_ACCOUNT_SESSIONS_MODIFIED, False)
        request.session = self.SessionStore(
            session_key,
            last_ip=ClientIPMiddleware.get_client_ip(request),
            last_user_agent=request.META.get("HTTP_USER_AGENT", ""),
        )

    def _set_session_cookie(
        self,
        response: HttpResponse,
        session_key: str,
        user: User | AnonymousUser,
        max_age: int | None,
        expires: str | None,
        same_site: str,
        secure: bool,
    ):
        response.set_cookie(
            settings.SESSION_COOKIE_NAME,
            SessionMiddleware.encode_session(session_key, user),
            max_age=max_age,
            expires=expires,
            domain=settings.SESSION_COOKIE_DOMAIN,
            path=settings.SESSION_COOKIE_PATH,
            secure=secure,
            httponly=settings.SESSION_COOKIE_HTTPONLY or None,
            samesite=same_site,
        )

    def _set_account_sessions_cookie(
        self,
        request: HttpRequest,
        response: HttpResponse,
        same_site: str,
        secure: bool,
    ):
        if not getattr(request, REQUEST_ATTR_ACCOUNT_SESSIONS_MODIFIED, False):
            return
        entries = get_account_session_entries(request)
        if not entries:
            response.delete_cookie(
                ACCOUNT_SESSION_COOKIE_NAME,
                path=settings.SESSION_COOKIE_PATH,
                domain=settings.SESSION_COOKIE_DOMAIN,
                samesite=same_site,
            )
            return
        max_age, expires = self._get_account_sessions_cookie_expiry(entries)
        response.set_cookie(
            ACCOUNT_SESSION_COOKIE_NAME,
            encode_account_sessions(entries),
            max_age=max_age,
            expires=expires,
            domain=settings.SESSION_COOKIE_DOMAIN,
            path=settings.SESSION_COOKIE_PATH,
            secure=secure,
            httponly=settings.SESSION_COOKIE_HTTPONLY or None,
            samesite=same_site,
        )

    def _get_account_sessions_cookie_expiry(
        self, entries: list[dict[str, Any]]
    ) -> tuple[int | None, str | None]:
        persistent_session_keys = [
            entry["sid"] for entry in entries if not entry.get("browser_close", True)
        ]
        if not persistent_session_keys:
            return None, None
        expires_at = (
            Session.objects.filter(
                session_key__in=persistent_session_keys,
                expires__gt=timezone_now(),
            )
            .order_by("-expires")
            .values_list("expires", flat=True)
            .first()
        )
        if not expires_at:
            return None, None
        return max(0, int(expires_at.timestamp() - time())), http_date(expires_at.timestamp())

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie or delete
        the session cookie if the session has been emptied.
        """
        try:
            accessed = request.session.accessed
            modified = request.session.modified
            empty = request.session.is_empty()
        except AttributeError:
            return response
        # Set SameSite based on whether or not the request is secure
        secure = SessionMiddleware.is_secure(request)
        same_site = "None" if secure else "Lax"
        override = getattr(request, REQUEST_ATTR_SESSION_COOKIE_OVERRIDE, None)
        # First check if we need to delete this cookie.
        # The session should be deleted only if the session is entirely empty.
        if settings.SESSION_COOKIE_NAME in request.COOKIES and empty and not override:
            response.delete_cookie(
                settings.SESSION_COOKIE_NAME,
                path=settings.SESSION_COOKIE_PATH,
                domain=settings.SESSION_COOKIE_DOMAIN,
                samesite=same_site,
            )
            patch_vary_headers(response, ("Cookie",))
        else:
            if accessed:
                patch_vary_headers(response, ("Cookie",))
            if (modified or settings.SESSION_SAVE_EVERY_REQUEST) and not empty:
                if request.session.get_expire_at_browser_close():
                    max_age = None
                    expires = None
                else:
                    max_age = request.session.get_expiry_age()
                    expires_time = time() + max_age
                    expires = http_date(expires_time)
                # Save the session data and refresh the client cookie.
                # Skip session save for 500 responses, refs #3881.
                if response.status_code != HttpResponseServerError.status_code:
                    try:
                        request.session.save()
                    except UpdateError:
                        raise SessionInterrupted(
                            "The request's session was deleted before the "
                            "request completed. The user may have logged "
                            "out in a concurrent request, for example."
                        ) from None
                    self._set_session_cookie(
                        response,
                        request.session.session_key,
                        request.user,
                        max_age,
                        expires,
                        same_site,
                        secure,
                    )
        if override:
            max_age = None
            expires = None
            if not override.get("browser_close", True):
                expires_at = override.get("expires")
                if expires_at:
                    max_age = max(0, int(expires_at.timestamp() - time()))
                    expires = http_date(expires_at.timestamp())
                else:
                    max_age = request.session.get_expiry_age()
                    expires = http_date(time() + max_age)
            self._set_session_cookie(
                response,
                override["session_key"],
                override["user"],
                max_age,
                expires,
                same_site,
                secure,
            )
        self._set_account_sessions_cookie(request, response, same_site, secure)
        return response


class CsrfViewMiddleware(UpstreamCsrfViewMiddleware):
    """Dynamically set secure depending if the upstream connection is TLS or not"""

    def _set_csrf_cookie(self, request: HttpRequest, response: HttpResponse):
        if settings.CSRF_USE_SESSIONS:
            if request.session.get(CSRF_SESSION_KEY) != request.META["CSRF_COOKIE"]:
                request.session[CSRF_SESSION_KEY] = request.META["CSRF_COOKIE"]
        else:
            secure = SessionMiddleware.is_secure(request)
            response.set_cookie(
                settings.CSRF_COOKIE_NAME,
                request.META["CSRF_COOKIE"],
                max_age=settings.CSRF_COOKIE_AGE,
                domain=settings.CSRF_COOKIE_DOMAIN,
                path=settings.CSRF_COOKIE_PATH,
                secure=secure,
                httponly=settings.CSRF_COOKIE_HTTPONLY,
                samesite=settings.CSRF_COOKIE_SAMESITE,
            )
            # Set the Vary header since content varies with the CSRF cookie.
            patch_vary_headers(response, ("Cookie",))


class ClientIPMiddleware:
    """Set a "known-good" client IP on the request, by default based off of x-forwarded-for
    which is set by the go proxy, but also allowing the remote IP to be overridden by an outpost
    for protocols like LDAP"""

    get_response: Callable[[HttpRequest], HttpResponse]
    outpost_remote_ip_header = "HTTP_X_AUTHENTIK_REMOTE_IP"
    outpost_token_header = "HTTP_X_AUTHENTIK_OUTPOST_TOKEN"  # nosec
    default_ip = "255.255.255.255"

    request_attr_client_ip = "client_ip"
    request_attr_outpost_user = "outpost_user"

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        self.logger = get_logger().bind()

    def _get_client_ip_from_meta(self, meta: dict[str, Any]) -> str:
        """Attempt to get the client's IP by checking common HTTP Headers.
        Returns none if no IP Could be found

        No additional validation is done here as requests are expected to only arrive here
        via the go proxy, which deals with validating these headers for us"""
        headers = (
            "HTTP_X_FORWARDED_FOR",
            "REMOTE_ADDR",
        )
        try:
            for _header in headers:
                if _header in meta:
                    ips: list[str] = meta.get(_header).split(",")
                    # Ensure the IP parses as a valid IP
                    return str(ip_address(ips[0].strip()))
            return self.default_ip
        except ValueError as exc:
            self.logger.debug("Invalid remote IP", exc=exc)
            return self.default_ip

    # FIXME: this should probably not be in `root` but rather in a middleware in `outposts`
    # but for now it's fine
    def _get_outpost_override_ip(self, request: HttpRequest) -> str | None:
        """Get the actual remote IP when set by an outpost. Only
        allowed when the request is authenticated, by an outpost internal service account"""
        if (
            self.outpost_remote_ip_header not in request.META
            or self.outpost_token_header not in request.META
        ):
            return None
        delegated_ip = request.META[self.outpost_remote_ip_header]
        token = (
            Token.objects.filter(
                key=request.META.get(self.outpost_token_header), intent=TokenIntents.INTENT_API
            )
            .select_related("user")
            .first()
        )
        if not token:
            LOGGER.warning("Attempted remote-ip override without token", delegated_ip=delegated_ip)
            return None
        user: User = token.user
        if user.type != UserTypes.INTERNAL_SERVICE_ACCOUNT:
            LOGGER.warning(
                "Remote-IP override: user doesn't have permission",
                user=user,
                delegated_ip=delegated_ip,
            )
            return None
        # Update sentry scope to include correct IP
        sentry_user = Scope.get_isolation_scope()._user or {}
        sentry_user["ip_address"] = delegated_ip
        Scope.get_isolation_scope().set_user(sentry_user)
        # Set the outpost service account on the request
        setattr(request, self.request_attr_outpost_user, user)
        try:
            return str(ip_address(delegated_ip))
        except ValueError as exc:
            self.logger.debug("Invalid remote IP from Outpost", exc=exc)
            return None

    def _get_client_ip(self, request: HttpRequest | None) -> str:
        """Attempt to get the client's IP by checking common HTTP Headers.
        Returns none if no IP Could be found"""
        if not request:
            return self.default_ip
        override = self._get_outpost_override_ip(request)
        if override:
            return override
        return self._get_client_ip_from_meta(request.META)

    @staticmethod
    def get_outpost_user(request: HttpRequest) -> User | None:
        """Get outpost user that authenticated this request"""
        return getattr(request, ClientIPMiddleware.request_attr_outpost_user, None)

    @staticmethod
    def get_client_ip(request: HttpRequest) -> str:
        """Get correct client IP, including any overrides from outposts that
        have the permission to do so"""
        if request and not hasattr(request, ClientIPMiddleware.request_attr_client_ip):
            ClientIPMiddleware(lambda request: request).set_ip(request)
        return getattr(
            request, ClientIPMiddleware.request_attr_client_ip, ClientIPMiddleware.default_ip
        )

    def set_ip(self, request: HttpRequest):
        """Set the IP"""
        setattr(request, self.request_attr_client_ip, self._get_client_ip(request))

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self.set_ip(request)
        return self.get_response(request)


class ChannelsLoggingMiddleware:
    """Logging middleware for channels"""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        self.log(scope)
        try:
            return await self.inner(scope, receive, send)
        except DenyConnection:
            return await send({"type": "websocket.close"})
        except Exception as exc:
            if settings.DEBUG or settings.TEST:
                raise exc
            LOGGER.warning("Exception in ASGI application", exc=exc)
            return await send({"type": "websocket.close"})

    def log(self, scope: dict, **kwargs):
        """Log request"""
        headers = dict(scope.get("headers", {}))
        LOGGER.info(
            scope["path"],
            scheme="ws",
            remote=headers.get(b"x-forwarded-for", b"").decode(),
            user_agent=headers.get(b"user-agent", b"").decode(),
            **kwargs,
        )


class LoggingMiddleware:
    """Logger middleware"""

    get_response: Callable[[HttpRequest], HttpResponse]

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        headers = CONFIG.get("log.http_headers", [])
        if isinstance(headers, str):
            headers = headers.split(",")
        self.headers_to_log = headers

    def __call__(self, request: HttpRequest) -> HttpResponse:
        start = perf_counter()
        response = self.get_response(request)
        status_code = response.status_code
        kwargs = {
            "request_id": getattr(request, "request_id", None),
        }
        kwargs.update(getattr(response, "ak_context", {}))
        self.log(request, status_code, int((perf_counter() - start) * 1000), **kwargs)
        return response

    def log(self, request: HttpRequest, status_code: int, runtime: int, **kwargs):
        """Log request"""
        for header in self.headers_to_log:
            header_value = request.headers.get(header)
            if not header_value:
                continue
            kwargs[header.lower().replace("-", "_")] = header_value
        LOGGER.info(
            request.get_full_path(),
            remote=ClientIPMiddleware.get_client_ip(request),
            method=request.method,
            scheme=request.scheme,
            status=status_code,
            runtime=runtime,
            **kwargs,
        )
