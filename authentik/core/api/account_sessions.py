"""Connected account session API."""

from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest
from django.urls import reverse
from django.utils.http import urlencode
from django.utils.timezone import now
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework.decorators import action
from rest_framework.fields import (
    BooleanField,
    CharField,
    DateTimeField,
    SerializerMethodField,
    UUIDField,
)
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from authentik.core.api.utils import ModelSerializer, PassiveSerializer
from authentik.core.models import AuthenticatedSession, User
from authentik.core.sessions import SessionStore
from authentik.flows.models import FlowDesignation
from authentik.flows.views.executor import NEXT_ARG_NAME, ToDefaultFlow
from authentik.lib.avatars import get_avatar
from authentik.root.middleware import (
    ClientIPMiddleware,
    add_account_session,
    ensure_current_account_session,
    get_account_session_entries,
    set_account_session_entries,
    set_session_cookie_override,
)


class AccountSessionUserSerializer(ModelSerializer):
    """Minimal user identity for the account switcher."""

    avatar = SerializerMethodField()

    def get_avatar(self, user: User) -> str:
        """User's avatar, either a http/https URL or a data URI."""
        return get_avatar(user, self.context.get("request"))

    class Meta:
        model = User
        fields = [
            "pk",
            "username",
            "name",
            "email",
            "avatar",
        ]
        read_only_fields = fields


class AccountSessionSerializer(PassiveSerializer):
    """A connected account known by this browser."""

    user = AccountSessionUserSerializer(read_only=True)
    current = BooleanField(read_only=True)
    active = BooleanField(read_only=True)
    disconnected = BooleanField(read_only=True)
    session_uuid = UUIDField(read_only=True, allow_null=True)
    expires = DateTimeField(read_only=True, allow_null=True)
    last_used = DateTimeField(read_only=True, allow_null=True)
    last_ip = CharField(read_only=True, allow_null=True)


class AccountSessionSwitchSerializer(PassiveSerializer):
    """Request to switch the active browser session."""

    session_uuid = UUIDField(required=True)


class AccountSessionLoginSerializer(PassiveSerializer):
    """Request to start login for another account."""

    next = CharField(required=False, allow_blank=True)


class AccountSessionLoginResponseSerializer(PassiveSerializer):
    """Response containing the flow URL for another account login."""

    to = CharField()


class AccountSessionViewSet(GenericViewSet):
    """Manage account sessions connected to the current browser."""

    queryset = AuthenticatedSession.objects.none()
    serializer_class = AccountSessionSerializer
    pagination_class = None
    filter_backends = []
    permission_classes = [AllowAny]

    def _entry_browser_close(self, request: HttpRequest, session_key: str) -> bool:
        for entry in get_account_session_entries(request):
            if entry.get("sid") == session_key:
                return entry.get("browser_close", True)
        return True

    def _connected_accounts(self, request: Request) -> list[dict]:
        http_request = request._request
        ensure_current_account_session(http_request)
        entries = get_account_session_entries(http_request)
        session_keys = [entry["sid"] for entry in entries]
        user_pks = [entry["user_pk"] for entry in entries if "user_pk" in entry]

        auth_sessions = {
            auth_session.session.session_key: auth_session
            for auth_session in AuthenticatedSession.objects.select_related(
                "session", "user"
            ).filter(session__session_key__in=session_keys)
        }
        users = {user.pk: user for user in User.objects.filter(pk__in=user_pks).exclude_anonymous()}

        current_session_key = http_request.session.session_key
        seen_users: set[int] = set()
        accounts = []
        pruned_entries = []

        for entry in entries:
            session_key = entry["sid"]
            auth_session = auth_sessions.get(session_key)
            user = auth_session.user if auth_session else users.get(entry.get("user_pk"))
            if not user or user.pk in seen_users:
                continue
            seen_users.add(user.pk)

            session = auth_session.session if auth_session else None
            active = bool(
                auth_session
                and session
                and session.expires
                and session.expires > now()
                and auth_session.user.is_active
            )
            current = bool(active and session_key == current_session_key)
            accounts.append(
                {
                    "user": user,
                    "current": current,
                    "active": active,
                    "disconnected": not active,
                    "session_uuid": auth_session.uuid if active else None,
                    "expires": session.expires if session else None,
                    "last_used": session.last_used if session else None,
                    "last_ip": session.last_ip if session else None,
                }
            )
            pruned_entries.append(entry)

        if len(pruned_entries) != len(entries):
            set_account_session_entries(http_request, pruned_entries)
        return accounts

    @extend_schema(responses={200: AccountSessionSerializer(many=True)})
    def list(self, request: Request) -> Response:
        """List connected accounts for this browser."""
        return Response(
            AccountSessionSerializer(
                self._connected_accounts(request), many=True, context={"request": request}
            ).data
        )

    @extend_schema(
        request=AccountSessionSwitchSerializer,
        responses={204: OpenApiResponse(description="Successfully switched account")},
    )
    @action(detail=False, methods=["POST"])
    def switch(self, request: Request) -> Response:
        """Switch the active browser session to another connected account."""
        serializer = AccountSessionSwitchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        http_request = request._request
        session_uuid = serializer.validated_data["session_uuid"]
        allowed_session_keys = {entry["sid"] for entry in get_account_session_entries(http_request)}
        auth_session = (
            AuthenticatedSession.objects.select_related("session", "user")
            .filter(uuid=session_uuid)
            .first()
        )
        if not auth_session or auth_session.session.session_key not in allowed_session_keys:
            return Response(status=404)
        if (
            not auth_session.user.is_active
            or not auth_session.session.expires
            or auth_session.session.expires <= now()
        ):
            return Response(status=404)
        set_session_cookie_override(
            http_request,
            auth_session.session.session_key,
            auth_session.user,
            browser_close=self._entry_browser_close(http_request, auth_session.session.session_key),
            expires=auth_session.session.expires,
        )
        add_account_session(
            http_request,
            auth_session.session.session_key,
            auth_session.user,
            browser_close=self._entry_browser_close(http_request, auth_session.session.session_key),
        )
        return Response(status=204)

    @extend_schema(
        request=AccountSessionLoginSerializer,
        responses={200: AccountSessionLoginResponseSerializer},
    )
    @action(detail=False, methods=["POST"])
    def login(self, request: Request) -> Response:
        """Start a fresh authentication flow for another connected account."""
        serializer = AccountSessionLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        http_request = request._request
        ensure_current_account_session(http_request)

        store = SessionStore(
            last_ip=ClientIPMiddleware.get_client_ip(http_request),
            last_user_agent=http_request.META.get("HTTP_USER_AGENT", ""),
        )
        store.create()
        set_session_cookie_override(http_request, store.session_key, AnonymousUser())

        auth_flow = ToDefaultFlow.get_flow(http_request, FlowDesignation.AUTHENTICATION)
        next_url = serializer.validated_data.get("next") or reverse("authentik_core:root-redirect")
        query = urlencode({NEXT_ARG_NAME: next_url})
        to = reverse("authentik_core:if-flow", kwargs={"flow_slug": auth_flow.slug})
        return Response({"to": f"{to}?{query}"})
