"""authentik SAML IDP Views"""

from uuid import uuid4

from django.core.cache import cache
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.http import urlencode
from django.utils.translation import gettext as _
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.decorators.csrf import csrf_exempt
from structlog.stdlib import get_logger

from authentik.core.models import Application, AuthenticatedSession
from authentik.events.models import Event, EventAction
from authentik.flows.exceptions import FlowNonApplicableException
from authentik.flows.models import in_memory_stage
from authentik.flows.planner import PLAN_CONTEXT_APPLICATION, PLAN_CONTEXT_SSO, FlowPlanner
from authentik.flows.views.executor import NEXT_ARG_NAME, SESSION_KEY_POST
from authentik.lib.views import bad_request_message
from authentik.policies.views import PolicyAccessView, RequestValidationError
from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLBindings, SAMLProvider
from authentik.providers.saml.processors.authn_request_parser import AuthNRequestParser
from authentik.providers.saml.views.flows import (
    PLAN_CONTEXT_SAML_AUTH_N_REQUEST,
    REQUEST_KEY_RELAY_STATE,
    REQUEST_KEY_SAML_REQUEST,
    REQUEST_KEY_SAML_SIG_ALG,
    REQUEST_KEY_SAML_SIGNATURE,
    SAMLFlowFinalView,
)
from authentik.root.middleware import ensure_current_account_session, get_account_session_entries
from authentik.stages.consent.stage import (
    PLAN_CONTEXT_CONSENT_HEADER,
    PLAN_CONTEXT_CONSENT_PERMISSIONS,
)

LOGGER = get_logger()

QS_ACCOUNT_SELECTED = "authentik_account_selected"
QS_ACCOUNT_SELECTION_TOKEN = "authentik_saml_account_selection_token"
ACCOUNT_SELECTION_CACHE_KEY = "authentik.providers.saml.account_selection.post.{}"
ACCOUNT_SELECTION_CACHE_TIMEOUT = 300


class SAMLSSOView(PolicyAccessView):
    """SAML SSO Base View, which plans a flow and injects our final stage.
    Calls get/post handler."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.plan_context = {}

    def resolve_provider_application(self):
        self.application = get_object_or_404(Application, slug=self.kwargs["application_slug"])
        self.provider: SAMLProvider = get_object_or_404(
            SAMLProvider, pk=self.application.provider_id
        )

    def _switchable_account_count(self) -> int:
        """Count active connected accounts that can be selected for this browser."""
        if not self.request.user.is_authenticated:
            return 0
        ensure_current_account_session(self.request)
        entries = get_account_session_entries(self.request)
        session_keys = [entry["sid"] for entry in entries]
        if not session_keys:
            return 0
        return len(
            set(
                AuthenticatedSession.objects.filter(
                    session__session_key__in=session_keys,
                    session__expires__gt=timezone.now(),
                    user__is_active=True,
                ).values_list("user_id", flat=True)
            )
        )

    def _should_select_account(self) -> bool:
        """Redirect to the account chooser when multiple active accounts are available."""
        if QS_ACCOUNT_SELECTED in self.request.GET:
            return False
        return self._switchable_account_count() > 1

    def _cache_post_payload(self) -> str | None:
        """Store a POSTed AuthNRequest while the user is selecting an account."""
        source_payload = None
        if self.request.method.lower() == "post":
            source_payload = self.request.POST
        elif SESSION_KEY_POST in self.request.session:
            source_payload = self.request.session[SESSION_KEY_POST]
        if not source_payload or REQUEST_KEY_SAML_REQUEST not in source_payload:
            return None

        token = uuid4().hex
        payload = {REQUEST_KEY_SAML_REQUEST: source_payload[REQUEST_KEY_SAML_REQUEST]}
        if REQUEST_KEY_RELAY_STATE in source_payload:
            payload[REQUEST_KEY_RELAY_STATE] = source_payload[REQUEST_KEY_RELAY_STATE]
        cache.set(
            ACCOUNT_SELECTION_CACHE_KEY.format(token),
            payload,
            timeout=ACCOUNT_SELECTION_CACHE_TIMEOUT,
        )
        return token

    def _account_select_redirect(self) -> HttpResponseRedirect:
        query = self.request.GET.copy()
        query[QS_ACCOUNT_SELECTED] = "1"
        if token := self._cache_post_payload():
            query[QS_ACCOUNT_SELECTION_TOKEN] = token
        next_url = self.request.path
        if query:
            next_url = f"{next_url}?{query.urlencode()}"
        return HttpResponseRedirect(
            f"{reverse('authentik_core:if-account-select')}?{urlencode({NEXT_ARG_NAME: next_url})}"
        )

    def pre_permission_check(self):
        if self._should_select_account():
            raise RequestValidationError(self._account_select_redirect())

    def check_saml_request(self) -> HttpRequest | None:
        """Handler to verify the SAML Request. Must be implemented by a subclass"""
        raise NotImplementedError

    def get(self, request: HttpRequest, application_slug: str) -> HttpResponse:
        """Verify the SAML Request, and if valid initiate the FlowPlanner for the application"""
        # Call the method handler, which checks the SAML
        # Request and returns a HTTP Response on error
        method_response = self.check_saml_request()
        if method_response:
            return method_response
        # Regardless, we start the planner and return to it
        planner = FlowPlanner(self.provider.authorization_flow)
        planner.allow_empty_flows = True
        try:
            plan = planner.plan(
                request,
                {
                    PLAN_CONTEXT_SSO: True,
                    PLAN_CONTEXT_APPLICATION: self.application,
                    PLAN_CONTEXT_CONSENT_HEADER: _("You're about to sign into %(application)s.")
                    % {"application": self.application.name},
                    PLAN_CONTEXT_CONSENT_PERMISSIONS: [],
                    **self.plan_context,
                },
            )
        except FlowNonApplicableException:
            raise Http404 from None
        plan.append_stage(in_memory_stage(SAMLFlowFinalView))
        return plan.to_redirect(
            request,
            self.provider.authorization_flow,
            allowed_silent_types=(
                [SAMLFlowFinalView] if self.provider.sp_binding in [SAMLBindings.REDIRECT] else []
            ),
        )

    def post(self, request: HttpRequest, application_slug: str) -> HttpResponse:
        """GET and POST use the same handler, but we can't
        override .dispatch easily because PolicyAccessView's dispatch"""
        return self.get(request, application_slug)


class SAMLSSOBindingRedirectView(SAMLSSOView):
    """SAML Handler for SSO/Redirect bindings, which are sent via GET"""

    def check_saml_request(self) -> HttpRequest | None:
        """Handle REDIRECT bindings"""
        if REQUEST_KEY_SAML_REQUEST not in self.request.GET:
            LOGGER.info("SAML payload missing")
            return bad_request_message(self.request, "The SAML request payload is missing.")

        try:
            auth_n_request = AuthNRequestParser(self.provider).parse_detached(
                self.request.GET[REQUEST_KEY_SAML_REQUEST],
                self.request.GET.get(REQUEST_KEY_RELAY_STATE),
                self.request.GET.get(REQUEST_KEY_SAML_SIGNATURE),
                self.request.GET.get(REQUEST_KEY_SAML_SIG_ALG),
            )
            self.plan_context[PLAN_CONTEXT_SAML_AUTH_N_REQUEST] = auth_n_request
        except CannotHandleAssertion as exc:
            Event.new(
                EventAction.CONFIGURATION_ERROR,
                provider=self.provider,
                message=str(exc),
            ).save()
            LOGGER.info(str(exc))
            return bad_request_message(self.request, str(exc))
        return None


@method_decorator(xframe_options_sameorigin, name="dispatch")
@method_decorator(csrf_exempt, name="dispatch")
class SAMLSSOBindingPOSTView(SAMLSSOView):
    """SAML Handler for SSO/POST bindings"""

    def check_saml_request(self) -> HttpRequest | None:
        """Handle POST bindings"""
        payload = self.request.POST
        # Restore the post body from the session
        # This happens when using POST bindings but the user isn't logged in
        # (user gets redirected and POST body is 'lost')
        if token := self.request.GET.get(QS_ACCOUNT_SELECTION_TOKEN):
            payload = cache.get(ACCOUNT_SELECTION_CACHE_KEY.format(token))
            cache.delete(ACCOUNT_SELECTION_CACHE_KEY.format(token))
            if payload:
                self.request.session.pop(SESSION_KEY_POST, None)
            else:
                payload = self.request.session.pop(SESSION_KEY_POST, {})
        elif SESSION_KEY_POST in self.request.session:
            payload = self.request.session.pop(SESSION_KEY_POST)
        if REQUEST_KEY_SAML_REQUEST not in payload:
            LOGGER.info("SAML payload missing")
            return bad_request_message(self.request, "The SAML request payload is missing.")

        try:
            auth_n_request = AuthNRequestParser(self.provider).parse(
                payload[REQUEST_KEY_SAML_REQUEST],
                payload.get(REQUEST_KEY_RELAY_STATE),
            )
            self.plan_context[PLAN_CONTEXT_SAML_AUTH_N_REQUEST] = auth_n_request
        except CannotHandleAssertion as exc:
            LOGGER.info(str(exc))
            return bad_request_message(self.request, str(exc))
        return None


class SAMLSSOBindingInitView(SAMLSSOView):
    """SAML Handler for for IdP Initiated login flows"""

    def check_saml_request(self) -> HttpRequest | None:
        """Create SAML Response from scratch"""
        LOGGER.debug("No SAML Request, using IdP-initiated flow.")
        auth_n_request = AuthNRequestParser(self.provider).idp_initiated()
        self.plan_context[PLAN_CONTEXT_SAML_AUTH_N_REQUEST] = auth_n_request
