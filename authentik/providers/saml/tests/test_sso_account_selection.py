"""Test SAML SSO account selection."""

from base64 import b64encode
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

from django.core.cache import cache
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils.timezone import now

from authentik.common.saml.constants import NS_SAML_PROTOCOL
from authentik.core.models import Application, AuthenticatedSession, Session
from authentik.core.tests.utils import create_test_admin_user, create_test_flow, create_test_user
from authentik.flows.views.executor import NEXT_ARG_NAME, SESSION_KEY_POST
from authentik.lib.generators import generate_id
from authentik.providers.saml.models import SAMLBindings, SAMLProvider
from authentik.providers.saml.utils.encoding import deflate_and_base64_encode
from authentik.providers.saml.views.flows import (
    PLAN_CONTEXT_SAML_AUTH_N_REQUEST,
    REQUEST_KEY_RELAY_STATE,
    REQUEST_KEY_SAML_REQUEST,
)
from authentik.providers.saml.views.sso import (
    ACCOUNT_SELECTION_CACHE_KEY,
    QS_ACCOUNT_SELECTED,
    QS_ACCOUNT_SELECTION_TOKEN,
    SAMLSSOBindingPOSTView,
)
from authentik.root.middleware import (
    ACCOUNT_SESSION_COOKIE_NAME,
    ClientIPMiddleware,
    encode_account_sessions,
)


class TestSAMLSSOAccountSelection(TestCase):
    """Test SAML SSO account selection."""

    def setUp(self):
        self.factory = RequestFactory()
        cache.clear()
        self.provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://testserver/saml/acs/",
            sp_binding=SAMLBindings.POST,
        )
        self.application = Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=self.provider,
        )

    def _create_authenticated_session(self, user) -> AuthenticatedSession:
        session = Session.objects.create(
            session_key=generate_id(),
            session_data=b"",
            last_ip=ClientIPMiddleware.default_ip,
            expires=now() + timedelta(hours=1),
        )
        return AuthenticatedSession.objects.create(session=session, user=user)

    def _authn_request_xml(self) -> str:
        request_id = generate_id()
        return (
            f'<saml2p:AuthnRequest xmlns:saml2p="{NS_SAML_PROTOCOL}" '
            f'AssertionConsumerServiceURL="{self.provider.acs_url}" '
            f'ID="{request_id}" Version="2.0" />'
        )

    def _post_authn_request(self) -> str:
        return b64encode(self._authn_request_xml().encode()).decode()

    def _redirect_authn_request(self) -> str:
        return deflate_and_base64_encode(self._authn_request_xml())

    def _login_with_connected_account(self):
        user = create_test_admin_user()
        other_user = create_test_user("other-user")
        other_session = self._create_authenticated_session(other_user)
        self.client.force_login(user)
        self.client.cookies[ACCOUNT_SESSION_COOKIE_NAME] = encode_account_sessions(
            [
                {
                    "sid": other_session.session.session_key,
                    "user_pk": other_user.pk,
                    "browser_close": True,
                }
            ]
        )
        return user, other_user

    def _assert_account_select_redirect(self, response, url_name: str) -> dict[str, list[str]]:
        self.assertEqual(response.status_code, 302)
        parsed = urlparse(response.url)
        self.assertEqual(parsed.path, reverse("authentik_core:if-account-select"))
        next_url = parse_qs(parsed.query)[NEXT_ARG_NAME][0]
        next_parsed = urlparse(next_url)
        self.assertEqual(
            next_parsed.path,
            reverse(
                f"authentik_providers_saml:{url_name}",
                kwargs={"application_slug": self.application.slug},
            ),
        )
        next_query = parse_qs(next_parsed.query)
        self.assertEqual(next_query[QS_ACCOUNT_SELECTED], ["1"])
        return next_query

    def test_redirect_binding_multiple_accounts_redirects(self):
        """Multiple connected accounts redirect SAML Redirect binding to the account chooser."""
        self._login_with_connected_account()
        saml_request = self._redirect_authn_request()
        relay_state = generate_id()

        response = self.client.get(
            reverse(
                "authentik_providers_saml:sso-redirect",
                kwargs={"application_slug": self.application.slug},
            ),
            data={REQUEST_KEY_SAML_REQUEST: saml_request, REQUEST_KEY_RELAY_STATE: relay_state},
        )

        next_query = self._assert_account_select_redirect(response, "sso-redirect")
        self.assertEqual(next_query[REQUEST_KEY_SAML_REQUEST], [saml_request])
        self.assertEqual(next_query[REQUEST_KEY_RELAY_STATE], [relay_state])

    def test_post_binding_multiple_accounts_redirects_and_restores_payload(self):
        """Multiple connected accounts redirect SAML POST binding and keep the AuthNRequest."""
        self._login_with_connected_account()
        saml_request = self._post_authn_request()
        relay_state = generate_id()

        response = self.client.post(
            reverse(
                "authentik_providers_saml:sso-post",
                kwargs={"application_slug": self.application.slug},
            ),
            data={REQUEST_KEY_SAML_REQUEST: saml_request, REQUEST_KEY_RELAY_STATE: relay_state},
        )

        next_query = self._assert_account_select_redirect(response, "sso-post")
        token = next_query[QS_ACCOUNT_SELECTION_TOKEN][0]
        self.assertEqual(
            cache.get(ACCOUNT_SELECTION_CACHE_KEY.format(token)),
            {REQUEST_KEY_SAML_REQUEST: saml_request, REQUEST_KEY_RELAY_STATE: relay_state},
        )

        request = self.factory.get(
            reverse(
                "authentik_providers_saml:sso-post",
                kwargs={"application_slug": self.application.slug},
            ),
            data={QS_ACCOUNT_SELECTED: "1", QS_ACCOUNT_SELECTION_TOKEN: token},
        )
        request.session = {}
        view = SAMLSSOBindingPOSTView()
        view.setup(request, application_slug=self.application.slug)
        view.provider = self.provider

        self.assertIsNone(view.check_saml_request())
        auth_n_request = view.plan_context[PLAN_CONTEXT_SAML_AUTH_N_REQUEST]
        self.assertEqual(auth_n_request.relay_state, relay_state)
        self.assertIsNone(cache.get(ACCOUNT_SELECTION_CACHE_KEY.format(token)))

    def test_post_binding_session_payload_is_cached_for_account_switch(self):
        """POST payloads saved during login survive account selection and switching accounts."""
        self._login_with_connected_account()
        saml_request = self._post_authn_request()
        relay_state = generate_id()
        session = self.client.session
        session[SESSION_KEY_POST] = {
            REQUEST_KEY_SAML_REQUEST: saml_request,
            REQUEST_KEY_RELAY_STATE: relay_state,
        }
        session.save()

        response = self.client.get(
            reverse(
                "authentik_providers_saml:sso-post",
                kwargs={"application_slug": self.application.slug},
            )
        )

        next_query = self._assert_account_select_redirect(response, "sso-post")
        token = next_query[QS_ACCOUNT_SELECTION_TOKEN][0]
        self.assertEqual(
            cache.get(ACCOUNT_SELECTION_CACHE_KEY.format(token)),
            {REQUEST_KEY_SAML_REQUEST: saml_request, REQUEST_KEY_RELAY_STATE: relay_state},
        )
