"""Test connected account sessions API."""

from datetime import timedelta
from json import loads

from django.conf import settings
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.test import APITestCase

from authentik.core.middleware import SESSION_KEY_IMPERSONATE_USER
from authentik.core.models import AuthenticatedSession, Session
from authentik.core.tests.utils import create_test_brand, create_test_flow, create_test_user
from authentik.flows.models import FlowDesignation
from authentik.lib.generators import generate_id
from authentik.root.middleware import (
    ACCOUNT_SESSION_COOKIE_NAME,
    ClientIPMiddleware,
    encode_account_sessions,
)


class TestAccountSessionsAPI(APITestCase):
    """Test connected account sessions API."""

    def setUp(self) -> None:
        self.user = create_test_user("user")
        self.other_user = create_test_user("other-user")

    def _create_auth_session(self, user, expires=None):
        session = Session.objects.create(
            session_key=generate_id(),
            session_data=b"",
            last_ip=ClientIPMiddleware.default_ip,
            expires=expires or now() + timedelta(hours=1),
        )
        return AuthenticatedSession.objects.create(session=session, user=user)

    def _set_account_cookie(self, entries):
        self.client.cookies[ACCOUNT_SESSION_COOKIE_NAME] = encode_account_sessions(entries)

    def test_list_current_session(self):
        """Current authenticated session is listed as a connected account."""
        self.client.force_login(self.user)
        response = self.client.get(reverse("authentik_api:accountsession-list"))

        self.assertEqual(response.status_code, 200)
        body = loads(response.content)
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["user"]["username"], self.user.username)
        self.assertTrue(body[0]["current"])
        self.assertTrue(body[0]["active"])
        self.assertIn(ACCOUNT_SESSION_COOKIE_NAME, response.cookies)

    def test_list_disconnected_session(self):
        """Missing session entries are returned as disconnected accounts."""
        self.client.force_login(self.user)
        self._set_account_cookie(
            [
                {
                    "sid": generate_id(),
                    "user_pk": self.other_user.pk,
                    "browser_close": True,
                }
            ]
        )
        response = self.client.get(reverse("authentik_api:accountsession-list"))

        self.assertEqual(response.status_code, 200)
        body = loads(response.content)
        # Current user + disconnected other user
        disconnected = [a for a in body if a["disconnected"]]
        self.assertEqual(len(disconnected), 1)
        self.assertEqual(set(disconnected[0]["user"]), {"pk", "username", "name", "email", "avatar"})
        self.assertEqual(disconnected[0]["user"]["username"], self.other_user.username)
        self.assertFalse(disconnected[0]["active"])
        self.assertTrue(disconnected[0]["disconnected"])
        self.assertIsNone(disconnected[0]["session_uuid"])

    def test_switch_session(self):
        """Switch active session cookie to another connected account."""
        self.client.force_login(self.user)
        current_session_key = self.client.session.session_key
        other_auth_session = self._create_auth_session(self.other_user)
        self._set_account_cookie(
            [
                {
                    "sid": current_session_key,
                    "user_pk": self.user.pk,
                    "browser_close": True,
                },
                {
                    "sid": other_auth_session.session.session_key,
                    "user_pk": self.other_user.pk,
                    "browser_close": True,
                },
            ]
        )

        response = self.client.post(
            reverse("authentik_api:accountsession-switch"),
            data={"session_uuid": str(other_auth_session.uuid)},
        )

        self.assertEqual(response.status_code, 204)
        self.assertEqual(
            self.client.cookies[settings.SESSION_COOKIE_NAME].value,
            other_auth_session.session.session_key,
        )

    def test_switch_session_preserves_persistent_expiry(self):
        """Switching to a persistent session uses the target session expiry."""
        self.client.force_login(self.user)
        current_session_key = self.client.session.session_key
        expires = now() + timedelta(hours=2)
        other_auth_session = self._create_auth_session(self.other_user, expires=expires)
        self._set_account_cookie(
            [
                {
                    "sid": current_session_key,
                    "user_pk": self.user.pk,
                    "browser_close": True,
                },
                {
                    "sid": other_auth_session.session.session_key,
                    "user_pk": self.other_user.pk,
                    "browser_close": False,
                },
            ]
        )

        response = self.client.post(
            reverse("authentik_api:accountsession-switch"),
            data={"session_uuid": str(other_auth_session.uuid)},
        )

        self.assertEqual(response.status_code, 204)
        max_age = int(response.cookies[settings.SESSION_COOKIE_NAME]["max-age"])
        self.assertGreater(max_age, 7100)
        self.assertLessEqual(max_age, 7200)
        account_cookie_max_age = int(response.cookies[ACCOUNT_SESSION_COOKIE_NAME]["max-age"])
        self.assertGreater(account_cookie_max_age, 7100)
        self.assertLessEqual(account_cookie_max_age, 7200)

    def test_list_uses_original_user_when_impersonating(self):
        """Impersonation does not add the impersonated user as a connected account."""
        self.client.force_login(self.user)
        session = self.client.session
        session[SESSION_KEY_IMPERSONATE_USER] = self.other_user
        session.save()

        response = self.client.get(reverse("authentik_api:accountsession-list"))

        self.assertEqual(response.status_code, 200)
        body = loads(response.content)
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["user"]["username"], self.user.username)

    def test_login_another_account(self):
        """Starting login for another account switches to a fresh anonymous session."""
        flow = create_test_flow(FlowDesignation.AUTHENTICATION)
        create_test_brand(flow_authentication=flow)
        self.client.force_login(self.user)
        current_session_key = self.client.session.session_key

        response = self.client.post(
            reverse("authentik_api:accountsession-login"),
            data={"next": "/if/user/"},
        )

        self.assertEqual(response.status_code, 200)
        body = loads(response.content)
        self.assertIn(f"/if/flow/{flow.slug}/", body["to"])
        self.assertIn("next=%2Fif%2Fuser%2F", body["to"])
        self.assertNotEqual(
            self.client.cookies[settings.SESSION_COOKIE_NAME].value, current_session_key
        )
        self.assertIn(ACCOUNT_SESSION_COOKIE_NAME, response.cookies)

    def test_login_another_account_preserves_persistent_account_cookie(self):
        """Persistent sessions remain recoverable after starting another account login."""
        flow = create_test_flow(FlowDesignation.AUTHENTICATION)
        create_test_brand(flow_authentication=flow)
        self.client.force_login(self.user)
        session = self.client.session
        session.set_expiry(timedelta(hours=2))
        session.save()

        response = self.client.post(
            reverse("authentik_api:accountsession-login"),
            data={"next": "/if/user/"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.cookies[settings.SESSION_COOKIE_NAME]["max-age"], "")
        account_cookie_max_age = int(response.cookies[ACCOUNT_SESSION_COOKIE_NAME]["max-age"])
        self.assertGreater(account_cookie_max_age, 7100)
        self.assertLessEqual(account_cookie_max_age, 7200)
