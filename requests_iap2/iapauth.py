import datetime
import logging
import re
from pathlib import Path

import requests
from google.auth.exceptions import DefaultCredentialsError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.oauth2 import id_token
from requests.auth import AuthBase, extract_cookies_to_jar

from requests_iap2.get_oauth_creds import fetch_user_credentials, fetch_gcp_credentials, fetch_env_credentials
from exceptions import UserCredentialError, RequestsIAP2Error

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

_DEFAULT_CACHE_FILENAME = "~/.requests_iap2_credentials.json"
_DEFAULT_PORT = 8044


# https://cloud.google.com/iap/docs/authentication-howto


class IAPAuth(requests.auth.AuthBase):
    """Custom requests Auth class used to authenticate HTTP requests to OIDC-authenticated resources using a service account.
    The major use case is to use this flow to make requests to resources behind an Identity-Aware Proxy (https://cloud.google.com/iap).

    This JWT is then exchanged for a Google-signed OIDC token for the client id specified in the JWT claims.
    Authenticated requests are made by setting the token in the `Authorization: Bearer` header.
    This token has roughly a 1-hour expiration and is renewed transparently by this authentication class.
    """

    server_oauth_client_id: str
    client_oauth_client_id: str
    client_oauth_client_secret: str
    credentials_cache: Path

    def __init__(
            self,
            server_oauth_client_id: str = None,
            client_oauth_client_id: str = None,
            client_oauth_client_secret: str = None,
            credentials_cache: str = None,
    ):

        self.client_oauth_client_id = client_oauth_client_id
        self.client_oauth_client_secret = client_oauth_client_secret
        self.server_oauth_client_id = server_oauth_client_id

        if credentials_cache is None:
            credentials_cache = Path.expanduser(Path(_DEFAULT_CACHE_FILENAME))
        else:
            credentials_cache = Path.expanduser(Path(credentials_cache))

        self.credentials_cache = credentials_cache

        self.credentials = None
        self._id_token = None
        self._expires_at = None

        if self.credentials is None:
            try:
                logger.info("Trying credentials from APPLICAION_DEFAULT_CREDENTIALS")
                self.credentials = fetch_env_credentials(self.server_oauth_client_id)
                self._is_user = False
            except DefaultCredentialsError:
                # APPLICATION_DEFAULT_CREDENTIALS not set or some other issue
                pass

        if self.credentials is None:
            try:
                logger.info("Trying user credentials")
                self.credentials = fetch_user_credentials(
                    self.client_oauth_client_id,
                    self.client_oauth_client_secret,
                    self.credentials_cache,
                )
                self._is_user = True
            except UserCredentialError:
                pass

        if self.credentials is None:
            try:
                logger.info("Trying GCP credentials")
                self.credentials = fetch_gcp_credentials(self.server_oauth_client_id)
                self._is_user = False
            except DefaultCredentialsError:
                pass

        if self.credentials is None:
            raise RequestsIAP2Error("Could not find credentials")

    def handle_401(self, r, **kwargs):
        if (
                r.status_code == 401
                and r.headers.get("X-Goog-IAP-Generated-Response") == "true"
        ):
            # print("IAPAuth: 401 response from IAP, retrying with new aud claim")
            try:
                aud = re.search(r"expected value \((.*)\)\)$", r.text).group(1)
            except AttributeError:
                logger.warning("IAPAuth: could not parse aud claim from 401 response")
                return r

            # Set the aud claim to the expected value and retry
            self.server_oauth_client_id = aud
            self._id_token = None

            # Retry the request with the new aud claim
            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            _ = r.content
            r.close()
            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep.headers["Authorization"] = "Bearer {}".format(self.id_token)

            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        return r

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer {}".format(self.id_token)
        r.register_hook("response", self.handle_401)
        return r

    @property
    def id_token(self):
        if not self._id_token_valid():
            self._get_id_token()
        return self._id_token

    def _get_id_token(self):
        if self._is_user:
            return self._get_user_id_token()
        else:
            return self._get_sa_id_token()

    def _get_sa_id_token(self):
        if self.server_oauth_client_id is None:
            self.server_oauth_client_id = 'unknown'

        if self.credentials.token is None or self.credentials.expired:
            self.credentials.refresh(Request())

        id_token_credentials = id_token.fetch_id_token_credentials(self.server_oauth_client_id, request=Request())
        id_token_credentials.refresh(Request())

        self._id_token = id_token_credentials.token
        self._expires_at = self.credentials.expiry

        return self._id_token

    def _get_user_id_token(self):

        if self.credentials.token is None or self.credentials.expired:
            self.credentials.refresh(Request())

        data = {
            "client_id": self.credentials.client_id,
            "client_secret": self.credentials.client_secret,
            "refresh_token": self.credentials.refresh_token,
            "grant_type": "refresh_token",
        }

        if self.server_oauth_client_id is not None:
            data["audience"] = self.server_oauth_client_id

        response = requests.post(self.credentials.token_uri, data=data)
        response.raise_for_status()
        _oidc_token = response.json()

        self._id_token = _oidc_token["id_token"]
        self._expires_at = datetime.datetime.now() + datetime.timedelta(seconds=_oidc_token["expires_in"])

        return self._id_token

    def _id_token_valid(self):
        return self._id_token and self._expires_at > datetime.datetime.utcnow() - datetime.timedelta(
            seconds=300
        )  # 5 minutes before expiration


if __name__ == "__main__":
    import requests

    # This is the URL of the IAP-protected resource
    url = "https://stac-staging.climateengine.net/"

    # Create a requests Session object and set the authentication handler
    session = requests.Session()
    session.auth = IAPAuth()

    # Make the request
    r = session.get(url)
    print(r.status_code)
    print(r.headers)
    print(r.text)
