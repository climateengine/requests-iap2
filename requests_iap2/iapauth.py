import datetime
import re

import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from requests.auth import AuthBase, extract_cookies_to_jar

from .get_credentials import get_credentials


class IAPAuth(requests.auth.AuthBase):
    """Custom requests Auth class used to authenticate HTTP requests to OIDC-authenticated resources using a service account.
    The major use case is to use this flow to make requests to resources behind an Identity-Aware Proxy (https://cloud.google.com/iap).

    This JWT is then exchanged for a Google-signed OIDC token for the client id specified in the JWT claims.
    Authenticated requests are made by setting the token in the `Authorization: Bearer` header.
    This token has roughly a 1-hour expiration and is renewed transparently by this authentication class.
    """

    client_id: str
    credentials: Credentials

    def __init__(
        self,
        credentials: Credentials = None,
        server_oauth_client_id: str = None,
        client_oauth_client_id: str = None,
        client_oauth_client_secret: str = None,
        use_adc: bool = False,
        oob: bool = False,
    ):
        if credentials is None:
            credentials = get_credentials(
                client_id=client_oauth_client_id,
                client_secret=client_oauth_client_secret,
                use_adc=use_adc,
                oob=oob,
            )
        self.credentials = credentials
        self.server_oauth_client_id = server_oauth_client_id
        self.use_adc = use_adc
        self.oob = oob
        self._oidc_token = None
        self._id_token = None

    def handle_401(self, r, **kwargs):
        if (
            r.status_code == 401
            and r.headers.get("X-Goog-IAP-Generated-Response") == "true"
        ):
            # print("IAPAuth: 401 response from IAP, retrying with new aud claim")
            try:
                aud = re.search(r"expected value \((.*)\)\)$", r.text).group(1)
            except AttributeError:
                print("IAPAuth: could not parse aud claim from 401 response")
                return r

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
        if response.status_code == 400:
            try:
                error = response.json()["error"]
            except (KeyError, ValueError):
                error = "invalid_request"
            if error == "invalid_audience":
                if self.use_adc:
                    raise ValueError(
                        "The client_oauth_client_id must from the same GCP project as the IAP-protected resource. "
                        "If you are running this in a Vertex AI notebook, see "
                        "https://github.com/climateengine/requests-iap2/tree/main#cross-project-access"
                    )
                raise ValueError(
                    "The client_oauth_client_id must from the same GCP project as the IAP-protected resource. "
                )
            else:
                raise ValueError(
                    "Invalid client_oauth_client_id or client_oauth_client_secret."
                )
        response.raise_for_status()
        self._oidc_token = response.json()
        self._oidc_token[
            "expires_at"
        ] = datetime.datetime.utcnow() + datetime.timedelta(
            seconds=self._oidc_token["expires_in"]
        )
        self._id_token = self._oidc_token["id_token"]

        return self._id_token

    def _id_token_valid(self):
        return self._id_token and self._oidc_token[
            "expires_at"
        ] > datetime.datetime.utcnow() - datetime.timedelta(
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
