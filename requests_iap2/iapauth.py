import datetime

import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from requests.auth import AuthBase

from .get_oauth_creds import get_credentials

# https://cloud.google.com/iap/docs/authentication-howto


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
        credentials_file: str = None,
    ):
        if credentials is None:
            credentials = get_credentials(
                filename=credentials_file,
                client_id=client_oauth_client_id,
                client_secret=client_oauth_client_secret,
            )
        self.credentials = credentials
        self.server_oauth_client_id = server_oauth_client_id
        self._oidc_token = None
        self._id_token = None

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer {}".format(self.id_token)
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
            "audience": self.server_oauth_client_id,
        }

        response = requests.post(self.credentials.token_uri, data=data)
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
    session.auth = IAPAuth(
        credentials_file="ce_stac_auth",
        server_oauth_client_id="45034861422-2nlvg69msb7mdqsrnsqlia4sp0r6t73s.apps.googleusercontent.com",
    )

    # Make the request
    r = session.get(url)
    print(r.status_code)
    print(r.headers)
    print(r.text)
