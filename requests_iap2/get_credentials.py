import json

import google.auth
from google.oauth2.credentials import Credentials

from .constants import _DEFAULT_OAUTH_PARAMS, _SCOPES

_DEFAULT_PORT = 8044


def get_credentials(client_id, client_secret, use_adc=False):
    if use_adc:
        creds = get_adc_creds()
    else:
        creds = get_app_creds(client_id, client_secret)

    return creds


def get_adc_creds():
    creds, _ = google.auth.default(scopes=_SCOPES)
    return creds


def get_app_creds(client_id, client_secret):
    creds = auth_flow(client_id=client_id, client_secret=client_secret)
    return creds


def auth_flow(client_id, client_secret):
    from google_auth_oauthlib.flow import InstalledAppFlow

    client_config = _DEFAULT_OAUTH_PARAMS.copy()
    client_config["installed"]["client_id"] = client_id
    client_config["installed"]["client_secret"] = client_secret

    # Create the flow using the client secrets file from the Google API console.
    flow = InstalledAppFlow.from_client_config(
        client_config,
        scopes=_SCOPES,
    )

    credentials = None
    port = _DEFAULT_PORT
    while credentials is None:
        try:
            credentials = flow.run_local_server(
                host="localhost",
                port=port,
                authorization_prompt_message="Please visit this URL: {url}",
                success_message="The auth flow is complete; you may close this window.",
                open_browser=True,
            )
        except OSError:
            port += 1
            if port > _DEFAULT_PORT + 100:
                raise

    return credentials
