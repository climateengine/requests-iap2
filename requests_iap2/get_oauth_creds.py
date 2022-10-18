from pathlib import Path
import json
from google.oauth2.credentials import Credentials

_DEFAULT_OAUTH_PARAMS = {
    "installed": {
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "redirect_uris": ["http://localhost"],
    }
}

_DEFAULT_CACHE_FILENAME = ".requests_iap2_credentials.json"

_DEFAULT_PORT = 8044


def get_credentials(client_id=None, client_secret=None, credentials_cache=None):
    creds = get_oauth_creds(
        credentials_cache=credentials_cache,
        client_id=client_id,
        client_secret=client_secret,
    )
    if "expiry" in creds:
        del creds["expiry"]
    return Credentials(**creds)


def get_oauth_creds(client_id=None, client_secret=None, credentials_cache=None):
    if credentials_cache is None:
        credentials_cache = Path.home() / _DEFAULT_CACHE_FILENAME

    if Path.exists(credentials_cache):
        with open(credentials_cache) as f:
            try:
                creds = json.load(f)
                if "expiry" in creds:
                    del creds["expiry"]
                return creds
            except json.decoder.JSONDecodeError:
                pass

    creds = auth_flow(client_id=client_id, client_secret=client_secret)
    with open(credentials_cache, "w") as f:
        creds_copy = creds.copy()
        if "expiry" in creds_copy:
            del creds_copy["expiry"]
        json.dump(creds_copy, f)

    return creds


def auth_flow(client_id, client_secret):
    """Returns a dictionary of environment variables needed for authentication."""

    if client_id is None or client_secret is None:
        raise ValueError("Must provide client_id and client_secret for first-time auth")

    from google_auth_oauthlib.flow import InstalledAppFlow

    client_config = _DEFAULT_OAUTH_PARAMS.copy()
    client_config["installed"]["client_id"] = client_id
    client_config["installed"]["client_secret"] = client_secret

    # Create the flow using the client secrets file from the Google API console.
    flow = InstalledAppFlow.from_client_config(
        client_config,
        scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid",
        ],
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

    return json.loads(credentials.to_json())
