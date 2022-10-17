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


def get_credentials(filename="requests_iap_auth", client_id=None, client_secret=None):
    creds = get_oauth_creds(filename, client_id, client_secret)
    if "expiry" in creds:
        del creds["expiry"]
    return Credentials(**creds)


def get_oauth_creds(filename, project_id=None, client_id=None, client_secret=None):
    if Path.exists(Path.home() / filename):
        with open(Path.home() / filename) as f:
            creds = json.load(f)
            if "expiry" in creds:
                del creds["expiry"]
    else:
        if client_id is None or client_secret is None or project_id is None:
            raise ValueError(
                "Must provide client_id, client_secret, and project_id for first-time auth"
            )

        creds = auth_flow(project_id, client_id, client_secret)
        with open(Path.home() / filename, "w") as f:
            creds_copy = creds.copy(deep=True)
            if "expiry" in creds_copy:
                del creds_copy["expiry"]
            json.dump(creds_copy, f)

    return creds


def auth_flow(project_id, client_id, client_secret):
    """Returns a dictionary of environment variables needed for authentication."""
    from google_auth_oauthlib.flow import InstalledAppFlow

    client_config = _DEFAULT_OAUTH_PARAMS.copy()
    client_config["installed"]["project_id"] = project_id
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

    credentials = flow.run_local_server(
        host="localhost",
        port=8044,
        authorization_prompt_message="Please visit this URL: {url}",
        success_message="The auth flow is complete; you may close this window.",
        open_browser=True,
    )

    return json.loads(credentials.to_json())
