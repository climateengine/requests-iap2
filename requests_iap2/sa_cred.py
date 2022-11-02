from google.auth.transport.requests import Request
from google.oauth2 import id_token

import requests


def get_id_token_credentials_token():

    client_id = "my_client_id"
    credentials = id_token.fetch_id_token_credentials(client_id)
    if credentials.token is None or credentials.expired:
        credentials.refresh(Request())
    print(credentials)
    print(credentials.token)

    return credentials.token


def get_default_credentials_token():
    import google.auth

    credentials, project = google.auth.default(scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "openid",
        ],)
    if credentials.token is None or credentials.expired:
        credentials.refresh(Request())
    print(credentials)
    print(credentials.token)

    return credentials.token


if __name__ == "__main__":


    token = get_id_token_credentials_token()

    print(token)

    url = "https://stac-staging.climateengine.net/"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)

    print(response.status_code)
    print(response.text)
