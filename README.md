# requests-iap2
Auth class for [requests](https://github.com/kennethreitz/requests) used to authenticate HTTP requests to 
Google Cloud [Identity-Aware Proxy](https://cloud.google.com/iap/) using **user** credentials.

This is in contrast to most other IAP authentication libraries which use **service account** credentials.

Original inpiration came from https://github.com/kiwicom/requests-iap 

## Installation

```
pip install git+https://github.com/climateengine/requests-iap2@main
```

## Usage

You will need to have a Google Cloud project with IAP enabled and a user account with `IAP Webapp User` role.

Additionally, you will need to create 2 OAuth 2.0 client IDs in the Google Cloud Console:
one for the IAP server (created as a Web application) and one for the client application (created as a Desktop application).
You will need the client ID and secret for the client application.

Set you application default credentials using the following:
```shell
gcloud auth login
gcloud application-default login
```

```python
import requests
from requests_iap2 import IAPAuth

# This is the URL of the IAP-protected resource
url = "https://stac-staging.climateengine.net/"

# Create a requests Session object and set the authentication handler
session = requests.Session()
session.auth = IAPAuth(
    server_oauth_client_id="something.apps.googleusercontent.com",
    client_oauth_client_id="something_else.apps.googleusercontent.com",
    client_oauth_client_secret="client_secret_fjnclakjwencaiewnl",
    credentials_file="credentials_cache.json",
)

resp = session.get(url)

# Alternatively, you can use the IAPAuth without a Session object
resp = requests.get(url,
                    auth=IAPAuth(
                        server_oauth_client_id="something.apps.googleusercontent.com",
                        client_oauth_client_id="something_else.apps.googleusercontent.com",
                        client_oauth_client_secret="client_secret_fjnclakjwencaiewnl",
                        credentials_file="credentials_cache.json"),
                    )
```

### Caching
Credentials are cached in a file specified by the `credentials_file` parameter.
If this file exists, it will be used to load the credentials, and specifying `client_oauth_client_id` and 
`client_oauth_client_secret` will be optional.

## Code formatting

[black](https://github.com/ambv/black/)

## Releasing

We need to write this...
