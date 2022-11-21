# requests-iap2
Auth class for [requests](https://github.com/kennethreitz/requests) used to authenticate HTTP requests to 
Google Cloud [Identity-Aware Proxy](https://cloud.google.com/iap/) using **user** credentials.

This is in contrast to most other IAP authentication libraries which use **service account** credentials.

Original inspiration came from https://github.com/kiwicom/requests-iap 

## Installation

Typical installation via pip:

```shell
pip install requests-iap2
```

Alternatively you can install from source:

```shell
git clone https://github.com/climateengine/requests-iap2.git
cd requests-iap2
pip install .
```


### Setup
You will need to have a Google Cloud project with IAP enabled and a user account with `IAP Webapp User` role.

Additionally, you will need to create 2 OAuth 2.0 client IDs in the Google Cloud Console:
one for the IAP server (created as a Web application) and one for the client application (created as a Desktop application).
You will need the client ID and secret for the "desktop" client application.

In most cases, IAP will have already creates a "Web application" client ID for you, and you do not need to create a new one.

## Usage

### Example

```python
import requests
from requests_iap2 import IAPAuth

# This is the URL of the IAP-protected resource
url = "https://stac-staging.climateengine.net/"

# Create a requests Session object and set the authentication handler
session = requests.Session()
session.auth = IAPAuth(
    client_oauth_client_id="something_else.apps.googleusercontent.com",  # "Desktop" client
    client_oauth_client_secret="client_secret_key",  # "Desktop" client secret
    server_oauth_client_id="something.apps.googleusercontent.com",  # optional, "Web" client created by IAP
    use_adc=False,  # optional, set to True to use ADC instead of user credentials
    oob=False,  # optional, set to True if running in a headless environment or cannot run a webserver (e.g. on Vertex AI)
)

# Use the session to make requests
r = session.get(url)

# Alternatively, you can use the IAPAuth without a Session object
r = requests.get(url,
                    auth=IAPAuth(
                        server_oauth_client_id="something.apps.googleusercontent.com",  # optional
                        client_oauth_client_id="something_else.apps.googleusercontent.com",
                        client_oauth_client_secret="client_secret_key"),
                    )
```

### On Vertex AI or Cloud AI Platform Notebooks

If you are running on Vertex AI or Cloud AI Platform Notebooks, you will need to set `oob=True` when creating the `IAPAuth` object.


## Cross-Project ADC Credentials
ADC credentials only work within the same project as the IAP resource.

If you are running in Vertex AI, you can change the project that ADC uses, but the process can be a bit cumbersome.

In the Vertex AI notebook (Python), run the following, replacing `client_oauth_client_id` and 
`client_oauth_client_secret` with the values from the "Desktop" OAuth2 client.

```python
from requests_iap2.create_client_id_file import create_client_id_file

create_client_id_file(client_id, client_secret)
```

This will create a file called `client_id.json` in the current directory.

Then in the Vertex AI notebook, create a *Terminal* and run the following (this wii not work in the Python notebook):

```shell
gcloud auth application-default login --no-browser --client-id-file=client_id.json
```

You will be given a very long command to copy. **You will need to run this command in a Terminal outside of the Vertex AI notebook.**

Copy and paste the command into a terminal running *on your local machine*. You will be required to go through multiple
prompts to authenticate.

You may receive an error message in a browser that says "Google hasn't verified this app".
To continue, click "Advanced" and then "Go to <app name> (unsafe)".

Check the boxes to allow the app to access your Google account and then click "Continue".

After allowing access, your local terminal will display a code that you will need to copy and paste into the 
terminal running in Vertex AI notebook.  Note: this code may look like a url starting with `https://localhost:8085/...`

Your Vertex AI notebook should now be able to authenticate to an IAP resource in a different project.
You may need to restart the notebook kernel to pick up the new credentials.

## Development

### Future work

- [ ] Add tests
- [ ] Add support for service account credentials
- [x] Add support for ADC (Application Default Credentials)

### Code formatting

[black](https://github.com/ambv/black/)

### Package versioning

Versioning of this package is done through [setuptools-scm](https://github.com/pypa/setuptools_scm),
which auto-generates the version number based on git tags and commits. setuptools-scm generates a
unique version number for each commit in the repository according to
[this scheme](https://github.com/pypa/setuptools_scm/#default-versioning-scheme).

The version of the package is read from `requests_iap2/_version.py`
(which is generated by setuptools_scm during the package build) when running as a package, and derived
from git when running from source.

### Updating requirements.txt and test-requirements.txt

See `scripts/gen_requirements.sh`.

### Releasing

This project uses [semantic versioning](https://semver.org/).

For a new minor version release (`X.X.0`), create a `vX.X.0` tag in main branch,
and create a `vX.X` branch from the same commit for future patches to the minor version.

For patch versions, commit to and create `vX.X.Y` tags in the respective minor version branch.
(e.g `v1.1.1`, `v1.1.2`.. tags in the `v1.1` branch)

For building the package and publishing it on PyPI, see `scripts/build_package.sh`
and `scripts/publish_package.sh`.
