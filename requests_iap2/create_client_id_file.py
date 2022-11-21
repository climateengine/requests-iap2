import json

from requests_iap2.constants import _DEFAULT_OAUTH_PARAMS


def create_client_id_file(client_id, client_secret, client_id_file=None):
    """Create a client ID file with the given client ID and secret."""

    if client_id_file is None:
        client_id_file = "client_id.json"

    credentials = _DEFAULT_OAUTH_PARAMS.copy()
    credentials["installed"]["client_id"] = client_id
    credentials["installed"]["client_secret"] = client_secret

    with open(client_id_file, "w") as f:
        json.dump(credentials, f)

    print(f"Created client ID file: {client_id_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--client_id", required=True)
    parser.add_argument("--client_secret", required=True)
    parser.add_argument("--client_id_file", default="client_id.json", action="store")
    args = parser.parse_args()

    create_client_id_file(args.client_id, args.client_secret, args.client_id_file)
