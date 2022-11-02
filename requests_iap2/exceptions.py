class RequestsIAP2Error(Exception):
    pass


class UserCredentialError(RequestsIAP2Error):
    pass


class DefaultCredentialsError(RequestsIAP2Error):
    pass


class FileCredentialsError(RequestsIAP2Error):
    pass
