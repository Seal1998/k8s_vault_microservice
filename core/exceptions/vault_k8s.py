from core.exceptions.api import ApiException

class VaultException(ApiException):
    def __init__(self, status_code, request_type, request_url, response_text):
        super().__init__(status_code, request_type, request_url, response_text)