class VaultException(Exception):

    def __init__(self, status_code, request_type, request_url, response_text=None):
        self.status_code = status_code
        self.request_url = request_url
        self.request_type = request_type
        self.response_text = response_text
        
        super().__init__(self.log_str())
    
    def __str__(self):
        return self.log_str()

    def log_str(self):
        text = f'\n{self.response_text}' if self.response_text else False
        return f'{self.request_type} - {self.request_url} - {self.status_code}{text if text else ""}'