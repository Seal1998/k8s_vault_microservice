from collections import namedtuple
from types import SimpleNamespace
from core.helpers import validate_vault_secret
from core.logging import system_logger

injector_config_fields = ['simple_secrets_paths', 'complex_secrets_paths']

InjectorConfig = namedtuple('InejctorConfig', injector_config_fields, defaults=(None,)*len(injector_config_fields))

class InjectorOperator:
    
    config = SimpleNamespace()

    def __init__(self, vault_operator, k8s_injector, vault_secret_config_path=None, k8s_configmap_config=None):
        self.vault = vault_operator
        self.k8s = k8s_injector

        self.secrets = []

        if vault_secret_config_path:
            self.load_vault_config_secret(vault_secret_config_path)
        elif k8s_configmap_config:
            self.load_k8s_config_configmap(k8s_configmap_config)

#workflow
    def process_simple_secrets(self):
        self.secrets = [*self.secrets, *self.process_secret_paths_iter(self.config.simple_secrets_paths)]

    def process_complex_secrets(self):
        complex_secrets = []
        required_fields = tuple(['path', 'id'])
        for complex_secret in self.config.complex_secrets_paths:
            if all(field in complex_secret.keys() for field in required_fields):
                
                if type(complex_secret['path']) is str:
                    secret_path_raw = self.process_secret_path(complex_secret['path'])
                elif type(complex_secret['path']) is list:
                    secret_path_raw = self.process_secret_paths_iter(complex_secret['path'])

                for secret in secret_path_raw: #because it might be like path1/path2/*
                    secret = self.process_complex_secret_pipe(secret, complex_secret) 
                    complex_secrets.append(secret)
            else:
                system_logger.error(f'Not all requred fields specified - {required_fields}')

        self.secrets = [*self.secrets, *complex_secrets]

#operations

    def process_complex_secret_pipe(self, vault_secret, complex_secret):
        if 'exclude_keys' in complex_secret.keys():
            for key in complex_secret['exclude_keys']:
                if key in vault_secret.secret_data.keys():
                    vault_secret.secret_data.pop(key)
        
        return vault_secret

    def upload_secrets_to_kubernetes(self):
        for secret in self.secrets:
            self.k8s.upload_secret(secret_name=secret.secret_name, secret_data=secret.secret_data)

    def load_vault_config_secret(self, secret_path):
        system_logger.info('Loading secrets via Vault secret paths source')
        config_secret = self.vault.get_secrets_by_path(path=secret_path)
        if not config_secret:
            system_logger.info('Cannot pull paths from Vault')
            exit(1)
        elif 'vault-injector-paths' not in config_secret.secret_data.keys():
            system_logger.info('Config secret does not contain [vault-injector-paths] field')
            exit(1)
        
        vault_injector_paths = config_secret.secret_data['vault-injector-paths']

        self.config.simple_secrets_paths = tuple(filter(lambda s: type(s) is not dict, vault_injector_paths))
        self.config.complex_secrets_paths = tuple(filter(lambda s: type(s) is dict, vault_injector_paths))

    def load_k8s_config_configmap(self, configmap_name):
        return False

    def process_secret_paths_iter(self, secret_paths):
        secrets_raw = (secret for secret_tuple in map(self.process_secret_path, secret_paths) for secret in secret_tuple)
        return tuple(filter(lambda s: s is not False, secrets_raw))

    def process_secret_path(self, secret_path):
        if secret_path[-1] in ('*','+'):
            secret_path_secrets = self.process_wildcard_secret_path(secret_path)
            secret_path_secrets = tuple(filter(lambda s: s is not False, secret_path_secrets))
            if len(secret_path_secrets) == 0:
                return ()
        else:
            secret_path_secrets = self.process_casual_secret_path(secret_path)
            if not secret_path_secrets:
                return False
            else:
                secret_path_secrets = tuple([secret_path_secrets])
        
        return secret_path_secrets

    def validate_secret(self, secret):
        if not validate_vault_secret(secret):
            system_logger.warning(f'{secret.full_path} is invalid. Upload aborted')
            return False
        else:
            return True

    def process_wildcard_secret_path(self, wildcard_path):
        vault_secrets_wildcard_raw = self.vault.get_secrets_by_path(path=wildcard_path)
        if not vault_secrets_wildcard_raw:
            return ()
        vault_secrets_wildcard = tuple(filter(lambda s: self.validate_secret(s), vault_secrets_wildcard_raw))
        return vault_secrets_wildcard

    def process_casual_secret_path(self, casual_path):
        vault_secret_casual_raw = self.vault.get_secrets_by_path(path=casual_path)
        if not self.validate_secret(vault_secret_casual_raw) or not vault_secret_casual_raw:
            return False
        return vault_secret_casual_raw