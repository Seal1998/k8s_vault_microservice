from collections import namedtuple, defaultdict
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
    def process_excluded_secrets(self):
        list(map(lambda p: self.vault.exclude_secret(path=p), self.config.exclude_secrets_paths))

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

    def clean_up(self):
        self.k8s.remove_unprocessed_secrets()

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

#configs
    def load_vault_config_secret(self, secret_path):
        system_logger.info('Loading config via Vault secret paths source')
        config_secret = self.vault.get_secrets_by_path(path=secret_path)
        if not config_secret:
            system_logger.info('Cannot pull config from Vault')
            exit(1)
        else:
            config_secret = config_secret.secret_data

        injector_config = defaultdict(list)

        #processing child configs
        if 'injector-configs' in config_secret.keys() and \
                type(config_secret['injector-configs']) is list:
            config_secrets = tuple(c.secret_data for c \
                                    in self.process_secret_paths_iter(config_secret['injector-configs'], skip_verify=True) if c)

            for config in config_secrets:
                injector_config = self.merge_configs(injector_config, config)
        
            #remove injector-configs key in order to skip it. Actually not need to do so, but why not?
            del config_secret['injector-configs']

        injector_config = self.merge_configs(injector_config, config_secret)

        

        if 'vault-injector-paths' in injector_config.keys():
            vault_injector_paths = injector_config['vault-injector-paths']
            self.__load_vault_injector_paths(vault_injector_paths)
            

    def __load_vault_injector_paths(self, vault_injector_paths):
        self.config.exclude_secrets_paths = []
        for path in vault_injector_paths:
            if type(path) is str:
                if path[0] == '!':
                    self.config.exclude_secrets_paths.append(path[1:])
                    vault_injector_paths.remove(path)

        self.config.simple_secrets_paths = list(filter(lambda s: type(s) is not dict, vault_injector_paths))
        self.config.complex_secrets_paths = list(filter(lambda s: type(s) is dict, vault_injector_paths))

        # secret_exclude_paths_raw = filter(lambda path: path[0]=='!', simple_secret_paths)
        # secret_exclude_paths = (path[1:] for path in secret_exclude_paths_raw)
        # list(map(vault.exclude_secret, secret_exclude_paths))

    def load_k8s_config_configmap(self, configmap_name):
        return False

    def merge_configs(self, first_config, second_config):
        for key, value in second_config.items():
            if type(value) is dict:
                if not first_config[key]:
                    first_config[key] = {} #if no such key - create it. Need for unpacking
                first_config[key] = {**first_config[key], **value}
            elif type(value) is list:
                first_config[key] = [*first_config[key], *value]
        
        return first_config

    def process_secret_paths_iter(self, secret_paths, skip_verify=False):
        secrets_raw = (secret for secret_tuple in map(lambda p: self.process_secret_path(p, skip_verify), secret_paths) 
                                                                                                for secret in secret_tuple)
        return tuple(filter(lambda s: s is not False, secrets_raw))

    def process_secret_path(self, secret_path, skip_verify=False):
        if secret_path[-1] in ('*','+'):
            secret_path_secrets = self.process_wildcard_secret_path(secret_path, skip_verify)
            if not secret_path_secrets:
                return ()
        else:
            secret_path_secrets = self.process_casual_secret_path(secret_path, skip_verify)
            if not secret_path_secrets:
                return ()
            else:
                secret_path_secrets = tuple([secret_path_secrets])
        
        return secret_path_secrets

    def validate_secret(self, secret):
        if not validate_vault_secret(secret):
            system_logger.warning(f'{secret.full_path} is invalid. Upload aborted')
            return False
        else:
            return True

    def process_wildcard_secret_path(self, wildcard_path, skip_verify):
        vault_secrets_wildcard_raw = self.vault.get_secrets_by_path(path=wildcard_path)
        if not vault_secrets_wildcard_raw:
            return False
        else:
            vault_secrets_wildcard_raw = tuple(filter(lambda s: s is not False, vault_secrets_wildcard_raw))#filter False response from vault-operator

        if not skip_verify:
            vault_secrets_wildcard = tuple(filter(lambda s: self.validate_secret(s), vault_secrets_wildcard_raw))
        elif skip_verify:
            vault_secrets_wildcard = vault_secrets_wildcard_raw
        return vault_secrets_wildcard

    def process_casual_secret_path(self, casual_path, skip_verify):
        vault_secret_casual_raw = self.vault.get_secrets_by_path(path=casual_path)
        if not vault_secret_casual_raw:
            return False
        elif not skip_verify and not self.validate_secret(vault_secret_casual_raw):
            return False
        return vault_secret_casual_raw