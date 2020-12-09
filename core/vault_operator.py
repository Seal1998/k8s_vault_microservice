import requests
import logging
from collections import namedtuple
from core.helpers import unwrap_response
from core.decorators import Log
from core.exceptions import VaultException

vault_log = Log.create_vault_logger()

class VaultOperator:

    def __init__(self, address, verify_ssl):
        self.address = address
        self.verify_ssl = verify_ssl

        self.token = None
        self.mounts_info = None
        self.exclude_list = [] #list of secret paths for exclude

    @vault_log.info(msg='Login via kubernetes method with [[k8s_role]] role', on_success='Success', fatal=True, template_kvargs=True)
    def login_kubernetes(self, *, k8s_role=None, jwt_token=None, auth_mount=None):
        auth_url = f'{self.address}/v1/auth/{auth_mount}/login'
        token_responce = requests.post(auth_url, data={"role": k8s_role, "jwt": jwt_token}, verify=self.verify_ssl)
        token_responce_dict = token_responce.json()
        if token_responce.status_code != 200:
            raise VaultException(*unwrap_response(token_responce))
        else:
            self.token = token_responce_dict['auth']['client_token']

    @vault_log.info(msg='Getting mounts info', on_success='Success', fatal=True)
    def get_mounts_info(self):
        mounts_info_response = requests.get(f'{self.address}/v1/sys/mounts', headers={'X-Vault-Token': self.token}, verify=self.verify_ssl)

        if mounts_info_response.status_code != 200:
            raise VaultException(*unwrap_response(mounts_info_response))
        else:
            return mounts_info_response.json()

    @vault_log.info(msg='Checking HC Vault connection to [[address]]...', on_success='OK', fatal=True, 
                                                            print_exception=True, template_kvargs=True)
    def check_vault_connection(self, *, timeout=10, address=None):
        check_response = requests.get(f'{self.address}/v1/sys/health', verify=self.verify_ssl, timeout=timeout)
        if check_response.status_code != 200:
            raise VaultException(*unwrap_response(check_response))

    @vault_log.info(msg='Checking HC Vault token policies...', print_return=True)
    def check_vault_token_policies(self):
        token_info = requests.post(f'{self.address}/v1/auth/token/lookup', data={"token": self.token}, 
                                    headers={'X-Vault-Token': self.token}, verify=self.verify_ssl)
        if token_info.status_code != 200:
            raise VaultException(*unwrap_response(token_info))
        else:
            return f"Token policies - {str(token_info.json()['data']['policies'])}"

    @vault_log.info(on_error='No such KV engine [[[kv_mount]]]. Skipped', template_kvargs=True)
    def get_kv_mount_version(self, *, kv_mount):
        if f'{kv_mount}/' not in self.mounts_info.keys():
            return False
        kv_mount_version = self.mounts_info[f'{kv_mount}/']['options']['version']
        return kv_mount_version

    @vault_log.info(msg='Preparing HC Vault connection')
    def prepare_connection(self, *, vault_k8s_role=None, k8s_jwt_token=None, vault_k8s_auth_mount=None, vault_token=None):
        self.check_vault_connection(address=self.address)
        if not vault_k8s_auth_mount:
            #use default mount path
            vault_k8s_auth_mount = 'kubernetes'
        if not vault_token:
            self.login_kubernetes(k8s_role=vault_k8s_role, jwt_token=k8s_jwt_token, auth_mount=vault_k8s_auth_mount)
        else:
            self.token = vault_token
        self.check_vault_token_policies()
        self.mounts_info = self.get_mounts_info()

    @vault_log.warning(msg='Excluding [[path]]', print_return=True, template_kvargs=True)
    def exclude_secret(self, *, path=None):
        [kv_mount_path, kv_mountless_path,
        secret_name] = self.__split_path_by_parts(path)
        if secret_name in ('*', '+'):
            if secret_name == '*':
                secrets = self.list_secrets_by_path_recurse(path=f'{kv_mount_path}/{kv_mountless_path}')
            elif secret_name == '+':
                secrets = self.list_secrets_by_path(path=f'{kv_mount_path}/{kv_mountless_path}')
            
            list(map(self.exclude_list.append, secrets))
        else:
            self.exclude_list.append(path)
        return f'Excluded {len(self.exclude_list)} secrets'


    def get_secrets_by_path(self, *, path=None):
        [kv_mount_path, kv_mountless_path,
        secret_name] = self.__split_path_by_parts(path)

        if secret_name in ('*', '+'):
            vault_secrets = self.get_wildcard_secrets(path=path,recursively=(secret_name=='*'))
            if not vault_secrets:
                return False
            return vault_secrets
        else:
            vault_secret = self.get_single_secret(path=path)
            if not vault_secret: # prevent None return
                return False
            return vault_secret

    def get_wildcard_secrets(self, *, path=None, recursively=False):
        if recursively:
            listed_secrets_paths = self.list_secrets_by_path_recurse(path=path)
        else:
            listed_secrets_paths = self.list_secrets_by_path(path=path)
        
        if not listed_secrets_paths:
            return False
            
        listed_secrets_paths = tuple(filter(lambda path: path[-1]!='/', listed_secrets_paths))
        wildcard_secrets = map(lambda path: self.get_single_secret(path=path), listed_secrets_paths)

        return (*wildcard_secrets,)

    @vault_log.info(msg='Processing [[path]] secret', on_error='Can`t retrieve secret. Skipped', template_kvargs=True)
    def get_single_secret(self, *, path=None):
        if path in self.exclude_list:
            vault_log.log_msg(logging.WARNING, f'Secret [{path}] excluded')
            return False
        kv_mount, kv_mountless, secret_name = self.__split_path_by_parts(path)

        VaultSecret = namedtuple('VaultSecret', ['full_path', 'secret_name', 'secret_data'])

        kv_mount_version = self.get_kv_mount_version(kv_mount=kv_mount)
        if not kv_mount_version:
            vault_log.log_msg(logging.ERROR, f'No kv engine [{kv_mount}]. Skipping')
            return False
        
        pull_api_endpoint = '/data' if kv_mount_version == '2' else ''
        secret_response = requests.get(f'{self.address}/v1/{kv_mount}{pull_api_endpoint}/{kv_mountless}', 
                                                                                    headers={'X-Vault-Token': self.token},
                                                                                    verify=self.verify_ssl)
        if secret_response.status_code == 200:
            response_data = secret_response.json()['data'] if kv_mount_version == '1' else secret_response.json()['data']['data']
        else:
            raise VaultException(*unwrap_response(secret_response))

        secret = VaultSecret(f'{kv_mount}/{kv_mountless}', secret_name, response_data)
        return secret

    @vault_log.info(msg='Listing [[path]]...', template_kvargs=True)
    def list_secrets_by_path(self, *, path=None, full_path=True):
        kv_mount, kv_mountless, _ = self.__split_path_by_parts(path)
        kv_mount_version = self.get_kv_mount_version(kv_mount=kv_mount)
        # if not kv_mount_version:
        #     return False
        list_api_endpoint = '/metadata' if kv_mount_version == '2' else ''
        listed_secrets_response = requests.request('LIST', f'{self.address}/v1/{kv_mount}{list_api_endpoint}/{kv_mountless}',
                                                                                                headers={'X-Vault-Token': self.token},
                                                                                                verify=self.verify_ssl)
        if listed_secrets_response.status_code != 200:
            raise VaultException(*unwrap_response(listed_secrets_response))
        else:
            listed_secrets = listed_secrets_response.json()['data']['keys']
            if full_path:
                listed_secrets = (self.__build_path_from_secret_attrs(secret, kv_mount, kv_mountless) for secret in listed_secrets)
            return (*listed_secrets,)

    @vault_log.info(msg='Listing [[path]] recursively...', template_kvargs=True)
    def list_secrets_by_path_recurse(self, *, path=None, full_path=True):
        listed_secrets = self.list_secrets_by_path(path=path, full_path=full_path) #CAN RETURN FALSE!!!

        if not listed_secrets:
            return False
        listed_secrets_dir = filter(lambda path: path and path[-1]=='/', listed_secrets)
        listed_secrets_casual = filter(lambda path: path and path[-1]!='/', listed_secrets)

        listed_secrets_recurse_raw = map(lambda dirct: self.list_secrets_by_path_recurse(path=dirct), listed_secrets_dir)
        listed_secrets_recurse = (i for subtuple in listed_secrets_recurse_raw for i in subtuple)
        listed_secrets_recurse_casual = filter(lambda path: path and path[-1]!='/', listed_secrets_recurse)

        listed_secrets = (*listed_secrets_casual, *listed_secrets_recurse_casual)
        return tuple(filter(lambda path: path!=False, listed_secrets))


    def __build_path_from_secret_attrs(self, listed_secret, kv_mount, kv_mountless):
        secret_postfix = f"{'*' if listed_secret[-1] == '/' else ''}"
        secret_path = f"{kv_mount}/{kv_mountless.strip('/')}{'/' if kv_mountless != '' else ''}{listed_secret}"
        return secret_path

    def __split_path_by_parts(self, path):
        full_path_parts = path.split('/')
        kv_mount_path = full_path_parts[0]
        secret_name = full_path_parts[-1]
        if secret_name in ('*', '+'):
            full_path_parts = full_path_parts[:-1] # remove * +
        kv_mountless_path = '/'.join(full_path_parts[1:])
        return kv_mount_path, kv_mountless_path, secret_name