import requests, json
import logging
from collections import namedtuple

class Vault:

    def __init__(self, address, verify_ssl):
        self.address = address
        self.verify_ssl = verify_ssl

        self.token = None
        self.mounts_info = None
        self.exclude_list = [] #list of secret paths for exclude

    def login_kubernetes(self, k8s_role, jwt_token, auth_mount):
        logging.info('HVAULT | Getting vault token...')
        auth_url = f'{self.address}/v1/auth/{auth_mount}/login'
        token_responce = requests.post(auth_url, data={"role": k8s_role, "jwt": jwt_token}, verify=self.verify_ssl)
        token_responce_dict = token_responce.json()
        try:
            self.token = token_responce_dict['auth']['client_token']
        except:
            logging.error(f'HVAULT | Login error \n{token_responce.text}\n{token_responce_dict}\n{self.address}/v1/auth/{auth_mount}/login')    
            exit(1)

    def get_mounts_info(self):
        logging.info('HVAULT | Getting mounts info...')
        mounts_info_response = requests.get(f'{self.address}/v1/sys/mounts', headers={'X-Vault-Token': self.token}, verify=self.verify_ssl)
        mounts_info = mounts_info_response.json()
        
        if mounts_info_response.status_code == 403:
            logging.error('HVAULT | Token has no permissions to retrieve mounts info from sys/mounts')
            exit(1)
        elif mounts_info_response.status_code != 200:
            logging.error('HVAULT | Can`t retrieve mounts info due to \n%s', mounts_info_response.text)
            exit(1)
        return mounts_info

    def check_vault_connection(self):
        try:
            check_response = requests.get(f'{self.address}/v1/sys/health', verify=self.verify_ssl)
            if check_response.status_code == 503:
                logging.error('FATAL | Vault is sealed')
                exit(1)
            elif check_response.status_code == 501:
                logging.error('FATAL | Vault not initialized')
                exit(1)
            elif check_response.status_code == 200:
                logging.info('HVAULT | Connection - OK')
        except requests.exceptions.ConnectionError as err:
            logging.error('FATAL | Can`t connect to Vault \n\n {}'.format(err))
            exit(1)

    def check_vault_token_policies(self):
        token_info = requests.post(f'{self.address}/v1/auth/token/lookup', data={"token": self.token}, 
                                    headers={'X-Vault-Token': self.token}, verify=self.verify_ssl)
        if token_info.status_code == 200:
            logging.info('HVAULT | Token policies - %s', str(token_info.json()['data']['policies']))
        elif token_info.status_code == 403:
            logging.error('HVAULT | Token has no permissions to retrieve token info from auth/token/lookup')
        else:
            logging.error('HVAULT | Can`t retrieve policies for token due to \n%s', token_info.text)

    def get_kv_mount_version(self, kv_mount):
        try:
            kv_mount_version = self.mounts_info[f'{kv_mount}/']['options']['version']
            return kv_mount_version
        except KeyError:
            logging.error(f'HVAULT | No such kv engine - {kv_mount}. Skipping...')
            return False

    def prepare_connection(self, vault_k8s_role=None, k8s_jwt_token=None, vault_k8s_auth_mount=None, vault_token=None):
        self.check_vault_connection()
        if not vault_k8s_auth_mount:
            #use default mount path
            vault_k8s_auth_mount = 'kubernetes'
        if not vault_token:
            self.login_kubernetes(k8s_role=vault_k8s_role, jwt_token=k8s_jwt_token, auth_mount=vault_k8s_auth_mount)
        else:
            self.token = vault_token
        self.check_vault_token_policies()
        self.mounts_info = self.get_mounts_info()

    def exclude_secret(self, path):
        [kv_mount_path, kv_mountless_path,
        secret_name] = self.__split_path_by_parts(path)
        if secret_name in ('*', '+'):
            if secret_name == '*':
                secrets = self.list_secrets_by_path_recurse(f'{kv_mount_path}/{kv_mountless_path}')
            elif secret_name == '+':
                secrets = self.list_secrets_by_path(f'{kv_mount_path}/{kv_mountless_path}')
            list(map(self.exclude_list.append, secrets))
        else:
            self.exclude_list.append(path)
        logging.info(f'HVAULT | Excluded {len(self.exclude_list)} secrets')


    def get_secrets_by_path(self, path):
        [kv_mount_path, kv_mountless_path,
        secret_name] = self.__split_path_by_parts(path)

        if secret_name in ('*', '+'):
            vault_secrets = self.get_wildcard_secrets(path,recursively=(secret_name=='*'))
            return vault_secrets
        else:
            vault_secret = self.get_single_secret(path)
            return vault_secret

    def get_wildcard_secrets(self, path, recursively=False):
        if recursively:
            listed_secrets_paths = self.list_secrets_by_path_recurse(path)
        else:
            listed_secrets_paths = self.list_secrets_by_path(path)
        wildcard_secrets = map(self.get_single_secret, listed_secrets_paths)

        return (*wildcard_secrets,)

    def get_single_secret(self, path):
        if path in self.exclude_list:
            logging.warning(f'HVAULT | Secret [{path}] excluded')
            return False
        kv_mount, kv_mountless, secret_name = self.__split_path_by_parts(path)
        VaultSecret = namedtuple('VaultSecret', ['status_code', 'full_path', 'secret_name', 'secret_data'])

        kv_mount_version = self.get_kv_mount_version(kv_mount)
        if not kv_mount_version:
            return False
        logging.info(f'HVAULT | Getting secret from {kv_mount}/{kv_mountless}...')
        pull_api_endpoint = '/data' if kv_mount == '2' else ''
        secret_response = requests.get(f'{self.address}/v1/{kv_mount}{pull_api_endpoint}/{kv_mountless}', 
                                                                                    headers={'X-Vault-Token': self.token},
                                                                                    verify=self.verify_ssl)
        if secret_response.status_code == 404:
            logging.warning(f'HVAULT | No such secret {kv_mount}/{kv_mountless} Skipping')
            status_code = 404
        elif secret_response.status_code == 403:
            logging.error(f'HVAULT | Token has no access to {kv_mount}/{kv_mountless}')
            status_code = 403
        elif secret_response.status_code == 200:
            status_code = 200
            
        if status_code == 200:
            response_data = secret_response.json()['data'] if kv_mount_version == '1' else secret_response.json()['data']['data']
        else:
            response_data = {}

        secret = VaultSecret(status_code, f'{kv_mount}/{kv_mountless}', secret_name, response_data)
        return secret

    def list_secrets_by_path(self, path, full_path=True):
        kv_mount, kv_mountless, _ = self.__split_path_by_parts(path)
        kv_mount_version = self.get_kv_mount_version(kv_mount)
        if not kv_mount_version:
            return False
        list_api_endpoint = '/metadata' if kv_mount_version == '2' else ''
        logging.info(f"HVAULT | Listing secrets under {kv_mount}/{kv_mountless} location")
        listed_secrets_response = requests.request('LIST', f'{self.address}/v1/{kv_mount}{list_api_endpoint}/{kv_mountless}',
                                                                                                headers={'X-Vault-Token': self.token},
                                                                                                verify=self.verify_ssl)
        if listed_secrets_response.status_code == 403:
            logging.warning(f'HVAULT | Token has no permissions to list {kv_mount}/{kv_mountless}. Skipping...')
            return False
        elif listed_secrets_response.status_code == 404:
            logging.warning(f'HVAULT | No such location - {kv_mount}/{kv_mountless}. Skipping...')
            return False
        elif listed_secrets_response.status_code == 200:
            listed_secrets = listed_secrets_response.json()['data']['keys']
            if full_path:
                listed_secrets = (self.__build_path_from_secret_attrs(secret, kv_mount, kv_mountless) for secret in listed_secrets)
            return (*listed_secrets,)

    def list_secrets_by_path_recurse(self, path, full_path=True):
        listed_secrets = self.list_secrets_by_path(path, full_path)
        listed_secrets_dir = filter(lambda path: path and path[-1]=='/', listed_secrets)
        listed_secrets_casual = filter(lambda path: path and path[-1]!='/', listed_secrets)

        listed_secrets_recurse_raw = map(self.list_secrets_by_path_recurse, listed_secrets_dir)
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