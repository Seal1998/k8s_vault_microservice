import requests, json
import logging

class vault_Secret:
    vault_address = None
    vault_token = None
    mounts_info = None

    def __init__(self, kv_mount_path, kv_mountless_path):
        self.kv_mount_path = kv_mount_path
        self.kv_mountless_path = kv_mountless_path
        self.secret_name = kv_mountless_path[-1:][0]
        self.kv_mount_version = self.mounts_info[f'{self.kv_mount_path}/']['options']['version']
        
        self.secret_data = self.__get_secret() #getting secret

    def __repr__(self):
        return self.secret_data

    def __get_secret(self):
        pull_api_endpoint = '/data/' if self.kv_mount_version == 2 else ''
        secret_response = requests.get(f'{self.vault_address}/v1/{self.kv_mount_path}{pull_api_endpoint}/{self.kv_mountless_path}', 
                                                                                    headers={'X-Vault-Token': self.vault_token})
        response_data = secret_response.json()['data'] if self.kv_mount_version == '1' else secret_response.json()['data']['data']
        return response_data

    @classmethod
    def pull_secrets(cls, relative_path):
        full_path_parts = relative_path.split('/')
        kv_mount_path = full_path_parts[:-1][0]
        secret_name = full_path_parts[-1:][0]
        if secret_name == '*':
            full_path_parts = full_path_parts[:-1] # remove *
        mountless_path = '/'.join(full_path_parts[1:]) if len(full_path_parts) > 1 else '' #e.q kv/dir1/dir2/* or kv/* can`t get slice
        try:
            kv_mount_version = cls.mounts_info[f'{kv_mount_path}/']['options']['version']
        except KeyError:
            logging.error(f'HVAULT | No such kv engine - {kv_mount_path}')
            exit(1)
        if secret_name == '*':
            #list secrets
            list_api_endpoint = '/metadata/' if kv_mount_version == 2 else ''
            logging.info(f"HVAULT | Listing secrets under {kv_mount_path}/{mountless_path} location")
            listed_secrets_response = requests.request('LIST', f'{cls.vault_address}/v1/{kv_mount_path}{list_api_endpoint}/{mountless_path}',
                                                                                                headers={'X-Vault-Token': cls.vault_token})
            if listed_secrets_response.status_code == 403:
                logging.warning(f'HVAULT | Token has no permissions to access {kv_mount_path}/{mountless_path}. Skipping...')
                return []
            elif listed_secrets_response.status_code == 404:
                logging.warning(f'HVAULT | No such location - {kv_mount_path}/{mountless_path}. Skipping...')
            elif listed_secrets_response.status_code == 200:
                listed_secrets = listed_secrets_response.json()['data']['keys']

            #recurse call to pull_secrets func
            secrets_list = []
            for secret in listed_secrets:
                secrets_list = [
                    *secrets_list,
                    *cls.pull_secrets(f"{kv_mount_path}/{mountless_path}{'/' if mountless_path != '' else ''}{secret}{'*' if secret[-1:] == '/' else ''}")
                ]
                
            return secrets_list
        
        else:
            return [cls(kv_mount_path, mountless_path),]
            
    
    @classmethod
    def prepare_connection(cls, vault_addres, vault_k8s_role=None, vault_token=None, k8s_jwt_token=None, auth_path=None):
        cls.vault_address = vault_addres
        logging.info('HVAULT | Getting vault token...')
        if not vault_token:
            #get token
            auth_url = f'{cls.vault_address}/v1/auth/{auth_path}/login'
            token_responce = requests.post(auth_url, data={"role": vault_k8s_role, "jwt": k8s_jwt_token})
            token_responce_dict = token_responce.json()
            cls.vault_token = token_responce_dict['auth']['client_token']
        else:
            cls.vault_token = vault_token
        #mounts info
        logging.info('HVAULT | Getting mounts info...')
        mounts_info_response = requests.get(f'{cls.vault_address}/v1/sys/mounts', headers={'X-Vault-Token': cls.vault_token})
        mounts_info = mounts_info_response.json()
        if mounts_info_response.status_code == 403:
            logging.error('HVAULT | Token has no permissions to retrieve mounts info from sys/mounts')
            exit(1)
        cls.mounts_info = mounts_info



def check_vault_connection(vault_addr):
    try:
        check_response = requests.get('{}/v1/sys/health'.format(vault_addr))
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

def check_vault_token_policies(vault_addr, token):
    token_info = requests.post('{}/v1/auth/token/lookup'.format(vault_addr), data={"token": token}, headers={'X-Vault-Token': token})
    if token_info.status_code == 200:
        logging.info('HVAULT | Token policies - %s', str(token_info.json()['data']['policies']))
    elif token_info.status_code == 403:
        logging.error('HVAULT | Token has no permissions to retrieve token info from auth/token/lookup')
    else:
        logging.error('HVAULT | Can`t retrieve policies for token due to \n%s', token_info.text)