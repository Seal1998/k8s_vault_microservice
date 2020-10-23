import requests, json
import logging

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

def get_vault_token(vault_addr, k8s_role, jwt_token, auth_path='kubernetes'):
    auth_url = '{}/v1/auth/{}/login'.format(vault_addr, auth_path)
    token_responce = requests.post(auth_url, data={"role": k8s_role, "jwt": jwt_token})
    token_responce_dict = token_responce.json()
    return token_responce_dict['auth']['client_token']

def get_secret(vault_addr, token, path, mounts_info=None):
    full_path_parts = path.split('/')
    kv_engine = full_path_parts[:-1][0]
    secret_name = full_path_parts[-1:][0]
    if secret_name == '*':
        return get_all_secrets_from_path(vault_addr, token, path, mounts_info)
    mountless_path = '/'.join(full_path_parts[1:])
    if mounts_info is None:
        mounts_info = get_mounts_info(vault_addr, token)
    engine_version = get_kv_mount_version(vault_addr, token, kv_engine, mounts_info)
    if engine_version == '2':
        kv_engine = kv_engine + '/data'
    secret_response = requests.get('{}/v1/{}/{}'.format(vault_addr, kv_engine, mountless_path), headers={'X-Vault-Token': token})
    logging.info('HVAULT | Secret %s pulled', path)
    response_data = secret_response.json()['data'] if engine_version == '1' else secret_response.json()['data']['data']
    return {secret_name: response_data}

def get_all_secrets_from_path(vault_addr, token, path, mounts_info=None):
    full_glob_path_parts = path.split('/')
    full_path_parts = full_glob_path_parts[:len(full_glob_path_parts)-1]
    mountless_path_parts = full_path_parts[1:] if len (full_path_parts) > 1 else []
    kv_engine = full_path_parts[:-1][0] if len(full_path_parts) > 1 else full_path_parts[0]
    if mounts_info is None:
        mounts_info = get_mounts_info(vault_addr, token)
    if get_kv_mount_version(vault_addr, token, kv_engine, mounts_info) == '2':
        kv_engine = kv_engine + '/metadata'
    listed_secrets = requests.request('LIST', '{}/v1/{}/{}'.format(
        vault_addr, kv_engine, 
        '/'.join(mountless_path_parts)
    ), headers={'X-Vault-Token': token})
    pulled_secrets = {}
    for secret in listed_secrets.json()['data']['keys']:
        new_secret = get_secret(vault_addr, token, '{}/{}{}'.format(
            '/'.join(full_path_parts), 
            secret, 
            '*' if secret[-1:] == '/' else ''
        ), mounts_info=mounts_info)
        pulled_secrets = {**pulled_secrets, **new_secret}
    return pulled_secrets

def get_mounts_info(vault_addr, token):
    logging.info('HVAULT | Getting mounts info...')
    mounts_info_response = requests.get('{}/v1/sys/mounts'.format(vault_addr), headers={'X-Vault-Token': token})
    mounts_info = mounts_info_response.json()
    if mounts_info_response.status_code == 403:
        logging.error('HVAULT | Token has no permissions to retrieve mounts info from sys/mounts')
        exit(1)
    return mounts_info

def get_kv_mount_version(vault_addr, token, kv_mount, mounts_info=None):
    if mounts_info is None:
        mounts_info = get_mounts_info(vault_addr, token)
    engine_info = mounts_info['data']['{}/'.format(kv_mount)]
    return engine_info['options']['version']