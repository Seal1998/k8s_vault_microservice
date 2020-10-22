import requests, json

def get_vault_token(vault_addr, k8s_role, auth_path='kubernetes'):
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token_file:
        jwt_token = token_file.read()
    auth_url = '{}/v1/auth/{}/login'.format(vault_addr, auth_path)
    token_responce = requests.post(auth_url, data={"role": k8s_role, "jwt": jwt_token})
    token_responce_dict = token_responce.json()
    return token_responce_dict['auth']['client_token']

def get_secret(vault_addr, token, path):
    full_path_parts = path.split('/')
    kv_engine = full_path_parts[:-1][0]
    secret_name = full_path_parts[-1:][0]
    path = '/'.join(full_path_parts[1:])
    mounts_info_response = requests.get('{}/v1/sys/mounts'.format(vault_addr), headers={'X-Vault-Token': token})
    engine_info = mounts_info_response.json()['data']['{}/'.format(kv_engine)]
    if engine_info['options']['version'] == '2':
        kv_engine = kv_engine + '/data'
    secret_response = requests.get('{}/v1/{}/{}'.format(vault_addr, kv_engine, path), headers={'X-Vault-Token': token})
    return {secret_name: secret_response.json()['data']}