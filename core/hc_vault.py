import requests

def get_vault_token(vault_addr, k8s_role, auth_path='kubernetes'):
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token_file:
        jwt_token = token_file.read()
    token_responce = requests.post(f'{vault_addr}/auth/{auth_path}/login', data='{role: %s, jwt: %s}'.format(k8s_role, jwt_token))
    return token_responce