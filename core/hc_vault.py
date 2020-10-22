import requests

def get_vault_token(vault_addr, auth_path='kubernetes', role='k8s_test'):
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token_file:
        jwt_token = token_file.read()
    token_responce = requests.post(f'{vault_addr}/auth/{auth_path}/login', data='{role: %s, jwt: %s}'.format(role, jwt_token))
