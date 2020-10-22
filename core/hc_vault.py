import requests

def get_vault_token(vault_addr, k8s_role, auth_path='kubernetes'):
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token_file:
        jwt_token = token_file.read()
    token_responce = requests.post('http://172.17.0.3/auth/kubernetes/login', data={'role': k8s_role, 'j2t': jwt_token})
    return token_responce