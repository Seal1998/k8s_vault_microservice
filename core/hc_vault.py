import requests

def get_vault_token(vault_addr, k8s_role, auth_path='kubernetes'):
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token_file:
        jwt_token = token_file.read()
    auth_url = '{}/v1/auth/{}/login'.format(vault_addr, auth_path)
    token_responce = requests.post(auth_url, data={"role": k8s_role, "j2t": jwt_token})
    return token_responce