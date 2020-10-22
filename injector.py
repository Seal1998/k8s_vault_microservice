import jinja2
import os, sys
import yaml, json
import logging
from kubernetes import config, client, utils
from pathlib import Path
from core.helpers import base64_encode_string, get_pod_namespace, get_pod_jwt
from core.hc_vault import get_vault_token, get_secret
from core.secret import Secret


#TEMPLATE_PATH,SECRETS_PATH

#system globals
env = os.environ
templates_path = Path(env['TEMPLATE_PATH'])
secrets_path = Path(env['SECRETS_PATH'])
vault_address = env['VAULT_ADDR']
vault_role = env['VAULT_ROLE']
vault_path_file = env['VAULT_PATH_FILE']

#logs options
formatter_string = '%(asctime)s - %(levelname)s - %(message)s'
formatter = logging.Formatter(formatter_string)
logging.basicConfig(format=formatter_string, level=logging.INFO)

file_template_loader = jinja2.FileSystemLoader(searchpath=templates_path)
template_env = jinja2.Environment(loader=file_template_loader)
secret_template = template_env.get_template('Secret.j2')

#k8s globals
#config.load_kube_config()
k8s_namespace = get_pod_namespace()
k8s_jwt_token = get_pod_jwt()

print(k8s_namespace)
print(k8s_jwt_token)
k8s_v1 = client.CoreV1Api()
vault_token = get_vault_token(vault_addr=vault_address, k8s_role=vault_role)
#vault_token = 's.3e03uMMwGBSYPxuKUT0Y3Jtc'

secrets = []

with open(vault_path_file, 'r') as hc_paths:
    lines = hc_paths.readlines()
    for path in lines:
        path = path.strip()
        secret = get_secret(vault_addr=vault_address, token=vault_token, path=path)
        secrets.append(secret)

for secret in secrets:
    for key, value in secret.items():
        Secret(yaml.safe_load(secret_template.render(secret_name=key, secrets_dict=value)), k8s_namespace, k8s_v1)    