import jinja2
import os, sys
import yaml, json
import logging
from kubernetes import config, client, utils
from pathlib import Path
from core.helpers import base64_encode_string, get_pod_namespace, get_pod_jwt
from core.hc_vault import get_vault_token, get_secret, check_vault_connection, check_vault_token_policies
from core.secret import Secret


#TEMPLATE_PATH,SECRETS_PATH

#system globals
env = os.environ
templates_path = Path(env['TEMPLATE_PATH'])
vault_address = env['VAULT_ADDR']
vault_role = env['VAULT_ROLE']
vault_path_file = env['VAULT_PATHS_FILE']

#non k8s dev args
try:
    dev_vault_token = env['DEV_VAULT_TOKEN']
    dev_k8s_namespace = env['DEV_K8S_NS']
    dev_mode = True
except:
    dev_mode = False

#logs options
formatter_string = '%(asctime)s - %(levelname)s - %(message)s'
formatter = logging.Formatter(formatter_string)
logging.basicConfig(format=formatter_string, level=logging.INFO)

file_template_loader = jinja2.FileSystemLoader(searchpath=templates_path)
template_env = jinja2.Environment(loader=file_template_loader)
secret_template = template_env.get_template('Secret.j2')

#k8s globals
if dev_mode:
    config.load_kube_config()
    vault_token = dev_vault_token
    k8s_namespace = dev_k8s_namespace
else:
    config.load_incluster_config()
    k8s_namespace = get_pod_namespace()
    k8s_jwt_token = get_pod_jwt()
    #vault
    vault_token = get_vault_token(vault_addr=vault_address, k8s_role=vault_role, jwt_token=k8s_jwt_token)

secrets = {}

Secret.check_token_permissions(k8s_namespace, secret_template)
check_vault_connection(vault_addr=vault_address)
check_vault_token_policies(vault_addr=vault_address, token=vault_token)

with open(vault_path_file, 'r') as hc_paths:
    path_lines = hc_paths.readlines()
    for path in path_lines:
        path = path.strip()
        new_secrets = get_secret(vault_addr=vault_address, token=vault_token, path=path)
        secrets = {**secrets, **new_secrets}

for key, value in secrets.items():
    Secret(yaml.safe_load(secret_template.render(secret_name=key, secrets_dict=value)), k8s_namespace)    