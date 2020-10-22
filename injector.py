import jinja2
import os, sys
import yaml, json
import logging
from kubernetes import config, client, utils
from pathlib import Path
from core.helpers import base64_encode_string, get_pod_namespace
from core.hc_vault import get_vault_token
from core.secret import Secret


#TEMPLATE_PATH,SECRETS_PATH

#system globals
env = os.environ
templates_path = Path(env['TEMPLATE_PATH'])
secrets_path = Path(env['SECRETS_PATH'])
vault_address = env['VAULT_ADDR']
vault_role = env['VAULT_ROLE']

namespace = get_pod_namespace(non_k8s='default')

#logs options
formatter_string = '%(asctime)s - %(levelname)s - %(message)s'
formatter = logging.Formatter(formatter_string)
logging.basicConfig(format=formatter_string, level=logging.INFO)


#k8s globals
#config.load_kube_config()
k8s_v1 = client.CoreV1Api()
vault_token_response = get_vault_token(vault_addr=vault_address, role=vault_role)

print(vault_token_response)

file_template_loader = jinja2.FileSystemLoader(searchpath=templates_path)
template_env = jinja2.Environment(loader=file_template_loader)
secret_template = template_env.get_template('Secret.j2')

k8s_rendered_secrets = []

for secret in secrets_path.iterdir():
    with open(secret, 'r') as stream:
        secret_yml = yaml.safe_load(stream)
        Secret(
            yaml.safe_load(secret_template.render(secret_name=str(secret).split('/')[-1:][0], secrets_dict=secret_yml)),
            namespace,
            k8s_v1
        )    