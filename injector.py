import os
import logging
from kubernetes import config, client
from pathlib import Path
from core.helpers import base64_encode_string, get_pod_namespace, get_pod_jwt
from core.vault_secret import vault_Secret
from core.k8s_secret import k8s_Secret

#system globals
env = os.environ
vault_address = env['VAULT_ADDR']
vautl_k8s_auth_mount = env['VAULT_K8S_AUTH_MOUNT']
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

#k8s vault globals
if dev_mode:
    config.load_kube_config()
    vault_token = dev_vault_token
    k8s_namespace = dev_k8s_namespace
    vault_Secret.prepare_connection(vault_address, vault_token=dev_vault_token)
else:
    config.load_incluster_config()
    k8s_namespace = get_pod_namespace()
    k8s_jwt_token = get_pod_jwt()
    #vault
    vault_Secret.prepare_connection(vault_address, vault_role, k8s_jwt_token, auth_path=vautl_k8s_auth_mount)

k8s_Secret.prepare_connection(k8s_namespace)

secrets = []

with open(vault_path_file, 'r') as hc_paths:
    path_lines = hc_paths.readlines()
    for path in path_lines:
        path = path.strip()
        new_secrets = vault_Secret.pull_secrets(path)
        secrets = [*secrets, *new_secrets]

#creating k8s secrets
list(map(k8s_Secret.upload_vault_secret, secrets))  