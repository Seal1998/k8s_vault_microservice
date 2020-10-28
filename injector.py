import os
import logging
from collections import namedtuple
from kubernetes import config, client
from pathlib import Path
from core.helpers import base64_encode_string, get_pod_namespace, get_pod_jwt
from core import vault_Secret
from core import k8s_Secret

def load_environment():
    env = os.environ

    source_fields = ['vault_secret', 'path_file', 'path']
    Source = namedtuple('Source', source_fields, defaults=(None,)*len(source_fields)) 

    required_vars = [
                        'VAULT_ADDR',
                        'VAULT_K8S_AUTH_MOUNT',
                        'VAULT_ROLE'
                    ]
    optional_vars = [
                        'VAULT_INJECTOR_ID'
                    ]
    path_source_vars = [
                        'VAULT_PATHS_FILE', 
                        'VAULT_PATHS_SECRET'
                        ]
    #required vars
    variables = []
    if all(env_var in env.keys() for env_var in required_vars):
        logging.info('SYSTEM | BASE ENV - OK')
        variables = [*variables, *[env[var] for var in required_vars]]
    else:
        logging.error(f'SYSTEM | Not all required env vars defined {required_vars}')
        exit(1)

    if 'VAULT_INJECTOR_ID' in env.keys():
        variables.append(env['VAULT_INJECTOR_ID'])
    else:
        logging.error(f'SYSTEM | Injector id not defined. ID will be set to namespace name')
        variables.append(None)

    if all(env_var in env.keys() for env_var in path_source_vars):
        logging.error('SYSTEM | Can`t use several path sources. Specify VAULT_PATHS_FILE or VAULT_PATHS_SECRET')
        exit(1)
    elif 'VAULT_PATHS_FILE' not in env.keys() and \
        'VAULT_PATHS_SECRET' not in env.keys():
        logging.error('SYSTEM | Paths sources not specified. Specify VAULT_PATHS_FILE or VAULT_PATHS_SECRET')
        exit(1)
    elif 'VAULT_PATHS_FILE' in env.keys():
        logging.info('SYSTEM | Using path file as Vault paths source')
        variables.append(Source(path_file=True, path=env['VAULT_PATHS_FILE']))
    elif 'VAULT_PATHS_SECRET' in env.keys():
        logging.info('SYSTEM | Using Vault secret as Vault paths source')
        variables.append(Source(vault_secret=True, path=env['VAULT_PATHS_SECRET']))

    return variables

#non k8s dev args
try:
    dev_vault_token = os.environ['DEV_VAULT_TOKEN']
    dev_k8s_namespace = os.environ['DEV_K8S_NS']
    dev_mode = True
except:
    dev_mode = False

#logs options
formatter_string = '%(asctime)s - %(levelname)s - %(message)s'
formatter = logging.Formatter(formatter_string)
logging.basicConfig(format=formatter_string, level=logging.INFO)

[
    vault_address,
    vautl_k8s_auth_mount,
    vault_role,
    vault_injector_id,
    paths_source        ] = load_environment()

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
    vault_Secret.prepare_connection(
        vault_addres=vault_address,
        vault_k8s_role=vault_role,
        k8s_jwt_token=k8s_jwt_token,
        auth_path=vautl_k8s_auth_mount
        )

# if vault injector value not provided, namespace name will be used
if vault_injector_id is None:
    vault_injector_id = k8s_namespace

k8s_Secret.prepare_connection(k8s_namespace, vault_injector_id)

vault_secrets = []

if paths_source.path_file:
    logging.info('SYSTEM | Loading secrets via file paths source')
    with open(paths_source.path, 'r') as hc_paths:
        path_lines = hc_paths.readlines()
        for path in path_lines:
            path = path.strip()
            new_secrets = vault_Secret.pull_secrets(path)
            vault_secrets = [*vault_secrets, *new_secrets]

elif paths_source.vault_secret:
    logging.info('SYSTEM | Loading secrets via Vault secret paths source')
    path_secret = vault_Secret.pull_secrets(paths_source.path)[0]
    secret_paths = path_secret.secret_data['vault-injector-paths']
    for path in secret_paths:
        new_secrets = vault_Secret.pull_secrets(path)
        vault_secrets = [*vault_secrets, *new_secrets]

#creating k8s secrets from vault objects
list(map(k8s_Secret.upload_vault_secret, vault_secrets))
k8s_Secret.remove_untrackable_secrets()