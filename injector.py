import os
from core.logging import system_logger
from collections import namedtuple
from kubernetes import config, client
from pathlib import Path
from core.helpers import base64_encode_string, get_pod_namespace, get_pod_jwt, validate_vault_secret
from core import k8s_Secret, Vault

def load_environment():
    env = os.environ

    source_fields = ['vault_secret', 'path_file', 'path']
    Source = namedtuple('Source', source_fields, defaults=(None,)*len(source_fields)) 

    required_vars = [
                        'VAULT_ADDR',
                        'VAULT_ROLE'
                    ]
    optional_vars = [
                        'VAULT_INJECTOR_ID',
                        'VAULT_K8S_AUTH_MOUNT'
                    ]
    path_source_vars = [
                        'VAULT_PATHS_FILE', 
                        'VAULT_PATHS_SECRET'
                        ]
    #required vars
    variables = []
    if all(env_var in env.keys() for env_var in required_vars):
        system_logger.info('SYSTEM | BASE ENV - OK')
        variables = [*variables, *[env[var] for var in required_vars]]
    else:
        system_logger.error(f'Not all required env vars defined {required_vars}')
        exit(1)

    for optional_var in optional_vars:
        if optional_var not in env.keys():
            variables.append(None)
        else:
            variables.append(env[optional_var])

    if all(env_var in env.keys() for env_var in path_source_vars):
        system_logger.error('Can`t use several path sources. Specify VAULT_PATHS_FILE or VAULT_PATHS_SECRET')
        exit(1)
    elif 'VAULT_PATHS_FILE' not in env.keys() and \
        'VAULT_PATHS_SECRET' not in env.keys():
        system_logger.error('Paths sources not specified. Specify VAULT_PATHS_FILE or VAULT_PATHS_SECRET')
        exit(1)
    elif 'VAULT_PATHS_FILE' in env.keys():
        system_logger.info('Using path file as Vault paths source')
        variables.append(Source(path_file=True, path=env['VAULT_PATHS_FILE']))
    elif 'VAULT_PATHS_SECRET' in env.keys():
        system_logger.info('Using Vault secret as Vault paths source')
        variables.append(Source(vault_secret=True, path=env['VAULT_PATHS_SECRET']))

    return variables

#non k8s dev args
try:
    dev_vault_token = os.environ['DEV_VAULT_TOKEN']
    dev_k8s_namespace = os.environ['DEV_K8S_NS']
    dev_mode = True
except:
    dev_mode = False

[
    vault_address,
    vault_role,
    vault_injector_id,
    vault_k8s_auth_mount,
    paths_source        ] = load_environment()

vault = Vault(address=vault_address, verify_ssl=False)

#k8s vault globals
if dev_mode:
    config.load_kube_config()
    vault_token = dev_vault_token
    k8s_namespace = dev_k8s_namespace
    vault.prepare_connection(vault_token=dev_vault_token)
else:
    config.load_incluster_config()
    k8s_namespace = get_pod_namespace()
    k8s_jwt_token = get_pod_jwt()
    #vault
    vault.prepare_connection(vault_k8s_role=vault_role, k8s_jwt_token=k8s_jwt_token,
                            vault_k8s_auth_mount=vault_k8s_auth_mount)

if not vault_injector_id:
    system_logger.info(f'Injector id not defined. ID will be set to namespace name')
    vault_injector_id = k8s_namespace
k8s_Secret.prepare_connection(k8s_namespace, vault_injector_id)

if paths_source.path_file:
    system_logger.info('Loading secrets via file paths source')
    with open(paths_source.path, 'r') as hc_paths:
        secret_paths = tuple(path.strip() for path in hc_paths.readlines())

elif paths_source.vault_secret:
    system_logger.info('Loading secrets via Vault secret paths source')
    path_secret = vault.get_secrets_by_path(paths_source.path)
    if not path_secret:
        system_logger.info('Cannot pull paths from Vault')
        exit(1)
    else:
        path_secret = path_secret
    secret_paths = path_secret.secret_data['vault-injector-paths']

#exclude and not exclude paths
secret_exclude_paths_raw = filter(lambda path: path[0]=='!', secret_paths)
secret_non_exclude_paths = tuple(filter(lambda path: path[0]!='!', secret_paths))
secret_exclude_paths = (path[1:] for path in secret_exclude_paths_raw)
list(map(vault.exclude_secret, secret_exclude_paths))

#filter and proceed wildcard and casual paths
secret_wildcard_paths = filter(lambda path: path[-1] in ('*','+'), secret_non_exclude_paths)
secret_casual_paths = filter(lambda path: path[-1] not in ('*','+'), secret_non_exclude_paths)
vault_secrets_wildcard_raw = tuple(map(vault.get_secrets_by_path, secret_wildcard_paths)) #-> generator of tuples with secrets
vault_secrets_casual_raw = map(vault.get_secrets_by_path, secret_casual_paths) #-> generator of secrets

vault_secrets_wildcard = (secret for subtuple in vault_secrets_wildcard_raw if subtuple for secret in subtuple) #generator
vault_secrets_casual = (secret for secret in vault_secrets_casual_raw) #generator
#merge wildcard and casual generators to one tuple
vault_secrets = (*vault_secrets_wildcard, *vault_secrets_casual) #tuple

#remove False requests
vault_secrets = tuple(filter(lambda secret: secret,vault_secrets))

#filter vault secrets
valid_vault_secrets = filter(lambda v_secret: validate_vault_secret(v_secret), vault_secrets)
invalid_vault_secrets = filter(lambda v_secret: not validate_vault_secret(v_secret), vault_secrets)

for inv_s in invalid_vault_secrets:
    system_logger.warning(f'SYSTEM | {inv_s.full_path} is invalid. Upload aborted')

#creating k8s secrets from vault objects
list(map(k8s_Secret.upload_vault_secret, valid_vault_secrets))
k8s_Secret.remove_untrackable_secrets()