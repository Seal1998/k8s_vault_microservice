import os, urllib3
from core.logging import system_logger
from collections import namedtuple
from kubernetes import config
from pathlib import Path
from core.helpers import get_pod_namespace, get_pod_jwt
from core.injector_operator import InjectorOperator
from core import VaultOperator, KubeInjector

def load_environment():
    env = os.environ

    #source_fields = ['vault_secret', 'path_file', 'path']
    source_fields = ['vault_config_path', 'k8s_configmap_name']
    ConfigSource = namedtuple('Source', source_fields, defaults=(None,)*len(source_fields)) 

    required_vars = [
                        'VAULT_ADDR',
                        'VAULT_ROLE'
                    ]
    optional_vars = [
                        'VAULT_INJECTOR_ID',
                        'VAULT_K8S_AUTH_MOUNT',
                        'VAULT_NAMESPACE'
                    ]
    config_source_vars = [
                        'VAULT_SECRET_CONFIG', 
                        'VAULT_CONFIGMAP_CONFIG'
                        ]
    #required vars
    variables = []
    if all(env_var in env.keys() for env_var in required_vars):
        system_logger.info('BASE ENV - OK')
        variables = [*variables, *[env[var] for var in required_vars]]
    else:
        system_logger.error(f'Not all required env vars defined {required_vars}')
        exit(1)

    for optional_var in optional_vars:
        if optional_var not in env.keys():
            variables.append(None)
        else:
            variables.append(env[optional_var])

    if all(env_var in env.keys() for env_var in config_source_vars):
        system_logger.error('Can`t use several config sources. Specify VAULT_SECRET_CONFIG or VAULT_CONFIGMAP_CONFIG')
        exit(1)
    elif not any(env_var in env.keys() for env_var in config_source_vars):
        system_logger.error('Config sources not specified. Specify VAULT_SECRET_CONFIG or VAULT_CONFIGMAP_CONFIG')
        exit(1)
    elif 'VAULT_SECRET_CONFIG' in env.keys():
        system_logger.info('Using Vault secret as Vault-Injector configuration source')
        variables.append(ConfigSource(vault_config_path=env['VAULT_SECRET_CONFIG']))
    elif 'VAULT_CONFIGMAP_CONFIG' in env.keys():
        system_logger.info('Using k8s configmap as Vault-Injector configuration source')
        variables.append(ConfigSource(k8s_configmap_name=env['VAULT_CONFIGMAP_CONFIG']))

    return variables

#disable self signed certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#non k8s dev args
try:# kostyl.py
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
    vault_namespace,
    config_source        ] = load_environment()

vault_operator = VaultOperator(address=vault_address, verify_ssl=False)

#k8s vault globals
if dev_mode:
    config.load_kube_config()
    vault_token = dev_vault_token
    k8s_namespace = dev_k8s_namespace
    vault_operator.prepare_connection(vault_token=dev_vault_token, vault_namespace=vault_namespace)
else:
    config.load_incluster_config()
    k8s_namespace = get_pod_namespace()
    k8s_jwt_token = get_pod_jwt()
    #vault
    vault_operator.prepare_connection(vault_k8s_role=vault_role, k8s_jwt_token=k8s_jwt_token,
                            vault_k8s_auth_mount=vault_k8s_auth_mount, vault_namespace=vault_namespace)



if not vault_injector_id:
    system_logger.info(f'Injector id not defined. ID will be set to namespace name')
    vault_injector_id = k8s_namespace
    
k8s_injector = KubeInjector(k8s_namespace, vault_injector_id)

injector = InjectorOperator(vault_operator, k8s_injector, config_source.vault_config_path, config_source.k8s_configmap_name)

injector.process_excluded_secrets()
injector.process_simple_secrets()
injector.process_complex_secrets()
injector.upload_secrets_to_kubernetes()
injector.clean_up()