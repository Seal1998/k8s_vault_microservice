import os
from kubernetes import config
from core.helpers import get_pod_namespace
from core.k8s_secret_operator import KubeSecretOperator

config.load_incluster_config()

env = os.environ

namespace = get_pod_namespace()

if 'VAULT_INJECTOR_ID' in env.keys():
    vault_injector_id = env['VAULT_INJECTOR_ID']
else:
    vault_injector_id = namespace

secrets_operator = KubeSecretOperator(namespace, check_permissions=False)

injector_secrets = secrets_operator.list_secrets(label_dict={'vault-injector': vault_injector_id})
secrets_to_delete = tuple(secret.metadata.name for secret in injector_secrets)

for secret in secrets_to_delete:
    secrets_operator.delete_secret(secret_name=secret)