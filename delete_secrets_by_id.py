import os
from kubernetes import config
from core.helpers import get_pod_namespace
from core.k8s_secret_operator import KubeSecretOperator

config.load_kube_config()

env = os.environ

vault_id = env['VAULT_INJECTOR_ID']
namespace = get_pod_namespace()

secrets_operator = KubeSecretOperator(namespace, check_permissions=False)

injector_secrets = secrets_operator.list_secrets(label_dict={'vault-injector': vault_id})
secrets_to_delete = tuple(secret.metadata.name for secret in injector_secrets)

for secret in secrets_to_delete:
    secrets_operator.delete_secret(secret_name=secret)